"""Explain why a rule's address reference did or did not resolve.

`unresolved address reference: <name>` says a name is in neither the enforcement point's
objects nor its appliance group's. It does not say why, and the answer is usually in the
raw snapshot rather than in the normalized rows: which read carried the entry, what @loc
it had, and therefore which owner should hold it.

This walks the same path normalization does and reports each step, so the gap between
"the device sent it" and "we stored it" is visible instead of inferred.

Read-only. Safe to run against a deployment mid-failure.
"""

from __future__ import annotations

from typing import Any

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressObject,
    EnforcementPoint,
    Region,
    scope_for,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ensure_list,
    entry_provenance,
    merged_shared,
    merged_vsys_entry,
    pushed_shared,
    pushed_vsys_panorama,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    choose_local_appliance,
    is_panorama_managed,
    latest_merged_snapshot,
    latest_pushed_shared_snapshot,
    latest_pushed_vsys_snapshot,
)

OBJECT_NODES = ("address", "address-group", "external-list", "region")


def _persisted(enforcement_point: EnforcementPoint, name: str) -> dict[str, Any]:
    """Where the name currently is in normalized data, if anywhere."""
    group = enforcement_point.appliance_group
    found: list[dict[str, Any]] = []
    for model, kind in ((AddressObject, "address object"), (AddressGroup, "address group"), (Region, "region")):
        for owner_label, filters in (
            ("enforcement_point", {"enforcement_point": enforcement_point}),
            ("appliance_group", {"appliance_group": group} if group else None),
        ):
            if filters is None:
                continue
            for row in model.objects.filter(name=name, **filters):
                found.append({
                    "kind": kind,
                    "owner": owner_label,
                    "namespace_type": row.namespace_type,
                    "namespace_value": row.namespace_value,
                    "scope": scope_for(row.namespace_type),
                    "value": getattr(row, "value", None),
                })
    return {"rows": found, "resolvable": bool(found)}


def _entries_named(root: dict[str, Any], name: str) -> list[dict[str, Any]]:
    hits = []
    for node in OBJECT_NODES:
        container = root.get(node)
        if not isinstance(container, dict):
            continue
        for entry in ensure_list(container.get("entry")):
            if isinstance(entry, dict) and entry.get("@name") == name:
                raw_key, raw_value = entry_provenance(entry)
                hits.append({"node": node, "provenance_key": raw_key, "loc": raw_value})
    return hits


def _appliance_context(enforcement_point: EnforcementPoint) -> dict[str, Any]:
    """Which appliance the local reads resolve to, and what else is in the group.

    The two pushed reads are stored at DIFFERENT scopes: the per-vsys response on the
    enforcement point, the non-vsys response on the appliance group. When a group holds
    several appliances - a cloud NGFW presenting multiple instances, only one in scope -
    the group-scoped lookup takes the most recent snapshot on the GROUP, which need not
    come from the appliance the point actually reads. That asymmetry is invisible while
    pushed objects are scoped by read position, and becomes load-bearing once @loc routes
    shared objects to the non-vsys read.
    """
    group = enforcement_point.appliance_group
    chosen = choose_local_appliance(enforcement_point)
    context: dict[str, Any] = {
        "chosen_local_appliance": str(chosen) if chosen else None,
        "chosen_serial": getattr(chosen, "serial_number", None),
        "group_active_appliance": str(group.active_appliance) if group and group.active_appliance else None,
        "nodes": [str(node.appliance) for node in
                  enforcement_point.nodes.select_related("appliance").order_by("id")],
        "appliances_in_group": [],
    }
    if group is None:
        return context

    for appliance in group.appliances.order_by("hostname", "serial_number", "pk"):
        context["appliances_in_group"].append({
            "appliance": str(appliance),
            "serial_number": appliance.serial_number,
            "hostname": appliance.hostname,
            "is_chosen": chosen is not None and appliance.pk == chosen.pk,
            "snapshot_counts": {
                source_type: appliance.snapshots.filter(source_type=source_type).count()
                for source_type in ("show_merged_config",)
            },
        })

    group_shared = group.snapshots.filter(source_type="show_pushed_shared_policy")
    context["group_pushed_shared_snapshots"] = group_shared.count()
    context["duplicate_hostnames_in_group"] = sorted(
        {a["hostname"] for a in context["appliances_in_group"]
         if [b["hostname"] for b in context["appliances_in_group"]].count(a["hostname"]) > 1
         and a["hostname"]}
    )
    return context


def _raw_sources(enforcement_point: EnforcementPoint, name: str) -> dict[str, Any]:
    """Which collected read carried the name, and with what @loc."""
    sources: dict[str, Any] = {}

    merged = latest_merged_snapshot(enforcement_point)
    if merged is None:
        sources["merged"] = {"snapshot": None}
    else:
        sources["merged"] = {
            "snapshot": str(merged),
            "vsys_node": _entries_named(
                merged_vsys_entry(merged.payload, enforcement_point.vsys_name), name),
            "shared_node": _entries_named(merged_shared(merged.payload), name),
        }

    pushed_shared_snapshot = latest_pushed_shared_snapshot(enforcement_point)
    if pushed_shared_snapshot is None:
        sources["pushed_non_vsys"] = {
            "snapshot": None,
            "note": "absent - expected when the station is not Panorama-managed"
                    if not is_panorama_managed(enforcement_point) else
                    "MISSING for a Panorama-managed point - shared scope cannot be built",
        }
    else:
        try:
            root = pushed_shared(pushed_shared_snapshot.payload)
        except ValueError as exc:
            sources["pushed_non_vsys"] = {"snapshot": str(pushed_shared_snapshot), "error": str(exc)}
        else:
            sources["pushed_non_vsys"] = {
                "snapshot": str(pushed_shared_snapshot), "entries": _entries_named(root, name)}

    pushed_vsys_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    if pushed_vsys_snapshot is None:
        sources["pushed_vsys"] = {"snapshot": None}
    else:
        try:
            root = pushed_vsys_panorama(pushed_vsys_snapshot.payload)
        except ValueError as exc:
            sources["pushed_vsys"] = {"snapshot": str(pushed_vsys_snapshot), "error": str(exc)}
        else:
            sources["pushed_vsys"] = {
                "snapshot": str(pushed_vsys_snapshot), "entries": _entries_named(root, name)}
    return sources


def explain_address_reference(enforcement_point: EnforcementPoint, name: str) -> dict[str, Any]:
    """Report where `name` is, where the device says it should be, and any gap."""
    persisted = _persisted(enforcement_point, name)
    raw = _raw_sources(enforcement_point, name)
    appliances = _appliance_context(enforcement_point)

    findings: list[str] = []
    seen_in_pushed = [
        (source, entry)
        for source in ("pushed_non_vsys", "pushed_vsys")
        for entry in (raw.get(source) or {}).get("entries", []) or []
    ]
    local_hits = (
        ((raw.get("merged") or {}).get("vsys_node") or [])
        + ((raw.get("merged") or {}).get("shared_node") or [])
    )

    for source in ("pushed_non_vsys", "pushed_vsys"):
        error = (raw.get(source) or {}).get("error")
        if error:
            findings.append(
                f"{source} could not be parsed: {error}. Normalization would have raised here, "
                f"so nothing from this read was stored."
            )
        if (raw.get(source) or {}).get("note", "").startswith("MISSING"):
            findings.append(f"{source}: {(raw.get(source) or {}).get('note')}")

    for source, entry in seen_in_pushed:
        if entry["provenance_key"] != "@loc" or not entry["loc"]:
            findings.append(
                f"{source} carries {name!r} under <{entry['node']}> with NO @loc marker "
                f"(provenance key {entry['provenance_key']!r}). pushed_entry_scope() raises on "
                f"that, which fails the whole build for this point - so every object from this "
                f"read is missing, not just this one."
            )
        else:
            expected = "appliance_group" if entry["loc"] == "shared" else "enforcement_point"
            findings.append(
                f"{source} carries {name!r} under <{entry['node']}> with @loc={entry['loc']!r} "
                f"-> should be owned by the {expected}."
            )

    if not seen_in_pushed and not local_hits:
        findings.append(
            f"{name!r} appears in NO collected source for this enforcement point. The rule "
            f"references a name the device never reported here - check whether the snapshots "
            f"are stale, or whether the reference resolves from a scope not collected."
        )

    in_group = appliances.get("appliances_in_group") or []
    if len(in_group) > 1:
        findings.append(
            f"The appliance group holds {len(in_group)} appliances; local reads resolve to "
            f"{appliances['chosen_local_appliance']!r}. The per-vsys pushed response is stored on "
            f"the enforcement point, but the non-vsys response is stored on the GROUP - so shared "
            f"scope can come from a different appliance than the point's own reads. Compare the "
            f"snapshot identities above."
        )
    if appliances.get("duplicate_hostnames_in_group"):
        findings.append(
            f"Appliances in this group share hostname(s) "
            f"{appliances['duplicate_hostnames_in_group']}, so choose_local_appliance()'s "
            f"hostname ordering cannot distinguish them and falls through to serial then pk."
        )
    if appliances.get("group_pushed_shared_snapshots", 0) > 1:
        findings.append(
            f"{appliances['group_pushed_shared_snapshots']} non-vsys pushed snapshots exist on this "
            f"group; the newest wins regardless of which appliance produced it."
        )

    if persisted["resolvable"]:
        findings.append(
            "The name IS persisted, so a rule failing on it now would be a lookup problem "
            "rather than a collection one."
        )
    elif seen_in_pushed or local_hits:
        findings.append(
            "The device reported it but nothing persisted it - the gap is in normalization, "
            "not collection."
        )

    return {
        "enforcement_point": str(enforcement_point),
        "vsys_name": enforcement_point.vsys_name,
        "appliance_group": str(enforcement_point.appliance_group) if enforcement_point.appliance_group else None,
        "panorama_managed": is_panorama_managed(enforcement_point),
        "name": name,
        "appliance_context": appliances,
        "persisted": persisted,
        "raw_sources": raw,
        "findings": findings,
    }
