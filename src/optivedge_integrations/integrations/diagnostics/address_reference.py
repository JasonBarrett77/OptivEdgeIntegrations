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


def _build_outcome(enforcement_point: EnforcementPoint) -> dict[str, Any]:
    """Run the real address build and report what it does.

    A rule error naming one object is often downstream of the whole build failing:
    resolve_rule_address_refs() raises on the FIRST unresolved member and source is
    processed before destination, so "every rule fails on a NET-* source" looks identical
    to "this point has no objects at all". Running the build settles which.

    Several paths that used to return an empty result now raise deliberately - an absent
    @loc, conflicting pushed definitions, an unrecognised pushed payload root. Each is a
    better failure than a silent wrong answer, but each also converts a partial result
    into none at all, so the exception text is the thing worth reading.
    """
    from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import (
        build_normalized_addresses,
    )

    try:
        objects, groups = build_normalized_addresses(enforcement_point)
    except Exception as exc:  # noqa: BLE001 - the exception IS the diagnosis
        return {
            "succeeded": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    return {
        "succeeded": True,
        "object_count": len(objects),
        "group_count": len(groups),
    }


def _pushed_payload_roots(enforcement_point: EnforcementPoint) -> dict[str, Any]:
    """Top-level keys of each pushed payload, before any parsing.

    A product whose response roots at neither `shared` nor `policy.panorama` - a cloud
    NGFW is a different product from VM-series, not merely a different configuration -
    would show up here as an unfamiliar key.
    """
    roots: dict[str, Any] = {}
    for label, snapshot in (
        ("pushed_non_vsys", latest_pushed_shared_snapshot(enforcement_point)),
        ("pushed_vsys", latest_pushed_vsys_snapshot(enforcement_point)),
    ):
        if snapshot is None:
            roots[label] = None
            continue
        payload = snapshot.payload
        if isinstance(payload, dict):
            roots[label] = {"type": "dict", "keys": sorted(payload)[:12]}
        else:
            roots[label] = {"type": type(payload).__name__, "value": repr(payload)[:200]}
    return roots


def _owner_totals(enforcement_point: EnforcementPoint) -> dict[str, Any]:
    """How many objects each owner holds, and whether the group is even eligible for the
    shared pass.

    The decisive number when shared references fail wholesale: if the GROUP holds zero
    objects, the shared pass either never ran or failed, and the object named in a rule
    error is incidental. `group_in_scope_for_shared_pass` separates "it ran and failed"
    from "it was never selected" - get_in_scope_appliance_groups() picks groups by having
    at least one in-scope enforcement point, so a group whose points are all out of scope
    is skipped silently.
    """
    from optivedge_integrations.integrations.platforms.pan_os.flows import (
        get_in_scope_appliance_groups,
    )

    group = enforcement_point.appliance_group
    totals: dict[str, Any] = {
        "enforcement_point": {
            "address_objects": enforcement_point.address_objects.count(),
            "address_groups": enforcement_point.address_groups.count(),
            "regions": enforcement_point.regions.count(),
        },
        "appliance_group": None,
        "group_in_scope_for_shared_pass": None,
    }
    if group is None:
        return totals

    totals["appliance_group"] = {
        "address_objects": group.address_objects.count(),
        "address_groups": group.address_groups.count(),
        "regions": group.regions.count(),
    }
    eligible = get_in_scope_appliance_groups(enforcement_point.management_station)
    totals["group_in_scope_for_shared_pass"] = any(g.pk == group.pk for g in eligible)
    return totals


def explain_address_reference(enforcement_point: EnforcementPoint, name: str) -> dict[str, Any]:
    """Report where `name` is, where the device says it should be, and any gap."""
    persisted = _persisted(enforcement_point, name)
    raw = _raw_sources(enforcement_point, name)
    appliances = _appliance_context(enforcement_point)
    build = _build_outcome(enforcement_point)
    totals = _owner_totals(enforcement_point)
    payload_roots = _pushed_payload_roots(enforcement_point)

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

    group_totals = totals.get("appliance_group") or {}
    if totals.get("group_in_scope_for_shared_pass") is False:
        findings.insert(0, (
            "This appliance group is NOT selected by get_in_scope_appliance_groups(), so the "
            "shared pass never runs for it and nothing owns its shared scope. That selection "
            "requires at least one in-scope enforcement point on the group."
        ))
    elif group_totals and not any(group_totals.values()) and build.get("succeeded"):
        findings.insert(0, (
            "The appliance group holds ZERO objects while the build for this point succeeds and "
            "produces shared-scoped ones. The shared pass either never ran or failed - look for "
            "an AddressNormalizationFailed event naming 'shared scope for appliance group'. Every "
            "shared reference here will be unresolved, so the object named in a rule error is "
            "incidental."
        ))

    if not build["succeeded"]:
        findings.insert(0, (
            f"ADDRESS NORMALIZATION FAILS FOR THIS POINT: {build['error_type']}: {build['error']}. "
            f"Every rule here will report an unresolved reference to whatever its first source "
            f"member happens to be - the named object is a symptom, not the cause. Fix this first."
        ))
    elif build["object_count"] == 0:
        findings.insert(0, (
            "The address build succeeds but yields NO objects for this point, so every rule "
            "reference will be unresolved regardless of the name in the error."
        ))

    for label, root in payload_roots.items():
        if isinstance(root, dict) and root.get("type") == "dict":
            keys = root["keys"]
            if not ({"shared", "policy"} & set(keys)):
                findings.append(
                    f"{label} payload roots at {keys} - neither 'shared' nor 'policy'. "
                    f"pushed_shared() raises on an unrecognised root, which fails the whole build. "
                    f"Before that raise was added it returned {{}} silently, which is why this "
                    f"could have worked previously while losing objects."
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
        "build_outcome": build,
        "owner_totals": totals,
        "pushed_payload_roots": payload_roots,
        "persisted": persisted,
        "raw_sources": raw,
        "findings": findings,
    }
