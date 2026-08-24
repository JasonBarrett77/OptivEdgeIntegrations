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
        "persisted": persisted,
        "raw_sources": raw,
        "findings": findings,
    }
