"""PAN-OS runtime EDL/FQDN resolved-content normalization.

Turns collected show_external_list / show_dns_proxy_fqdn_all snapshots (see
platforms/pan_os/collectors/external_list.py and dns_proxy_fqdn.py) into
AddressObjectResolvedEntry rows on the matching EDL(ip)/FQDN AddressObject.

This is deliberately best-effort, unlike the rest of this normalization package's "raise loudly
on anything unresolved" philosophy: the data parsed here is external operational cache content
(an EDL's downloaded list, a DNS resolver's cache), not PAN-OS configuration that must fully
validate - a malformed or unexpected entry here should be skipped, not abort the whole refresh.
An object that ends up with zero resolved entries (never collected yet, or nothing parseable)
simply falls back to today's "excluded from IP-semantic search" behavior, with no special-case
handling required downstream.

NOTE: the exact per-entry field names in a real `request system external-list show` or
`show dns-proxy fqdn all` response haven't been verified against a live payload yet (only the
command syntax has been confirmed against a real device - see
/home/jason/.claude/plans/deep-bouncing-shamir.md). Entry-parsing here scans every string leaf
value in each entry dict rather than assuming a specific field name, to be resilient to that
uncertainty; revisit once a real payload is captured.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.db.models import Q
from django.utils import timezone

from optivedge_integrations.integrations.models import (
    AddressObject,
    AddressObjectResolvedEntry,
    EnforcementPoint,
    SecurityRuleDestinationAddressRef,
    SecurityRuleSourceAddressRef,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import derive_address_fields
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import ensure_list, merge_intervals
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
    classify_literal_address_type,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import choose_local_appliance


@dataclass(slots=True)
class NormalizedDynamicAddressContent:
    updated_address_objects: list[AddressObject]
    total_resolved_entries: int


def _candidate_dynamic_address_objects(enforcement_point: EnforcementPoint) -> list[AddressObject]:
    """EDL(ip)/FQDN address objects actually referenced by this enforcement point's rules -
    directly or via any level of nested static group, already flattened onto ref rows by
    resolve_static_group_members - not merely present in the address book."""
    candidate_type_filter = Q(address_object__address_type=AddressObject.TYPE_FQDN) | Q(
        address_object__address_type=AddressObject.TYPE_EDL,
        address_object__edl_list_type="ip",
    )
    source_ids = (
        SecurityRuleSourceAddressRef.objects.filter(security_rule__enforcement_point=enforcement_point)
        .filter(candidate_type_filter)
        .values_list("address_object_id", flat=True)
    )
    destination_ids = (
        SecurityRuleDestinationAddressRef.objects.filter(security_rule__enforcement_point=enforcement_point)
        .filter(candidate_type_filter)
        .values_list("address_object_id", flat=True)
    )
    candidate_ids = set(source_ids) | set(destination_ids)
    if not candidate_ids:
        return []
    return list(AddressObject.objects.filter(pk__in=candidate_ids))


def _iter_leaf_strings(node: Any):
    if isinstance(node, dict):
        for value in node.values():
            yield from _iter_leaf_strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_leaf_strings(item)
    elif isinstance(node, str):
        yield node


def _parse_ipv4_literal_interval(raw_value: str) -> tuple[int, int] | None:
    address_type = classify_literal_address_type(raw_value)
    if address_type is None:
        return None
    literal_value = raw_value.strip()
    if address_type == AddressObject.TYPE_IP_NETMASK and "/" not in literal_value:
        literal_value = f"{literal_value}/32"
    _normalized, start_int, end_int, _num_hosts, _is_any = derive_address_fields(address_type, literal_value)
    if start_int is None or end_int is None:
        return None
    return start_int, end_int


def _entries_from_snapshot(snapshot: Snapshot) -> list[dict[str, Any]]:
    payload = snapshot.payload
    entries = payload.get("entry") if isinstance(payload, dict) else None
    return [entry for entry in ensure_list(entries) if isinstance(entry, dict)]


def _intervals_from_entries(entries: list[dict[str, Any]]) -> list[tuple[int, int]]:
    intervals: list[tuple[int, int]] = []
    for entry in entries:
        for leaf in _iter_leaf_strings(entry):
            interval = _parse_ipv4_literal_interval(leaf)
            if interval is not None:
                intervals.append(interval)
    return merge_intervals(intervals)


def _latest_external_list_snapshot(appliance_id: int, *, scope_name: str) -> Snapshot | None:
    return (
        Snapshot.objects.filter(
            appliance_id=appliance_id,
            source_type="show_external_list",
            scope_name=scope_name,
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def _latest_fqdn_cache_snapshot(appliance_id: int) -> Snapshot | None:
    return (
        Snapshot.objects.filter(appliance_id=appliance_id, source_type="show_dns_proxy_fqdn_all")
        .order_by("-collected_at", "-pk")
        .first()
    )


def _fqdn_entries_matching(entries: list[dict[str, Any]], normalized_fqdn: str) -> list[dict[str, Any]]:
    matching = []
    for entry in entries:
        leaf_values = {value.strip().lower() for value in _iter_leaf_strings(entry)}
        if normalized_fqdn in leaf_values:
            matching.append(entry)
    return matching


def normalize_enforcement_point_dynamic_address_content(
    enforcement_point: EnforcementPoint,
) -> NormalizedDynamicAddressContent:
    candidates = _candidate_dynamic_address_objects(enforcement_point)
    if not candidates:
        return NormalizedDynamicAddressContent(updated_address_objects=[], total_resolved_entries=0)

    appliance = choose_local_appliance(enforcement_point)
    if appliance is None:
        return NormalizedDynamicAddressContent(updated_address_objects=[], total_resolved_entries=0)

    updated: list[AddressObject] = []
    total_entries = 0
    collected_at = timezone.now()

    fqdn_snapshot = _latest_fqdn_cache_snapshot(appliance.pk)
    fqdn_entries = _entries_from_snapshot(fqdn_snapshot) if fqdn_snapshot is not None else []

    for address_object in candidates:
        address_object.resolved_entries.all().delete()

        if address_object.address_type == AddressObject.TYPE_EDL:
            snapshot = _latest_external_list_snapshot(
                appliance.pk,
                scope_name=f"{enforcement_point.vsys_name}:{address_object.name}",
            )
            if snapshot is None:
                continue
            intervals = _intervals_from_entries(_entries_from_snapshot(snapshot))
            source_snapshot = snapshot
        else:
            if fqdn_snapshot is None:
                continue
            matching_entries = _fqdn_entries_matching(fqdn_entries, address_object.normalized_value)
            if not matching_entries:
                continue
            intervals = _intervals_from_entries(matching_entries)
            source_snapshot = fqdn_snapshot

        if not intervals:
            continue

        AddressObjectResolvedEntry.objects.bulk_create(
            AddressObjectResolvedEntry(
                address_object=address_object,
                ipv4_start_int=start,
                ipv4_end_int=end,
                source_snapshot=source_snapshot,
                collected_at=collected_at,
            )
            for start, end in intervals
        )
        total_entries += len(intervals)
        updated.append(address_object)

    return NormalizedDynamicAddressContent(
        updated_address_objects=updated,
        total_resolved_entries=total_entries,
    )
