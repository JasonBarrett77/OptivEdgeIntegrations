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

Both payload shapes were MEASURED on pan-fw-111 on 2026-09-22, and the guess this module
carried until then - "a list of entry dicts, scan every string leaf" - was wrong for both, so
every EDL and every FQDN object resolved to nothing. Silently: an object with no resolved
entries is indistinguishable from one that was never collected.

  * `request system external-list show` returns members under
    result > external-list > valid-members > member, not result > entry. See
    collectors/external_list.py, which also handles the paging this response needs.
  * `show dns-proxy fqdn all` returns a plain text table, not XML at all - a bare string
    payload, so `payload.get("entry")` never even had a dict to ask.

IPv6 is out of scope for interval search, so AAAA answers and the literal `unknown` placeholder
the device prints for an unresolved family are skipped. An FQDN that resolves ONLY to IPv6
therefore lands on zero intervals and falls back to "excluded from IP-semantic search" - the
same place it was before, and the right answer until v6 intervals exist.
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
from optivedge_integrations.integrations.platforms.pan_os.collectors.external_list import (
    members_from_result,
    total_valid_from_result,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import derive_address_fields
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import merge_intervals
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


def _edl_result_from_snapshot(snapshot: Snapshot) -> Any:
    """The `result` subtree of a collected external-list snapshot.

    The payload is stored in the device's own shape, whether it arrived as one response or was
    paged together by the collector, so one reader serves both.
    """
    payload = snapshot.payload
    if not isinstance(payload, dict):
        return None
    result = payload.get("response", payload)
    if isinstance(result, dict):
        result = result.get("result", result)
    return result


def _edl_members_from_snapshot(snapshot: Snapshot) -> list[str]:
    """Valid members of a collected external-list snapshot."""
    return members_from_result(_edl_result_from_snapshot(snapshot))


def _fqdn_payload_text(payload: Any) -> str:
    """The FQDN cache table as text.

    Measured shape is a bare string. The dict unwrapping is for a payload that arrives still
    wrapped in its response envelope, which costs nothing to tolerate.
    """
    if isinstance(payload, str):
        return payload
    node: Any = payload
    for key in ("response", "result"):
        if isinstance(node, dict) and key in node:
            node = node[key]
    if isinstance(node, dict):
        node = node.get("#text")
    return node if isinstance(node, str) else ""


def _fqdn_addresses_by_name(payload: Any) -> dict[str, list[str]]:
    """Parse `show dns-proxy fqdn all`'s text table into {fqdn: [address, ...]}.

    The table, as measured:

        FQDN Table : Request time 2026-09-22 22:07:46
        ------------------------------------------------------------------------
        \tIP Address
        ------------------------------------------------------------------------

        VSYS : (using mgmt-obj dnsproxy object)
        \tShared
        \tvsys1

        example.com
        \t104.20.23.154
        \t2606:4700:10::6814:179a

        sinkhole.paloaltonetworks.com
        \t198.135.184.22
        \t::  unknown

    Structure carries the meaning: a name sits at column zero, its answers are indented under
    it. Rather than pattern-match the banner lines - which would make the parser a hostage to
    the exact wording of a header - anything at column zero that cannot be a hostname (it holds
    a space or a colon, or it is the rule-off) simply ends the current block. The indented noise
    under `VSYS :` (`Shared`, `vsys1`, the `IP Address` column heading) needs no special case
    either: it is not an IPv4 literal, so it is not an address.
    """
    addresses: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in _fqdn_payload_text(payload).splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        if line[0].isspace():
            if current is not None:
                addresses.setdefault(current, []).append(line.strip())
            continue
        token = line.strip()
        current = None if (" " in token or ":" in token or token.startswith("-")) else token.lower()
    return addresses


def _intervals_from_values(values: list[str]) -> list[tuple[int, int]]:
    intervals: list[tuple[int, int]] = []
    for value in values:
        interval = _parse_ipv4_literal_interval(value)
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


def _record_completeness(address_object: AddressObject, *, truncated: bool, source_total: int | None) -> None:
    """Mark whether this object's resolved content is the whole of what the device reported."""
    if (
        address_object.resolved_content_truncated == truncated
        and address_object.resolved_content_source_total == source_total
    ):
        return
    address_object.resolved_content_truncated = truncated
    address_object.resolved_content_source_total = source_total
    address_object.save(update_fields=["resolved_content_truncated", "resolved_content_source_total"])


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
    fqdn_addresses = _fqdn_addresses_by_name(fqdn_snapshot.payload) if fqdn_snapshot is not None else {}

    for address_object in candidates:
        address_object.resolved_entries.all().delete()
        # Cleared on every pass, so a list that shrank below the ceiling - or an object whose
        # snapshot has gone - never keeps a stale "incomplete" mark from an earlier refresh.
        truncated = False
        source_total = None

        if address_object.address_type == AddressObject.TYPE_EDL:
            snapshot = _latest_external_list_snapshot(
                appliance.pk,
                scope_name=f"{enforcement_point.vsys_name}:{address_object.name}",
            )
            if snapshot is None:
                _record_completeness(address_object, truncated=False, source_total=None)
                continue
            result = _edl_result_from_snapshot(snapshot)
            members = members_from_result(result)
            source_total = total_valid_from_result(result)
            # Measured against the DEVICE's count, never against the members in hand - those
            # two are equal exactly when nothing was dropped, which is the thing being tested.
            truncated = source_total is not None and len(members) < source_total
            intervals = _intervals_from_values(members)
            source_snapshot = snapshot
        else:
            if fqdn_snapshot is None:
                _record_completeness(address_object, truncated=False, source_total=None)
                continue
            matching = fqdn_addresses.get((address_object.normalized_value or "").strip().lower())
            if not matching:
                _record_completeness(address_object, truncated=False, source_total=None)
                continue
            intervals = _intervals_from_values(matching)
            source_snapshot = fqdn_snapshot

        _record_completeness(address_object, truncated=truncated, source_total=source_total)

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
