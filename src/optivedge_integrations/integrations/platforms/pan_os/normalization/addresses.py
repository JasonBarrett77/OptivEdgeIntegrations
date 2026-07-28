"""PAN-OS address normalization helpers.

This module owns normalization of merged and pushed PAN-OS address objects and
address groups into enforcement-point scoped Django models.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import ipaddress
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressGroupMember,
    AddressGroupTag,
    AddressObject,
    AddressObjectTag,
    EnforcementPoint,
    FieldProvenance,
    PolicyObjectNamespace,
    PolicyObjectPrecedence,
    SecurityRule,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    classify_prov_type,
    ensure_list,
    entry_provenance,
    member_values,
    merged_shared,
    merged_vsys_entry,
    pushed_shared,
    pushed_vsys_panorama,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.regions import (
    build_normalized_regions,
    replace_regions,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    choose_local_appliance,
    latest_merged_snapshot,
    latest_predefined_ip_block_lists_snapshot,
    latest_predefined_url_lists_snapshot,
    latest_pushed_shared_snapshot,
    latest_pushed_vsys_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection


ANY_OBJECT_NAME = "any"


@dataclass(slots=True)
class NormalizedAddressTag:
    value: str
    prov: str
    position: int


@dataclass(slots=True)
class NormalizedAddressObject:
    source_snapshot: Snapshot
    config_source: str
    name: str
    namespace_type: str
    namespace_value: str
    precedence_rank: int
    address_type: str
    value: str
    normalized_value: str
    ipv4_start_int: int | None
    ipv4_end_int: int | None
    num_hosts: int | None
    is_any: bool
    is_edl: bool
    is_builtin: bool
    edl_list_type: str
    description: str
    raw_object: dict[str, Any]
    tags: list[NormalizedAddressTag]
    # (field_name, raw_key_or_ABSENT, raw_prov_value)
    field_provenance_data: list[tuple[str, Any, str | None]]


@dataclass(slots=True)
class NormalizedAddressGroup:
    source_snapshot: Snapshot
    config_source: str
    name: str
    namespace_type: str
    namespace_value: str
    precedence_rank: int
    dynamic_filter: str
    raw_group: dict[str, Any]
    tags: list[NormalizedAddressTag]
    members: list[NormalizedAddressTag]
    # (field_name, raw_key_or_ABSENT, raw_prov_value)
    field_provenance_data: list[tuple[str, Any, str | None]]


def external_list_value(entry: dict[str, Any]) -> tuple[str, Any, str | None, str]:
    """Return (value, raw_key, raw_prov_value, list_type) for an EDL address object entry.

    list_type is one of "ip"/"domain"/"url"/"imei"/"imsi" (whichever type node matched), or ""
    if no type node was recognized. Callers that only need the value/provenance can ignore the
    fourth element; it exists so config-normalization can record which runtime command variant
    (`request system external-list show type <list_type> ...`) applies to this EDL.
    """
    type_node = entry.get("type")
    if not isinstance(type_node, dict):
        return "", ABSENT, None, ""

    for list_type in ("ip", "domain", "url", "imei", "imsi"):
        list_node = type_node.get(list_type)
        if not isinstance(list_node, dict):
            continue
        url_node = list_node.get("url")
        if url_node is not None:
            value, rk, rv = scalar_value(url_node)
            return value, rk, rv, list_type
        # list_type name itself is the value; provenance from list_node's @loc
        rk, rv = entry_provenance(list_node)
        return list_type, rk, rv, list_type

    return "", ABSENT, None, ""


def derive_address_fields(address_type: str, value: str) -> tuple[str, int | None, int | None, int | None, bool]:
    raw_value = (value or "").strip()

    if address_type == AddressObject.TYPE_BUILTIN_ANY:
        return ("any", 0, 4_294_967_295, 4_294_967_296, True)

    if address_type == AddressObject.TYPE_EDL:
        return (raw_value, None, None, None, False)

    if address_type == AddressObject.TYPE_FQDN:
        return (raw_value.lower(), None, None, None, False)

    if address_type == AddressObject.TYPE_IP_NETMASK:
        try:
            network = ipaddress.ip_network(raw_value, strict=False)
        except ValueError:
            return (raw_value, None, None, None, False)
        if network.version != 4:
            return (str(network), None, None, None, False)
        return (
            str(network),
            int(network.network_address),
            int(network.broadcast_address),
            int(network.num_addresses),
            False,
        )

    if address_type == AddressObject.TYPE_IP_RANGE:
        try:
            start_text, end_text = [part.strip() for part in raw_value.split("-", 1)]
            start_ip = ipaddress.ip_address(start_text)
            end_ip = ipaddress.ip_address(end_text)
        except (ValueError, TypeError):
            return (raw_value, None, None, None, False)
        if start_ip.version != 4 or end_ip.version != 4:
            return (f"{start_ip}-{end_ip}", None, None, None, False)
        start_int = int(start_ip)
        end_int = int(end_ip)
        if end_int < start_int:
            return (f"{start_ip}-{end_ip}", None, None, None, False)
        return (
            f"{start_ip}-{end_ip}",
            start_int,
            end_int,
            end_int - start_int + 1,
            False,
        )

    return (raw_value, None, None, None, False)


def build_builtin_any_object(source_snapshot: Snapshot) -> NormalizedAddressObject:
    normalized_value, start_int, end_int, num_hosts, is_any = derive_address_fields(
        AddressObject.TYPE_BUILTIN_ANY,
        ANY_OBJECT_NAME,
    )
    return NormalizedAddressObject(
        source_snapshot=source_snapshot,
        config_source=SecurityRule.SOURCE_LOCAL,
        name=ANY_OBJECT_NAME,
        namespace_type=PolicyObjectNamespace.BUILTIN,
        namespace_value=ANY_OBJECT_NAME,
        precedence_rank=PolicyObjectPrecedence.BUILTIN,
        address_type=AddressObject.TYPE_BUILTIN_ANY,
        value=ANY_OBJECT_NAME,
        normalized_value=normalized_value,
        ipv4_start_int=start_int,
        ipv4_end_int=end_int,
        num_hosts=num_hosts,
        is_any=is_any,
        is_edl=False,
        is_builtin=True,
        edl_list_type="",
        description="Built-in any match",
        raw_object={"builtin": True, "kind": "any"},
        tags=[],
        field_provenance_data=[],
    )


def normalize_address_object(
    *,
    source_snapshot: Snapshot,
    config_source: str,
    namespace_type: str,
    namespace_value: str,
    precedence_rank: int,
    entry: dict[str, Any],
) -> NormalizedAddressObject:
    entry_rk, entry_rv = entry_provenance(entry)
    description, description_rk, description_rv = scalar_value(entry.get("description"))

    address_type = ""
    value = ""
    value_rk: Any = ABSENT
    value_rv: str | None = None
    for entry_key, normalized_type in [
        ("ip-netmask", AddressObject.TYPE_IP_NETMASK),
        ("fqdn", AddressObject.TYPE_FQDN),
        ("ip-range", AddressObject.TYPE_IP_RANGE),
        ("ip-wildcard", AddressObject.TYPE_IP_WILDCARD),
    ]:
        if entry_key in entry:
            address_type = normalized_type
            value, value_rk, value_rv = scalar_value(entry.get(entry_key))
            break
    if not address_type:
        raise ValueError(f"unsupported address object type for {entry.get('@name')}")
    normalized_value, start_int, end_int, num_hosts, is_any = derive_address_fields(address_type, value)

    tags = [
        NormalizedAddressTag(value=value_text, prov=prov, position=position)
        for position, (value_text, prov) in enumerate(member_values(entry.get("tag")))
    ]

    return NormalizedAddressObject(
        source_snapshot=source_snapshot,
        config_source=config_source,
        name=str(entry.get("@name") or ""),
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_rank,
        address_type=address_type,
        value=value,
        normalized_value=normalized_value,
        ipv4_start_int=start_int,
        ipv4_end_int=end_int,
        num_hosts=num_hosts,
        is_any=is_any,
        is_edl=False,
        is_builtin=False,
        edl_list_type="",
        description=description,
        raw_object=entry,
        tags=tags,
        field_provenance_data=[
            ("__entry__", entry_rk, entry_rv),
            ("value",     value_rk, value_rv),
            ("description", description_rk, description_rv),
        ],
    )


def normalize_external_list_object(
    *,
    source_snapshot: Snapshot,
    config_source: str,
    namespace_type: str,
    namespace_value: str,
    precedence_rank: int,
    entry: dict[str, Any],
) -> NormalizedAddressObject:
    entry_rk, entry_rv = entry_provenance(entry)
    description, description_rk, description_rv = scalar_value(entry.get("description"))
    value, value_rk, value_rv, list_type = external_list_value(entry)
    normalized_value, start_int, end_int, num_hosts, is_any = derive_address_fields(AddressObject.TYPE_EDL, value)

    return NormalizedAddressObject(
        source_snapshot=source_snapshot,
        config_source=config_source,
        name=str(entry.get("@name") or ""),
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_rank,
        address_type=AddressObject.TYPE_EDL,
        value=value,
        normalized_value=normalized_value,
        ipv4_start_int=start_int,
        ipv4_end_int=end_int,
        num_hosts=num_hosts,
        is_any=is_any,
        is_edl=True,
        is_builtin=False,
        edl_list_type=list_type,
        description=description,
        raw_object=entry,
        tags=[],
        field_provenance_data=[
            ("__entry__",   entry_rk,       entry_rv),
            ("value",       value_rk,       value_rv),
            ("description", description_rk, description_rv),
        ],
    )


def normalize_predefined_address_object(
    *,
    source_snapshot: Snapshot,
    edl_list_type: str,
    entry: dict[str, Any],
) -> NormalizedAddressObject:
    """A PAN-OS-shipped predefined list entry (e.g. panw-known-ip-list) from `show predefined`.

    Not user-configured - no @loc/@ptpl provenance to record, and PAN-OS doesn't expose actual
    member IPs/URLs for these the way it does for user-defined EDLs (see external_list.py), so
    this only makes the name resolvable (ipv4_start_int/end_int stay null, same as an EDL that
    has never been refreshed) - real interval data is a separate, not-yet-supported follow-up.
    """
    name = str(entry.get("@name") or "")
    display_name, _display_name_rk, _display_name_rv = scalar_value(entry.get("display-name"))
    description, _description_rk, _description_rv = scalar_value(entry.get("description"))
    normalized_value, start_int, end_int, num_hosts, is_any = derive_address_fields(AddressObject.TYPE_EDL, name)

    return NormalizedAddressObject(
        source_snapshot=source_snapshot,
        config_source=SecurityRule.SOURCE_LOCAL,
        name=name,
        namespace_type=PolicyObjectNamespace.PREDEFINED,
        namespace_value="predefined",
        precedence_rank=PolicyObjectPrecedence.PREDEFINED,
        address_type=AddressObject.TYPE_EDL,
        value=name,
        normalized_value=normalized_value,
        ipv4_start_int=start_int,
        ipv4_end_int=end_int,
        num_hosts=num_hosts,
        is_any=is_any,
        is_edl=True,
        is_builtin=True,
        edl_list_type=edl_list_type,
        description=description or display_name,
        raw_object=entry,
        tags=[],
        field_provenance_data=[],
    )


def build_normalized_predefined_address_objects(
    enforcement_point: EnforcementPoint,
) -> list[NormalizedAddressObject]:
    """Predefined IP block list and URL list catalogs for this enforcement point's appliance.

    Optional: environments that haven't yet collected these new snapshot types (or whose
    appliance doesn't support the command) simply get no predefined objects, same as any other
    best-effort PAN-OS data source in this pipeline - not a normalization failure.
    """
    normalized_objects: list[NormalizedAddressObject] = []

    ip_block_snapshot = latest_predefined_ip_block_lists_snapshot(enforcement_point)
    if ip_block_snapshot is not None:
        list_node = ip_block_snapshot.payload.get("ip-block-list-v2")
        for entry in ensure_list(list_node.get("entry") if isinstance(list_node, dict) else None):
            if not isinstance(entry, dict):
                continue
            normalized_objects.append(
                normalize_predefined_address_object(
                    source_snapshot=ip_block_snapshot,
                    edl_list_type="ip",
                    entry=entry,
                )
            )

    url_list_snapshot = latest_predefined_url_lists_snapshot(enforcement_point)
    if url_list_snapshot is not None:
        list_node = url_list_snapshot.payload.get("url-predefined")
        for entry in ensure_list(list_node.get("entry") if isinstance(list_node, dict) else None):
            if not isinstance(entry, dict):
                continue
            normalized_objects.append(
                normalize_predefined_address_object(
                    source_snapshot=url_list_snapshot,
                    edl_list_type="url",
                    entry=entry,
                )
            )

    return normalized_objects


def normalize_address_group(
    *,
    source_snapshot: Snapshot,
    config_source: str,
    namespace_type: str,
    namespace_value: str,
    precedence_rank: int,
    entry: dict[str, Any],
) -> NormalizedAddressGroup:
    entry_rk, entry_rv = entry_provenance(entry)
    dynamic_node = entry.get("dynamic")
    if isinstance(dynamic_node, dict) and "filter" in dynamic_node:
        dynamic_filter, filter_rk, filter_rv = scalar_value(dynamic_node.get("filter"))
    else:
        dynamic_filter, filter_rk, filter_rv = scalar_value(dynamic_node)
    tags = [
        NormalizedAddressTag(value=value_text, prov=prov, position=position)
        for position, (value_text, prov) in enumerate(member_values(entry.get("tag")))
    ]
    members = [
        NormalizedAddressTag(value=value_text, prov=prov, position=position)
        for position, (value_text, prov) in enumerate(member_values(entry.get("static")))
    ]
    return NormalizedAddressGroup(
        source_snapshot=source_snapshot,
        config_source=config_source,
        name=str(entry.get("@name") or ""),
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_rank,
        dynamic_filter=dynamic_filter,
        raw_group=entry,
        tags=tags,
        members=members,
        field_provenance_data=[
            ("__entry__",      entry_rk,  entry_rv),
            ("dynamic_filter", filter_rk, filter_rv),
        ],
    )


def build_normalized_addresses(enforcement_point: EnforcementPoint) -> tuple[list[NormalizedAddressObject], list[NormalizedAddressGroup]]:
    merged_snapshot = latest_merged_snapshot(enforcement_point)
    pushed_shared_snapshot = latest_pushed_shared_snapshot(enforcement_point)
    pushed_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    if merged_snapshot is None:
        raise ValueError(f"missing merged config snapshot for {enforcement_point}")
    if enforcement_point.appliance_group_id is not None and pushed_shared_snapshot is None:
        raise ValueError(f"missing pushed shared policy snapshot for {enforcement_point}")
    if pushed_snapshot is None:
        raise ValueError(f"missing pushed VSYS snapshot for {enforcement_point}")

    merged_root = merged_vsys_entry(merged_snapshot.payload, enforcement_point.vsys_name)
    merged_shared_root = merged_shared(merged_snapshot.payload)
    pushed_shared_root = pushed_shared(pushed_shared_snapshot.payload) if pushed_shared_snapshot is not None else {}
    pushed_root = pushed_vsys_panorama(pushed_snapshot.payload)

    normalized_objects: list[NormalizedAddressObject] = []
    normalized_groups: list[NormalizedAddressGroup] = []

    for entry in ensure_list((merged_root.get("address") or {}).get("entry") if isinstance(merged_root.get("address"), dict) else None):
        if not isinstance(entry, dict):
            continue
        normalized_objects.append(
            normalize_address_object(
                source_snapshot=merged_snapshot,
                config_source=SecurityRule.SOURCE_LOCAL,
                namespace_type=PolicyObjectNamespace.LOCAL_VSYS,
                namespace_value=enforcement_point.vsys_name,
                precedence_rank=PolicyObjectPrecedence.LOCAL_VSYS,
                entry=entry,
            )
        )

    for entry in ensure_list((merged_root.get("address-group") or {}).get("entry") if isinstance(merged_root.get("address-group"), dict) else None):
        if not isinstance(entry, dict):
            continue
        normalized_groups.append(
            normalize_address_group(
                source_snapshot=merged_snapshot,
                config_source=SecurityRule.SOURCE_LOCAL,
                namespace_type=PolicyObjectNamespace.LOCAL_VSYS,
                namespace_value=enforcement_point.vsys_name,
                precedence_rank=PolicyObjectPrecedence.LOCAL_VSYS,
                entry=entry,
            )
        )

    for entry in ensure_list((merged_shared_root.get("address") or {}).get("entry") if isinstance(merged_shared_root.get("address"), dict) else None):
        if not isinstance(entry, dict):
            continue
        normalized_objects.append(
            normalize_address_object(
                source_snapshot=merged_snapshot,
                config_source=SecurityRule.SOURCE_LOCAL,
                namespace_type=PolicyObjectNamespace.LOCAL_SHARED,
                namespace_value="shared",
                precedence_rank=PolicyObjectPrecedence.LOCAL_SHARED,
                entry=entry,
            )
        )

    for entry in ensure_list((merged_shared_root.get("address-group") or {}).get("entry") if isinstance(merged_shared_root.get("address-group"), dict) else None):
        if not isinstance(entry, dict):
            continue
        normalized_groups.append(
            normalize_address_group(
                source_snapshot=merged_snapshot,
                config_source=SecurityRule.SOURCE_LOCAL,
                namespace_type=PolicyObjectNamespace.LOCAL_SHARED,
                namespace_value="shared",
                precedence_rank=PolicyObjectPrecedence.LOCAL_SHARED,
                entry=entry,
            )
        )

    for entry in ensure_list((pushed_shared_root.get("address") or {}).get("entry") if isinstance(pushed_shared_root.get("address"), dict) else None):
        if not isinstance(entry, dict):
            continue
        normalized_objects.append(
            normalize_address_object(
                source_snapshot=pushed_shared_snapshot,
                config_source=SecurityRule.SOURCE_PUSHED_PRE,
                namespace_type=PolicyObjectNamespace.PANORAMA_SHARED,
                namespace_value="shared",
                precedence_rank=PolicyObjectPrecedence.PANORAMA_SHARED,
                entry=entry,
            )
        )

    for entry in ensure_list((pushed_shared_root.get("address-group") or {}).get("entry") if isinstance(pushed_shared_root.get("address-group"), dict) else None):
        if not isinstance(entry, dict):
            continue
        normalized_groups.append(
            normalize_address_group(
                source_snapshot=pushed_shared_snapshot,
                config_source=SecurityRule.SOURCE_PUSHED_PRE,
                namespace_type=PolicyObjectNamespace.PANORAMA_SHARED,
                namespace_value="shared",
                precedence_rank=PolicyObjectPrecedence.PANORAMA_SHARED,
                entry=entry,
            )
        )

    for entry in ensure_list((pushed_root.get("address") or {}).get("entry") if isinstance(pushed_root.get("address"), dict) else None):
        if not isinstance(entry, dict):
            continue
        normalized_objects.append(
            normalize_address_object(
                source_snapshot=pushed_snapshot,
                config_source=SecurityRule.SOURCE_PUSHED_PRE,
                namespace_type=PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE,
                namespace_value=enforcement_point.vsys_name,
                precedence_rank=PolicyObjectPrecedence.PUSHED_VSYS_EFFECTIVE,
                entry=entry,
            )
        )

    for entry in ensure_list((pushed_root.get("external-list") or {}).get("entry") if isinstance(pushed_root.get("external-list"), dict) else None):
        if not isinstance(entry, dict):
            continue
        normalized_objects.append(
            normalize_external_list_object(
                source_snapshot=pushed_snapshot,
                config_source=SecurityRule.SOURCE_PUSHED_PRE,
                namespace_type=PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE,
                namespace_value=enforcement_point.vsys_name,
                precedence_rank=PolicyObjectPrecedence.PUSHED_VSYS_EFFECTIVE,
                entry=entry,
            )
        )

    for entry in ensure_list((pushed_root.get("address-group") or {}).get("entry") if isinstance(pushed_root.get("address-group"), dict) else None):
        if not isinstance(entry, dict):
            continue
        normalized_groups.append(
            normalize_address_group(
                source_snapshot=pushed_snapshot,
                config_source=SecurityRule.SOURCE_PUSHED_PRE,
                namespace_type=PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE,
                namespace_value=enforcement_point.vsys_name,
                precedence_rank=PolicyObjectPrecedence.PUSHED_VSYS_EFFECTIVE,
                entry=entry,
            )
        )

    normalized_objects.extend(build_normalized_predefined_address_objects(enforcement_point))
    normalized_objects.append(build_builtin_any_object(merged_snapshot))

    if any(not address.name for address in normalized_objects):
        raise ValueError(f"encountered address object without a name for {enforcement_point}")
    if any(not group.name for group in normalized_groups):
        raise ValueError(f"encountered address group without a name for {enforcement_point}")

    duplicate_object_keys = [
        key for key, count in Counter(
            (address.name, address.namespace_type, address.namespace_value) for address in normalized_objects
        ).items() if count > 1
    ]
    duplicate_group_keys = [
        key for key, count in Counter(
            (group.name, group.namespace_type, group.namespace_value) for group in normalized_groups
        ).items() if count > 1
    ]
    if duplicate_object_keys:
        raise ValueError(
            f"duplicate address object namespaces for {enforcement_point}: {', '.join(sorted('/'.join(key) for key in duplicate_object_keys))}"
        )
    if duplicate_group_keys:
        raise ValueError(
            f"duplicate address group namespaces for {enforcement_point}: {', '.join(sorted('/'.join(key) for key in duplicate_group_keys))}"
        )

    return normalized_objects, normalized_groups


def replace_addresses(
    enforcement_point: EnforcementPoint,
    normalized_objects: list[NormalizedAddressObject],
    normalized_groups: list[NormalizedAddressGroup],
) -> tuple[list[AddressObject], list[AddressGroup]]:
    enforcement_point.address_objects.all().delete()
    enforcement_point.address_groups.all().delete()

    ao_ct = ContentType.objects.get_for_model(AddressObject)
    ag_ct = ContentType.objects.get_for_model(AddressGroup)

    created_objects: list[AddressObject] = []
    for normalized in normalized_objects:
        address_object = AddressObject.objects.create(
            management_station=enforcement_point.management_station,
            enforcement_point=enforcement_point,
            source_snapshot=normalized.source_snapshot,
            config_source=normalized.config_source,
            name=normalized.name,
            namespace_type=normalized.namespace_type,
            namespace_value=normalized.namespace_value,
            precedence_rank=normalized.precedence_rank,
            address_type=normalized.address_type,
            value=normalized.value,
            normalized_value=normalized.normalized_value,
            ipv4_start_int=normalized.ipv4_start_int,
            ipv4_end_int=normalized.ipv4_end_int,
            num_hosts=normalized.num_hosts,
            is_any=normalized.is_any,
            is_edl=normalized.is_edl,
            is_builtin=normalized.is_builtin,
            edl_list_type=normalized.edl_list_type,
            description=normalized.description,
            raw_object=normalized.raw_object,
            last_synced_at=normalized.source_snapshot.collected_at,
        )
        for tag in normalized.tags:
            AddressObjectTag.objects.create(
                address_object=address_object,
                value=tag.value,
                prov=tag.prov,
                position=tag.position,
            )
        prov_rows = [
            FieldProvenance(
                content_type=ao_ct,
                object_id=address_object.pk,
                field_name=fname,
                provenance_type=classify_prov_type(rk),
                raw_key=rk or "",
                raw_value=rv or "",
            )
            for fname, rk, rv in normalized.field_provenance_data
            if rk is not ABSENT
        ]
        if prov_rows:
            FieldProvenance.objects.bulk_create(prov_rows)
        created_objects.append(address_object)

    created_groups: list[AddressGroup] = []
    for normalized in normalized_groups:
        address_group = AddressGroup.objects.create(
            management_station=enforcement_point.management_station,
            enforcement_point=enforcement_point,
            source_snapshot=normalized.source_snapshot,
            config_source=normalized.config_source,
            name=normalized.name,
            namespace_type=normalized.namespace_type,
            namespace_value=normalized.namespace_value,
            precedence_rank=normalized.precedence_rank,
            dynamic_filter=normalized.dynamic_filter,
            raw_group=normalized.raw_group,
            last_synced_at=normalized.source_snapshot.collected_at,
        )
        for tag in normalized.tags:
            AddressGroupTag.objects.create(
                address_group=address_group,
                value=tag.value,
                prov=tag.prov,
                position=tag.position,
            )
        for member in normalized.members:
            AddressGroupMember.objects.create(
                address_group=address_group,
                value=member.value,
                prov=member.prov,
                position=member.position,
            )
        prov_rows = [
            FieldProvenance(
                content_type=ag_ct,
                object_id=address_group.pk,
                field_name=fname,
                provenance_type=classify_prov_type(rk),
                raw_key=rk or "",
                raw_value=rv or "",
            )
            for fname, rk, rv in normalized.field_provenance_data
            if rk is not ABSENT
        ]
        if prov_rows:
            FieldProvenance.objects.bulk_create(prov_rows)
        created_groups.append(address_group)

    return created_objects, created_groups


def normalize_addresses(enforcement_point: EnforcementPoint) -> PANOSNormalizedCollection:
    with transaction.atomic():
        normalized_objects, normalized_groups = build_normalized_addresses(enforcement_point)
        created_objects, created_groups = replace_addresses(
            enforcement_point,
            normalized_objects,
            normalized_groups,
        )
        normalized_regions = build_normalized_regions(enforcement_point)
        created_regions = replace_regions(enforcement_point, normalized_regions)

    return PANOSNormalizedCollection(
        address_objects=created_objects,
        address_groups=created_groups,
        regions=created_regions,
        appliances=[],
        appliance_groups=[],
        enforcement_points=[],
        enforcement_nodes=[],
        device_configuration_profiles=[],
        security_rules=[],
    )
