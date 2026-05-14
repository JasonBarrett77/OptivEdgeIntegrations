"""PAN-OS address normalization helpers.

This module owns normalization of merged and pushed PAN-OS address objects and
address groups into enforcement-point scoped Django models.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import ipaddress
from typing import Any

from django.db import transaction

from optivedge.integrations.models import (
    AddressGroup,
    AddressGroupMember,
    AddressGroupTag,
    AddressObject,
    AddressObjectTag,
    Appliance,
    EnforcementPoint,
    PolicyObjectNamespace,
    PolicyObjectPrecedence,
    SecurityRule,
    Snapshot,
)
from optivedge.integrations.platforms.pan_os.normalization.common import ensure_list
from optivedge.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection


LOCAL_PROVENANCE = "local"
BUILTIN_PROVENANCE = "builtin"
ANY_OBJECT_NAME = "any"
NO_PUSHED_POLICY_MESSAGE = "No shared policy pushed to device"


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
    provenance: str
    namespace_type: str
    namespace_value: str
    precedence_rank: int
    address_type: str
    address_type_prov: str
    value: str
    normalized_value: str
    ipv4_start_int: int | None
    ipv4_end_int: int | None
    num_hosts: int | None
    is_any: bool
    is_edl: bool
    is_builtin: bool
    value_prov: str
    description: str
    description_prov: str
    raw_object: dict[str, Any]
    tags: list[NormalizedAddressTag]


@dataclass(slots=True)
class NormalizedAddressGroup:
    source_snapshot: Snapshot
    config_source: str
    name: str
    provenance: str
    namespace_type: str
    namespace_value: str
    precedence_rank: int
    dynamic_filter: str
    dynamic_filter_prov: str
    raw_group: dict[str, Any]
    tags: list[NormalizedAddressTag]
    members: list[NormalizedAddressTag]


def choose_local_appliance(enforcement_point: EnforcementPoint) -> Appliance | None:
    if enforcement_point.appliance is not None:
        return enforcement_point.appliance

    appliance_group = enforcement_point.appliance_group
    if appliance_group is None:
        return None

    if appliance_group.active_appliance is not None:
        return appliance_group.active_appliance

    node = enforcement_point.nodes.select_related("appliance").order_by("id").first()
    if node is not None:
        return node.appliance

    return appliance_group.appliances.order_by("hostname", "serial_number", "pk").first()


def latest_merged_snapshot(enforcement_point: EnforcementPoint) -> Snapshot | None:
    appliance = choose_local_appliance(enforcement_point)
    if appliance is None:
        return None
    return (
        Snapshot.objects.filter(
            appliance=appliance,
            source_type="show_merged_config",
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def latest_pushed_vsys_snapshot(enforcement_point: EnforcementPoint) -> Snapshot | None:
    return (
        Snapshot.objects.filter(
            enforcement_point=enforcement_point,
            source_type="show_pushed_shared_policy_vsys",
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def latest_pushed_shared_snapshot(enforcement_point: EnforcementPoint) -> Snapshot | None:
    appliance_group = enforcement_point.appliance_group
    if appliance_group is None:
        return None
    return (
        Snapshot.objects.filter(
            appliance_group=appliance_group,
            source_type="show_pushed_shared_policy",
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def scalar_value(node: Any, default_prov: str) -> tuple[str, str]:
    if node is None:
        return "", ""
    if isinstance(node, dict):
        value = node.get("#text")
        return (str(value or ""), str(node.get("@loc") or default_prov or ""))
    return str(node), default_prov


def member_values(node: Any, default_prov: str) -> list[tuple[str, str]]:
    if node is None:
        return []
    if isinstance(node, dict):
        members = ensure_list(node.get("member"))
        node_prov = str(node.get("@loc") or default_prov or "")
        values: list[tuple[str, str]] = []
        for member in members:
            if isinstance(member, dict):
                value = member.get("#text")
                if value is None:
                    continue
                values.append((str(value), str(member.get("@loc") or node_prov or "")))
            else:
                values.append((str(member), node_prov))
        return values
    if isinstance(node, list):
        return [(str(member), default_prov) for member in node]
    return [(str(node), default_prov)]


def object_provenance(entry: dict[str, Any], default_prov: str) -> str:
    return str(entry.get("@loc") or default_prov or "")


def merged_vsys(payload: dict[str, Any], vsys_name: str) -> dict[str, Any]:
    config = payload.get("config", {})
    devices = config.get("devices", {}) if isinstance(config, dict) else {}
    device_entry = ensure_list(devices.get("entry"))[0] if isinstance(devices, dict) and ensure_list(devices.get("entry")) else {}
    vsys = device_entry.get("vsys", {}) if isinstance(device_entry, dict) else {}
    for entry in ensure_list(vsys.get("entry")) if isinstance(vsys, dict) else []:
        if isinstance(entry, dict) and entry.get("@name") == vsys_name:
            return entry
    return {}


def merged_shared(payload: dict[str, Any]) -> dict[str, Any]:
    config = payload.get("config", {})
    if not isinstance(config, dict):
        return {}
    shared = config.get("shared", {})
    return shared if isinstance(shared, dict) else {}


def pushed_panorama(payload: dict[str, Any] | Any) -> dict[str, Any]:
    if payload == NO_PUSHED_POLICY_MESSAGE:
        return {}
    if not isinstance(payload, dict):
        raise ValueError(f"unexpected pushed policy payload type: {type(payload).__name__}")
    policy = payload.get("policy", {})
    if not isinstance(policy, dict):
        raise ValueError(f"unexpected pushed policy root type: {type(policy).__name__}")
    panorama = policy.get("panorama", {})
    if not isinstance(panorama, dict):
        raise ValueError(f"unexpected pushed panorama subtree type: {type(panorama).__name__}")
    return panorama


def external_list_value(entry: dict[str, Any], provenance: str) -> tuple[str, str]:
    type_node = entry.get("type")
    if not isinstance(type_node, dict):
        return ("", provenance)

    for list_type in ("ip", "domain", "url", "imei", "imsi"):
        list_node = type_node.get(list_type)
        if not isinstance(list_node, dict):
            continue
        url_node = list_node.get("url")
        if url_node is not None:
            return scalar_value(url_node, provenance)
        return (list_type, str(list_node.get("@loc") or provenance or ""))

    return ("", provenance)


def pushed_shared(payload: dict[str, Any] | Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError(f"unexpected pushed shared payload type: {type(payload).__name__}")
    shared = payload.get("shared", {})
    if not isinstance(shared, dict):
        raise ValueError(f"unexpected pushed shared subtree type: {type(shared).__name__}")
    return shared


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
        provenance=BUILTIN_PROVENANCE,
        namespace_type=PolicyObjectNamespace.BUILTIN,
        namespace_value=ANY_OBJECT_NAME,
        precedence_rank=PolicyObjectPrecedence.BUILTIN,
        address_type=AddressObject.TYPE_BUILTIN_ANY,
        address_type_prov=BUILTIN_PROVENANCE,
        value=ANY_OBJECT_NAME,
        normalized_value=normalized_value,
        ipv4_start_int=start_int,
        ipv4_end_int=end_int,
        num_hosts=num_hosts,
        is_any=is_any,
        is_edl=False,
        is_builtin=True,
        value_prov=BUILTIN_PROVENANCE,
        description="Built-in any match",
        description_prov=BUILTIN_PROVENANCE,
        raw_object={"builtin": True, "kind": "any"},
        tags=[],
    )


def normalize_address_object(
    *,
    source_snapshot: Snapshot,
    config_source: str,
    namespace_type: str,
    namespace_value: str,
    precedence_rank: int,
    entry: dict[str, Any],
    default_prov: str,
) -> NormalizedAddressObject:
    provenance = object_provenance(entry, default_prov)
    description, description_prov = scalar_value(entry.get("description"), provenance)

    address_type = ""
    value = ""
    value_prov = ""
    for entry_key, normalized_type in [
        ("ip-netmask", AddressObject.TYPE_IP_NETMASK),
        ("fqdn", AddressObject.TYPE_FQDN),
        ("ip-range", AddressObject.TYPE_IP_RANGE),
        ("ip-wildcard", AddressObject.TYPE_IP_WILDCARD),
    ]:
        if entry_key in entry:
            address_type = normalized_type
            value, value_prov = scalar_value(entry.get(entry_key), provenance)
            break
    if not address_type:
        raise ValueError(f"unsupported address object type for {entry.get('@name')}")
    normalized_value, start_int, end_int, num_hosts, is_any = derive_address_fields(address_type, value)

    tags = [
        NormalizedAddressTag(value=value_text, prov=prov, position=position)
        for position, (value_text, prov) in enumerate(member_values(entry.get("tag"), provenance))
    ]

    return NormalizedAddressObject(
        source_snapshot=source_snapshot,
        config_source=config_source,
        name=str(entry.get("@name") or ""),
        provenance=provenance,
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_rank,
        address_type=address_type,
        address_type_prov=provenance,
        value=value,
        normalized_value=normalized_value,
        ipv4_start_int=start_int,
        ipv4_end_int=end_int,
        num_hosts=num_hosts,
        is_any=is_any,
        is_edl=False,
        is_builtin=False,
        value_prov=value_prov,
        description=description,
        description_prov=description_prov,
        raw_object=entry,
        tags=tags,
    )


def normalize_external_list_object(
    *,
    source_snapshot: Snapshot,
    config_source: str,
    namespace_type: str,
    namespace_value: str,
    precedence_rank: int,
    entry: dict[str, Any],
    default_prov: str,
) -> NormalizedAddressObject:
    provenance = object_provenance(entry, default_prov)
    description, description_prov = scalar_value(entry.get("description"), provenance)
    value, value_prov = external_list_value(entry, provenance)
    normalized_value, start_int, end_int, num_hosts, is_any = derive_address_fields(AddressObject.TYPE_EDL, value)

    return NormalizedAddressObject(
        source_snapshot=source_snapshot,
        config_source=config_source,
        name=str(entry.get("@name") or ""),
        provenance=provenance,
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_rank,
        address_type=AddressObject.TYPE_EDL,
        address_type_prov=provenance,
        value=value,
        normalized_value=normalized_value,
        ipv4_start_int=start_int,
        ipv4_end_int=end_int,
        num_hosts=num_hosts,
        is_any=is_any,
        is_edl=True,
        is_builtin=False,
        value_prov=value_prov,
        description=description,
        description_prov=description_prov,
        raw_object=entry,
        tags=[],
    )


def normalize_address_group(
    *,
    source_snapshot: Snapshot,
    config_source: str,
    namespace_type: str,
    namespace_value: str,
    precedence_rank: int,
    entry: dict[str, Any],
    default_prov: str,
) -> NormalizedAddressGroup:
    provenance = object_provenance(entry, default_prov)
    dynamic_node = entry.get("dynamic")
    if isinstance(dynamic_node, dict) and "filter" in dynamic_node:
        dynamic_filter, dynamic_filter_prov = scalar_value(dynamic_node.get("filter"), provenance)
    else:
        dynamic_filter, dynamic_filter_prov = scalar_value(dynamic_node, provenance)
    tags = [
        NormalizedAddressTag(value=value_text, prov=prov, position=position)
        for position, (value_text, prov) in enumerate(member_values(entry.get("tag"), provenance))
    ]
    members = [
        NormalizedAddressTag(value=value_text, prov=prov, position=position)
        for position, (value_text, prov) in enumerate(member_values(entry.get("static"), provenance))
    ]
    return NormalizedAddressGroup(
        source_snapshot=source_snapshot,
        config_source=config_source,
        name=str(entry.get("@name") or ""),
        provenance=provenance,
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_rank,
        dynamic_filter=dynamic_filter,
        dynamic_filter_prov=dynamic_filter_prov,
        raw_group=entry,
        tags=tags,
        members=members,
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

    merged_root = merged_vsys(merged_snapshot.payload, enforcement_point.vsys_name)
    merged_shared_root = merged_shared(merged_snapshot.payload)
    pushed_shared_root = pushed_shared(pushed_shared_snapshot.payload) if pushed_shared_snapshot is not None else {}
    pushed_root = pushed_panorama(pushed_snapshot.payload)

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
                default_prov=LOCAL_PROVENANCE,
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
                default_prov=LOCAL_PROVENANCE,
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
                default_prov=LOCAL_PROVENANCE,
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
                default_prov=LOCAL_PROVENANCE,
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
                default_prov=object_provenance(entry, ""),
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
                default_prov=object_provenance(entry, ""),
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
                default_prov=object_provenance(entry, ""),
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
                default_prov=object_provenance(entry, ""),
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
                default_prov=object_provenance(entry, ""),
            )
        )

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

    created_objects: list[AddressObject] = []
    for normalized in normalized_objects:
        address_object = AddressObject.objects.create(
            management_station=enforcement_point.management_station,
            enforcement_point=enforcement_point,
            source_snapshot=normalized.source_snapshot,
            config_source=normalized.config_source,
            name=normalized.name,
            provenance=normalized.provenance,
            namespace_type=normalized.namespace_type,
            namespace_value=normalized.namespace_value,
            precedence_rank=normalized.precedence_rank,
            address_type=normalized.address_type,
            address_type_prov=normalized.address_type_prov,
            value=normalized.value,
            normalized_value=normalized.normalized_value,
            ipv4_start_int=normalized.ipv4_start_int,
            ipv4_end_int=normalized.ipv4_end_int,
            num_hosts=normalized.num_hosts,
            is_any=normalized.is_any,
            is_edl=normalized.is_edl,
            is_builtin=normalized.is_builtin,
            value_prov=normalized.value_prov,
            description=normalized.description,
            description_prov=normalized.description_prov,
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
        created_objects.append(address_object)

    created_groups: list[AddressGroup] = []
    for normalized in normalized_groups:
        address_group = AddressGroup.objects.create(
            management_station=enforcement_point.management_station,
            enforcement_point=enforcement_point,
            source_snapshot=normalized.source_snapshot,
            config_source=normalized.config_source,
            name=normalized.name,
            provenance=normalized.provenance,
            namespace_type=normalized.namespace_type,
            namespace_value=normalized.namespace_value,
            precedence_rank=normalized.precedence_rank,
            dynamic_filter=normalized.dynamic_filter,
            dynamic_filter_prov=normalized.dynamic_filter_prov,
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

    return PANOSNormalizedCollection(
        address_objects=created_objects,
        address_groups=created_groups,
        appliances=[],
        appliance_groups=[],
        enforcement_points=[],
        enforcement_nodes=[],
        management_plane_profiles=[],
        security_rules=[],
    )
