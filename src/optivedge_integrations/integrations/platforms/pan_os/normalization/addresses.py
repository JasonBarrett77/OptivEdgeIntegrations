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
    ApplianceGroup,
    EnforcementPoint,
    FieldProvenance,
    PolicyObjectNamespace,
    PolicyObjectScope,
    precedence_for,
    scope_for,
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
    merge_pushed_entries,
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
    is_panorama_managed,
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
        precedence_rank=precedence_for(PolicyObjectNamespace.BUILTIN),
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
        precedence_rank=precedence_for(namespace_type),
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
        precedence_rank=precedence_for(namespace_type),
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
        precedence_rank=precedence_for(PolicyObjectNamespace.PREDEFINED),
        namespace_value="predefined",
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
        precedence_rank=precedence_for(namespace_type),
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
    if is_panorama_managed(enforcement_point) and pushed_shared_snapshot is None:
        raise ValueError(f"missing pushed shared policy snapshot for {enforcement_point}")
    if is_panorama_managed(enforcement_point) and pushed_snapshot is None:
        raise ValueError(f"missing pushed VSYS snapshot for {enforcement_point}")

    merged_root = merged_vsys_entry(merged_snapshot.payload, enforcement_point.vsys_name)
    merged_shared_root = merged_shared(merged_snapshot.payload)
    pushed_shared_root = pushed_shared(pushed_shared_snapshot.payload) if pushed_shared_snapshot is not None else {}
    pushed_root = pushed_vsys_panorama(pushed_snapshot.payload) if pushed_snapshot is not None else {}

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
                entry=entry,
            )
        )

    # Both pushed reads are merged and classified per entry by @loc - never by which
    # read returned them. See merge_pushed_entries() and common.pushed_entry_scope().
    pushed_reads = [
        (pushed_shared_root, pushed_shared_snapshot),
        (pushed_root, pushed_snapshot),
    ]

    for entry, snapshot, namespace_type, namespace_value in merge_pushed_entries(
            pushed_reads, "address", vsys_name=enforcement_point.vsys_name, label=str(enforcement_point)
    ):
        normalized_objects.append(
            normalize_address_object(
                source_snapshot=snapshot,
                config_source=SecurityRule.SOURCE_PUSHED_PRE,
                namespace_type=namespace_type,
                namespace_value=namespace_value,
                entry=entry,
            )
        )

    for entry, snapshot, namespace_type, namespace_value in merge_pushed_entries(
            pushed_reads, "external-list", vsys_name=enforcement_point.vsys_name, label=str(enforcement_point)
    ):
        normalized_objects.append(
            normalize_external_list_object(
                source_snapshot=snapshot,
                config_source=SecurityRule.SOURCE_PUSHED_PRE,
                namespace_type=namespace_type,
                namespace_value=namespace_value,
                entry=entry,
            )
        )

    for entry, snapshot, namespace_type, namespace_value in merge_pushed_entries(
            pushed_reads, "address-group", vsys_name=enforcement_point.vsys_name, label=str(enforcement_point)
    ):
        normalized_groups.append(
            normalize_address_group(
                source_snapshot=snapshot,
                config_source=SecurityRule.SOURCE_PUSHED_PRE,
                namespace_type=namespace_type,
                namespace_value=namespace_value,
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


def is_shared_scope(namespace_type: str) -> bool:
    """Whether an object belongs to the appliance group rather than an enforcement point.

    Owner follows SCOPE. Shared scope is group-wide - every vsys on the group reads the
    same /config/shared and the same Panorama-Shared push - so it is stored once on the
    group instead of once per vsys.

    Vendor objects (builtin/predefined) stay on the enforcement point: they are
    synthesized per point and there are two of them, so the duplication costs nothing and
    moving them would change more than it is worth.
    """
    return scope_for(namespace_type) == PolicyObjectScope.SHARED


def partition_by_owner(normalized):
    """Split normalized objects into (enforcement-point-owned, appliance-group-owned)."""
    point_owned = [n for n in normalized if not is_shared_scope(n.namespace_type)]
    group_owned = [n for n in normalized if is_shared_scope(n.namespace_type)]
    return point_owned, group_owned


def replace_addresses(
    owner: EnforcementPoint | ApplianceGroup,
    normalized_objects: list[NormalizedAddressObject],
    normalized_groups: list[NormalizedAddressGroup],
) -> tuple[list[AddressObject], list[AddressGroup]]:
    """Write the objects `owner` owns, replacing what it currently holds.

    An EnforcementPoint owns vsys-scoped and vendor objects; an ApplianceGroup owns
    shared-scoped ones. The caller passes the full normalized set either way and this
    keeps only its own share, so the two passes cannot write each other's rows.

    Shared scope MUST be written before any enforcement point's security rules are
    normalized. Rule address refs FK to these rows, and this is a delete-and-recreate, so
    rewriting shared scope after a point's rules would cascade those refs away. See
    flows.py, which orders the group pass first.
    """
    keep_here = (
        (lambda n: not is_shared_scope(n.namespace_type))
        if isinstance(owner, EnforcementPoint)
        else (lambda n: is_shared_scope(n.namespace_type))
    )
    normalized_objects = [n for n in normalized_objects if keep_here(n)]
    normalized_groups = [n for n in normalized_groups if keep_here(n)]

    owner_kwargs = (
        {"enforcement_point": owner}
        if isinstance(owner, EnforcementPoint)
        else {"appliance_group": owner}
    )

    owner.address_objects.all().delete()
    owner.address_groups.all().delete()

    ao_ct = ContentType.objects.get_for_model(AddressObject)
    ag_ct = ContentType.objects.get_for_model(AddressGroup)

    created_objects: list[AddressObject] = []
    for normalized in normalized_objects:
        address_object = AddressObject.objects.create(
            management_station=owner.management_station,
            **owner_kwargs,
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
            management_station=owner.management_station,
            **owner_kwargs,
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


def normalize_appliance_group_shared_objects(appliance_group: ApplianceGroup) -> PANOSNormalizedCollection:
    """Normalize the shared-scope objects the appliance group holds.

    Shared scope is one namespace per group, but it is NOT reported identically to every
    vsys. Panorama pushes only what each device group references (shared-object
    optimization), so a Panorama-Shared object can appear in one vsys's per-vsys response
    and not another's. Every in-scope point is therefore read and the shared halves
    unioned.

    An earlier version derived this from a single representative point. Any shared object
    that happened to be absent from that one point's response was then owned by nobody -
    the group pass never saw it, and the owning point's pass discards shared scope by
    design - and every rule referencing it failed with "unresolved address reference".

    Must run BEFORE the group's enforcement points are normalized: this is a
    delete-and-recreate, and security rule address refs FK to these rows.
    """
    points = list(
        appliance_group.enforcement_points.filter(in_scope=True).order_by("vsys_name", "pk")
    )
    if not points:
        return PANOSNormalizedCollection(
            address_objects=[], address_groups=[], regions=[], appliances=[],
            appliance_groups=[], enforcement_points=[], enforcement_nodes=[],
            device_configuration_profiles=[], security_rules=[],
        )

    def union(collected: dict, normalized_items, kind: str) -> None:
        """Keep one entry per (name, namespace_type, namespace_value).

        The same shared object arrives from several points - the non-vsys response is
        included in every point's build - so overlap is expected. Disagreeing values are
        not: shared scope is a single namespace on the device, so one name cannot hold two
        values, and a conflict means the collection or classification is wrong.
        """
        for item in normalized_items:
            if not is_shared_scope(item.namespace_type):
                continue
            key = (item.name, item.namespace_type, item.namespace_value)
            existing = collected.get(key)
            if existing is None:
                collected[key] = item
            elif getattr(existing, "raw_object", None) != getattr(item, "raw_object", None) or \
                    getattr(existing, "raw_group", None) != getattr(item, "raw_group", None) or \
                    getattr(existing, "raw_region", None) != getattr(item, "raw_region", None):
                raise ValueError(
                    f"conflicting shared {kind} definitions for {item.name!r} across the "
                    f"enforcement points of {appliance_group}: shared scope is one namespace, "
                    f"so this indicates a collection or classification fault"
                )

    shared_objects: dict = {}
    shared_groups: dict = {}
    shared_regions: dict = {}
    with transaction.atomic():
        for point in points:
            normalized_objects, normalized_groups = build_normalized_addresses(point)
            union(shared_objects, normalized_objects, "address object")
            union(shared_groups, normalized_groups, "address group")
            union(shared_regions, build_normalized_regions(point), "region")

        created_objects, created_groups = replace_addresses(
            appliance_group, list(shared_objects.values()), list(shared_groups.values())
        )
        created_regions = replace_regions(appliance_group, list(shared_regions.values()))

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
