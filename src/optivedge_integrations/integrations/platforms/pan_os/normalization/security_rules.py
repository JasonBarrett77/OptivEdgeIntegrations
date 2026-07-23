"""PAN-OS security-rule normalization helpers.

This module owns normalization of merged and pushed PAN-OS security rules into
enforcement-point scoped Django models. It keeps security policy extraction
separate from management-station inventory normalization.
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
    AddressObject,
    EnforcementPoint,
    FieldProvenance,
    PolicyObjectNamespace,
    Region,
    SecurityRule,
    SecurityRuleApplication,
    SecurityRuleCategory,
    SecurityRuleDestinationAddressRef,
    SecurityRuleDestinationHip,
    SecurityRuleFromZone,
    SecurityRuleProfile,
    SecurityRuleProfileGroup,
    SecurityRuleSaasTenant,
    SecurityRuleSaasUser,
    SecurityRuleService,
    SecurityRuleSourceAddressRef,
    SecurityRuleSourceHip,
    SecurityRuleSourceUser,
    SecurityRuleToZone,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import derive_address_fields
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    ISO_3166_1_ALPHA2_REGIONS,
    PANOS_VENDOR_REGION_CODES,
    classify_prov_type,
    ensure_list,
    entry_provenance,
    iter_member_values,
    merged_vsys_entry,
    parse_yes_no_field,
    pushed_vsys_panorama,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    choose_local_appliance,
    latest_merged_snapshot,
    latest_pushed_vsys_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection


EFFECTIVE_ORDER_RANKS = {
    SecurityRule.SOURCE_PUSHED_PRE: 100000,
    SecurityRule.SOURCE_LOCAL: 200000,
    SecurityRule.SOURCE_PUSHED_POST: 300000,
    SecurityRule.SOURCE_DEFAULT: 400000,
}


@dataclass(slots=True)
class NormalizedSecurityRuleMember:
    model: type
    value: str
    prov: str
    position: int
    extra_fields: dict[str, Any] | None = None


@dataclass(slots=True)
class NormalizedSecurityRule:
    source_snapshot: Snapshot
    config_source: str
    effective_order: int
    rule_position: int
    name: str
    uuid: str
    action: str
    disabled: bool
    rule_type: str
    description: str
    log_start: bool | None
    log_end: bool | None
    log_setting: str
    raw_rule: dict[str, Any]
    members: list[NormalizedSecurityRuleMember]
    source_address_members: list[NormalizedSecurityRuleMember]
    destination_address_members: list[NormalizedSecurityRuleMember]
    # (field_name, raw_key_or_ABSENT, raw_prov_value)
    field_provenance_data: list[tuple[str, Any, str | None]]


@dataclass(slots=True)
class ResolvedAddressRef:
    raw_value: str
    position: int
    ref_type: str
    address_object: AddressObject | None
    address_group: AddressGroup | None
    region: Region | None = None


@dataclass(slots=True)
class LiteralAddressObjectSpec:
    name: str
    namespace_type: str
    namespace_value: str
    precedence_rank: int
    config_source: str
    source_snapshot: Snapshot
    address_type: str
    value: str
    normalized_value: str
    ipv4_start_int: int | None
    ipv4_end_int: int | None
    num_hosts: int | None


def first_vsys_rulebase(payload: dict[str, Any], vsys_name: str) -> dict[str, Any]:
    entry = merged_vsys_entry(payload, vsys_name)
    rulebase = entry.get("rulebase")
    return rulebase if isinstance(rulebase, dict) else {}


def pushed_rulebases(payload: dict[str, Any] | Any) -> tuple[dict[str, Any], dict[str, Any]]:
    panorama = pushed_vsys_panorama(payload)
    pre = panorama.get("pre-rulebase", {})
    post = panorama.get("post-rulebase", {})
    if not isinstance(pre, dict):
        raise ValueError(f"unexpected pushed pre-rulebase type: {type(pre).__name__}")
    if not isinstance(post, dict):
        raise ValueError(f"unexpected pushed post-rulebase type: {type(post).__name__}")
    return (pre, post)


def classify_literal_address_type(value: str) -> str | None:
    raw_value = value.strip()
    if not raw_value or raw_value.lower() == "any":
        return None

    if "-" in raw_value:
        try:
            start_text, end_text = [part.strip() for part in raw_value.split("-", 1)]
            start_ip = ipaddress.ip_address(start_text)
            end_ip = ipaddress.ip_address(end_text)
        except ValueError:
            return None
        if start_ip.version == 4 and end_ip.version == 4:
            return AddressObject.TYPE_IP_RANGE
        return None

    if "/" in raw_value:
        try:
            network = ipaddress.ip_network(raw_value, strict=False)
        except ValueError:
            return None
        if network.version == 4:
            return AddressObject.TYPE_IP_NETMASK
        return None

    try:
        address = ipaddress.ip_address(raw_value)
    except ValueError:
        return None
    if address.version == 4:
        return AddressObject.TYPE_IP_NETMASK
    return None


def literal_namespace(
    *,
    enforcement_point: EnforcementPoint,
    source_snapshot: Snapshot,
) -> tuple[str, str, int]:
    if source_snapshot.appliance_id is not None:
        return (
            PolicyObjectNamespace.LOCAL_VSYS,
            enforcement_point.vsys_name,
            10,
        )
    return (
        PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE,
        enforcement_point.vsys_name,
        30,
    )


def build_literal_address_object_spec(
    *,
    enforcement_point: EnforcementPoint,
    source_snapshot: Snapshot,
    config_source: str,
    raw_value: str,
) -> LiteralAddressObjectSpec | None:
    address_type = classify_literal_address_type(raw_value)
    if address_type is None:
        return None

    literal_value = raw_value.strip()
    if address_type == AddressObject.TYPE_IP_NETMASK and "/" not in literal_value:
        literal_value = f"{literal_value}/32"

    normalized_value, start_int, end_int, num_hosts, _is_any = derive_address_fields(
        address_type,
        literal_value,
    )
    namespace_type, namespace_value, precedence_rank = literal_namespace(
        enforcement_point=enforcement_point,
        source_snapshot=source_snapshot,
    )
    return LiteralAddressObjectSpec(
        name=raw_value,
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_rank,
        config_source=config_source,
        source_snapshot=source_snapshot,
        address_type=address_type,
        value=literal_value,
        normalized_value=normalized_value,
        ipv4_start_int=start_int,
        ipv4_end_int=end_int,
        num_hosts=num_hosts,
    )


def normalize_rule(
    *,
    source_snapshot: Snapshot,
    config_source: str,
    rule_position: int,
    rule: dict[str, Any],
) -> NormalizedSecurityRule:
    entry_rk, entry_rv = entry_provenance(rule)
    action, action_rk, action_rv = scalar_value(rule.get("action"))
    disabled, disabled_rk, disabled_rv = parse_yes_no_field(rule.get("disabled"), default_effective=False)
    rule_type, rule_type_rk, rule_type_rv = scalar_value(rule.get("rule-type"))
    description, description_rk, description_rv = scalar_value(rule.get("description"))
    log_start, log_start_rk, log_start_rv = parse_yes_no_field(rule.get("log-start"), default_effective=False)
    log_end, log_end_rk, log_end_rv = parse_yes_no_field(rule.get("log-end"), default_effective=False)
    log_setting, log_setting_rk, log_setting_rv = scalar_value(rule.get("log-setting"))

    # log_start/log_end: treat ABSENT as null (not configured at all)
    log_start_value: bool | None = None if log_start_rk is ABSENT else bool(log_start)
    log_end_value: bool | None = None if log_end_rk is ABSENT else bool(log_end)

    members: list[NormalizedSecurityRuleMember] = []

    for model, field_name in [
        (SecurityRuleFromZone, "from"),
        (SecurityRuleToZone, "to"),
        (SecurityRuleSourceUser, "source-user"),
        (SecurityRuleApplication, "application"),
        (SecurityRuleService, "service"),
        (SecurityRuleCategory, "category"),
        (SecurityRuleSourceHip, "source-hip"),
        (SecurityRuleDestinationHip, "destination-hip"),
        (SecurityRuleSaasUser, "saas-user-list"),
        (SecurityRuleSaasTenant, "saas-tenant-list"),
    ]:
        for position, (value, prov) in enumerate(iter_member_values(rule.get(field_name))):
            members.append(
                NormalizedSecurityRuleMember(
                    model=model,
                    value=value,
                    prov=prov,
                    position=position,
                )
            )

    source_address_members = [
        NormalizedSecurityRuleMember(
            model=SecurityRuleSourceAddressRef,
            value=value,
            prov=prov,
            position=position,
        )
        for position, (value, prov) in enumerate(iter_member_values(rule.get("source")))
    ]
    destination_address_members = [
        NormalizedSecurityRuleMember(
            model=SecurityRuleDestinationAddressRef,
            value=value,
            prov=prov,
            position=position,
        )
        for position, (value, prov) in enumerate(iter_member_values(rule.get("destination")))
    ]

    profile_setting = rule.get("profile-setting")
    if isinstance(profile_setting, dict):
        group = profile_setting.get("group")
        for position, (value, prov) in enumerate(iter_member_values(group)):
            members.append(
                NormalizedSecurityRuleMember(
                    model=SecurityRuleProfileGroup,
                    value=value,
                    prov=prov,
                    position=position,
                )
            )

        profiles = profile_setting.get("profiles")
        if isinstance(profiles, dict):
            for profile_type, profile_value in profiles.items():
                for position, (value, prov) in enumerate(iter_member_values(profile_value)):
                    members.append(
                        NormalizedSecurityRuleMember(
                            model=SecurityRuleProfile,
                            value=value,
                            prov=prov,
                            position=position,
                            extra_fields={"profile_type": profile_type},
                        )
                    )

    return NormalizedSecurityRule(
        source_snapshot=source_snapshot,
        config_source=config_source,
        effective_order=EFFECTIVE_ORDER_RANKS[config_source] + rule_position,
        rule_position=rule_position,
        name=str(rule.get("@name") or ""),
        uuid=str(rule.get("@uuid") or ""),
        action=action,
        disabled=bool(disabled),
        rule_type=rule_type,
        description=description,
        log_start=log_start_value,
        log_end=log_end_value,
        log_setting=log_setting,
        raw_rule=rule,
        members=members,
        source_address_members=source_address_members,
        destination_address_members=destination_address_members,
        field_provenance_data=[
            ("__entry__",   entry_rk,       entry_rv),
            ("action",      action_rk,      action_rv),
            ("disabled",    disabled_rk,    disabled_rv),
            ("rule_type",   rule_type_rk,   rule_type_rv),
            ("description", description_rk, description_rv),
            ("log_start",   log_start_rk,   log_start_rv),
            ("log_end",     log_end_rk,     log_end_rv),
            ("log_setting", log_setting_rk, log_setting_rv),
        ],
    )


def merged_local_rules(snapshot: Snapshot, enforcement_point: EnforcementPoint) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rulebase = first_vsys_rulebase(snapshot.payload, enforcement_point.vsys_name)
    security_rules = ensure_list((((rulebase.get("security") or {}).get("rules") or {}).get("entry")))
    default_rules = ensure_list((((rulebase.get("default-security-rules") or {}).get("rules") or {}).get("entry")))
    return security_rules, default_rules


def pushed_rules(snapshot: Snapshot) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    pre_rulebase, post_rulebase = pushed_rulebases(snapshot.payload)
    pre_rules = ensure_list((((pre_rulebase.get("security") or {}).get("rules") or {}).get("entry")))
    post_rules = ensure_list((((post_rulebase.get("security") or {}).get("rules") or {}).get("entry")))
    default_rules = ensure_list((((post_rulebase.get("default-security-rules") or {}).get("rules") or {}).get("entry")))
    return pre_rules, post_rules, default_rules


def default_rule_source(
    merged_rule: dict[str, Any],
    pushed_defaults_by_name: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    if str(merged_rule.get("@panorama") or "").lower() == "true":
        rule_name = str(merged_rule.get("@name") or "")
        pushed_rule = pushed_defaults_by_name.get(rule_name)
        if pushed_rule is None:
            raise ValueError(f"missing pushed default rule for {rule_name}")
        return SecurityRule.SOURCE_DEFAULT, pushed_rule
    return SecurityRule.SOURCE_DEFAULT, merged_rule


def build_address_lookup_maps(
    enforcement_point: EnforcementPoint,
) -> tuple[dict[str, list[AddressObject]], dict[str, list[AddressGroup]], dict[str, list[Region]]]:
    address_objects: dict[str, list[AddressObject]] = {}
    for address_object in enforcement_point.address_objects.all().order_by("precedence_rank", "id"):
        address_objects.setdefault(address_object.name, []).append(address_object)

    address_groups: dict[str, list[AddressGroup]] = {}
    for address_group in enforcement_point.address_groups.prefetch_related("members").order_by("precedence_rank", "id"):
        address_groups.setdefault(address_group.name, []).append(address_group)

    regions: dict[str, list[Region]] = {}
    for region in enforcement_point.regions.all().order_by("precedence_rank", "id"):
        regions.setdefault(region.name, []).append(region)

    return address_objects, address_groups, regions


def realize_literal_address_objects(
    enforcement_point: EnforcementPoint,
    normalized_rules: list[NormalizedSecurityRule],
) -> None:
    existing_keys = {
        (obj.name, obj.namespace_type, obj.namespace_value)
        for obj in enforcement_point.address_objects.all()
    }
    existing_group_names = {group.name for group in enforcement_point.address_groups.all()}
    created_specs: set[tuple[str, str, str]] = set()

    for normalized_rule in normalized_rules:
        for member in [*normalized_rule.source_address_members, *normalized_rule.destination_address_members]:
            raw_value = member.value
            if raw_value in existing_group_names:
                continue

            spec = build_literal_address_object_spec(
                enforcement_point=enforcement_point,
                source_snapshot=normalized_rule.source_snapshot,
                config_source=normalized_rule.config_source,
                raw_value=raw_value,
            )
            if spec is None:
                continue

            key = (spec.name, spec.namespace_type, spec.namespace_value)
            if key in existing_keys or key in created_specs:
                continue

            AddressObject.objects.create(
                management_station=enforcement_point.management_station,
                enforcement_point=enforcement_point,
                source_snapshot=spec.source_snapshot,
                config_source=spec.config_source,
                name=spec.name,
                namespace_type=spec.namespace_type,
                namespace_value=spec.namespace_value,
                precedence_rank=spec.precedence_rank,
                address_type=spec.address_type,
                value=spec.value,
                normalized_value=spec.normalized_value,
                ipv4_start_int=spec.ipv4_start_int,
                ipv4_end_int=spec.ipv4_end_int,
                num_hosts=spec.num_hosts,
                is_any=False,
                is_builtin=False,
                description="Synthetic literal address reference",
                raw_object={"synthetic": True, "kind": "rule_literal", "raw_value": raw_value},
                last_synced_at=spec.source_snapshot.collected_at,
            )
            created_specs.add(key)


def first_effective_object(
    name: str,
    address_objects_by_name: dict[str, list[AddressObject]],
) -> AddressObject | None:
    candidates = address_objects_by_name.get(name, [])
    return candidates[0] if candidates else None


def first_effective_group(
    name: str,
    address_groups_by_name: dict[str, list[AddressGroup]],
) -> AddressGroup | None:
    candidates = address_groups_by_name.get(name, [])
    return candidates[0] if candidates else None


def first_effective_region(
    name: str,
    regions_by_name: dict[str, list[Region]],
) -> Region | None:
    candidates = regions_by_name.get(name, [])
    return candidates[0] if candidates else None


def resolve_group_member_object(
    *,
    member_name: str,
    address_group: AddressGroup,
    address_objects_by_name: dict[str, list[AddressObject]],
) -> AddressObject | None:
    candidates = address_objects_by_name.get(member_name, [])
    if not candidates:
        return None

    for candidate in candidates:
        if (
            candidate.namespace_type == address_group.namespace_type
            and candidate.namespace_value == address_group.namespace_value
        ):
            return candidate

    if address_group.namespace_type == PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE:
        for candidate in candidates:
            if candidate.namespace_type == PolicyObjectNamespace.PANORAMA_SHARED:
                return candidate

    return candidates[0]


def resolve_static_group_members(
    *,
    current_group: AddressGroup,
    top_level_group: AddressGroup,
    raw_value: str,
    position: int,
    address_objects_by_name: dict[str, list[AddressObject]],
    address_groups_by_name: dict[str, list[AddressGroup]],
    visited_group_ids: set[int],
    seen_targets: set[tuple[str, int]],
) -> list[ResolvedAddressRef]:
    """Recursively resolve a static address group's members, including nested groups.

    Nested static groups are expanded inline (their objects are attributed to
    top_level_group, matching the existing stored-data shape). A nested group that is
    itself dynamic produces its own DYNAMIC_ADDRESS_GROUP ref pointing at that nested
    group. seen_targets de-dupes a diamond-shaped nesting graph within one raw_value;
    visited_group_ids raises on a cycle instead of looping forever.
    """
    if current_group.pk in visited_group_ids:
        raise ValueError(
            f"circular static address group reference detected: {raw_value} involves {current_group.name} more than once"
        )
    visited_group_ids = visited_group_ids | {current_group.pk}

    resolved: list[ResolvedAddressRef] = []
    for group_member in current_group.members.all():
        member_name = group_member.value
        member_object = resolve_group_member_object(
            member_name=member_name,
            address_group=current_group,
            address_objects_by_name=address_objects_by_name,
        )
        if member_object is not None:
            key = ("object", member_object.pk)
            if key not in seen_targets:
                seen_targets.add(key)
                resolved.append(
                    ResolvedAddressRef(
                        raw_value=raw_value,
                        position=position,
                        ref_type=SecurityRuleSourceAddressRef.RefType.STATIC_ADDRESS_GROUP,
                        address_object=member_object,
                        address_group=top_level_group,
                    )
                )
            continue

        nested_group = first_effective_group(member_name, address_groups_by_name)
        if nested_group is None:
            raise ValueError(
                f"static address group member {member_name} for {raw_value} does not resolve to an address object or group"
            )

        if nested_group.dynamic_filter:
            key = ("dynamic_group", nested_group.pk)
            if key not in seen_targets:
                seen_targets.add(key)
                resolved.append(
                    ResolvedAddressRef(
                        raw_value=raw_value,
                        position=position,
                        ref_type=SecurityRuleSourceAddressRef.RefType.DYNAMIC_ADDRESS_GROUP,
                        address_object=None,
                        address_group=nested_group,
                    )
                )
            continue

        resolved.extend(
            resolve_static_group_members(
                current_group=nested_group,
                top_level_group=top_level_group,
                raw_value=raw_value,
                position=position,
                address_objects_by_name=address_objects_by_name,
                address_groups_by_name=address_groups_by_name,
                visited_group_ids=visited_group_ids,
                seen_targets=seen_targets,
            )
        )
    return resolved


def resolve_rule_address_refs(
    *,
    members: list[NormalizedSecurityRuleMember],
    address_objects_by_name: dict[str, list[AddressObject]],
    address_groups_by_name: dict[str, list[AddressGroup]],
    regions_by_name: dict[str, list[Region]],
) -> list[ResolvedAddressRef]:
    resolved: list[ResolvedAddressRef] = []
    for member in members:
        raw_value = member.value
        address_object = first_effective_object(raw_value, address_objects_by_name)
        address_group = first_effective_group(raw_value, address_groups_by_name)
        region = first_effective_region(raw_value, regions_by_name)
        is_region = (
            region is not None
            or raw_value in ISO_3166_1_ALPHA2_REGIONS
            or raw_value in PANOS_VENDOR_REGION_CODES
        )

        namespace_hits = sum([address_object is not None, address_group is not None, is_region])
        if namespace_hits > 1:
            raise ValueError(
                f"ambiguous address reference: {raw_value} matches multiple namespaces "
                f"(address_object={address_object is not None}, address_group={address_group is not None}, "
                f"region={is_region})"
            )

        if address_object is not None:
            ref_type = (
                SecurityRuleSourceAddressRef.RefType.ANY
                if address_object.is_any
                else SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT
            )
            resolved.append(
                ResolvedAddressRef(
                    raw_value=raw_value,
                    position=member.position,
                    ref_type=ref_type,
                    address_object=address_object,
                    address_group=None,
                )
            )
            continue

        if address_group is None and is_region:
            resolved.append(
                ResolvedAddressRef(
                    raw_value=raw_value,
                    position=member.position,
                    ref_type=SecurityRuleSourceAddressRef.RefType.REGION,
                    address_object=None,
                    address_group=None,
                    region=region,
                )
            )
            continue

        if address_group is None:
            raise ValueError(f"unresolved address reference: {raw_value}")

        if address_group.dynamic_filter:
            resolved.append(
                ResolvedAddressRef(
                    raw_value=raw_value,
                    position=member.position,
                    ref_type=SecurityRuleSourceAddressRef.RefType.DYNAMIC_ADDRESS_GROUP,
                    address_object=None,
                    address_group=address_group,
                )
            )
            continue

        resolved.extend(
            resolve_static_group_members(
                current_group=address_group,
                top_level_group=address_group,
                raw_value=raw_value,
                position=member.position,
                address_objects_by_name=address_objects_by_name,
                address_groups_by_name=address_groups_by_name,
                visited_group_ids=set(),
                seen_targets=set(),
            )
        )

    return resolved


def build_normalized_security_rules(enforcement_point: EnforcementPoint) -> list[NormalizedSecurityRule]:
    merged_snapshot = latest_merged_snapshot(enforcement_point)
    pushed_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    if merged_snapshot is None:
        raise ValueError(f"missing merged config snapshot for {enforcement_point}")
    if pushed_snapshot is None:
        raise ValueError(f"missing pushed VSYS snapshot for {enforcement_point}")

    merged_security_rules, merged_default_rules = merged_local_rules(merged_snapshot, enforcement_point)
    pushed_pre_rules, pushed_post_rules, pushed_default_rules = pushed_rules(pushed_snapshot)
    pushed_defaults_by_name = {
        str(rule.get("@name") or ""): rule
        for rule in pushed_default_rules
        if isinstance(rule, dict) and rule.get("@name")
    }

    normalized_rules: list[NormalizedSecurityRule] = []

    for position, rule in enumerate(merged_security_rules):
        if not isinstance(rule, dict):
            continue
        normalized_rules.append(
            normalize_rule(
                source_snapshot=merged_snapshot,
                config_source=SecurityRule.SOURCE_LOCAL,
                rule_position=position,
                rule=rule,
            )
        )

    for position, rule in enumerate(pushed_pre_rules):
        if not isinstance(rule, dict):
            continue
        normalized_rules.append(
            normalize_rule(
                source_snapshot=pushed_snapshot,
                config_source=SecurityRule.SOURCE_PUSHED_PRE,
                rule_position=position,
                rule=rule,
            )
        )

    for position, rule in enumerate(pushed_post_rules):
        if not isinstance(rule, dict):
            continue
        normalized_rules.append(
            normalize_rule(
                source_snapshot=pushed_snapshot,
                config_source=SecurityRule.SOURCE_PUSHED_POST,
                rule_position=position,
                rule=rule,
            )
        )

    for position, merged_rule in enumerate(merged_default_rules):
        if not isinstance(merged_rule, dict):
            continue
        config_source, source_rule = default_rule_source(merged_rule, pushed_defaults_by_name)
        source_snapshot = pushed_snapshot if source_rule is not merged_rule else merged_snapshot
        normalized_rules.append(
            normalize_rule(
                source_snapshot=source_snapshot,
                config_source=config_source,
                rule_position=position,
                rule=source_rule,
            )
        )

    if any(not rule.name for rule in normalized_rules):
        raise ValueError(f"encountered security rule without a name for {enforcement_point}")

    names = [rule.name for rule in normalized_rules]
    duplicates = [name for name, count in Counter(names).items() if count > 1]
    if duplicates:
        raise ValueError(
            f"duplicate security rule names for {enforcement_point}: {', '.join(sorted(duplicates))}"
        )

    return normalized_rules


def replace_security_rules(
    enforcement_point: EnforcementPoint,
    normalized_rules: list[NormalizedSecurityRule],
) -> list[SecurityRule]:
    enforcement_point.security_rules.all().delete()
    realize_literal_address_objects(enforcement_point, normalized_rules)
    address_objects_by_name, address_groups_by_name, regions_by_name = build_address_lookup_maps(enforcement_point)
    sr_ct = ContentType.objects.get_for_model(SecurityRule)
    created_rules: list[SecurityRule] = []

    for normalized_rule in normalized_rules:
        rule_context = (
            f"rule='{normalized_rule.name}', uuid={normalized_rule.uuid or 'n/a'}, "
            f"config_source={normalized_rule.config_source}, position={normalized_rule.rule_position}"
        )
        try:
            source_resolved_refs = resolve_rule_address_refs(
                members=normalized_rule.source_address_members,
                address_objects_by_name=address_objects_by_name,
                address_groups_by_name=address_groups_by_name,
                regions_by_name=regions_by_name,
            )
        except ValueError as exc:
            raise ValueError(f"{exc} (field=source_address, {rule_context})") from exc
        try:
            destination_resolved_refs = resolve_rule_address_refs(
                members=normalized_rule.destination_address_members,
                address_objects_by_name=address_objects_by_name,
                address_groups_by_name=address_groups_by_name,
                regions_by_name=regions_by_name,
            )
        except ValueError as exc:
            raise ValueError(f"{exc} (field=destination_address, {rule_context})") from exc

        security_rule = SecurityRule.objects.create(
            management_station=enforcement_point.management_station,
            enforcement_point=enforcement_point,
            source_snapshot=normalized_rule.source_snapshot,
            config_source=normalized_rule.config_source,
            effective_order=normalized_rule.effective_order,
            rule_position=normalized_rule.rule_position,
            name=normalized_rule.name,
            uuid=normalized_rule.uuid,
            action=normalized_rule.action,
            disabled=normalized_rule.disabled,
            rule_type=normalized_rule.rule_type,
            description=normalized_rule.description,
            log_start=normalized_rule.log_start,
            log_end=normalized_rule.log_end,
            log_setting=normalized_rule.log_setting,
            raw_rule=normalized_rule.raw_rule,
            last_synced_at=normalized_rule.source_snapshot.collected_at,
        )
        prov_rows = [
            FieldProvenance(
                content_type=sr_ct,
                object_id=security_rule.pk,
                field_name=fname,
                provenance_type=classify_prov_type(rk),
                raw_key=rk or "",
                raw_value=rv or "",
            )
            for fname, rk, rv in normalized_rule.field_provenance_data
            if rk is not ABSENT
        ]
        if prov_rows:
            FieldProvenance.objects.bulk_create(prov_rows)
        for member in normalized_rule.members:
            extra_fields = member.extra_fields or {}
            member.model.objects.create(
                security_rule=security_rule,
                value=member.value,
                prov=member.prov,
                position=member.position,
                **extra_fields,
            )

        for resolved_ref in source_resolved_refs:
            SecurityRuleSourceAddressRef.objects.create(
                security_rule=security_rule,
                raw_value=resolved_ref.raw_value,
                position=resolved_ref.position,
                ref_type=resolved_ref.ref_type,
                address_object=resolved_ref.address_object,
                address_group=resolved_ref.address_group,
                region=resolved_ref.region,
            )

        for resolved_ref in destination_resolved_refs:
            SecurityRuleDestinationAddressRef.objects.create(
                security_rule=security_rule,
                raw_value=resolved_ref.raw_value,
                position=resolved_ref.position,
                ref_type=resolved_ref.ref_type,
                address_object=resolved_ref.address_object,
                address_group=resolved_ref.address_group,
                region=resolved_ref.region,
            )
        created_rules.append(security_rule)

    return created_rules


def normalize_security_rules(enforcement_point: EnforcementPoint) -> PANOSNormalizedCollection:
    with transaction.atomic():
        normalized_rules = build_normalized_security_rules(enforcement_point)
        created_rules = replace_security_rules(enforcement_point, normalized_rules)

    return PANOSNormalizedCollection(
        address_objects=[],
        address_groups=[],
        appliances=[],
        appliance_groups=[],
        enforcement_points=[],
        enforcement_nodes=[],
        device_configuration_profiles=[],
        security_rules=created_rules,
    )
