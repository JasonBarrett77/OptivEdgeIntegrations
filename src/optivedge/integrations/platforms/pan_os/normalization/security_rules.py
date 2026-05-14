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

from django.db import transaction

from optivedge.integrations.models import (
    AddressGroup,
    AddressObject,
    Appliance,
    EnforcementPoint,
    PolicyObjectNamespace,
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
from optivedge.integrations.platforms.pan_os.normalization.addresses import derive_address_fields
from optivedge.integrations.platforms.pan_os.normalization.common import ensure_list
from optivedge.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection


LOCAL_PROVENANCE = "local"
NO_PUSHED_POLICY_MESSAGE = "No shared policy pushed to device"
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
    provenance: str
    action: str
    action_prov: str
    disabled: bool
    disabled_prov: str
    rule_type: str
    rule_type_prov: str
    description: str
    description_prov: str
    log_start: bool | None
    log_start_prov: str
    log_end: bool | None
    log_end_prov: str
    log_setting: str
    log_setting_prov: str
    raw_rule: dict[str, Any]
    members: list[NormalizedSecurityRuleMember]
    source_address_members: list[NormalizedSecurityRuleMember]
    destination_address_members: list[NormalizedSecurityRuleMember]


@dataclass(slots=True)
class ResolvedAddressRef:
    raw_value: str
    position: int
    ref_type: str
    address_object: AddressObject | None
    address_group: AddressGroup | None


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


def rule_provenance(rule: dict[str, Any], default_prov: str) -> str:
    if not isinstance(rule, dict):
        return default_prov
    return str(rule.get("@loc") or default_prov or "")


def scalar_value(node: Any, default_prov: str) -> tuple[str, str]:
    if node is None:
        return "", ""
    if isinstance(node, dict):
        value = node.get("#text")
        if value is None:
            return "", str(node.get("@loc") or default_prov or "")
        return str(value), str(node.get("@loc") or default_prov or "")
    return str(node), default_prov


def bool_value(node: Any, default_prov: str) -> tuple[bool | None, str]:
    value, prov = scalar_value(node, default_prov)
    if value == "":
        return None, prov
    lowered = value.lower()
    if lowered in {"yes", "true"}:
        return True, prov
    if lowered in {"no", "false"}:
        return False, prov
    return None, prov


def iter_member_values(node: Any, default_prov: str) -> list[tuple[str, str]]:
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


def first_vsys_rulebase(payload: dict[str, Any], vsys_name: str) -> dict[str, Any]:
    config = payload.get("config", {})
    devices = config.get("devices", {}) if isinstance(config, dict) else {}
    device_entry = ensure_list(devices.get("entry"))[0] if isinstance(devices, dict) and ensure_list(devices.get("entry")) else {}
    vsys = device_entry.get("vsys", {}) if isinstance(device_entry, dict) else {}
    for entry in ensure_list(vsys.get("entry")) if isinstance(vsys, dict) else []:
        if isinstance(entry, dict) and entry.get("@name") == vsys_name:
            return entry.get("rulebase", {}) if isinstance(entry.get("rulebase"), dict) else {}
    return {}


def pushed_rulebases(payload: dict[str, Any] | Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if payload == NO_PUSHED_POLICY_MESSAGE:
        return {}, {}
    if not isinstance(payload, dict):
        raise ValueError(f"unexpected pushed policy payload type: {type(payload).__name__}")
    policy = payload.get("policy", {})
    if not isinstance(policy, dict):
        raise ValueError(f"unexpected pushed policy root type: {type(policy).__name__}")
    panorama = policy.get("panorama", {})
    if not isinstance(panorama, dict):
        raise ValueError(f"unexpected pushed panorama subtree type: {type(panorama).__name__}")
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
    default_prov: str,
) -> NormalizedSecurityRule:
    provenance = rule_provenance(rule, default_prov)
    action, action_prov = scalar_value(rule.get("action"), provenance)
    disabled, disabled_prov = bool_value(rule.get("disabled"), provenance)
    rule_type, rule_type_prov = scalar_value(rule.get("rule-type"), provenance)
    description, description_prov = scalar_value(rule.get("description"), provenance)
    log_start, log_start_prov = bool_value(rule.get("log-start"), provenance)
    log_end, log_end_prov = bool_value(rule.get("log-end"), provenance)
    log_setting, log_setting_prov = scalar_value(rule.get("log-setting"), provenance)

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
        for position, (value, prov) in enumerate(iter_member_values(rule.get(field_name), provenance)):
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
        for position, (value, prov) in enumerate(iter_member_values(rule.get("source"), provenance))
    ]
    destination_address_members = [
        NormalizedSecurityRuleMember(
            model=SecurityRuleDestinationAddressRef,
            value=value,
            prov=prov,
            position=position,
        )
        for position, (value, prov) in enumerate(iter_member_values(rule.get("destination"), provenance))
    ]

    profile_setting = rule.get("profile-setting")
    if isinstance(profile_setting, dict):
        group = profile_setting.get("group")
        for position, (value, prov) in enumerate(iter_member_values(group, provenance)):
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
                for position, (value, prov) in enumerate(iter_member_values(profile_value, provenance)):
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
        provenance=provenance,
        action=action,
        action_prov=action_prov,
        disabled=bool(disabled),
        disabled_prov=disabled_prov,
        rule_type=rule_type,
        rule_type_prov=rule_type_prov,
        description=description,
        description_prov=description_prov,
        log_start=log_start,
        log_start_prov=log_start_prov,
        log_end=log_end,
        log_end_prov=log_end_prov,
        log_setting=log_setting,
        log_setting_prov=log_setting_prov,
        raw_rule=rule,
        members=members,
        source_address_members=source_address_members,
        destination_address_members=destination_address_members,
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
) -> tuple[dict[str, list[AddressObject]], dict[str, list[AddressGroup]]]:
    address_objects: dict[str, list[AddressObject]] = {}
    for address_object in enforcement_point.address_objects.all().order_by("precedence_rank", "id"):
        address_objects.setdefault(address_object.name, []).append(address_object)

    address_groups: dict[str, list[AddressGroup]] = {}
    for address_group in enforcement_point.address_groups.prefetch_related("members").order_by("precedence_rank", "id"):
        address_groups.setdefault(address_group.name, []).append(address_group)
    return address_objects, address_groups


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
                provenance="literal",
                namespace_type=spec.namespace_type,
                namespace_value=spec.namespace_value,
                precedence_rank=spec.precedence_rank,
                address_type=spec.address_type,
                address_type_prov="literal",
                value=spec.value,
                normalized_value=spec.normalized_value,
                ipv4_start_int=spec.ipv4_start_int,
                ipv4_end_int=spec.ipv4_end_int,
                num_hosts=spec.num_hosts,
                is_any=False,
                is_builtin=False,
                value_prov="literal",
                description="Synthetic literal address reference",
                description_prov="literal",
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


def resolve_rule_address_refs(
    *,
    members: list[NormalizedSecurityRuleMember],
    address_objects_by_name: dict[str, list[AddressObject]],
    address_groups_by_name: dict[str, list[AddressGroup]],
) -> list[ResolvedAddressRef]:
    resolved: list[ResolvedAddressRef] = []
    for member in members:
        raw_value = member.value
        address_object = first_effective_object(raw_value, address_objects_by_name)
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

        address_group = first_effective_group(raw_value, address_groups_by_name)
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

        for group_member in address_group.members.all():
            member_name = group_member.value
            member_object = resolve_group_member_object(
                member_name=member_name,
                address_group=address_group,
                address_objects_by_name=address_objects_by_name,
            )
            if member_object is None:
                if first_effective_group(member_name, address_groups_by_name) is not None:
                    raise ValueError(
                        f"nested static address groups are not supported: {raw_value} -> {member_name}"
                    )
                raise ValueError(
                    f"static address group member {member_name} for {raw_value} does not resolve to an address object"
                )
            resolved.append(
                ResolvedAddressRef(
                    raw_value=raw_value,
                    position=member.position,
                    ref_type=SecurityRuleSourceAddressRef.RefType.STATIC_ADDRESS_GROUP,
                    address_object=member_object,
                    address_group=address_group,
                )
            )

    return resolved


def rule_uses_edl(resolved_refs: list[ResolvedAddressRef]) -> bool:
    for resolved_ref in resolved_refs:
        if resolved_ref.address_object is not None and resolved_ref.address_object.is_edl:
            return True
    return False


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
                default_prov=LOCAL_PROVENANCE,
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
                default_prov=rule_provenance(rule, ""),
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
                default_prov=rule_provenance(rule, ""),
            )
        )

    for position, merged_rule in enumerate(merged_default_rules):
        if not isinstance(merged_rule, dict):
            continue
        config_source, source_rule = default_rule_source(merged_rule, pushed_defaults_by_name)
        source_snapshot = pushed_snapshot if source_rule is not merged_rule else merged_snapshot
        default_prov = rule_provenance(source_rule, LOCAL_PROVENANCE if source_snapshot == merged_snapshot else "")
        normalized_rules.append(
            normalize_rule(
                source_snapshot=source_snapshot,
                config_source=config_source,
                rule_position=position,
                rule=source_rule,
                default_prov=default_prov,
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
    address_objects_by_name, address_groups_by_name = build_address_lookup_maps(enforcement_point)
    created_rules: list[SecurityRule] = []

    for normalized_rule in normalized_rules:
        source_resolved_refs = resolve_rule_address_refs(
            members=normalized_rule.source_address_members,
            address_objects_by_name=address_objects_by_name,
            address_groups_by_name=address_groups_by_name,
        )
        destination_resolved_refs = resolve_rule_address_refs(
            members=normalized_rule.destination_address_members,
            address_objects_by_name=address_objects_by_name,
            address_groups_by_name=address_groups_by_name,
        )

        if rule_uses_edl(source_resolved_refs) or rule_uses_edl(destination_resolved_refs):
            continue

        security_rule = SecurityRule.objects.create(
            management_station=enforcement_point.management_station,
            enforcement_point=enforcement_point,
            source_snapshot=normalized_rule.source_snapshot,
            config_source=normalized_rule.config_source,
            effective_order=normalized_rule.effective_order,
            rule_position=normalized_rule.rule_position,
            name=normalized_rule.name,
            uuid=normalized_rule.uuid,
            provenance=normalized_rule.provenance,
            action=normalized_rule.action,
            action_prov=normalized_rule.action_prov,
            disabled=normalized_rule.disabled,
            disabled_prov=normalized_rule.disabled_prov,
            rule_type=normalized_rule.rule_type,
            rule_type_prov=normalized_rule.rule_type_prov,
            description=normalized_rule.description,
            description_prov=normalized_rule.description_prov,
            log_start=normalized_rule.log_start,
            log_start_prov=normalized_rule.log_start_prov,
            log_end=normalized_rule.log_end,
            log_end_prov=normalized_rule.log_end_prov,
            log_setting=normalized_rule.log_setting,
            log_setting_prov=normalized_rule.log_setting_prov,
            raw_rule=normalized_rule.raw_rule,
            last_synced_at=normalized_rule.source_snapshot.collected_at,
        )
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
            )

        for resolved_ref in destination_resolved_refs:
            SecurityRuleDestinationAddressRef.objects.create(
                security_rule=security_rule,
                raw_value=resolved_ref.raw_value,
                position=resolved_ref.position,
                ref_type=resolved_ref.ref_type,
                address_object=resolved_ref.address_object,
                address_group=resolved_ref.address_group,
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
        management_plane_profiles=[],
        security_rules=created_rules,
    )
