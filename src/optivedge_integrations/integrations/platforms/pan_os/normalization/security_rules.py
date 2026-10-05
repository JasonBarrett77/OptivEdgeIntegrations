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
from django.db.models import Q
from django.utils import timezone

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressObject,
    AddressObjectResolvedEntry,
    EnforcementPoint,
    FieldProvenance,
    PolicyObjectNamespace,
    PolicyObjectScope,
    precedence_for,
    scope_for,
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
from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import (
    ANY_OBJECT_NAME,
    derive_address_fields,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ABSENT,
    was_absent,
    ISO_3166_1_ALPHA2_REGIONS,
    PANOS_VENDOR_REGION_CODES,
    classify_prov_type,
    provenance_raw_key,
    provenance_value,
    ensure_list,
    entry_provenance,
    iter_member_values,
    merge_intervals,
    merged_vsys_entry,
    parse_yes_no_field,
    pushed_vsys_panorama,
    scalar_value,
    num_hosts_from_intervals,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    choose_local_appliance,
    is_panorama_managed,
    latest_merged_snapshot,
    latest_pushed_vsys_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import (
    SECURITY_RULE_KIND,
    replace_normalization_issues,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.types import (
    PolicyObjectIssue,
    PANOSNormalizedCollection,
    SecurityRuleFailure,
)


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
    negate_source: bool
    negate_destination: bool
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


#: What PAN-OS does with an absent log flag. Measured rather than read, because the Help says
#: both things: p.134 "Log At Session End (enabled by default)" on the security rule screen, and
#: p.142 "cleared by default" on another. The measurement settles it for the rule screen.
LOG_FLAG_CITATION = (
    "measured 2026-09-22 on pan-fw-111. `log_default_probe`, a shared rule pushed with NEITHER "
    "key - absent in Panorama running and candidate, in the device's pushed-shared-policy and "
    "in effective-running - renders Log at Session End TICKED and Log at Session Start unticked "
    "in the device's own UI. Help p.134 agrees for log-end, 'enabled by default'; p.142 says "
    "'cleared by default' about the same field on another screen, which is why this was "
    "measured rather than read")


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
) -> tuple[str, str]:
    """Namespace for an address literal typed directly into a rule.

    Both outcomes are **vsys scope** - the literal belongs to the vsys whose rule carries
    it. They differ only in provenance: local when the rule came from the firewall's own
    config, pushed when it arrived from Panorama. Ownership is not a precedence level, so
    the rank is identical either way and is derived by precedence_for(), not returned
    here. This function previously returned hardcoded 10 and 30, which both bypassed
    PolicyObjectPrecedence and encoded the refuted ladder.
    """
    if source_snapshot.appliance_id is not None:
        return PolicyObjectNamespace.LOCAL_VSYS, enforcement_point.vsys_name
    return PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE, enforcement_point.vsys_name


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
    namespace_type, namespace_value = literal_namespace(
        enforcement_point=enforcement_point,
        source_snapshot=source_snapshot,
    )
    return LiteralAddressObjectSpec(
        name=raw_value,
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_for(namespace_type),
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
    disabled, disabled_rk, disabled_rv = parse_yes_no_field(
        rule.get("disabled"),
        implicit=Implicit.measured(
            False, "read-a-security-rule.md: 'disabled absent -> no'"))
    rule_type, rule_type_rk, rule_type_rv = scalar_value(rule.get("rule-type"))
    description, description_rk, description_rv = scalar_value(rule.get("description"))
    log_start, log_start_rk, log_start_rv = parse_yes_no_field(
        rule.get("log-start"),
        # The guide says this one outright: "**Unmeasured:** `log-start` / `log-end` defaults.
        # If a consumer needs them, it needs to measure them, not assume." PAN-POL-009 asserts
        # log-end, so presenting this as a vendor default would fabricate the fact the control
        # turns on.
        implicit=Implicit.measured(False, f"log-start absent means NO - {LOG_FLAG_CITATION}"))
    log_end, log_end_rk, log_end_rv = parse_yes_no_field(
        rule.get("log-end"),
        implicit=Implicit.measured(True, f"log-end absent means YES - {LOG_FLAG_CITATION}"))
    log_setting, log_setting_rk, log_setting_rv = scalar_value(rule.get("log-setting"))
    negate_source, negate_source_rk, negate_source_rv = parse_yes_no_field(
        rule.get("negate-source"),
        implicit=Implicit.measured(
            False, "read-a-security-rule.md: 'negate-source absent -> no'")
    )
    negate_destination, negate_destination_rk, negate_destination_rv = parse_yes_no_field(
        rule.get("negate-destination"),
        implicit=Implicit.measured(
            False, "read-a-security-rule.md: 'negate-destination absent -> no'")
    )

    # Both flags now carry their MEASURED default when the key is absent, so neither is null any
    # more. They were null from the day this module was written until 2026-09-22, because the
    # corpus recorded the defaults as unmeasured and a guess would have decided PAN-POL-009 on
    # nothing. They are measured now - see LOG_FLAG_CITATION - and the provenance row says
    # `pan_os_default` rather than `not_configured`, which is the difference between "the device
    # logs this and nobody wrote it down" and "we have no idea".
    log_start_value: bool = bool(log_start)
    log_end_value: bool = bool(log_end)

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

    # PAN-OS treats a rule with no <source>/<destination> element (or an empty member list) as
    # matching "any" - it does not mean the rule has no source/destination. Default to an
    # explicit "any" member so these rules get a resolvable ref instead of silently ending up
    # with zero address refs (and rendering as "-" everywhere refs are displayed).
    source_address_values = iter_member_values(rule.get("source")) or [(ANY_OBJECT_NAME, "")]
    source_address_members = [
        NormalizedSecurityRuleMember(
            model=SecurityRuleSourceAddressRef,
            value=value,
            prov=prov,
            position=position,
        )
        for position, (value, prov) in enumerate(source_address_values)
    ]
    destination_address_values = iter_member_values(rule.get("destination")) or [(ANY_OBJECT_NAME, "")]
    destination_address_members = [
        NormalizedSecurityRuleMember(
            model=SecurityRuleDestinationAddressRef,
            value=value,
            prov=prov,
            position=position,
        )
        for position, (value, prov) in enumerate(destination_address_values)
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
        negate_source=bool(negate_source),
        negate_destination=bool(negate_destination),
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
            ("negate_source", negate_source_rk, negate_source_rv),
            ("negate_destination", negate_destination_rk, negate_destination_rv),
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
    # Candidates come from BOTH owners: the point holds vsys-scoped and vendor objects,
    # the appliance group holds shared-scoped ones. Neither alone is the visible set.
    # effective_in_scope_order() then picks between them by scope, so the order the two
    # querysets are concatenated in does not matter.
    group = enforcement_point.appliance_group

    address_objects: dict[str, list[AddressObject]] = {}
    for source in (enforcement_point.address_objects, getattr(group, "address_objects", None)):
        if source is None:
            continue
        for address_object in source.all().order_by("precedence_rank", "id"):
            address_objects.setdefault(address_object.name, []).append(address_object)

    address_groups: dict[str, list[AddressGroup]] = {}
    for source in (enforcement_point.address_groups, getattr(group, "address_groups", None)):
        if source is None:
            continue
        for address_group in source.prefetch_related("members").order_by("precedence_rank", "id"):
            address_groups.setdefault(address_group.name, []).append(address_group)

    regions: dict[str, list[Region]] = {}
    for source in (enforcement_point.regions, getattr(group, "regions", None)):
        if source is None:
            continue
        for region in source.all().order_by("precedence_rank", "id"):
            regions.setdefault(region.name, []).append(region)

    return address_objects, address_groups, regions


#: Which provenance to record when one literal appears in rules of both kinds. The choice
#: is cosmetic - both are vsys scope at the same rank, so resolution is unaffected - but it
#: has to be deterministic, or the row's namespace would depend on rule iteration order.
LITERAL_NAMESPACE_PREFERENCE = (
    PolicyObjectNamespace.LOCAL_VSYS,
    PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE,
)


def _literal_rank(spec: "LiteralAddressObjectSpec") -> int:
    """Position in LITERAL_NAMESPACE_PREFERENCE; unknown namespaces sort last."""
    try:
        return LITERAL_NAMESPACE_PREFERENCE.index(spec.namespace_type)
    except ValueError:
        return len(LITERAL_NAMESPACE_PREFERENCE)


def realize_literal_address_objects(
    enforcement_point: EnforcementPoint,
    normalized_rules: list[NormalizedSecurityRule],
    address_objects_by_name: dict[str, list[AddressObject]],
    address_groups_by_name: dict[str, list[AddressGroup]],
    regions_by_name: dict[str, list[Region]],
) -> None:
    """Materialise inline rule addresses as synthetic AddressObjects, once each.

    Runs AFTER the lookup maps are built and BEFORE rules resolve, and both halves of that
    matter. Building the maps first means this can ask `name_is_owned()` - the same
    question the resolver asks - instead of approximating it. Running before resolution
    means the rows it creates are already in the maps when refs resolve against them, so
    it appends each new row rather than relying on a second map build.

    The maps are mutated in place. That is safe here and would not be inside the per-rule
    loop: this runs outside any savepoint, so nothing it writes can be rolled back while
    the map keeps pointing at it. A synthesized row created inside a rule's
    `transaction.atomic()` would vanish on that rule's failure and leave a dead pk in the
    map for every later rule to resolve against.

    A literal is deduplicated **by name alone**, not by (name, namespace). The namespace of
    a literal records only provenance - local rule versus pushed rule - and provenance is
    not a precedence level, so two rows for one inline IP are identical in name, value,
    scope, rank and owner. They are a duplicate, not two candidates to resolve between, and
    PAN-OS would reject the equivalent configuration.

    Keying on the namespace produced exactly that: `172.200.255.254` typed into both a local
    and a pushed rule became `local_vsys` and `pushed_vsys_effective` rows on one
    enforcement point, blocking the Stage B unique constraint on a duplicate we invented.

    Synthesis is also skipped when a **collected** object of that name exists in any
    namespace, on the point or its group. A rule member is a name reference first; PAN-OS
    only treats it as an inline address when nothing owns that name. An object legitimately
    named for an IP is unusual but legal, and synthesising alongside it would manufacture a
    second collision - this time between something real and something we made up.
    """
    #: name -> spec, keeping the preferred provenance and remembering every one seen.
    chosen: dict[str, LiteralAddressObjectSpec] = {}
    namespaces_seen: dict[str, set[str]] = {}

    for normalized_rule in normalized_rules:
        for member in [*normalized_rule.source_address_members, *normalized_rule.destination_address_members]:
            raw_value = member.value
            if name_is_owned(
                raw_value, address_objects_by_name, address_groups_by_name, regions_by_name
            ):
                continue

            spec = build_literal_address_object_spec(
                enforcement_point=enforcement_point,
                source_snapshot=normalized_rule.source_snapshot,
                config_source=normalized_rule.config_source,
                raw_value=raw_value,
            )
            if spec is None:
                continue

            namespaces_seen.setdefault(spec.name, set()).add(spec.namespace_type)
            incumbent = chosen.get(spec.name)
            if incumbent is None or _literal_rank(spec) < _literal_rank(incumbent):
                chosen[spec.name] = spec

    for spec in chosen.values():
        seen = sorted(namespaces_seen.get(spec.name, {spec.namespace_type}))
        # Nothing owned this name - name_is_owned() said so - so the map entry is empty and
        # this append cannot create a second candidate in one scope, which is the state
        # effective_in_scope_order() raises on. Asserted rather than commented because it
        # is the invariant that would break silently if the ownership check were relaxed.
        assert not address_objects_by_name.get(spec.name), (
            f"synthesizing {spec.name!r} over an existing candidate: the ownership check "
            f"and the map disagree, which means one of them is wrong"
        )
        address_object = AddressObject.objects.create(
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
            is_synthetic=True,
            synthetic_kind=AddressObject.SYNTHETIC_KIND_RULE_LITERAL,
            description="Synthetic literal address reference",
            # `namespaces` keeps what the single namespace_type above has to drop: a literal
            # appearing in both a local and a pushed rule has both provenances, and the row
            # can only carry one.
            raw_object={
                "synthetic": True,
                "kind": "rule_literal",
                "raw_value": spec.name,
                "namespaces": seen,
            },
            last_synced_at=spec.source_snapshot.collected_at,
        )
        # In place, so the resolve pass below sees it. Position in the list is irrelevant -
        # effective_in_scope_order() groups by scope before choosing.
        address_objects_by_name.setdefault(spec.name, []).append(address_object)


def effective_in_scope_order(name: str, candidates_by_name: dict, kind: str):
    """Resolve a name the way PAN-OS does: by scope, most specific first.

    The scope order is walked explicitly rather than inferred from a sort, because the
    order IS the rule:

        vsys-specific  >  shared  >  vendor-supplied

    Ownership - firewall-local versus Panorama-pushed - is provenance and plays no part.
    A pushed device-group object is vsys-scoped and beats a firewall-local *shared*
    object; sorting by a per-namespace rank got that backwards for years.

    Within one scope a name has at most one definition. PAN-OS rejects the configuration
    when two owners try to occupy the same scope under the same name - at the candidate
    write for the vsys pair, at commit validation for the shared pair - so a device cannot
    present two. Finding two here means the collection or the @loc classification is
    wrong, and picking one would bury that. It raises instead.
    """
    candidates = candidates_by_name.get(name, [])
    if not candidates:
        return None

    by_scope: dict[str, list] = {}
    for candidate in candidates:
        by_scope.setdefault(scope_for(candidate.namespace_type), []).append(candidate)

    for scope in PolicyObjectScope.ORDER:
        in_scope = by_scope.get(scope)
        if not in_scope:
            continue
        if len(in_scope) > 1:
            raise ValueError(
                f"{len(in_scope)} definitions of {kind} {name!r} in {scope} scope "
                f"({', '.join(sorted(c.namespace_type for c in in_scope))}): PAN-OS rejects "
                f"this configuration, so it indicates a collection or classification fault"
            )
        return in_scope[0]
    return None


def first_effective_object(
    name: str,
    address_objects_by_name: dict[str, list[AddressObject]],
) -> AddressObject | None:
    return effective_in_scope_order(name, address_objects_by_name, "address object")


def first_effective_group(
    name: str,
    address_groups_by_name: dict[str, list[AddressGroup]],
) -> AddressGroup | None:
    return effective_in_scope_order(name, address_groups_by_name, "address group")


def first_effective_region(
    name: str,
    regions_by_name: dict[str, list[Region]],
) -> Region | None:
    return effective_in_scope_order(name, regions_by_name, "region")


def name_is_owned(
    name: str,
    address_objects_by_name: dict[str, list[AddressObject]],
    address_groups_by_name: dict[str, list[AddressGroup]],
    regions_by_name: dict[str, list[Region]],
) -> bool:
    """Does anything on this enforcement point already answer to `name`?

    The single definition of that question. `resolve_rule_address_refs()` asks it to decide
    whether to raise `UnresolvedAddressReference`; `realize_literal_address_objects()` asks
    it to decide whether an IP-shaped member is a literal at all. The two MUST agree - a
    name the resolver would have matched must never be synthesized over, or the synthetic
    row shadows a real object and the rule is reported as matching traffic the firewall
    never matches.

    It previously had two implementations. The synthesis side used a flat set of names
    gathered from its own queries, which asked a subtly different question ("does a row
    with this name exist") and omitted regions entirely. Keeping them in one function is
    the point: any future check that resolution grows is inherited here for free.

    Measured basis: a rule member is a name reference first. An address object *named*
    `172.200.255.254` and holding `10.99.99.99/32` makes a rule sourcing that string
    compile to `10.99.99.99` - the name wins, and the literal reading is what PAN-OS falls
    back to when nothing owns the name (OptivEdgeProbe `rule-member-name-beats-literal`).
    """
    return (
        first_effective_object(name, address_objects_by_name) is not None
        or first_effective_group(name, address_groups_by_name) is not None
        or first_effective_region(name, regions_by_name) is not None
        or name in ISO_3166_1_ALPHA2_REGIONS
        or name in PANOS_VENDOR_REGION_CODES
    )


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

    # No same-namespace member: fall back to the scope order, which also surfaces an
    # impossible same-scope duplicate rather than silently taking the first row.
    return effective_in_scope_order(member_name, address_objects_by_name, "address object")


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


def _with_rule_context(exc: Exception, field: str, rule_context: str) -> ValueError:
    """Re-raise with rule context, preserving an unresolved name if the original had one.

    The context wrapper used to build a plain ValueError, which discarded the typed
    exception and with it the link between a failing rule and the object that caused it -
    so every rule failure looked like its own root cause.
    """
    detail = f"{exc} (field={field}, {rule_context})"
    name = getattr(exc, "name", "")
    return UnresolvedAddressReference(name, detail) if name else ValueError(detail)


class UnresolvedAddressReference(ValueError):
    """A rule referenced a name nothing resolves to.

    Carries the name structurally so the failure can be linked to the object issue that
    caused it. Parsing it back out of the message would work until someone rewords the
    message, and the whole point of the link is that it survives.
    """

    def __init__(self, name: str, detail: str) -> None:
        super().__init__(detail)
        self.name = name


def resolve_rule_address_refs(
    *,
    members: list[NormalizedSecurityRuleMember],
    address_objects_by_name: dict[str, list[AddressObject]],
    address_groups_by_name: dict[str, list[AddressGroup]],
    regions_by_name: dict[str, list[Region]],
) -> list[ResolvedAddressRef]:
    """Resolve each rule source/destination member to the object PAN-OS actually uses.

    A name can match more than one namespace, and the outcomes are not symmetric.
    Measured on a PA-VM 11.2.3, 2026-08 (see the object-scope section of CLAUDE.md):

        address object + address group   rejected by PAN-OS at the candidate WRITE
        address object + EDL             rejected at COMMIT VALIDATION
        address group  + EDL             rejected at COMMIT VALIDATION
        anything above + REGION          LEGAL, and the REGION wins

    So the two cases need opposite handling:

    **Within the address namespace** - objects, groups and EDLs share one namespace and a
    device cannot present a collision, so seeing one here means our own collection or
    classification is wrong. That raises.

    **Region versus the address namespace** - legal, and committed on a real device. The
    region wins and the address-namespace object contributes nothing: given a name that
    was both, the object's own address did not match the rule carrying its name, and the
    same held for a static group holding a routable member. PAN-OS reports it at commit
    as `Warning: <name> is used as a region, not an address object` (it says "address
    object" even for a group, naming the namespace rather than the type).

    This previously raised for any multi-namespace hit, which failed normalization for a
    configuration the firewall had accepted. Predefined region names are not reserved -
    `US` may simultaneously be an address object, a group, a custom region and the
    predefined region - so this is reachable in ordinary configurations.

    Known limitation: a custom region sharing a predefined region's name UNIONS with it
    rather than overriding it - both sets of addresses are live. The `region` FK here
    points at the custom definition only, so anything computing a region's address extent
    from it alone under-reports.
    """
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

        # Objects, groups and EDLs are one namespace on the device - PAN-OS rejects a
        # collision between them, at the write or at commit validation depending on the
        # pair. Reaching this means our data is wrong, not the device's.
        if address_object is not None and address_group is not None:
            raise ValueError(
                f"address object and address group both named {raw_value}: PAN-OS rejects "
                f"this configuration, so it indicates a collection or classification fault"
            )

        # A region beats the address namespace. Checked before them, not alongside them.
        if is_region:
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

        if address_group is None:
            # Same question name_is_owned() answers, reached from the other side: nothing
            # matched, so nothing owns the name. A literal that could be synthesized was
            # already turned into an object by the pre-pass, so reaching here means the
            # name is genuinely unresolvable.
            raise UnresolvedAddressReference(
                raw_value, f"unresolved address reference: {raw_value}"
            )

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


IPV4_MAX = 4_294_967_295


def _member_intervals_or_none(ref: ResolvedAddressRef) -> list[tuple[int, int]] | None:
    """The IPv4 interval(s) a single resolved ref represents, or None if unresolvable.

    None means: a dynamic address group or region member (unknowable statically), an address
    object with no known IPv4 data at all (e.g. an EDL/FQDN never refreshed via "Refresh
    EDL/FQDN Cache"), or an object whose resolved content is TRUNCATED. Callers computing a
    negate complement must treat None as "can't soundly compute this" and skip materializing a
    complement, not guess.

    Truncation belongs in that list because a complement inverts the set: intervals missing
    from a partial EDL become intervals the complement CLAIMS, so a negated rule would be
    recorded as matching addresses the list actually contains. A partial set is fine for "does
    it contain this" (it under-reports) and unsound the moment it is inverted.
    """
    if ref.ref_type in (
        SecurityRuleSourceAddressRef.RefType.DYNAMIC_ADDRESS_GROUP,
        SecurityRuleSourceAddressRef.RefType.REGION,
    ):
        return None
    address_object = ref.address_object
    if address_object is None:
        return None
    if address_object.resolved_content_truncated:
        return None
    resolved_entries = list(address_object.resolved_entries.all())
    if resolved_entries:
        return [(entry.ipv4_start_int, entry.ipv4_end_int) for entry in resolved_entries]
    if address_object.ipv4_start_int is not None and address_object.ipv4_end_int is not None:
        return [(address_object.ipv4_start_int, address_object.ipv4_end_int)]
    return None


def _complement_of(merged_intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Gaps in [0, IPV4_MAX] left uncovered by a sorted, merged, disjoint interval list."""
    if not merged_intervals:
        return [(0, IPV4_MAX)]
    complement: list[tuple[int, int]] = []
    cursor = 0
    for start, end in merged_intervals:
        if start > cursor:
            complement.append((cursor, start - 1))
        cursor = max(cursor, end + 1)
    if cursor <= IPV4_MAX:
        complement.append((cursor, IPV4_MAX))
    return complement


def compute_negated_complement_intervals(
    resolved_refs: list[ResolvedAddressRef],
) -> list[tuple[int, int]] | None:
    """The effective (post-negation) IPv4 range for a negated source/destination member list.

    Returns None if any member is unresolvable (dynamic group, region, or an EDL/FQDN with no
    resolved entries yet) - the caller must skip materializing a complement for this rule/side
    rather than guess. A negated "any" member degrades correctly for free: its own interval is
    the full [0, IPV4_MAX] range, so its complement is empty (matches nothing).
    """
    all_intervals: list[tuple[int, int]] = []
    for ref in resolved_refs:
        intervals = _member_intervals_or_none(ref)
        if intervals is None:
            return None
        all_intervals.extend(intervals)
    return _complement_of(merge_intervals(all_intervals))


def side_num_hosts(
    resolved_refs: list[ResolvedAddressRef],
    *,
    negated: bool,
    complement_ref: ResolvedAddressRef | None,
) -> int | None:
    """How many IPv4 addresses one side of a rule permits, AFTER negation.

    None means INDETERMINATE and is the answer whenever any member cannot be sized - a dynamic
    address group, a region, an EDL or FQDN with no resolved content, or content truncated at
    the collection ceiling. It is never 0: zero is the narrowest value there is, and a rule
    nobody could measure must not read as the tightest rule on the device.

    NEGATION READS THE COMPLEMENT, NOT THE MEMBERS. A negated side keeps its member refs - they
    are what the config says and what name search needs - and gains a synthetic complement ref
    beside them. Unioning all of them would cover the whole space on every negated rule. The
    complement alone is what the rule actually permits; where one could not be computed, the
    side is indeterminate for the same reason the complement was refused.

    The union is MERGED before counting, so two members covering the same /8 are one /8 rather
    than two.
    """
    if negated:
        if complement_ref is None:
            return None
        intervals = _member_intervals_or_none(complement_ref)
        return num_hosts_from_intervals(intervals) if intervals else None

    all_intervals: list[tuple[int, int]] = []
    for ref in resolved_refs:
        intervals = _member_intervals_or_none(ref)
        if intervals is None:
            return None
        all_intervals.extend(intervals)
    if not all_intervals:
        return None
    return num_hosts_from_intervals(merge_intervals(all_intervals))


def build_normalized_security_rules(enforcement_point: EnforcementPoint) -> list[NormalizedSecurityRule]:
    merged_snapshot = latest_merged_snapshot(enforcement_point)
    pushed_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    if merged_snapshot is None:
        raise ValueError(f"missing merged config snapshot for {enforcement_point}")
    if is_panorama_managed(enforcement_point) and pushed_snapshot is None:
        raise ValueError(f"missing pushed VSYS snapshot for {enforcement_point}")

    merged_security_rules, merged_default_rules = merged_local_rules(merged_snapshot, enforcement_point)
    pushed_pre_rules, pushed_post_rules, pushed_default_rules = (
        pushed_rules(pushed_snapshot) if pushed_snapshot is not None else ([], [], [])
    )
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


def _materialize_negated_complement_ref(
    *,
    enforcement_point: EnforcementPoint,
    normalized_rule: NormalizedSecurityRule,
    side: str,
    resolved_refs: list[ResolvedAddressRef],
) -> ResolvedAddressRef | None:
    """Create a synthetic AddressObject representing the effective (post-negation) IPv4 range
    for one side of a negated rule.

    Returns None if the complement isn't computable (see compute_negated_complement_intervals -
    a dynamic group/region member, or an EDL/FQDN member with no resolved entries yet) or if it
    computes to "matches nothing" (e.g. a negated "any"). In either case the caller leaves this
    side without a complement ref; the negate_source/negate_destination flag on SecurityRule
    still correctly records that negation is in effect.
    """
    complement_intervals = compute_negated_complement_intervals(resolved_refs)
    if not complement_intervals:
        return None

    name = f"__negated_complement__{normalized_rule.name}__{side}"
    namespace_type, namespace_value = literal_namespace(
        enforcement_point=enforcement_point,
        source_snapshot=normalized_rule.source_snapshot,
    )
    summary = ", ".join(
        f"{ipaddress.IPv4Address(start)}-{ipaddress.IPv4Address(end)}"
        for start, end in complement_intervals[:5]
    )
    if len(complement_intervals) > 5:
        summary += f", +{len(complement_intervals) - 5} more"

    address_object = AddressObject.objects.create(
        management_station=enforcement_point.management_station,
        enforcement_point=enforcement_point,
        source_snapshot=normalized_rule.source_snapshot,
        config_source=normalized_rule.config_source,
        name=name,
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_for(namespace_type),
        address_type=AddressObject.TYPE_NEGATED_COMPLEMENT,
        value=summary,
        normalized_value=summary,
        # Sized like every other object. A complement is usually the BROADEST thing on a rule -
        # inverting one host gives 4,294,967,294 - and leaving it null read as "size unknown",
        # which for anything scoring breadth is indistinguishable from narrow. The intervals
        # are already merged and disjoint by the time they get here.
        num_hosts=num_hosts_from_intervals(complement_intervals),
        is_any=False,
        is_builtin=False,
        is_synthetic=True,
        synthetic_kind=AddressObject.SYNTHETIC_KIND_NEGATED_COMPLEMENT,
        description=(
            f"System-generated: effective (post-negation) range for {side} of rule "
            f"'{normalized_rule.name}'"
        ),
        raw_object={
            "synthetic": True,
            "kind": "negated_complement",
            "rule": normalized_rule.name,
            "side": side,
        },
        last_synced_at=normalized_rule.source_snapshot.collected_at,
    )
    collected_at = timezone.now()
    AddressObjectResolvedEntry.objects.bulk_create(
        AddressObjectResolvedEntry(
            address_object=address_object,
            ipv4_start_int=start,
            ipv4_end_int=end,
            source_snapshot=normalized_rule.source_snapshot,
            collected_at=collected_at,
        )
        for start, end in complement_intervals
    )

    position = max((ref.position for ref in resolved_refs), default=-1) + 1
    return ResolvedAddressRef(
        raw_value=name,
        position=position,
        ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
        address_object=address_object,
        address_group=None,
    )


def _persist_one_security_rule(
    *,
    enforcement_point: EnforcementPoint,
    normalized_rule: NormalizedSecurityRule,
    address_objects_by_name: dict[str, list[AddressObject]],
    address_groups_by_name: dict[str, list[AddressGroup]],
    regions_by_name: dict[str, list[Region]],
    sr_ct: ContentType,
) -> SecurityRule:
    """Resolve and persist one rule's refs. Raises on any unresolvable member - callers must
    treat that as a failure scoped to this one rule, not the whole enforcement point."""
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
        raise _with_rule_context(exc, "source_address", rule_context) from exc
    try:
        destination_resolved_refs = resolve_rule_address_refs(
            members=normalized_rule.destination_address_members,
            address_objects_by_name=address_objects_by_name,
            address_groups_by_name=address_groups_by_name,
            regions_by_name=regions_by_name,
        )
    except ValueError as exc:
        raise _with_rule_context(exc, "destination_address", rule_context) from exc

    # Kept per side rather than reusing one name: side_num_hosts needs to know which complement
    # belongs to which side, and a shared variable would hand the destination's to both.
    source_complement_ref = None
    destination_complement_ref = None
    if normalized_rule.negate_source:
        source_complement_ref = _materialize_negated_complement_ref(
            enforcement_point=enforcement_point,
            normalized_rule=normalized_rule,
            side="source",
            resolved_refs=source_resolved_refs,
        )
        if source_complement_ref is not None:
            source_resolved_refs = [*source_resolved_refs, source_complement_ref]
    if normalized_rule.negate_destination:
        destination_complement_ref = _materialize_negated_complement_ref(
            enforcement_point=enforcement_point,
            normalized_rule=normalized_rule,
            side="destination",
            resolved_refs=destination_resolved_refs,
        )
        if destination_complement_ref is not None:
            destination_resolved_refs = [*destination_resolved_refs, destination_complement_ref]

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
        negate_source=normalized_rule.negate_source,
        negate_destination=normalized_rule.negate_destination,
        source_num_hosts=side_num_hosts(
            source_resolved_refs,
            negated=normalized_rule.negate_source,
            complement_ref=source_complement_ref,
        ),
        destination_num_hosts=side_num_hosts(
            destination_resolved_refs,
            negated=normalized_rule.negate_destination,
            complement_ref=destination_complement_ref,
        ),
        raw_rule=normalized_rule.raw_rule,
        last_synced_at=normalized_rule.source_snapshot.collected_at,
    )
    prov_rows = [
        FieldProvenance(
            content_type=sr_ct,
            object_id=security_rule.pk,
            field_name=fname,
            provenance_type=classify_prov_type(rk),
            raw_key=provenance_raw_key(rk),
            raw_value=provenance_value(rk, rv),
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
    return security_rule


def replace_security_rules(
    enforcement_point: EnforcementPoint,
    normalized_rules: list[NormalizedSecurityRule],
) -> tuple[list[SecurityRule], list[SecurityRuleFailure]]:
    enforcement_point.security_rules.all().delete()
    enforcement_point.address_objects.filter(
        synthetic_kind=AddressObject.SYNTHETIC_KIND_NEGATED_COMPLEMENT,
    ).delete()
    # Maps FIRST, then synthesis, then resolution. The order is the design: synthesis has
    # to know whether a name is already owned, and the maps are what answer that. Built the
    # other way round - as this was - synthesis ran before the answer existed and had to
    # approximate it with a flat set of names, which asked a different question and omitted
    # regions. realize_literal_address_objects() appends what it creates, so one build
    # serves both passes.
    address_objects_by_name, address_groups_by_name, regions_by_name = build_address_lookup_maps(enforcement_point)
    realize_literal_address_objects(
        enforcement_point,
        normalized_rules,
        address_objects_by_name,
        address_groups_by_name,
        regions_by_name,
    )
    sr_ct = ContentType.objects.get_for_model(SecurityRule)
    created_rules: list[SecurityRule] = []
    failures: list[SecurityRuleFailure] = []

    for normalized_rule in normalized_rules:
        try:
            with transaction.atomic():
                security_rule = _persist_one_security_rule(
                    enforcement_point=enforcement_point,
                    normalized_rule=normalized_rule,
                    address_objects_by_name=address_objects_by_name,
                    address_groups_by_name=address_groups_by_name,
                    regions_by_name=regions_by_name,
                    sr_ct=sr_ct,
                )
        except Exception as exc:
            # Scoped to this one rule (a savepoint rollback, not the whole enforcement
            # point) so one bad reference (an unmapped region/vendor code, a genuinely
            # missing address object, etc.) doesn't leave every other rule on this
            # enforcement point stuck with stale data.
            failures.append(
                SecurityRuleFailure(
                    name=normalized_rule.name,
                    config_source=normalized_rule.config_source,
                    rule_position=normalized_rule.rule_position,
                    error_text=str(exc),
                    unresolved_name=getattr(exc, "name", ""),
                )
            )
            continue
        created_rules.append(security_rule)

    return created_rules, failures


def rule_failures_as_issues(enforcement_point: EnforcementPoint, failures) -> list[PolicyObjectIssue]:
    """Turn rule failures into issues, marking the ones caused by an object that failed.

    A rule that could not resolve a name is a CONSEQUENCE when that same name already has
    an object issue - which is the case that made a single unclassifiable object look like
    1,300 separate problems, each naming an object that was fine.

    Both owners are consulted, because a rule sees the union of its point's objects and
    its appliance group's shared scope; a rule can therefore fail on an object whose issue
    is recorded against the group.
    """
    from optivedge_integrations.integrations.models import NormalizationIssue

    owners = Q(enforcement_point=enforcement_point)
    if enforcement_point.appliance_group_id is not None:
        owners |= Q(appliance_group_id=enforcement_point.appliance_group_id)
    failed_object_names = set(
        NormalizationIssue.objects.filter(owners)
        .exclude(kind="security rule")
        .exclude(name="")
        .values_list("name", flat=True)
    )

    issues = []
    for failure in failures:
        unresolved = getattr(failure, "unresolved_name", "")
        issues.append(PolicyObjectIssue(
            kind="security rule",
            name=failure.name,
            severity=PolicyObjectIssue.ERROR,
            disposition=PolicyObjectIssue.SKIPPED,
            reason=failure.error_text,
            source=failure.config_source,
            related_object_name=unresolved,
            is_consequent=bool(unresolved) and unresolved in failed_object_names,
        ))
    return issues


def normalize_security_rules(enforcement_point: EnforcementPoint) -> PANOSNormalizedCollection:
    with transaction.atomic():
        normalized_rules = build_normalized_security_rules(enforcement_point)
        created_rules, failures = replace_security_rules(enforcement_point, normalized_rules)
        replace_normalization_issues(
            enforcement_point,
            rule_failures_as_issues(enforcement_point, failures),
            kinds=(SECURITY_RULE_KIND,),
        )

    return PANOSNormalizedCollection(
        address_objects=[],
        address_groups=[],
        appliances=[],
        appliance_groups=[],
        enforcement_points=[],
        enforcement_nodes=[],
        security_rules=created_rules,
        security_rule_failures=failures,
    )
