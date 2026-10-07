"""PAN-OS anti-spyware and vulnerability profiles, and security profile groups.

Follows normalization/addresses.py deliberately: the same four sources (merged vsys, merged
shared, and the two pushed reads merged and classified by @loc), the same owner split (vsys
and vendor scope on the enforcement point, shared scope on the appliance group), and the same
per-entry failure handling. What is specific to profiles:

- PREDEFINED `default` and `strict` come from /config/predefined/profiles, which `show config
  merged` does not carry - a separate snapshot per appliance, synthesized per point like the
  other vendor objects. A missing snapshot is reported, not assumed empty.
- Every definition gets a VERDICT per severity and a REFERRER list. The verdict rule is on the
  model; the referrer walk is below.

THE REFERRER WALK does not scan by path. It walks every payload for a `spyware` or
`vulnerability` key holding a MEMBER LIST - which is what a rule's `profile-setting/profiles`
and a profile group both carry - and skips the same keys holding `entry`, which are the
definitions. The checklist item on "unused" controls is why: an enumerated path list is only as
good as its hiding places, and two referrer walks have already missed member-list references.
A reference resolves within its own scope first - vsys, then shared, then predefined - which is
PolicyObjectScope.ORDER. For profiles that order is ASSUMED, as it is for policy objects: what a
custom profile named `default` would do has not been measured.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import Q

from optivedge_integrations.integrations.models import (
    ApplianceGroup,
    EnforcementPoint,
    FieldProvenance,
    PolicyObjectNamespace,
    PolicyObjectScope,
    SecurityProfile,
    SecurityProfileGroup,
    SecurityProfileSeverityVerdict,
    SecurityRule,
    Snapshot,
    precedence_for,
    scope_for,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import (
    is_shared_scope,
    replace_normalization_issues,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    classify_prov_type,
    provenance_raw_key,
    provenance_value,
    ensure_list,
    entry_provenance,
    member_values,
    merged_shared,
    merged_vsys_entry,
    merge_pushed_entries,
    pushed_entry_scope,
    pushed_shared,
    pushed_vsys_panorama,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
    effective_in_scope_order,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    choose_local_appliance,
    is_panorama_managed,
    latest_merged_snapshot,
    latest_pushed_shared_snapshot,
    latest_pushed_vsys_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.types import (
    PolicyObjectIssue,
)

#: Every profile kind normalized into rows. Antivirus is here for PAN-AVW-006 and so a rule's
#: `virus` profile resolves to an object; it writes no severity verdicts - see below.
PROFILE_KINDS = (SecurityProfile.KIND_SPYWARE, SecurityProfile.KIND_VULNERABILITY,
                SecurityProfile.KIND_VIRUS)

#: What counts as blocking a threat. Jason, 2026-09-11: any blocking action passes - a deviation
#: from the corpus minimum, which names reset-both alone. `default` is NOT here: a signature's
#: default action is "typically either Alert or Reset Both" (Help p.272), so it cannot be relied
#: on to block, and the shipped `default` profile is exactly that case.
BLOCKING_ACTIONS = frozenset({"drop", "reset-client", "reset-server", "reset-both", "block-ip"})

#: Critical and high are what PAN-SPY-001 and PAN-VLN-001 assert; medium is the corpus
#: PREFERRED value, carried for the tab.
ASSESSED_SEVERITIES = ("critical", "high", "medium")

#: Every profile type a group can name. Read now so antivirus, URL filtering and the rest do not
#: need a second walk when their controls are built.
GROUP_MEMBER_TYPES = ("virus", "spyware", "vulnerability", "url-filtering", "file-blocking",
                      "wildfire-analysis", "data-filtering", "gtp", "sctp")

PREDEFINED_PROFILES_SOURCE_TYPE = "config_predefined_security_profiles"

ISSUE_KINDS = ("security profile", "security profile group", "security profile reference")

_DETAIL_MAX = 255


# --------------------------------------------------------------------------- the verdict


def rule_action(rule: dict[str, Any]) -> str:
    """The action a rule takes. `action` is a CHOICE element - `<action><reset-both/></action>`
    parses to {"reset-both": None} - and a pushed rule's carries @loc beside the choice."""
    node = rule.get("action")
    if isinstance(node, dict):
        choices = [k for k in node if not k.startswith("@") and k != "#text"]
        if len(choices) == 1:
            return choices[0]
        return str(node.get("#text") or "").strip() or ",".join(choices)
    if isinstance(node, str):
        return node.strip()
    return ""


def _members(node: Any) -> list[str]:
    return [value for value, _ in member_values(node)]


def _text(node: Any) -> str:
    return scalar_value(node)[0]


def _is_any_text(value: str) -> bool:
    # An absent threat-name or category is read as any. Unmeasured: every rule the device and
    # the predefined profiles store carries both explicitly.
    return value in ("", "any")


def _is_any_members(values: list[str]) -> bool:
    return not values or "any" in values


def is_catch_all(kind: str, rule: dict[str, Any]) -> bool:
    """A rule matching every signature of the severities it names - no name, category, CVE or
    vendor narrowing. Only such a rule COVERS a severity; a narrow one can only open a hole."""
    if not (_is_any_text(_text(rule.get("threat-name"))) and _is_any_text(_text(rule.get("category")))):
        return False
    if kind == SecurityProfile.KIND_VULNERABILITY:
        return _is_any_members(_members(rule.get("cve"))) and _is_any_members(_members(rule.get("vendor-id")))
    return True


def profile_rules(entry: dict[str, Any]) -> list[dict[str, Any]]:
    rules = entry.get("rules")
    return [r for r in ensure_list(rules.get("entry") if isinstance(rules, dict) else None)
            if isinstance(r, dict)]


def severity_verdict(kind: str, rules: list[dict[str, Any]], severity: str) -> tuple[bool, str]:
    """(blocked, detail) for one severity, ORDER-INDEPENDENT - see the model's docstring.

    Vulnerability rules also match on host, so a severity is judged separately for the client
    and the server side and must pass on both: a catch-all rule for `host client` leaves every
    server-side exploit of that severity unmatched.
    """
    sides = ("client", "server") if kind == SecurityProfile.KIND_VULNERABILITY else (None,)
    reasons: dict[Any, str | None] = {}
    actions: list[str] = []
    for side in sides:
        matching = []
        for rule in rules:
            severities = _members(rule.get("severity"))
            if severity not in severities and "any" not in severities:
                continue
            if side is not None and (_text(rule.get("host")) or "any") not in ("any", side):
                continue
            matching.append(rule)
        if not any(is_catch_all(kind, r) for r in matching):
            reasons[side] = "no catch-all rule"
            continue
        weak = [r for r in matching if rule_action(r) not in BLOCKING_ACTIONS]
        if weak:
            reasons[side] = f"{rule_action(weak[0]) or 'no action'} by rule {weak[0].get('@name')}"
            continue
        reasons[side] = None
        for rule in matching:
            if is_catch_all(kind, rule) and rule_action(rule) not in actions:
                actions.append(rule_action(rule))

    failures = {side: reason for side, reason in reasons.items() if reason}
    if not failures:
        return True, ", ".join(actions)[:_DETAIL_MAX]
    if len(failures) == len(sides) and len(set(failures.values())) == 1:
        # Both sides fail for the same reason - usually one host-any rule - so say it once.
        return False, next(iter(failures.values()))[:_DETAIL_MAX]
    return False, "; ".join(f"{side} side: {reason}" if side else reason
                            for side, reason in failures.items())[:_DETAIL_MAX]


# --------------------------------------------------------------------------- normalized forms


@dataclass(slots=True)
class NormalizedSecurityProfile:
    source_snapshot: Snapshot
    config_source: str
    kind: str
    name: str
    namespace_type: str
    namespace_value: str
    precedence_rank: int
    description: str
    rule_count: int
    threat_exception_count: int
    verdicts: dict[str, tuple[bool, str]]
    raw_profile: dict[str, Any]
    field_provenance_data: list[tuple[str, Any, str | None]]

    @property
    def is_predefined(self) -> bool:
        return self.namespace_type == PolicyObjectNamespace.PREDEFINED

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.kind, self.name, str(self.namespace_type), self.namespace_value)


@dataclass(slots=True)
class NormalizedSecurityProfileGroup:
    source_snapshot: Snapshot
    config_source: str
    name: str
    namespace_type: str
    namespace_value: str
    precedence_rank: int
    members: dict[str, list[str]]
    raw_group: dict[str, Any]
    field_provenance_data: list[tuple[str, Any, str | None]]


@dataclass(frozen=True, slots=True)
class ProfileReference:
    kind: str
    name: str
    #: Readable path to the rule or group that names the profile, e.g.
    #: "vsys1 rulebase/security/rules/allow-web".
    referrer: str
    #: Whether the REFERRER lives in shared scope. A shared referrer cannot see vsys
    #: definitions, so it resolves shared first.
    shared_scope: bool


@dataclass(slots=True)
class SecurityProfileBuild:
    profiles: list[NormalizedSecurityProfile] = field(default_factory=list)
    groups: list[NormalizedSecurityProfileGroup] = field(default_factory=list)
    references: list[ProfileReference] = field(default_factory=list)
    issues: list[PolicyObjectIssue] = field(default_factory=list)


def normalize_security_profile(
    *, kind: str, source_snapshot: Snapshot, config_source: str, namespace_type: str,
    namespace_value: str, entry: dict[str, Any],
) -> NormalizedSecurityProfile:
    entry_rk, entry_rv = entry_provenance(entry)
    description, description_rk, description_rv = scalar_value(entry.get("description"))
    rules = profile_rules(entry)
    exceptions = entry.get("threat-exception")
    return NormalizedSecurityProfile(
        source_snapshot=source_snapshot,
        config_source=config_source,
        kind=kind,
        name=str(entry.get("@name") or ""),
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_for(namespace_type),
        description=description,
        rule_count=len(rules),
        threat_exception_count=len([e for e in ensure_list(
            exceptions.get("entry") if isinstance(exceptions, dict) else None) if isinstance(e, dict)]),
        # EMPTY for a kind with no severity rules. severity_verdict() would return
        # (False, "no catch-all rule") for an antivirus profile - true of its rule list, which
        # does not exist, and read by a consumer as "critical threats are not blocked". A kind
        # that does not answer the question writes no rows at all.
        verdicts=({severity: severity_verdict(kind, rules, severity)
                   for severity in ASSESSED_SEVERITIES}
                  if kind in SecurityProfile.THREAT_RULE_KINDS else {}),
        raw_profile=entry,
        field_provenance_data=[
            ("__entry__", entry_rk, entry_rv),
            ("description", description_rk, description_rv),
        ],
    )


def normalize_security_profile_group(
    *, source_snapshot: Snapshot, config_source: str, namespace_type: str, namespace_value: str,
    entry: dict[str, Any],
) -> NormalizedSecurityProfileGroup:
    entry_rk, entry_rv = entry_provenance(entry)
    return NormalizedSecurityProfileGroup(
        source_snapshot=source_snapshot,
        config_source=config_source,
        name=str(entry.get("@name") or ""),
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_for(namespace_type),
        members={kind: _members(entry.get(kind)) for kind in GROUP_MEMBER_TYPES
                 if entry.get(kind) is not None},
        raw_group=entry,
        field_provenance_data=[("__entry__", entry_rk, entry_rv)],
    )


# --------------------------------------------------------------------------- references


def collect_references(root: Any, *, where: str, shared_root: bool, pushed: bool) -> list[ProfileReference]:
    """Every rule or group in `root` naming a profile. See the module docstring for why this walks
    the whole payload rather than enumerating paths.

    A pushed referrer's scope comes from its @loc, like a pushed object's: "shared" is Panorama
    Shared, anything else a device group, which is vsys-scoped on the firewall.
    """
    found: list[ProfileReference] = []

    def walk(node: Any, path: str, owner: str, owner_loc: str | None) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item, path, owner, owner_loc)
            return
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            if key.startswith("@") or key == "#text":
                continue
            if key in PROFILE_KINDS and isinstance(value, dict) and "entry" not in value:
                shared = (owner_loc == "shared") if pushed else shared_root
                for name in _members(value):
                    found.append(ProfileReference(kind=key, name=name, referrer=owner or f"{where}{path}",
                                                  shared_scope=shared))
                continue
            if key == "entry":
                for entry in ensure_list(value):
                    if isinstance(entry, dict):
                        walk(entry, path, f"{where}{path.strip('/')}/{entry.get('@name')}",
                             entry.get("@loc", owner_loc))
                continue
            walk(value, f"{path}/{key}", owner, owner_loc)

    walk(root, "", "", None)
    return found


def attribute_references(
    references: list[ProfileReference], profiles: list[NormalizedSecurityProfile],
) -> tuple[dict[tuple[str, str, str, str], list[str]], list[ProfileReference]]:
    """Map each reference to the definition it resolves to: vsys, then shared, then predefined.
    Returns ({profile key: [referrer, ...]}, unresolved references)."""
    by_scope: dict[str, dict[tuple[str, str], NormalizedSecurityProfile]] = {
        PolicyObjectScope.VSYS: {}, PolicyObjectScope.SHARED: {}, PolicyObjectScope.VENDOR: {}}
    for profile in profiles:
        by_scope[scope_for(profile.namespace_type)].setdefault((profile.kind, profile.name), profile)

    attributed: dict[tuple[str, str, str, str], list[str]] = {}
    unresolved: list[ProfileReference] = []
    for reference in dict.fromkeys(references):
        scopes = PolicyObjectScope.ORDER[1:] if reference.shared_scope else PolicyObjectScope.ORDER
        target = next((by_scope[s][(reference.kind, reference.name)] for s in scopes
                       if (reference.kind, reference.name) in by_scope[s]), None)
        if target is None:
            unresolved.append(reference)
            continue
        referrers = attributed.setdefault(target.key, [])
        if reference.referrer not in referrers:
            referrers.append(reference.referrer)
    return attributed, unresolved


# --------------------------------------------------------------------------- the build


def latest_predefined_profiles_snapshot(enforcement_point: EnforcementPoint) -> Snapshot | None:
    appliance = choose_local_appliance(enforcement_point)
    if appliance is None:
        return None
    return (Snapshot.objects.filter(appliance=appliance, source_type=PREDEFINED_PROFILES_SOURCE_TYPE)
            .order_by("-collected_at", "-pk").first())


def _predefined_root(payload: Any) -> dict[str, Any]:
    """The `profiles` node of a predefined-profiles snapshot, whichever way the read wrapped it."""
    if not isinstance(payload, dict):
        return {}
    for candidate in (payload, payload.get("result"), (payload.get("response") or {}).get("result")):
        if isinstance(candidate, dict) and isinstance(candidate.get("profiles"), dict):
            return candidate["profiles"]
    return {}


def _entries(root: dict[str, Any], key: str) -> list[dict[str, Any]]:
    node = root.get(key) if isinstance(root, dict) else None
    return [e for e in ensure_list(node.get("entry") if isinstance(node, dict) else None)
            if isinstance(e, dict)]


def build_normalized_security_profiles(enforcement_point: EnforcementPoint) -> SecurityProfileBuild:
    """Every profile, group and reference visible from this point. Raises only when a READ is
    unusable - a missing merged or pushed snapshot - as the address build does."""
    merged_snapshot = latest_merged_snapshot(enforcement_point)
    pushed_shared_snapshot = latest_pushed_shared_snapshot(enforcement_point)
    pushed_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    if merged_snapshot is None:
        raise ValueError(f"missing merged config snapshot for {enforcement_point}")
    if is_panorama_managed(enforcement_point) and pushed_shared_snapshot is None:
        raise ValueError(f"missing pushed shared policy snapshot for {enforcement_point}")
    if is_panorama_managed(enforcement_point) and pushed_snapshot is None:
        raise ValueError(f"missing pushed VSYS snapshot for {enforcement_point}")

    vsys = enforcement_point.vsys_name
    merged_root = merged_vsys_entry(merged_snapshot.payload, vsys)
    merged_shared_root = merged_shared(merged_snapshot.payload)
    pushed_shared_root = pushed_shared(pushed_shared_snapshot.payload) if pushed_shared_snapshot else {}
    pushed_root = pushed_vsys_panorama(pushed_snapshot.payload) if pushed_snapshot else {}

    build = SecurityProfileBuild()

    def collect(target, kind_label, node, source, entry, make, shared=False):
        name = str(entry.get("@name") or "")
        if not name:
            build.issues.append(PolicyObjectIssue(
                kind=kind_label, name="", severity=PolicyObjectIssue.ERROR, node=node, source=source,
                reason="entry has no @name, so it cannot be identified or referenced",
                raw_entry=entry, shared_scope=shared))
            return
        try:
            target.append(make())
        except Exception as exc:  # noqa: BLE001 - one bad entry must not take the rest
            build.issues.append(PolicyObjectIssue(
                kind=kind_label, name=name, severity=PolicyObjectIssue.ERROR, node=node, source=source,
                reason=f"{type(exc).__name__}: {exc}", raw_entry=entry, shared_scope=shared))

    local_sources = (
        (merged_root, PolicyObjectNamespace.LOCAL_VSYS, vsys, "merged vsys", False),
        (merged_shared_root, PolicyObjectNamespace.LOCAL_SHARED, "shared", "merged shared", True),
    )
    for root, namespace_type, namespace_value, source, shared in local_sources:
        profiles_root = root.get("profiles") if isinstance(root.get("profiles"), dict) else {}
        for kind in PROFILE_KINDS:
            for entry in _entries(profiles_root, kind):
                collect(build.profiles, "security profile", f"profiles/{kind}", source, entry,
                        lambda entry=entry, kind=kind, namespace_type=namespace_type,
                        namespace_value=namespace_value: normalize_security_profile(
                            kind=kind, source_snapshot=merged_snapshot, config_source=SecurityRule.SOURCE_LOCAL,
                            namespace_type=namespace_type, namespace_value=namespace_value, entry=entry),
                        shared=shared)
        for entry in _entries(root, "profile-group"):
            collect(build.groups, "security profile group", "profile-group", source, entry,
                    lambda entry=entry, namespace_type=namespace_type, namespace_value=namespace_value:
                    normalize_security_profile_group(
                        source_snapshot=merged_snapshot, config_source=SecurityRule.SOURCE_LOCAL,
                        namespace_type=namespace_type, namespace_value=namespace_value, entry=entry),
                    shared=shared)

    pushed_reads = [(pushed_shared_root, pushed_shared_snapshot), (pushed_root, pushed_snapshot)]
    pushed_profile_reads = [(r.get("profiles") if isinstance(r.get("profiles"), dict) else {}, s)
                            for r, s in pushed_reads]
    for kind, reads, kind_label, node in (
        [(k, pushed_profile_reads, "security profile", f"profiles/{k}") for k in PROFILE_KINDS]
        + [("profile-group", pushed_reads, "security profile group", "profile-group")]
    ):
        entries, notes = merge_pushed_entries(reads, kind, vsys_name=vsys, label=str(enforcement_point))
        for severity, reason, entry in notes:
            build.issues.append(PolicyObjectIssue(
                kind=kind_label, name=str(entry.get("@name") or ""), severity=severity, node=node,
                source="pushed", reason=reason, raw_entry=entry, disposition=PolicyObjectIssue.KEPT,
                shared_scope=is_shared_scope(pushed_entry_scope(entry, vsys)[0])))
        for entry, snapshot, namespace_type, namespace_value in entries:
            shared = is_shared_scope(namespace_type)
            if kind == "profile-group":
                make = (lambda entry=entry, snapshot=snapshot, namespace_type=namespace_type,
                        namespace_value=namespace_value: normalize_security_profile_group(
                            source_snapshot=snapshot, config_source=SecurityRule.SOURCE_PUSHED_PRE,
                            namespace_type=namespace_type, namespace_value=namespace_value, entry=entry))
                collect(build.groups, kind_label, node, "pushed", entry, make, shared=shared)
            else:
                make = (lambda entry=entry, snapshot=snapshot, kind=kind, namespace_type=namespace_type,
                        namespace_value=namespace_value: normalize_security_profile(
                            kind=kind, source_snapshot=snapshot, config_source=SecurityRule.SOURCE_PUSHED_PRE,
                            namespace_type=namespace_type, namespace_value=namespace_value, entry=entry))
                collect(build.profiles, kind_label, node, "pushed", entry, make, shared=shared)

    predefined_snapshot = latest_predefined_profiles_snapshot(enforcement_point)
    if predefined_snapshot is None:
        build.issues.append(PolicyObjectIssue(
            kind="security profile", name="", severity=PolicyObjectIssue.WARNING, node="predefined",
            source="predefined", disposition=PolicyObjectIssue.KEPT,
            reason=("predefined security profiles were not collected for this appliance, so a rule "
                    "or group naming 'default' or 'strict' cannot be assessed"),
            raw_entry={}))
    else:
        predefined_root = _predefined_root(predefined_snapshot.payload)
        for kind in PROFILE_KINDS:
            for entry in _entries(predefined_root, kind):
                collect(build.profiles, "security profile", f"predefined/profiles/{kind}", "predefined",
                        entry, lambda entry=entry, kind=kind: normalize_security_profile(
                            kind=kind, source_snapshot=predefined_snapshot,
                            config_source=SecurityRule.SOURCE_LOCAL,
                            namespace_type=PolicyObjectNamespace.PREDEFINED,
                            namespace_value="predefined", entry=entry))

    for root, where, shared_root, pushed in (
        (merged_root, f"{vsys} ", False, False),
        (merged_shared_root, "shared ", True, False),
        (pushed_shared_root, "pushed ", False, True),
        (pushed_root, "pushed ", False, True),
    ):
        build.references.extend(collect_references(root, where=where, shared_root=shared_root, pushed=pushed))
    return build


# --------------------------------------------------------------------------- writing


def replace_security_profiles(
    owner: EnforcementPoint | ApplianceGroup,
    profiles: list[NormalizedSecurityProfile],
    groups: list[NormalizedSecurityProfileGroup],
    referrers: dict[tuple[str, str, str, str], list[str]],
) -> tuple[list[SecurityProfile], list[SecurityProfileGroup]]:
    """Write the definitions `owner` owns, replacing what it holds. As replace_addresses: the
    caller passes everything and this keeps its own share."""
    keep_here = ((lambda n: not is_shared_scope(n.namespace_type)) if isinstance(owner, EnforcementPoint)
                 else (lambda n: is_shared_scope(n.namespace_type)))
    owner_kwargs = ({"enforcement_point": owner} if isinstance(owner, EnforcementPoint)
                    else {"appliance_group": owner})
    owner.security_profiles.all().delete()
    owner.security_profile_groups.all().delete()

    def provenance(content_type, row, data):
        rows = [FieldProvenance(content_type=content_type, object_id=row.pk, field_name=name,
                                provenance_type=classify_prov_type(rk), raw_key=provenance_raw_key(rk), raw_value=provenance_value(rk, rv))
                for name, rk, rv in data if rk is not ABSENT]
        if rows:
            FieldProvenance.objects.bulk_create(rows)

    profile_ct = ContentType.objects.get_for_model(SecurityProfile)
    group_ct = ContentType.objects.get_for_model(SecurityProfileGroup)
    created_profiles: list[SecurityProfile] = []
    for normalized in (p for p in profiles if keep_here(p)):
        used_by = referrers.get(normalized.key, [])
        verdict = normalized.verdicts
        row = SecurityProfile.objects.create(
            management_station=owner.management_station, **owner_kwargs,
            source_snapshot=normalized.source_snapshot, config_source=normalized.config_source,
            name=normalized.name, namespace_type=normalized.namespace_type,
            namespace_value=normalized.namespace_value, precedence_rank=normalized.precedence_rank,
            kind=normalized.kind, description=normalized.description,
            is_predefined=normalized.is_predefined, rule_count=normalized.rule_count,
            threat_exception_count=normalized.threat_exception_count,
            referrer_count=len(used_by), is_used=bool(used_by), referrers=used_by,
            raw_profile=normalized.raw_profile, last_synced_at=normalized.source_snapshot.collected_at,
        )
        # One row per severity the profile actually answers for. A kind with no threat rules
        # writes none, so "makes no claim" is the absence of a row rather than a `False`.
        SecurityProfileSeverityVerdict.objects.bulk_create([
            SecurityProfileSeverityVerdict(
                security_profile=row, severity=severity, blocked=blocked, detail=detail)
            for severity, (blocked, detail) in verdict.items()
        ])
        provenance(profile_ct, row, normalized.field_provenance_data)
        created_profiles.append(row)

    created_groups: list[SecurityProfileGroup] = []
    for normalized in (g for g in groups if keep_here(g)):
        row = SecurityProfileGroup.objects.create(
            management_station=owner.management_station, **owner_kwargs,
            source_snapshot=normalized.source_snapshot, config_source=normalized.config_source,
            name=normalized.name, namespace_type=normalized.namespace_type,
            namespace_value=normalized.namespace_value, precedence_rank=normalized.precedence_rank,
            spyware_profile=", ".join(normalized.members.get("spyware", [])),
            vulnerability_profile=", ".join(normalized.members.get("vulnerability", [])),
            members=normalized.members, raw_group=normalized.raw_group,
            last_synced_at=normalized.source_snapshot.collected_at,
        )
        provenance(group_ct, row, normalized.field_provenance_data)
        created_groups.append(row)
    return created_profiles, created_groups


def _unresolved_issues(unresolved: list[ProfileReference]) -> list[PolicyObjectIssue]:
    return [PolicyObjectIssue(
        kind="security profile reference", name=ref.name, severity=PolicyObjectIssue.WARNING,
        node=ref.kind, source="reference", disposition=PolicyObjectIssue.KEPT,
        reason=(f"{ref.referrer} names {ref.kind} profile {ref.name!r}, which resolves to no "
                f"collected definition. PAN-OS refuses a commit naming a missing profile, so "
                f"this is a collection gap, not a configuration fault."),
        raw_entry={}, shared_scope=ref.shared_scope) for ref in unresolved]


def _own_issues(owner, issues: list[PolicyObjectIssue]) -> list[PolicyObjectIssue]:
    # replace_normalization_issues filters by scope only for the address kinds, so do it here:
    # both passes see every issue, and without this each is stored twice.
    want_shared = not isinstance(owner, EnforcementPoint)
    return [i for i in issues if getattr(i, "shared_scope", False) == want_shared]


def normalize_security_profiles(enforcement_point: EnforcementPoint) -> dict[str, int]:
    """The point's own definitions: vsys scope and predefined. Shared scope is written by the
    appliance-group pass, which must run first for the same reason the address one does."""
    with transaction.atomic():
        build = build_normalized_security_profiles(enforcement_point)
        referrers, unresolved = attribute_references(build.references, build.profiles)
        issues = build.issues + _unresolved_issues(unresolved)
        profiles, groups = replace_security_profiles(enforcement_point, build.profiles, build.groups, referrers)
        replace_normalization_issues(enforcement_point, _own_issues(enforcement_point, issues), kinds=ISSUE_KINDS)
    return {"security_profiles": len(profiles), "security_profile_groups": len(groups), "issues": len(issues)}


def normalize_appliance_group_security_profiles(appliance_group: ApplianceGroup) -> dict[str, int]:
    """The group's shared-scope definitions, unioned across its in-scope points as the address
    group pass does - Panorama pushes only what each device group references, so no single point
    is guaranteed to see every shared definition. A shared profile's referrers are likewise
    gathered from every point, since a rule in any vsys can name it."""
    points = list(appliance_group.enforcement_points.filter(in_scope=True).order_by("vsys_name", "pk"))
    shared_profiles: dict[tuple[str, str, str, str], NormalizedSecurityProfile] = {}
    shared_groups: dict[tuple[str, str, str], NormalizedSecurityProfileGroup] = {}
    referrers: dict[tuple[str, str, str, str], list[str]] = {}
    issues: list[PolicyObjectIssue] = []
    with transaction.atomic():
        for point in points:
            build = build_normalized_security_profiles(point)
            issues.extend(build.issues)
            point_referrers, _ = attribute_references(build.references, build.profiles)
            for profile in build.profiles:
                if not is_shared_scope(profile.namespace_type):
                    continue
                existing = shared_profiles.setdefault(profile.key, profile)
                if existing.raw_profile != profile.raw_profile:
                    raise ValueError(
                        f"conflicting shared {profile.kind} profile definitions for {profile.name!r} across "
                        f"the enforcement points of {appliance_group}: shared scope is one namespace")
                for referrer in point_referrers.get(profile.key, []):
                    if referrer not in referrers.setdefault(profile.key, []):
                        referrers[profile.key].append(referrer)
            for group in build.groups:
                if is_shared_scope(group.namespace_type):
                    shared_groups.setdefault((group.name, str(group.namespace_type), group.namespace_value), group)
        profiles, groups = replace_security_profiles(
            appliance_group, list(shared_profiles.values()), list(shared_groups.values()), referrers)
        replace_normalization_issues(appliance_group, _own_issues(appliance_group, issues), kinds=ISSUE_KINDS)
    return {"security_profiles": len(profiles), "security_profile_groups": len(groups), "issues": len(issues)}


# --------------------------------------------------------------------------------------------
# Which threat profiles actually reach a rule
# --------------------------------------------------------------------------------------------

#: The config element names for the three types PAN-POL-008 asserts, mapped to the columns they
#: set. These are PAN-OS's own names, the same vocabulary `profile-setting/profiles` uses and the
#: same keys `SecurityProfileGroup.members` is keyed by, so no translation table is needed.
PROFILE_COVERAGE_COLUMNS = {
    "virus": "has_antivirus_profile",
    "spyware": "has_spyware_profile",
    "vulnerability": "has_vulnerability_profile",
}


def profile_types_in_force(rule, groups_by_name: dict[str, list]) -> set[str]:
    """Every profile type protecting `rule`, from its own profiles AND through its group.

    A rule names either individual profiles or one profile group. The group has to be RESOLVED -
    looked up by name, by scope, and read for what it actually contains - because a group that
    names nothing protects nothing. The lab's `default` group is exactly that, and 113 rules
    point at it.
    """
    types: set[str] = set()
    for direct in rule.securityruleprofiles.all():
        if direct.profile_type:
            types.add(direct.profile_type)
    for reference in rule.securityruleprofilegroups.all():
        group = effective_in_scope_order(
            reference.value, groups_by_name, "security profile group")
        if group is not None:
            types.update(group.members or {})
    return types


def normalize_security_rule_profile_coverage(enforcement_point: EnforcementPoint) -> dict:
    """Set each rule's profile-coverage columns. Runs AFTER the profile groups are normalized.

    A separate pass rather than part of rule normalization, because the groups it reads are
    written later in the refresh - rules at flows.py normalize before profiles do. Computing
    this inline would read the PREVIOUS run's groups, or none at all on a first collection,
    and be wrong in a way nothing would report.
    """
    groups_by_name: dict[str, list] = {}
    owner = Q(enforcement_point=enforcement_point)
    if enforcement_point.appliance_group_id:
        owner = owner | Q(appliance_group_id=enforcement_point.appliance_group_id)
    for group in SecurityProfileGroup.objects.filter(owner):
        groups_by_name.setdefault(group.name, []).append(group)

    updated = 0
    counts = {column: 0 for column in PROFILE_COVERAGE_COLUMNS.values()}
    rules = (SecurityRule.objects.filter(enforcement_point=enforcement_point)
             .prefetch_related("securityruleprofiles", "securityruleprofilegroups"))
    for rule in rules:
        types = profile_types_in_force(rule, groups_by_name)
        changed = []
        for element, column in PROFILE_COVERAGE_COLUMNS.items():
            value = element in types
            if value:
                counts[column] += 1
            if getattr(rule, column) != value:
                setattr(rule, column, value)
                changed.append(column)
        if changed:
            rule.save(update_fields=changed)
            updated += 1
    return {"rules": rules.count(), "updated": updated, **counts}
