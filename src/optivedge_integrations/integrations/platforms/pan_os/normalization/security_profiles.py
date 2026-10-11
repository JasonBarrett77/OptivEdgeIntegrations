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
    SecurityProfileApplicationOverride,
    SecurityProfileDecoder,
    SecurityProfileDnsSignatureSource,
    SecurityProfileGroup,
    SecurityProfileMlModel,
    SecurityProfileInlineDetector,
    SecurityProfileWildfireRule,
    SecurityProfileCategoryVerdict,
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
                SecurityProfile.KIND_VIRUS, SecurityProfile.KIND_WILDFIRE_ANALYSIS)

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


def _narrows_beyond_category(kind: str, rule: dict[str, Any]) -> bool:
    """Does this rule pick out particular signatures, rather than a whole category?

    `is_catch_all` cannot be reused: it requires `category any`, and a rule naming exactly the
    category being asked about is the BEST case here, not a disqualifying one.
    """
    if not _is_any_text(_text(rule.get("threat-name"))):
        return True
    if kind == SecurityProfile.KIND_VULNERABILITY:
        return not (_is_any_members(_members(rule.get("cve")))
                    and _is_any_members(_members(rule.get("vendor-id"))))
    return False


def _blocks_source(rule: dict[str, Any]) -> bool:
    """`block-ip` WITH a `track-by`. Anything else lets the next attempt through.

    `track-by` is required at commit, so a rule without one cannot be running - but it can sit
    in a candidate, and a profile read from one should not be credited with blocking.
    """
    if rule_action(rule) != "block-ip":
        return False
    node = rule.get("action")
    block = node.get("block-ip") if isinstance(node, dict) else None
    return bool(_text(block.get("track-by")) if isinstance(block, dict) else "")


def _block_ip_settings(rule: dict[str, Any]) -> tuple[str, int | None]:
    """(track_by, duration) off a `block-ip` rule. duration None means the config is SILENT."""
    node = rule.get("action")
    block = node.get("block-ip") if isinstance(node, dict) else None
    if not isinstance(block, dict):
        return "", None
    raw = _text(block.get("duration"))
    return _text(block.get("track-by")), (int(raw) if raw.isdigit() else None)


def category_verdict(
    kind: str, rules: list[dict[str, Any]], category: str,
) -> tuple[bool, str, str, int | None, str]:
    """(blocks_source, weakest_action, track_by, duration, detail) for one threat category.

    PAN-VLN-002. Order-independent and conservative in the same way `severity_verdict` is: the
    WEAKEST rule covering the category decides, because which rule a given signature hits is
    not knowable from the config alone.

    **A rule NAMING the category establishes coverage; a `category any` rule can only ADD
    coverage, never remove it.** That is a deliberate asymmetry, and the one place this differs
    from `severity_verdict`'s weakest-wins. Without it the two vulnerability controls are
    mutually unsatisfiable in practice: PAN-VLN-001 wants a catch-all rule blocking critical,
    high and medium, the vendor says that action should be `reset-both` (Help p.291), and any
    such rule also matches brute-force signatures - so weakest-wins let it defeat a dedicated
    `block-ip` rule and the only profile that could pass both controls was one using `block-ip`
    as its catch-all action for every severity. Measured against the lab 2026-10-11: a profile
    written exactly as the corpus's own remediation describes failed this control.

    **RULE ORDER IS NOT READ, and whether it matters here is NOT established.** PAN-OS
    evaluates a profile's rules top-down, so a `category any` reset-both rule sitting ABOVE a
    `brute-force` block-ip rule may well take precedence and leave the source unblocked. This
    reads the config as a set and credits the specific rule wherever it sits, because the
    alternative - reporting a profile whose rules express the right intent - is a false
    positive on a correct configuration, and because settling it needs brute-force traffic
    against both orderings rather than another read. See in-flight.json.

    A rule covers the category when it does not narrow to particular signatures by name, CVE or
    vendor id. Coverage is then required across ASSESSED_SEVERITIES and both host sides - the
    same two dimensions the severity verdict walks, reused rather than re-decided, so a rule
    blocking only critical brute-force does not read as blocking brute-force.
    """
    sides = ("client", "server") if kind == SecurityProfile.KIND_VULNERABILITY else (None,)
    weakest, track_by, duration = "", "", None
    failure = ""
    for side in sides:
        for severity in ASSESSED_SEVERITIES:
            named, broad = [], []
            for rule in rules:
                severities = _members(rule.get("severity"))
                if severity not in severities and not _is_any_members(severities):
                    continue
                if side is not None and (_text(rule.get("host")) or "any") not in ("any", side):
                    continue
                rule_category = _text(rule.get("category"))
                if rule_category not in ("", "any", category):
                    continue
                if _narrows_beyond_category(kind, rule):
                    continue
                (named if rule_category == category else broad).append(rule)

            # A broad rule counts only when it blocks the source - it can ADD coverage and
            # never take it away. See the asymmetry in the docstring.
            covering = named or [r for r in broad if _blocks_source(r)]
            if not covering:
                weak = [r for r in broad if not _blocks_source(r)]
                if weak:
                    action = rule_action(weak[0]) or "no action"
                    weakest = weakest or action
                    failure = failure or (
                        f"{action} by rule {weak[0].get('@name')}"
                        + (f" ({severity}, {side} side)" if side else f" ({severity})"))
                else:
                    failure = failure or (
                        f"no rule covers {category} for {severity}"
                        + (f" on the {side} side" if side else ""))
                continue

            weak = [r for r in covering if not _blocks_source(r)]
            if weak:
                action = rule_action(weak[0]) or "no action"
                weakest = weakest or action
                failure = failure or (
                    f"{action} by rule {weak[0].get('@name')}"
                    + (f" ({severity}, {side} side)" if side else f" ({severity})"))
                continue
            for rule in covering:
                found_track, found_duration = _block_ip_settings(rule)
                if found_track and not track_by:
                    track_by, duration = found_track, found_duration
            weakest = weakest or "block-ip"
    if failure:
        return False, weakest, track_by, duration, failure[:_DETAIL_MAX]
    return True, "block-ip", track_by, duration, ""


def _choice(node: Any) -> str:
    """The selected member of a PAN-OS choice element, e.g. `{"sinkhole": None}` -> "sinkhole"."""
    if isinstance(node, dict):
        chosen = [k for k in node if not k.startswith("@") and k != "#text"]
        if len(chosen) == 1:
            return chosen[0]
        return str(node.get("#text") or "").strip() or ",".join(chosen)
    return node.strip() if isinstance(node, str) else ""


def dns_signature_sources(entry: dict[str, Any]) -> list[tuple]:
    """(name, is_paloalto_content, configured, effective, sinkholes, implicit) per source.

    PAN-SPY-002. One row per entry under `botnet-domains/lists`, PLUS a synthesized row for the
    Palo Alto Networks Content list when the config does not name it - the same synthesis the
    antivirus decoders get, and for the same reason: a source that is absent still has an
    effective action, and only a row can carry it.

    THE SYNTHESIZED ROW PASSES, because Help p.284 says an unconfigured Palo Alto Networks
    Content list sinkholes. It is flagged `action_is_implicit` so the claim is visible as
    documentation rather than measurement - see the model's docstring.
    """
    botnet = entry.get("botnet-domains")
    lists = (botnet or {}).get("lists") if isinstance(botnet, dict) else None
    rows, seen_content = [], False
    for item in ensure_list(lists.get("entry") if isinstance(lists, dict) else None):
        if not isinstance(item, dict):
            continue
        name = str(item.get("@name") or "")
        action = _choice(item.get("action"))
        is_content = name == SecurityProfileDnsSignatureSource.PALOALTO_CONTENT
        seen_content = seen_content or is_content
        rows.append((name, is_content, action, action, action == "sinkhole", False))
    if not seen_content:
        implicit = SecurityProfileDnsSignatureSource.DOCUMENTED_IMPLICIT_ACTION
        rows.append((SecurityProfileDnsSignatureSource.PALOALTO_CONTENT, True, "",
                     implicit, implicit == "sinkhole", True))
    return rows


def dns_sinkhole_address(entry: dict[str, Any]) -> tuple[str, str]:
    """(ipv4, ipv6) from `botnet-domains/sinkhole`. A PREREQUISITE, not a setting.

    IPv4 is the one the device demands - measured 2026-10-11, setting only the IPv6 address
    leaves `sinkhole IPv4 information is missing` unchanged.
    """
    botnet = entry.get("botnet-domains")
    node = (botnet or {}).get("sinkhole") if isinstance(botnet, dict) else None
    if not isinstance(node, dict):
        return "", ""
    return scalar_value(node.get("ipv4-address"))[0], scalar_value(node.get("ipv6-address"))[0]


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
    #: {surface: count} for the surfaces that hold any. The total is what the column stores;
    #: this says WHERE, which is what a hygiene finding has to name.
    exception_surfaces: dict[str, int]
    verdicts: dict[str, tuple[bool, str]]
    #: Antivirus only, one tuple per decoder, THREE action columns each:
    #: (protocol, configured, effective, blocks, wf_configured, wf_effective, wf_blocks,
    #:  ml_configured, ml_effective, ml_blocks). Empty for every other kind.
    decoders: list[tuple]
    #: Antivirus only: {ml model name: configured action}, as the CONFIG holds it. Which models
    #: exist is settled against the catalogue at persist time.
    ml_models: dict[str, str]
    #: Antivirus only: (application, configured action, blocks) per per-application override.
    #: Only what the config names - see `profile_application_overrides`.
    application_overrides: list[tuple]
    #: WildFire-analysis only: one tuple per match rule. Empty for every other kind, AND for a
    #: wildfire-analysis profile that has no rules - which is a real state, not a missing one.
    wildfire_rules: list[tuple]
    #: Spyware and vulnerability only: {detector name: configured inline-policy-action}, as
    #: the CONFIG holds it. Which detectors exist is settled against the catalogue at persist
    #: time, the same way the antivirus ML models are.
    inline_detectors: dict[str, str]
    category_verdicts: dict[str, tuple[bool, str, str, int | None, str]]
    #: Anti-spyware only: one tuple per DNS signature source, including a
    #: synthesized row for the Palo Alto Networks Content list when absent.
    dns_signature_sources: list[tuple]
    dns_sinkhole_ipv4: str
    dns_sinkhole_ipv6: str
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


def profile_ml_models(entry: dict[str, Any]) -> dict[str, str]:
    """{model name: configured action} for the models this profile's config names.

    Only what the config holds. Which models EXIST is a content question answered by the
    predefined profile, and the catalogue is applied at persist time - see
    `ml_model_catalogue`.
    """
    node = entry.get("mlav-engine-filebased-enabled")
    models = {}
    for model in ensure_list(node.get("entry") if isinstance(node, dict) else None):
        if isinstance(model, dict) and model.get("@name"):
            models[str(model["@name"])] = _text(model.get("mlav-policy-action"))
    return models


def ml_model_catalogue(profiles: list) -> list[str]:
    """Every WildFire Inline ML model the device knows about, from this build's own reads.

    The PREDEFINED profile carries all of them, which is what makes this possible without
    hardcoding names controls.json explicitly says come from the content release and must be
    enumerated per version. Every virus profile in the build contributes, so a model named only
    by a custom profile is still catalogued rather than dropped.
    """
    names: list[str] = []
    for normalized in profiles:
        if normalized.kind != SecurityProfile.KIND_VIRUS:
            continue
        for name in normalized.ml_models:
            if name not in names:
                names.append(name)
    return sorted(names)


def resolve_decoder_action(protocol: str, configured: str) -> str:
    """What a decoder action MEANS. Two different things look like "nothing here".

    `default` is a POINTER and resolves per protocol - reset-both on http/http2/ftp/smb, alert
    on smtp/imap/pop3. Every decoder of every unedited profile stores it, the shipped one
    included, so a consumer reading the configured value learns nothing.

    ABSENT IS NOT `default`. It is `allow`. Measured 2026-10-07: a profile with no decoder node,
    one with a decoder carrying no action, and one naming `default` on http alone all render
    `allow` on every protocol the config does not give a value for. Conflating the two reports a
    profile that allows malware as one that blocks it.
    """
    if configured == "":
        return SecurityProfileDecoder.ABSENT_ACTION
    if configured == "default":
        return SecurityProfileDecoder.DEFAULT_RESOLUTION.get(protocol, "")
    return configured


#: Where each kind keeps its inline cloud-analysis detectors. NOT `cloud-inline-analysis`,
#: which controls.json names and which the device refuses - see SecurityProfileInlineDetector.
INLINE_DETECTOR_NODE = {
    SecurityProfile.KIND_SPYWARE: "mica-engine-spyware-enabled",
    SecurityProfile.KIND_VULNERABILITY: "mica-engine-vulnerability-enabled",
}


def exception_surfaces(entry: dict[str, Any]) -> dict[str, int]:
    """How many exceptions this profile holds, per SURFACE. PAN-SPY-005 and PAN-VLN-004.

    FOUR PLACES, not one. Measured 2026-10-10 on an anti-spyware profile:

        threat-exception                  signature exceptions
        botnet-domains/threat-exception   DNS signature exceptions
        botnet-domains/whitelist          a DNS allow-list
        inline-exception-ip-address       addresses exempt from inline cloud analysis
        inline-exception-edl-url          the EDL equivalent

    controls.json names only the first, and `threat_exception_count` counted only the first -
    so a profile exempting half an estate through `inline-exception-ip-address` counted ZERO
    exceptions. A hygiene control asking whether exceptions are minimal has to see all of
    them, which is the same reasoning that folded the application override into PAN-AVW-001.

    A vulnerability profile has no botnet tree, so two of these are always zero there. That
    is a real difference rather than a gap: the surfaces that exist are counted and the ones
    that cannot exist contribute nothing.
    """
    counts: dict[str, int] = {}

    def entries(node: Any) -> int:
        return len([e for e in ensure_list(
            node.get("entry") if isinstance(node, dict) else None) if isinstance(e, dict)])

    counts["threat-exception"] = entries(entry.get("threat-exception"))
    botnet = entry.get("botnet-domains")
    botnet = botnet if isinstance(botnet, dict) else {}
    counts["botnet-threat-exception"] = entries(botnet.get("threat-exception"))
    counts["botnet-whitelist"] = entries(botnet.get("whitelist"))
    for key in ("inline-exception-ip-address", "inline-exception-edl-url"):
        counts[key] = len([m for m in _members(entry.get(key)) if m])
    return {surface: n for surface, n in counts.items() if n}


def profile_inline_detectors(kind: str, entry: dict[str, Any]) -> dict[str, str]:
    """{detector name: configured inline-policy-action} for what the config names.

    Only what is present. Which detectors EXIST is a content question answered the same way
    the antivirus ML models answer it - catalogued across the build at persist time, so a
    detector a later content release adds is assessed without a code change.
    """
    node = entry.get(INLINE_DETECTOR_NODE.get(kind, ""))
    detectors = {}
    for detector in ensure_list(node.get("entry") if isinstance(node, dict) else None):
        if isinstance(detector, dict) and detector.get("@name"):
            detectors[str(detector["@name"])] = _text(detector.get("inline-policy-action"))
    return detectors


def inline_detector_catalogue(profiles: list, kind: str) -> list[str]:
    """Every detector of this kind seen anywhere in the build, plus the measured key space.

    UNLIKE the ML model catalogue, this falls back to a measured constant when the build
    names none. The antivirus case could rely on the predefined profile carrying every model;
    a predefined spyware profile need not mention the inline engine at all, and an empty
    catalogue would write no rows - which reads as "nothing is unprotected" and is the
    direction these controls must never fail in.

    The constant is the key SPACE, completed against a profile that does not exist, so it is
    schema rather than one device's membership. A content release that adds a detector is
    still picked up from the build.
    """
    names: list[str] = []
    for normalized in profiles:
        if normalized.kind != kind:
            continue
        for name in normalized.inline_detectors:
            if name not in names:
                names.append(name)
    for name in SecurityProfileInlineDetector.detectors_for(kind):
        if name not in names:
            names.append(name)
    return sorted(names)


def profile_wildfire_rules(entry: dict[str, Any]) -> list[tuple]:
    """(name, applications, file_types, direction, analysis, all_ft, all_app, both) per rule.

    ONLY what the config names, and nothing synthesized. A WildFire analysis profile with no
    rules is valid configuration and submits nothing - measured 2026-10-09 by writing a
    profile with no `rules` node, one with an empty node, and a rule carrying only a name, all
    three accepted. So an empty list is a real answer meaning "analyses nothing", and inventing
    a permissive default row would hide exactly the profile the control exists to find.

    `covers_both_directions` is None where `direction` is absent. The device stores nothing and
    no oracle establishes what it then does: the UI writes `both` when a rule is added through
    the form, so no instance of the absent case exists to read. Unestablished, not false.
    """
    node = entry.get("rules")
    rows = []
    for rule in ensure_list(node.get("entry") if isinstance(node, dict) else None):
        if not isinstance(rule, dict) or not rule.get("@name"):
            continue
        applications = _members(rule.get("application"))
        file_types = _members(rule.get("file-type"))
        direction = _text(rule.get("direction"))
        rows.append((
            str(rule["@name"]), applications, file_types, direction,
            _text(rule.get("analysis")),
            SecurityProfileWildfireRule.ANY in file_types,
            SecurityProfileWildfireRule.ANY in applications,
            None if not direction else direction == "both",
        ))
    return rows


def profile_application_overrides(entry: dict[str, Any]) -> list[tuple]:
    """(application, configured_action, blocks) per per-application override.

    UNLIKE `profile_decoders`, this walks ONLY what the config names and synthesizes nothing.
    A decoder is synthesized because PAN-OS evaluates all seven protocols whether the config
    mentions them or not; an override is an exception the operator added, so the absence of one
    is the absence of an override and not a silent default. Synthesizing 1454 rows per profile
    for the applications nobody overrode would be the same bug in the other direction.

    `blocks` is None for the literal `default`, whose resolution is not established here - an
    override is not per-protocol, so the decoder's resolution table cannot answer it. An entry
    with no action at all reads as `allow`, which is the same rule as an absent decoder action
    and which the device permits: it accepts an action-less entry and refuses an empty one.
    """
    node = entry.get("application")
    rows = []
    for override in ensure_list(node.get("entry") if isinstance(node, dict) else None):
        if not isinstance(override, dict) or not override.get("@name"):
            continue
        action = _text(override.get("action"))
        if action == "default":
            blocks = None
        else:
            # "" - no action element at all - falls here and resolves to ABSENT_ACTION, which
            # is `allow`, which does not block.
            effective = action or SecurityProfileDecoder.ABSENT_ACTION
            blocks = effective in SecurityProfileDecoder.BLOCKING_ACTIONS
        rows.append((str(override["@name"]), action, blocks))
    return rows


def profile_decoders(entry: dict[str, Any]) -> list[tuple]:
    """One tuple per protocol PAN-OS evaluates - ALL SEVEN, whatever the config names,
    carrying ALL THREE action columns.

    The config may name fewer decoders, or none at all, and the device still inspects every
    protocol: a profile with no decoder node renders seven rows of `allow` in the UI. Walking
    only the configured entries would leave those protocols unrepresented, and a control that
    sees no row cannot report a gap - which is how a profile that inspects nothing became
    invisible to PAN-AVW-001 in its first version.
    """
    node = entry.get("decoder")
    configured_by_protocol = {}
    for decoder in ensure_list(node.get("entry") if isinstance(node, dict) else None):
        if isinstance(decoder, dict) and decoder.get("@name"):
            configured_by_protocol[str(decoder["@name"])] = decoder

    rows = []
    for protocol in SecurityProfileDecoder.PROTOCOLS:
        decoder = configured_by_protocol.get(protocol, {})
        action = _text(decoder.get("action"))
        wildfire = _text(decoder.get("wildfire-action"))
        # The THIRD column, WILDFIRE INLINE ML ACTION. Same enum, same per-protocol
        # resolution of `default`, same absent-means-allow rule - measured 2026-10-07 from the
        # create form, which renders all three columns identically row for row.
        mlav = _text(decoder.get("mlav-action"))
        effective = resolve_decoder_action(protocol, action)
        wf_effective = resolve_decoder_action(protocol, wildfire)
        ml_effective = resolve_decoder_action(protocol, mlav)
        rows.append((
            protocol, action, effective,
            effective in SecurityProfileDecoder.BLOCKING_ACTIONS,
            wildfire, wf_effective,
            wf_effective in SecurityProfileDecoder.BLOCKING_ACTIONS,
            mlav, ml_effective,
            ml_effective in SecurityProfileDecoder.BLOCKING_ACTIONS,
        ))
    # A protocol PAN-OS adds in a later release: present in the config, unknown to PROTOCOLS.
    # Carried rather than dropped, so it is visible rather than silently unassessed.
    for protocol, decoder in configured_by_protocol.items():
        if protocol in SecurityProfileDecoder.PROTOCOLS:
            continue
        action = _text(decoder.get("action"))
        wildfire = _text(decoder.get("wildfire-action"))
        # The THIRD column, WILDFIRE INLINE ML ACTION. Same enum, same per-protocol
        # resolution of `default`, same absent-means-allow rule - measured 2026-10-07 from the
        # create form, which renders all three columns identically row for row.
        mlav = _text(decoder.get("mlav-action"))
        effective = resolve_decoder_action(protocol, action)
        wf_effective = resolve_decoder_action(protocol, wildfire)
        ml_effective = resolve_decoder_action(protocol, mlav)
        rows.append((
            protocol, action, effective,
            effective in SecurityProfileDecoder.BLOCKING_ACTIONS,
            wildfire, wf_effective,
            wf_effective in SecurityProfileDecoder.BLOCKING_ACTIONS,
            mlav, ml_effective,
            ml_effective in SecurityProfileDecoder.BLOCKING_ACTIONS,
        ))
    return rows


def normalize_security_profile(
    *, kind: str, source_snapshot: Snapshot, config_source: str, namespace_type: str,
    namespace_value: str, entry: dict[str, Any],
) -> NormalizedSecurityProfile:
    entry_rk, entry_rv = entry_provenance(entry)
    description, description_rk, description_rv = scalar_value(entry.get("description"))
    rules = profile_rules(entry)
    surfaces = exception_surfaces(entry)
    decoders = profile_decoders(entry) if kind == SecurityProfile.KIND_VIRUS else []
    ml_models = profile_ml_models(entry) if kind == SecurityProfile.KIND_VIRUS else {}
    overrides = (profile_application_overrides(entry)
                 if kind == SecurityProfile.KIND_VIRUS else [])
    wildfire = (profile_wildfire_rules(entry)
                if kind == SecurityProfile.KIND_WILDFIRE_ANALYSIS else [])
    detectors = (profile_inline_detectors(kind, entry)
                 if kind in INLINE_DETECTOR_NODE else {})
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
        # Every surface, not just the top-level node - see `exception_surfaces`. The column
        # keeps its name because it is what every consumer already reads; what changed is
        # that it no longer under-counts a profile exempting things somewhere else.
        threat_exception_count=sum(surfaces.values()),
        exception_surfaces=surfaces,
        # EMPTY for a kind with no severity rules. severity_verdict() would return
        # (False, "no catch-all rule") for an antivirus profile - true of its rule list, which
        # does not exist, and read by a consumer as "critical threats are not blocked". A kind
        # that does not answer the question writes no rows at all.
        decoders=decoders,
        ml_models=ml_models,
        application_overrides=overrides,
        wildfire_rules=wildfire,
        inline_detectors=detectors,
        verdicts=({severity: severity_verdict(kind, rules, severity)
                   for severity in ASSESSED_SEVERITIES}
                  if kind in SecurityProfile.THREAT_RULE_KINDS else {}),
        # VULNERABILITY ONLY, because `brute-force` is a member of the vulnerability rule's
        # category set and PAN-VLN-002 is the only control asking. A kind that does not answer
        # writes no row, the same rule as the severity verdict - so an antivirus profile is
        # absent here rather than recorded as failing to block brute force.
        # ANTI-SPYWARE ONLY. The DNS tree does not exist on any other kind, so no row and
        # no address rather than an empty one - a vulnerability profile makes no claim about
        # DNS sinkholing.
        dns_signature_sources=(dns_signature_sources(entry)
                               if kind == SecurityProfile.KIND_SPYWARE else []),
        dns_sinkhole_ipv4=(dns_sinkhole_address(entry)[0]
                           if kind == SecurityProfile.KIND_SPYWARE else ""),
        dns_sinkhole_ipv6=(dns_sinkhole_address(entry)[1]
                           if kind == SecurityProfile.KIND_SPYWARE else ""),
        category_verdicts=({SecurityProfileCategoryVerdict.BRUTE_FORCE:
                            category_verdict(kind, rules,
                                             SecurityProfileCategoryVerdict.BRUTE_FORCE)}
                           if kind == SecurityProfile.KIND_VULNERABILITY else {}),
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
    # From this build's own reads, before any row is written: the predefined profile carries
    # every model the content release knows about.
    catalogue = ml_model_catalogue(profiles)
    # One catalogue per kind: the two engines have different detectors, and a vulnerability
    # profile must not be given the spyware ones.
    inline_catalogues = {
        kind: inline_detector_catalogue(profiles, kind) for kind in INLINE_DETECTOR_NODE
    }
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
            exception_surfaces=normalized.exception_surfaces,
            dns_sinkhole_ipv4=normalized.dns_sinkhole_ipv4,
            dns_sinkhole_ipv6=normalized.dns_sinkhole_ipv6,
            referrer_count=len(used_by), is_used=bool(used_by), referrers=used_by,
            raw_profile=normalized.raw_profile, last_synced_at=normalized.source_snapshot.collected_at,
        )
        # One row per severity the profile actually answers for. A kind with no threat rules
        # writes none, so "makes no claim" is the absence of a row rather than a `False`.
        SecurityProfileMlModel.objects.bulk_create([
            SecurityProfileMlModel(
                security_profile=row, name=model,
                configured_action=normalized.ml_models.get(model, ""),
                # Absent means DISABLED, the same way an absent decoder action means allow.
                # `enable(alert-only)` RUNS but does not BLOCK - enumerated from the device
                # 2026-10-08, and the reason these are two flags rather than one.
                enabled=normalized.ml_models.get(model, "") in SecurityProfileMlModel.RUNS,
                blocks=normalized.ml_models.get(model, "") == SecurityProfileMlModel.BLOCKS)
            for model in (catalogue if normalized.kind == SecurityProfile.KIND_VIRUS else [])
        ])
        SecurityProfileDecoder.objects.bulk_create([
            SecurityProfileDecoder(
                security_profile=row, protocol=protocol, configured_action=configured,
                effective_action=effective, blocks=blocks,
                configured_wildfire_action=wf_configured,
                effective_wildfire_action=wf_effective, wildfire_blocks=wf_blocks,
                configured_mlav_action=ml_configured,
                effective_mlav_action=ml_effective, mlav_blocks=ml_blocks)
            for (protocol, configured, effective, blocks,
                 wf_configured, wf_effective, wf_blocks,
                 ml_configured, ml_effective, ml_blocks) in normalized.decoders
        ])
        # ONE ROW PER OVERRIDE THE CONFIG NAMES, and none otherwise - unlike the decoders
        # above, where all seven are synthesized. An override is an operator-added exception,
        # so no rows is the normal and correct state for almost every profile.
        SecurityProfileApplicationOverride.objects.bulk_create([
            SecurityProfileApplicationOverride(
                security_profile=row, application=application,
                configured_action=configured, blocks=blocks)
            for application, configured, blocks in normalized.application_overrides
        ])
        SecurityProfileInlineDetector.objects.bulk_create([
            SecurityProfileInlineDetector(
                security_profile=row, name=detector,
                configured_action=normalized.inline_detectors.get(detector, ""),
                # An unmentioned detector does not run, the same rule as an unmentioned
                # antivirus ML model. `alert` RUNS and does not block - the
                # `enable(alert-only)` case under another name.
                enabled=bool(normalized.inline_detectors.get(detector, "")),
                blocks=normalized.inline_detectors.get(detector, "")
                in SecurityProfileInlineDetector.BLOCKING_ACTIONS)
            for detector in inline_catalogues.get(normalized.kind, [])
        ])
        SecurityProfileWildfireRule.objects.bulk_create([
            SecurityProfileWildfireRule(
                security_profile=row, name=name, applications=applications,
                file_types=file_types, direction=direction, analysis=analysis,
                covers_all_file_types=all_ft, covers_all_applications=all_app,
                covers_both_directions=both)
            for (name, applications, file_types, direction, analysis,
                 all_ft, all_app, both) in normalized.wildfire_rules
        ])
        SecurityProfileSeverityVerdict.objects.bulk_create([
            SecurityProfileSeverityVerdict(
                security_profile=row, severity=severity, blocked=blocked, detail=detail)
            for severity, (blocked, detail) in verdict.items()
        ])
        SecurityProfileDnsSignatureSource.objects.bulk_create([
            SecurityProfileDnsSignatureSource(
                security_profile=row, name=name, is_paloalto_content=is_content,
                configured_action=configured, effective_action=effective,
                sinkholes=sinkholes, action_is_implicit=implicit)
            for name, is_content, configured, effective, sinkholes, implicit
            in normalized.dns_signature_sources
        ])
        SecurityProfileCategoryVerdict.objects.bulk_create([
            SecurityProfileCategoryVerdict(
                security_profile=row, category=category, blocks_source=blocks,
                weakest_action=weakest, track_by=track_by, duration=duration, detail=detail)
            for category, (blocks, weakest, track_by, duration, detail)
            in normalized.category_verdicts.items()
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


def profile_names_in_force(rule, groups_by_name: dict[str, list]) -> dict[str, str]:
    """{profile type: name} for `rule`, from its own profiles AND through its group.

    The sibling of `profile_types_in_force`, which answers only WHETHER a type is covered.
    PAN-AVW-003 needs the profile ITSELF - a rule can name a WildFire analysis profile that
    sends nothing, which is indistinguishable from a good one until you read its rules.

    A direct profile beats the group: PAN-OS takes one or the other per rule, and a rule that
    names both is resolved toward what it names explicitly.
    """
    names: dict[str, str] = {}
    for reference in rule.securityruleprofilegroups.all():
        group = effective_in_scope_order(
            reference.value, groups_by_name, "security profile group")
        if group is None:
            continue
        for profile_type, members in (group.members or {}).items():
            if members:
                names[profile_type] = members[0]
    for direct in rule.securityruleprofiles.all():
        if direct.profile_type and direct.value:
            names[direct.profile_type] = direct.value
    return names


def wildfire_analysis_verdict(rule, groups_by_name, profiles_by_name) -> tuple:
    """(submits_all, detail) for one rule. PAN-AVW-003's whole question.

    THREE OUTCOMES, and keeping them apart is the point - they have different fixes:

        None   no WildFire analysis profile reaches this rule at all. Attach one.
        False  one does and it does not send every file type. Fix the profile.
        True   one does and it does.

    The profile is RESOLVED by name and scope, not merely named: a rule pointing at a group
    that names a profile which does not exist in scope is protected by nothing, and so is a
    rule whose group names no WildFire profile at all. The lab's `default` group is that
    second case for every profile type, which is why this is resolved rather than assumed.
    """
    name = profile_names_in_force(rule, groups_by_name).get(
        SecurityProfile.KIND_WILDFIRE_ANALYSIS)
    if not name:
        return None, "no WildFire analysis profile is in force on this rule"
    profile = effective_in_scope_order(
        name, profiles_by_name, "wildfire analysis profile")
    if profile is None:
        return None, f"names WildFire analysis profile {name!r}, which resolves to nothing"
    gaps = profile.wildfire_coverage_gaps
    if not gaps:
        return True, ""
    return False, f"{name}: {'; '.join(gaps)}"[:255]


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

    # The WildFire analysis profiles reachable from here, by name, for the same scope
    # resolution the groups get. Prefetched because the verdict reads each one's rules.
    profiles_by_name: dict[str, list] = {}
    for profile in SecurityProfile.objects.filter(
            owner, kind=SecurityProfile.KIND_WILDFIRE_ANALYSIS).prefetch_related(
            "wildfire_rules"):
        profiles_by_name.setdefault(profile.name, []).append(profile)

    updated = 0
    counts = {column: 0 for column in PROFILE_COVERAGE_COLUMNS.values()}
    counts["wildfire_analysis_gap"] = 0
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
        submits_all, detail = wildfire_analysis_verdict(
            rule, groups_by_name, profiles_by_name)
        if submits_all is not True:
            counts["wildfire_analysis_gap"] += 1
        if rule.wildfire_analysis_submits_all != submits_all:
            rule.wildfire_analysis_submits_all = submits_all
            changed.append("wildfire_analysis_submits_all")
        if rule.wildfire_analysis_detail != detail:
            rule.wildfire_analysis_detail = detail
            changed.append("wildfire_analysis_detail")
        if changed:
            rule.save(update_fields=changed)
            updated += 1
    return {"rules": rules.count(), "updated": updated, **counts}
