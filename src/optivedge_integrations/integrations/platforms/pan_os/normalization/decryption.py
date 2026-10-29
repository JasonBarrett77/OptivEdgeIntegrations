"""Normalize the decryption rulebase and the SSL decryption exclusions on one estate.

Four models from three reads, at two owners:

    per ENFORCEMENT POINT   `show config merged`  -> vsys/.../rulebase/decryption/rules
                            `show config pushed-shared-policy <vsys>`
                              -> DecryptionPolicyRule, DecryptionRulebaseVerdict
    per APPLIANCE           `show config merged`  -> shared and vsys `ssl-decrypt`
                              -> SslDecryptionExclusion, SslDecryptionVendorExclusionOptOut
                            `show predefined ssl-exclude-cert` (op)
                              -> the right-hand side of the stale-residue set difference

THE READS ARE CANDIDATE-DERIVED AND THAT MATTERS ON THIS OBJECT. `show config merged` follows the
CANDIDATE (read-config-sources.md A2), and six of the decryption rule's keys are MANDATORY AT
COMMIT VALIDATION - `from`, `to`, `source`, `destination`, `action` and `type`, measured as
`validate full` job 217. So a committed rule always carries them and a STAGED one can reach this
code without them: an absent `action` here is not a default anybody applied, it is the rule not
yet being committable, and the blank plus a `not_configured` row is what says so.

THE CONTAINER HAS THREE STATES AND NOT TWO, which is the distinction `rule_count` rests on.
`common.entry_container` returns absent, empty and populated apart; absent `rulebase/decryption`
is the measured commonest state of this estate - all four lab appliances, all twenty vsys, both
Panorama Shared rulebases and all ten device groups, twice - and it is the state PAN-DEC-001
exists to raise. The operational read cannot make the distinction at all: stage 4 measured
`show running decryption-policy` answering `{"member": [null]}` - TRUTHY - on an appliance with
no rulebase, so a normalizer testing `if result:` on THAT read reports a rulebase that exists on
a device whose rulebase is empty. Every count here comes from the config read.

AND THAT READING HAS A SECOND CAUSE NOBODY HAD SEPARATED, measured 2026-10-29: the op command is
VSYS-CONTEXT-SCOPED and the context is an API PARAMETER rather than part of the command element.
Issued against fw-core-tpa-a with `target=` alone it answers `{"member": [null]}` - the same
empty-but-truthy shape - while the SAME command with `vsys=vsys2` returns all thirteen rules of
the rulebase that appliance is holding. So on a multi-vsys firewall that reply means "the default
vsys context has no decryption policy", which is strictly worse than the absence stage 4 read it
as: it is an empty answer from an appliance that DOES have a policy. Nothing here rests on the
operational read, for that reason.

NO PUSHED DECRYPTION RULE EXISTS ANYWHERE IN THIS LAB, re-measured 2026-10-29 on all four
appliances: `show config pushed-shared-policy <vsys>` returns `pre-rulebase` and `post-rulebase`
holding `security` and `default-security-rules` and NO `decryption` child. So the pushed limb
below is written from the security rulebase's measured shape at the same two paths and is
UNEXERCISED - the one part of this module a device has not confirmed. It is kept rather than
dropped because `decrypt-and-forward` is accepted ONLY at device-group scope (the firewall vsys
path refuses the write with code=12, measured), so the only rows that could ever carry that
action arrive through it.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    DecryptionPolicyRule,
    DecryptionPolicyRuleCategory,
    DecryptionPolicyRuleDestination,
    DecryptionPolicyRuleService,
    DecryptionPolicyRuleSource,
    DecryptionPolicyRuleSourceUser,
    DecryptionRulebaseVerdict,
    DecryptionSettings,
    EnforcementPoint,
    FieldProvenance,
    Snapshot,
    SslDecryptionExclusion,
    SslDecryptionVendorExclusionOptOut,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.predefined import (
    PREDEFINED_SSL_EXCLUDE_CERT_SOURCE_TYPE,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    DESCRIPTION_ABSENT,
    Implicit,
    choice_child,
    classify_prov_type,
    ensure_list,
    entry_container,
    entry_provenance,
    iter_member_values,
    merged_shared,
    merged_vsys_entry,
    parse_text_field,
    parse_yes_no_field,
    provenance_raw_key,
    provenance_value,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot as latest_appliance_merged_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
    first_vsys_rulebase,
    pushed_rulebases,
)
# The shared writer for a node-shaped model - one row per appliance, provenance per field, and
# it deletes only the provenance rows for the fields it writes so two normalizers can share a
# model. Reused rather than re-expressed: the private `_replace_for_appliance` beside it in this
# module predates it and is load-bearing for three shipped models.
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    write_node_row,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    is_panorama_managed,
    latest_merged_snapshot,
    latest_pushed_vsys_snapshot,
)


#: The entry-level provenance record - the entry's own marker rather than one of its fields.
ENTRY_FIELD = "__entry__"

#: Which satellite model carries each member-list criterion, and the key it is read from. The
#: five are declared together because PAN-DEC-002's structural half is a conjunction over EVERY
#: criterion, and a criterion left out of that conjunction is a rule bounded by something that
#: reads as bounded by nothing.
MEMBER_CRITERIA = (
    ("category", "category", DecryptionPolicyRuleCategory),
    ("source", "source", DecryptionPolicyRuleSource),
    ("destination", "destination", DecryptionPolicyRuleDestination),
    ("source_user", "source-user", DecryptionPolicyRuleSourceUser),
    ("service", "service", DecryptionPolicyRuleService),
)


# ---------------------------------------------------------------------------
# What an absent key means on this object. Every citation is stage 4's.
# ---------------------------------------------------------------------------

#: Mandatory at commit validation, so absence is a candidate-only rule rather than a default.
_MANDATORY_AT_COMMIT = (
    "MEASURED 2026-10-27, `validate full` job 217 on a decryption rule carrying no keys: the "
    "device answered `rules -> oep-dcp-bare is missing <key>` for from, to, source, destination, "
    "action and type. So {key} is mandatory on a committed rule and there is no absent state to "
    "assert a default for. The read normalized here is `show config merged`, which follows the "
    "CANDIDATE, so a STAGED rule can still arrive without it - and that is not a default anybody "
    "applied, it is the rule not yet being committable"
)

ACTION_ABSENT = Implicit.not_assumed(_MANDATORY_AT_COMMIT.format(key="`action`"))
SOURCE_ABSENT = Implicit.not_assumed(_MANDATORY_AT_COMMIT.format(key="`source`"))
DESTINATION_ABSENT = Implicit.not_assumed(_MANDATORY_AT_COMMIT.format(key="`destination`"))

#: `category` absent. MEASURED, and it is the firing side: a rule written to exempt one kind of
#: content and left without this key exempts ALL of it.
CATEGORY_ABSENT = Implicit.measured(
    ["any"],
    "MEASURED 2026-10-27 on fw-core-tpa-a: `show running decryption-policy`, which reads "
    "RUNNING, printed `category any` for a committed rule carrying only its six mandatory keys; "
    "the positive control wrote `gambling`, committed job 230, and both the compiled view and "
    "the Policies > Decryption grid's URL CATEGORY column moved and moved back on deletion, "
    "while a second rule untouched in the same two reads held the bare reading throughout")

#: `source-user` absent. MEASURED. Note the compiled view calls the field USER while the config
#: key is `source-user`.
SOURCE_USER_ABSENT = Implicit.measured(
    ["any"],
    "MEASURED 2026-10-27: `show running decryption-policy` printed `user any` for the bare "
    "committed rule; the positive control wrote `known-user`, committed job 230, and both the "
    "compiled view and the grid's USER column moved and moved back")

#: `service` absent. MEASURED.
SERVICE_ABSENT = Implicit.measured(
    ["any"],
    "MEASURED 2026-10-27: `show running decryption-policy` printed "
    "`application/service 0:ssl/any/any/any` for the bare committed rule, whose last three "
    "fields are the resolved protocol, source port and destination port")

#: `negate-source` / `negate-destination` absent. ASSUMED AND NOT MEASURED, deliberately: stage 4
#: reached no oracle that renders either key - `show running decryption-policy` does not carry
#: them and no cell of the grid row moved with them - so the absent state could not be read off a
#: rendering and this must not be presented as a vendor fact.
_NEGATE_ABSENT = (
    "ASSUMED, NOT MEASURED. Stage 4 recorded {key} as `status: unmeasured` on the decryption "
    "rule with `may_materialise: false`: no oracle it reached renders the key, so the absent "
    "state could not be read off any rendering. `no` rests on two things. (1) The payload "
    "contract's `security-rule-scope` node, measured 2026-10-05 on pan-fw-111: `ABSENT MEANS "
    "NO. When yes, the source member list is INVERTED` - a different rulebase on the same "
    "platform, so an inference here and not a reading. (2) A commit-validation refusal measured "
    "on THIS rulebase - `Negate cannot be enabled for decryption rule oep-dcp-bare with source "
    "address as 'any'` - which only makes sense if an absent key means no. A consumer must "
    "render this as assumed_default and never as a vendor default"
)
#: MEASURED 2026-10-29 BY STAGE 7'S READBACK, AND LEFT AS `assumed` ON PURPOSE. Stage 5's basis
#: says the key "is NOT RENDERED BY ANY ORACLE that run reached - `show running
#: decryption-policy` does not carry it". IT DOES: read with the API's `vsys` parameter against
#: fw-core-tpa-a/vsys2, that view renders the key as a SUFFIX ON THE SOURCE MEMBER -
#: `source 10.130.2.0/27(negate)` on oep-dec6-r04, whose config carries `negate-source: yes` -
#: while oep-dec6-r03, naming the SAME address object with the key ABSENT, renders
#: `source 10.130.2.0/27` with no suffix. That is a two-sided reading on one object, which is
#: stage 4's own bar for a measured implicit.
#:
#: IT IS NOT PROMOTED HERE. Stage 5's `rests_on: assumed` is its declaration, this stage
#: implements what stage 5 declared and reports the disagreement, and the direction of leaving it
#: is the safe one: the report prints `assumed_default` as not measured, which understates what
#: is now known rather than overstating it. Promoting it is one line and a person's call between
#: domains. THE DESTINATION SIDE IS STILL UNMEASURED - no rule in this lab carries
#: `negate-destination`, so only the source half of the rendering has been seen.
NEGATE_SOURCE_ABSENT = Implicit.assumed(False, _NEGATE_ABSENT.format(key="`negate-source`"))
NEGATE_DESTINATION_ABSENT = Implicit.assumed(
    False, _NEGATE_ABSENT.format(key="`negate-destination`"))

#: `disabled` absent. MEASURED by the sharpest control in stage 4's pass.
DISABLED_ABSENT = Implicit.measured(
    False,
    "MEASURED 2026-10-27: a decryption rule committed WITHOUT the key appears in `show running "
    "decryption-policy` and in `show running rule-use hit-count`, while the same rule committed "
    "WITH `disabled: yes` (job 231) is absent from BOTH and `action=show` still returns it "
    "carrying the key. So the compiled views render the policy in force and the absent key puts "
    "the rule there")

#: THE TWO LOG FLAGS DEFAULT OPPOSITE WAYS, two keys apart, and a consumer that assumes a
#: rulebase entry's log flags share a default gets one of them backwards.
_LOG_FLAG_CITATION = (
    "MEASURED 2026-10-27 on the Policies > Decryption grid at pan-fw-201 (serial "
    "691665AC334B458), by flipping each key in both directions on a rule carrying only its six "
    "mandatory keys and committing (job 230). THE PAIR WAS THE DISCRIMINATOR rather than the "
    "confirmation: the two cells are adjacent and unlabelled in that reader's output, so writing "
    "yes to one and no to the other is what attaches each reading to its key - under the reverse "
    "mapping the pair would have read `false | true` unchanged, and it read `true | false`. The "
    "vendor agrees independently and twice for each: Help p.175 `Enabled by default` for log-"
    "fail and p.174 `Disabled by default` for log-success, plus p.70 from the log-type end"
)
LOG_FAIL_ABSENT = Implicit.measured(True, f"log-fail absent means YES - {_LOG_FLAG_CITATION}")
LOG_SUCCESS_ABSENT = Implicit.measured(False, f"log-success absent means NO - {_LOG_FLAG_CITATION}")

#: `profile` absent. NOTHING IS ASSUMED, and the reason is a refutation rather than a gap.
PROFILE_ABSENT = Implicit.not_assumed(
    "A CONDITIONAL IMPLICIT, WHICH MUST NOT BE MATERIALISED AT ANY PRICE. Stage 4 promoted this "
    "to measured and then refuted itself: on a committed rule with only its six mandatory keys "
    "and `action: no-decrypt`, `show running decryption-policy` printed `decryption-profile ` - "
    "the key, a space, nothing - and the grid printed `none`. THEN, with the `profile` key still "
    "ABSENT, the same read printed `decryption-profile default` once `action` had been moved to "
    "`decrypt` and `type` to the ssl-inbound-inspection branch and that was committed. So the "
    "device resolves an absent profile to the PREDEFINED profile named `default` under some "
    "conditions and to nothing under others, and the value alone is not citable. PAN-DEC-008 "
    "confines itself with an applicability clause on `action equals no-decrypt`, which is one of "
    "the conditions under which the absence was measured resolving to NOTHING. "
    "WHICH SIBLING CARRIES IT IS NOW SEPARATED, 2026-10-29, which stage 4 could not do because "
    "`action` and `type` moved in the same write: IT IS `action`. Read with the API's `vsys` "
    "parameter, `show running decryption-policy` prints `decryption-profile ` - empty - for "
    "eleven of the twelve in-force rules of fw-core-tpa-a/vsys2, every one `ssl-forward-proxy` "
    "with `action: no-decrypt` and no `profile` key (the twelfth, oep-dec6-r08, names `default` "
    "explicitly and renders it); and `decryption-profile default` for all four of "
    "pan-fw-201/vsys1, every one `action: decrypt` with no `profile` key, across BOTH the "
    "ssl-forward-proxy and the ssl-inbound-inspection branch. Same branch, different action, "
    "different resolution - so the resolution follows the ACTION and not the type branch, and "
    "PAN-DEC-008's applicability clause on `action equals no-decrypt` confines the control to "
    "exactly the rows where the absent profile is known to resolve to nothing")

#: `log-setting` absent. The absence is real and measured; what the device DOES with it is not.
LOG_SETTING_ABSENT = Implicit.not_assumed(
    "THE ABSENCE IS REAL AND MEASURED; WHAT THE DEVICE DOES WITH IT IS NOT, and nothing is "
    "assumed in either direction. Measured 2026-10-27: the key is absent from the committed bare "
    "rule in all three config reads, the grid's LOG FORWARDING cell renders `none`, and `show "
    "running decryption-policy` does not render the field at all. NOT measured: where a "
    "decryption log goes when no profile is named - that needs a session to be decrypted and a "
    "log to be followed, and the appliance stage 4 held has no dataplane (0 ifnet, 0 hw, "
    "num-active 0). THE ATTACHMENT IS NOT THE DELIVERY in any case, and whether a forwarding "
    "attachment on an ORDINARY decryption rule forwards anything at all is unsettled in the "
    "vendor's own documentation - the sighting is filed in OptivEdgeProbe "
    "reference/known-vendor-contradictions.md with a three-release measurement")

#: `exclude` absent on an SSL decryption exclusion. Mandatory at commit, measured at BOTH scopes.
EXCLUDE_ABSENT = Implicit.not_assumed(
    "MEASURED 2026-10-27 by building a bare entry at EACH scope and validating: both were "
    "refused for this key - `ssl-decrypt -> ssl-exclude-cert -> oep-dcp-excl-vsys is missing "
    "'exclude'`, job 236 - so no committed exclusion is ever observed without it. The one case "
    "this does not cover is a BARE UNCOMMITTED entry, which returns only @name plus the staging "
    "attributes @admin/@dirtyId/@time, and the read normalized here is candidate-derived, so "
    "that case is real")

#: The vendor opt-out member list absent. THE ABSENCE IS MEASURED; THE READING OF IT IS ASSUMED.
DISABLED_FROM_PREDEFINED_ABSENT = Implicit.assumed(
    [],
    "ASSUMED, NOT MEASURED. The absence itself is measured - `action=get` at "
    "/config/shared/ssl-decrypt/disabled-ssl-exclude-cert-from-predefined returned null on all "
    "four lab appliances, so nobody there had switched a vendor exclusion off - but stage 4 "
    "could not establish whether an EMPTY node and an ABSENT node differ here, so an absent node "
    "is evidence of an absent node and not of a clean list. What is assumed is the READING of "
    "the absence as the empty list, and a consumer must render it as assumed_default")


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def latest_predefined_ssl_exclude_cert_snapshot(appliance: Appliance) -> Snapshot | None:
    """The newest `show predefined ssl-exclude-cert` snapshot for one appliance, or None.

    There is NO registry mapping a source type to a reader - the normalizer that wants one
    writes its own, which is why the source type is a constant beside the command and is
    imported rather than spelled again here.
    """
    return (Snapshot.objects
            .filter(appliance=appliance,
                    source_type=PREDEFINED_SSL_EXCLUDE_CERT_SOURCE_TYPE)
            .order_by("-collected_at", "-pk")
            .first())


def predefined_exclusion_names(snapshot: Snapshot | None) -> set[str]:
    """The @name of every vendor-shipped SSL decryption exclusion in one snapshot.

    An EMPTY SET AND A MISSING SNAPSHOT ARE NOT THE SAME THING and this function cannot tell the
    caller which it got - `stale_disabled_vendor_exclusion_count` is computed only where the
    snapshot exists, and the caller is what checks.

    AND THE NAME IS NOT UNIQUE IN THE VENDOR'S OWN LIST, measured 2026-10-29 on all four lab
    appliances: the reply carries 330 ENTRIES and 327 DISTINCT NAMES on both PA-5220s, and 385
    entries and 382 distinct names on both PA-VMs. The three collisions are the same three on
    every appliance - `api.lc.prod.us.cs.paloaltonetworks.com`,
    `lic.lc.prod.us.cs.paloaltonetworks.com` and `gs.apple.com` - each shipped TWICE with
    `exclude: yes` and two DIFFERENT descriptions. A SET OF NAMES IS THE RIGHT SHAPE for the
    membership test this feeds, so the collisions are harmless here; anything that keys the
    vendor list BY NAME and expects one row per entry gets 327 where the device says 330.
    Nothing here can attribute the 330-against-385 split either, because platform, PAN-OS major
    version and content release all differ together between the two appliance groups.
    """
    if snapshot is None:
        return set()
    payload = snapshot.payload
    if isinstance(payload, str) or not isinstance(payload, dict):
        # `Snapshot.payload` is a JSONField and an op reply that answers plain text stores a bare
        # `str` in it, which round-trips. `payload or {}` does not save a reader: a non-empty
        # string is truthy.
        return set()
    _, entries = entry_container(payload, "ssl-exclude-cert")
    return {str(e.get("@name")) for e in entries if e.get("@name")}


def merged_vsys_ssl_decrypt_exclusions(
    payload: dict[str, Any], vsys_name: str,
) -> tuple[str, list[dict[str, Any]]]:
    """(state, entries) for one vsys's own `ssl-decrypt/ssl-exclude-cert` collection.

    STAGE 4 RAISED THIS SCOPE AS AN OPEN QUESTION and stage 5 answered it: if the screen reads
    only /config/shared, a vsys-scoped exclusion is real, committable configuration no operator
    can see, acknowledge or remove through the interface they use. Holding the scope is what lets
    a finding name it.
    """
    return entry_container(
        merged_vsys_entry(payload, vsys_name), "ssl-decrypt", "ssl-exclude-cert")


def merged_shared_ssl_decrypt_exclusions(
    payload: dict[str, Any],
) -> tuple[str, list[dict[str, Any]]]:
    """(state, entries) for the appliance's OWN shared `ssl-decrypt/ssl-exclude-cert`.

    The owner here is LOCAL, unlike the decryption rule's shared scope, which is Panorama's. A
    collector reading only the vsys scope would report no exclusions on a firewall whose operator
    added them through the interface, which is where PAN-OS puts the screen.
    """
    return entry_container(merged_shared(payload), "ssl-decrypt", "ssl-exclude-cert")


def merged_disabled_from_predefined(payload: dict[str, Any]) -> Any:
    """The raw `disabled-ssl-exclude-cert-from-predefined` node, or None.

    SHARED SCOPE ONLY, measured by stage 4 at both scopes: /config/shared/ssl-decrypt completes
    to six children and the vsys one to five, and this node is the one the vsys scope is missing.
    So on a multi-vsys firewall the decision to switch a vendor exclusion off cannot be taken per
    vsys, and a row of this model is per appliance for a reason the device states.
    """
    shared = merged_shared(payload)
    node = shared.get("ssl-decrypt") if isinstance(shared, dict) else None
    if not isinstance(node, dict):
        return None
    return node.get("disabled-ssl-exclude-cert-from-predefined")


def local_decryption_rules(
    snapshot: Snapshot, enforcement_point: EnforcementPoint,
) -> tuple[str, list[dict[str, Any]]]:
    """(state, entries) for the firewall's OWN decryption rulebase at one enforcement point.

    `first_vsys_rulebase` is the security rulebase normalizer's own accessor for the same
    `rulebase` node and is imported rather than copied - the two rulebases are siblings under one
    parent and the walk to that parent is identical.
    """
    rulebase = first_vsys_rulebase(snapshot.payload, enforcement_point.vsys_name)
    return entry_container(rulebase, "decryption", "rules")


def pushed_decryption_rules(
    snapshot: Snapshot,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(pre, post) pushed decryption rules for one enforcement point.

    UNEXERCISED IN THIS LAB: re-measured 2026-10-29 on all four appliances, the pushed
    `pre-rulebase` and `post-rulebase` hold `security` and `default-security-rules` and no
    `decryption` child at all. `pushed_rulebases` is the security normalizer's own accessor for
    those two containers and raises on a shape nobody has seen, which is the behaviour CLAUDE.md's
    first principle asks for: being handed an unknown shape is worth failing on.
    """
    pre_rulebase, post_rulebase = pushed_rulebases(snapshot.payload)
    _, pre = entry_container(pre_rulebase, "decryption", "rules")
    _, post = entry_container(post_rulebase, "decryption", "rules")
    return pre, post


# ---------------------------------------------------------------------------
# The rule: parsing one entry
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class NormalizedDecryptionRuleMember:
    model: type
    value: str
    prov: str
    position: int


@dataclass(slots=True)
class NormalizedDecryptionRule:
    source_snapshot: Snapshot
    config_source: str
    rule_position: int
    rule_name: str
    rule_uuid: str
    action: str
    type_branch: str
    negate_source: bool
    negate_destination: bool
    disabled: bool
    log_fail: bool
    log_success: bool
    profile_name: str
    description: str
    log_setting: str
    source_user_is_keyword_population: bool
    success_record_disposition: str
    opens_session: bool
    members: list[NormalizedDecryptionRuleMember] = field(default_factory=list)
    #: (field_name, raw_key_or_Implicit, raw_prov_value)
    field_provenance_data: list[tuple[str, Any, str | None]] = field(default_factory=list)


def member_list(node: Any, *, implicit: Implicit) -> tuple[list[str], Any, str | None]:
    """A PAN-OS member list as (values, raw key, raw provenance value).

    THE DEVICE'S OWN ORDER IS KEPT, because a criterion is a set the dataplane matches against
    and nothing here ranks its members. Where the key is ABSENT the declared implicit's value is
    MATERIALISED - which for three of this object's five criteria is `["any"]`, the most
    permissive reading and the firing side.

    `scalar_value` is used only for the node's own provenance marker; `iter_member_values` reads
    the members, including the single-member case that arrives as a bare string.
    """
    _, raw_key, raw_prov = scalar_value(node)
    if raw_key is ABSENT:
        value = implicit.value
        return (list(value) if isinstance(value, list) else []), implicit, None
    return [v for v, _ in iter_member_values(node) if v], raw_key, raw_prov


def source_user_is_keyword_population(members: list[str]) -> bool:
    """Whether EVERY member of the user criterion is one of the four device keywords.

    A QUANTIFIER OVER A RELATED ROW SET, which the predicate has neither a quantifier nor an `in`
    operator for: written as clauses it is three `includes` comparisons joined by OR, and
    `clauses` is one conjunction with no OR.

    TRUE on an empty list, which is the same answer the measured implicit gives: an absent user
    criterion means `any`, and `any` IS one of the four keywords.

    WHAT THIS CANNOT DO is tell a directory GROUP from a single individual, which is the
    distinction PAN-DEC-006 actually draws. The device's own reference for the field points at
    the LOCAL user database, no stage 6 build offered a group, and the read that would separate
    them is `show user group list` on an appliance with group mapping - PAN-UID-001's subject,
    not done. So False here means `at least one member is a principal of unknown kind`.
    """
    return all(m in DecryptionPolicyRule.USER_KEYWORDS for m in members)


def success_record_disposition(*, log_success: bool, log_setting: str) -> str:
    """What this rule does with the record of a SUCCESSFUL session, as one of three states.

    ONE COLUMN AND NOT A COMPARISON BETWEEN TWO, and the reason is measured rather than
    stylistic: PAN-DEC-010's second half is graded at two severities, a grading holds exactly ONE
    column, and the two states differ by two columns at once. Graded on `log_success` instead,
    the placement for `the record is kept but nothing forwards it` compiles to a query that fires
    on EVERY rule keeping the record, including the ones forwarding it correctly, because a
    severity query fires on its own rather than refining the baseline.

    `no-record` is what both inputs' measured absences point at, and it is the firing value.
    """
    if not log_success:
        return DecryptionPolicyRule.RECORD_NONE
    if not log_setting:
        return DecryptionPolicyRule.RECORD_KEPT_NOT_FORWARDED
    return DecryptionPolicyRule.RECORD_KEPT_AND_FORWARDED


def opens_session(action: str) -> bool:
    """Whether the rule opens the session it matches - either of the two actions that do.

    A DISJUNCTION OVER ONE COLUMN that the query grammar cannot write, and the alternative is
    worse than verbose: an applicability clause on `action` alone would have to pick ONE of the
    two values and would silently exclude every rule carrying the other - and
    `decrypt-and-forward` is reachable at device-group scope.

    TRUE on a blank action, which is the inclusive side: `action` is mandatory at commit
    validation, so a blank one is a staged rule, and keeping it inside the control's population
    is the answer that cannot hide a finding.
    """
    if not action:
        return True
    return action in DecryptionPolicyRule.SESSION_OPENING_ACTIONS


def normalize_decryption_rule(
    *,
    source_snapshot: Snapshot,
    config_source: str,
    rule_position: int,
    rule: dict[str, Any],
) -> NormalizedDecryptionRule:
    """One decryption rule entry as columns, members and provenance rows.

    EVERY TRACKED LEAF GOES THROUGH A `parse_*` HELPER AND NEVER THROUGH BARE `scalar_value`: a
    tracked field read through `scalar_value` gets `ABSENT` and writes no provenance row, which
    then states "nothing tracks this field" about a field nobody configured.
    """
    entry_rk, entry_rv = entry_provenance(rule)

    action, action_rk, action_rv = parse_text_field(rule.get("action"), implicit=ACTION_ABSENT)
    # `type` is a CHOICE NODE: the device stores the selection as which empty child exists, so a
    # reader of a text value gets nothing from it. Writing TWO branches in one element was
    # ACCEPTED with status=success and no message and the read-back carried only the LAST,
    # measured - so this reads which branch is PRESENT and never assumes a write of one left the
    # others alone.
    type_branch, _ = choice_child(rule.get("type"), DecryptionPolicyRule.TYPE_BRANCHES)
    _, type_rk, type_rv = scalar_value(rule.get("type"))
    if type_rk is ABSENT:
        type_rk, type_rv = Implicit.not_assumed(
            _MANDATORY_AT_COMMIT.format(key="`type`")), None

    negate_source, ns_rk, ns_rv = parse_yes_no_field(
        rule.get("negate-source"), implicit=NEGATE_SOURCE_ABSENT)
    negate_destination, nd_rk, nd_rv = parse_yes_no_field(
        rule.get("negate-destination"), implicit=NEGATE_DESTINATION_ABSENT)
    disabled, dis_rk, dis_rv = parse_yes_no_field(
        rule.get("disabled"), implicit=DISABLED_ABSENT)
    log_fail, lf_rk, lf_rv = parse_yes_no_field(rule.get("log-fail"), implicit=LOG_FAIL_ABSENT)
    log_success, ls_rk, ls_rv = parse_yes_no_field(
        rule.get("log-success"), implicit=LOG_SUCCESS_ABSENT)
    profile_name, prof_rk, prof_rv = parse_text_field(
        rule.get("profile"), implicit=PROFILE_ABSENT)
    description, desc_rk, desc_rv = parse_text_field(
        rule.get("description"), implicit=DESCRIPTION_ABSENT)
    log_setting, lset_rk, lset_rv = parse_text_field(
        rule.get("log-setting"), implicit=LOG_SETTING_ABSENT)

    implicits = {
        "category": CATEGORY_ABSENT,
        "source": SOURCE_ABSENT,
        "destination": DESTINATION_ABSENT,
        "source_user": SOURCE_USER_ABSENT,
        "service": SERVICE_ABSENT,
    }
    members: list[NormalizedDecryptionRuleMember] = []
    provenance_rows: list[tuple[str, Any, str | None]] = [
        (ENTRY_FIELD, entry_rk, entry_rv),
        ("action", action_rk, action_rv),
        ("type_branch", type_rk, type_rv),
        ("negate_source", ns_rk, ns_rv),
        ("negate_destination", nd_rk, nd_rv),
        ("disabled", dis_rk, dis_rv),
        ("log_fail", lf_rk, lf_rv),
        ("log_success", ls_rk, ls_rv),
        ("profile_name", prof_rk, prof_rv),
        ("description", desc_rk, desc_rv),
        ("log_setting", lset_rk, lset_rv),
    ]
    user_members: list[str] = []
    for column, key, model in MEMBER_CRITERIA:
        node = rule.get(key)
        values, raw_key, raw_prov = member_list(node, implicit=implicits[column])
        if column == "source_user":
            user_members = values
        for position, value in enumerate(values):
            members.append(NormalizedDecryptionRuleMember(
                model=model, value=value, prov=str(raw_prov or ""), position=position))
        # A ROW FOR THE LIST'S OWN NODE, which the member rows cannot carry. The members store
        # their provenance as a plain `prov` CharField - the documented exception for member and
        # tag models - and that string cannot say that the KEY WAS ABSENT and PAN-OS means `any`.
        # For `category`, `source-user` and `service` that absence is a measured vendor fact and
        # it is the firing side, so a reader is owed the difference between "the rule says any"
        # and "nobody wrote one".
        provenance_rows.append((column, raw_key, raw_prov))

    return NormalizedDecryptionRule(
        source_snapshot=source_snapshot,
        config_source=config_source,
        rule_position=rule_position,
        rule_name=str(rule.get("@name") or ""),
        rule_uuid=str(rule.get("@uuid") or ""),
        action=action,
        type_branch=type_branch,
        negate_source=bool(negate_source),
        negate_destination=bool(negate_destination),
        disabled=bool(disabled),
        log_fail=bool(log_fail),
        log_success=bool(log_success),
        profile_name=profile_name,
        description=description,
        log_setting=log_setting,
        source_user_is_keyword_population=source_user_is_keyword_population(user_members),
        success_record_disposition=success_record_disposition(
            log_success=bool(log_success), log_setting=log_setting),
        opens_session=opens_session(action),
        members=members,
        field_provenance_data=provenance_rows,
    )


# ---------------------------------------------------------------------------
# The verdict over a whole rulebase
# ---------------------------------------------------------------------------

def rulebase_verdict(rules: list[NormalizedDecryptionRule]) -> dict[str, Any]:
    """The four verdict columns, over every rule in force on one enforcement point.

    PURE AND OVER THE NORMALIZED RULES rather than over the stored rows, so it is checkable
    without a device read and is what a subject with nothing standing can still be proved
    against. The rules passed in are every scope that reaches this enforcement point: the
    firewall's own rulebase and the pushed pre/post ones, because a pushed rule IS in force here
    and a verdict counting only the local ones reports a gap the management station has closed.

    EVERY VALUE AN EMPTY LIST YIELDS IS THE FIRING ONE. That is the whole reason this grain
    exists beside the per-rule one: an enforcement point nobody collected produces no rule rows
    at all, and a predicate cannot compare against a row that is not there.
    """
    in_force = [r for r in rules if not r.disabled]
    forward_proxy = [r for r in in_force
                     if r.type_branch == DecryptionPolicyRule.TYPE_SSL_FORWARD_PROXY]
    actions = {r.action for r in forward_proxy}

    if not forward_proxy:
        disposition = DecryptionRulebaseVerdict.OUTBOUND_NO_RULE
    elif DecryptionPolicyRule.ACTION_DECRYPT_AND_FORWARD in actions:
        disposition = DecryptionRulebaseVerdict.OUTBOUND_DECRYPT_AND_FORWARD
    elif DecryptionPolicyRule.ACTION_DECRYPT in actions:
        disposition = DecryptionRulebaseVerdict.OUTBOUND_DECRYPT
    else:
        # Rules exist on the branch and all of them leave the session encrypted. Kept distinct
        # from `no-rule-opens-outbound-web` because the remediation differs: here an engineer
        # edits a rule that exists, there they add one.
        disposition = DecryptionRulebaseVerdict.OUTBOUND_NO_DECRYPT

    inbound = any(r.type_branch == DecryptionPolicyRule.TYPE_SSL_INBOUND_INSPECTION
                  for r in in_force)
    return {
        "rule_count": len(in_force),
        "outbound_web_disposition": disposition,
        "inbound_inspection_posture": (
            DecryptionRulebaseVerdict.INBOUND_PRESENT if inbound
            else DecryptionRulebaseVerdict.INBOUND_NONE),
        # The BASELINE column, deliberately not derived from the disposition string: the baseline
        # must fire on BOTH failing states - no rule at all, and rules that all leave traffic
        # encrypted - in one conjunction, while the disposition carries the severity. Splitting
        # them is what lets `decrypt-and-forward` sit outside the baseline.
        "opens_outbound_web": bool(
            actions & set(DecryptionPolicyRule.SESSION_OPENING_ACTIONS)),
    }


# ---------------------------------------------------------------------------
# Persisting
# ---------------------------------------------------------------------------

def _write_provenance(content_type, obj, rows: list[tuple[str, Any, str | None]]) -> None:
    """One row per tracked field, plus the entry's own where this object has one.

    A row is written for a PRESENT key saying where it came from AND for an ABSENT one saying
    what the absence means - skipping the absent ones is what left "PAN-OS supplied it", "we
    inferred it" and "nobody tracks it" sharing one blank. A missing row now means only that the
    field is not tracked.
    """
    for field_name, key, value in rows:
        if key is ABSENT:
            continue
        if field_name == ENTRY_FIELD and key is None:
            # An UNMARKED entry is LOCAL, which is a positive statement and not the absence of
            # one. `entry_provenance` returns (None, None) for it, and a missing row would say
            # only that nothing tracks the entry.
            key, value = "", ""
        FieldProvenance.objects.create(
            content_type=content_type, object_id=obj.pk, field_name=field_name,
            provenance_type=classify_prov_type(key),
            raw_key=provenance_raw_key(key)[:32],
            raw_value=provenance_value(key, value)[:128])


def _replace_for_appliance(model, appliance: Appliance):
    """Drop this appliance's rows of one model and their provenance. Returns the content type."""
    content_type = ContentType.objects.get_for_model(model)
    FieldProvenance.objects.filter(
        content_type=content_type,
        object_id__in=list(
            model.objects.filter(appliance=appliance).values_list("pk", flat=True)),
    ).delete()
    model.objects.filter(appliance=appliance).delete()
    return content_type


def _replace_for_point(model, enforcement_point: EnforcementPoint):
    """The same, for a model owned by an enforcement point rather than by an appliance."""
    content_type = ContentType.objects.get_for_model(model)
    FieldProvenance.objects.filter(
        content_type=content_type,
        object_id__in=list(
            model.objects.filter(
                enforcement_point=enforcement_point).values_list("pk", flat=True)),
    ).delete()
    model.objects.filter(enforcement_point=enforcement_point).delete()
    return content_type


def build_normalized_decryption_rules(
    enforcement_point: EnforcementPoint,
) -> tuple[list[NormalizedDecryptionRule], str]:
    """Every decryption rule in force at one enforcement point, and the LOCAL container's state.

    The state is returned beside the rules because an empty list has two causes with different
    meanings - `absent` is an enforcement point with no decryption policy at all and `empty` is a
    container somebody emptied - and the verdict row is where that difference is recorded.

    A MISSING MERGED SNAPSHOT RAISES rather than returning nothing: there is nothing to iterate,
    which is the point-level failure CLAUDE.md's layering says still raises.
    """
    merged_snapshot = latest_merged_snapshot(enforcement_point)
    pushed_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    if merged_snapshot is None:
        raise ValueError(f"missing merged config snapshot for {enforcement_point}")
    if is_panorama_managed(enforcement_point) and pushed_snapshot is None:
        raise ValueError(f"missing pushed VSYS snapshot for {enforcement_point}")

    state, local_entries = local_decryption_rules(merged_snapshot, enforcement_point)
    pushed_pre, pushed_post = (
        pushed_decryption_rules(pushed_snapshot) if pushed_snapshot is not None else ([], []))

    rules: list[NormalizedDecryptionRule] = []
    for snapshot, config_source, entries in (
        (merged_snapshot, DecryptionPolicyRule.SOURCE_LOCAL, local_entries),
        (pushed_snapshot, DecryptionPolicyRule.SOURCE_PUSHED_PRE, pushed_pre),
        (pushed_snapshot, DecryptionPolicyRule.SOURCE_PUSHED_POST, pushed_post),
    ):
        for position, entry in enumerate(entries, start=1):
            rules.append(normalize_decryption_rule(
                source_snapshot=snapshot,
                config_source=config_source,
                rule_position=position,
                rule=entry,
            ))

    if any(not rule.rule_name for rule in rules):
        raise ValueError(f"encountered a decryption rule without a name for {enforcement_point}")
    duplicates = [
        f"{source}:{name}"
        for (source, name), count in Counter(
            (r.config_source, r.rule_name) for r in rules).items()
        if count > 1
    ]
    if duplicates:
        raise ValueError(
            f"duplicate decryption rule names for {enforcement_point}: "
            f"{', '.join(sorted(duplicates))}")
    return rules, state


def normalize_decryption_policy(enforcement_point: EnforcementPoint) -> dict[str, Any]:
    """Replace one enforcement point's decryption rules AND its rulebase verdict. PAN-DEC-001 to 010.

    BOTH MODELS IN ONE PASS, because the verdict is a conclusion about the rules this same pass
    parsed. Computed from the normalized rules rather than re-read from the stored rows, so the
    two cannot disagree about what one run produced and the order of two normalizers cannot
    decide the answer - which is the dependency `normalize_enforcement_point_rulebase_device_match`
    carries on its caller and this one does not need.

    THE VERDICT ROW IS WRITTEN EVEN WHERE THERE ARE NO RULES, and that is the whole reason the
    model exists: an enforcement point with no decryption policy at all is the commonest state in
    this estate, it is PAN-DEC-001's finding, and the per-entry grain has no row for it.
    """
    with transaction.atomic():
        rules, container_state = build_normalized_decryption_rules(enforcement_point)
        merged_snapshot = latest_merged_snapshot(enforcement_point)

        rule_ct = _replace_for_point(DecryptionPolicyRule, enforcement_point)
        written = 0
        for normalized in rules:
            rule = DecryptionPolicyRule.objects.create(
                management_station=enforcement_point.management_station,
                enforcement_point=enforcement_point,
                source_snapshot=normalized.source_snapshot,
                config_source=normalized.config_source,
                rule_position=normalized.rule_position,
                rule_name=normalized.rule_name,
                rule_uuid=normalized.rule_uuid,
                action=normalized.action,
                type_branch=normalized.type_branch,
                negate_source=normalized.negate_source,
                negate_destination=normalized.negate_destination,
                disabled=normalized.disabled,
                log_fail=normalized.log_fail,
                log_success=normalized.log_success,
                profile_name=normalized.profile_name,
                description=normalized.description,
                log_setting=normalized.log_setting,
                source_user_is_keyword_population=(
                    normalized.source_user_is_keyword_population),
                success_record_disposition=normalized.success_record_disposition,
                opens_session=normalized.opens_session,
            )
            for member in normalized.members:
                member.model.objects.create(
                    decryption_rule=rule, value=member.value[:255],
                    prov=member.prov[:128], position=member.position)
            _write_provenance(rule_ct, rule, normalized.field_provenance_data)
            written += 1

        _replace_for_point(DecryptionRulebaseVerdict, enforcement_point)
        verdict = rulebase_verdict(rules)
        # NO PROVENANCE ROW ON THIS MODEL AT ALL, not even `__entry__`: the row is not an entry
        # and every column is in DERIVED_FIELDS, so `provenance_for` answers `derived` without a
        # stored row and `test_declared_derived_fields` would fail if one existed.
        DecryptionRulebaseVerdict.objects.create(
            management_station=enforcement_point.management_station,
            enforcement_point=enforcement_point,
            source_snapshot=merged_snapshot,
            **verdict,
        )

    return {
        "decryption_rules": written,
        "rulebase_verdicts": 1,
        "local_container_state": container_state,
        **verdict,
    }


def normalize_ssl_decryption_exclusions(
    appliance: Appliance,
) -> list[SslDecryptionExclusion]:
    """Replace every SSL decryption exclusion the organisation added on one appliance.

    BOTH WRITABLE SCOPES, in one pass: the appliance's own shared container and every vsys. An
    appliance whose whole `ssl-decrypt` branch is absent writes no row and raises nothing - there
    is no exclusion to describe, which is a reading and not a failure, and it was the state of all
    four lab appliances at both scopes before stage 6 built two.

    WHAT NO ROW CAN SAY, recorded because it is the measured state of most of this estate: "the
    organisation has added no exclusion of its own here". The entry grain has no row for it and no
    control in this domain asserts on it - PAN-DEC-004's first half is about an exclusion that
    EXISTS and carries no reason.
    """
    snapshot = latest_appliance_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")
    payload = snapshot.payload
    device_entry = device_entry_from_snapshot(snapshot)
    vsys_names = [str(e.get("@name") or "")
                  for e in ensure_list((device_entry.get("vsys") or {}).get("entry"))
                  if isinstance(e, dict) and e.get("@name")]

    scopes: list[tuple[str, str, list[dict[str, Any]]]] = []
    _, shared_entries = merged_shared_ssl_decrypt_exclusions(payload)
    scopes.append((SslDecryptionExclusion.SCOPE_SHARED, "", shared_entries))
    for vsys_name in vsys_names:
        _, vsys_entries = merged_vsys_ssl_decrypt_exclusions(payload, vsys_name)
        scopes.append((SslDecryptionExclusion.SCOPE_VSYS, vsys_name, vsys_entries))

    written: list[SslDecryptionExclusion] = []
    with transaction.atomic():
        content_type = _replace_for_appliance(SslDecryptionExclusion, appliance)
        for scope, vsys_name, entries in scopes:
            seen: set[str] = set()
            for entry in entries:
                name = str(entry.get("@name") or "").strip()
                if not name or name in seen:
                    # An entry with no name is not an entry, and a duplicate name in one scope is
                    # not expressible in PAN-OS. Neither can be keyed, so neither is written.
                    continue
                seen.add(name)
                entry_rk, entry_rv = entry_provenance(entry)
                exclude, exc_rk, exc_rv = parse_yes_no_field(
                    entry.get("exclude"), implicit=EXCLUDE_ABSENT)
                description, desc_rk, desc_rv = parse_text_field(
                    entry.get("description"), implicit=DESCRIPTION_ABSENT)
                exclusion = SslDecryptionExclusion.objects.create(
                    management_station=appliance.management_station,
                    appliance=appliance,
                    appliance_group=appliance.appliance_group,
                    source_snapshot=snapshot,
                    name=name[:64],
                    scope=scope,
                    vsys_name=vsys_name,
                    exclude=bool(exclude),
                    description=description,
                )
                _write_provenance(content_type, exclusion, [
                    (ENTRY_FIELD, entry_rk, entry_rv),
                    ("exclude", exc_rk, exc_rv),
                    ("description", desc_rk, desc_rv),
                ])
                written.append(exclusion)
    return written


def normalize_ssl_decryption_vendor_exclusion_optout(
    appliance: Appliance,
) -> dict[str, Any]:
    """Replace one appliance's record of which VENDOR exclusions somebody switched off.

    ONE ROW PER APPLIANCE AND ALWAYS WRITTEN, including where the node is absent: the row is a
    conclusion about the vendor's entries - which of them are switched off here - and the empty
    answer is the compliant one PAN-DEC-004's second half needs to be able to see.

    THE RETURN VALUE SAYS WHETHER THE VENDOR LIST WAS READ, which no column does. Stage 5
    declared no `*_collected` companion for `stale_disabled_vendor_exclusion_count`, so zero on
    that column means both "no departure is stale" and "the `show predefined` snapshot did not
    exist" - stage 5 took that concession deliberately and this layer implements it as declared.
    A caller that needs the difference reads `predefined_list_collected` here.
    """
    snapshot = latest_appliance_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")

    node = merged_disabled_from_predefined(snapshot.payload)
    disabled, raw_key, raw_prov = member_list(
        node, implicit=DISABLED_FROM_PREDEFINED_ABSENT)

    predefined_snapshot = latest_predefined_ssl_exclude_cert_snapshot(appliance)
    shipped = predefined_exclusion_names(predefined_snapshot)
    # A SET DIFFERENCE, and the right-hand side is only ever the OP read's. Where the snapshot is
    # absent the difference is not computed at all: a `set()` right-hand side would make EVERY
    # switched-off entry look stale, which is the loudest possible false finding on exactly the
    # appliances that are configured correctly.
    stale = (len([name for name in disabled if name not in shipped])
             if predefined_snapshot is not None else 0)

    with transaction.atomic():
        content_type = _replace_for_appliance(SslDecryptionVendorExclusionOptOut, appliance)
        row = SslDecryptionVendorExclusionOptOut.objects.create(
            management_station=appliance.management_station,
            appliance=appliance,
            appliance_group=appliance.appliance_group,
            source_snapshot=snapshot,
            disabled_vendor_exclusions=disabled,
            disabled_vendor_exclusion_count=len(disabled),
            stale_disabled_vendor_exclusion_count=stale,
        )
        # The member list is the only tracked key, and its ABSENT state is an ASSUMPTION - a
        # reader is owed the fact that the empty list they are relying on was inferred rather
        # than read. The two counts are derived and carry no row.
        _write_provenance(content_type, row, [
            ("disabled_vendor_exclusions", raw_key, raw_prov),
        ])

    return {
        "disabled_vendor_exclusions": len(disabled),
        "stale_disabled_vendor_exclusions": stale,
        "predefined_list_collected": predefined_snapshot is not None,
        "predefined_entries_seen": len(shipped),
    }


# ---------------------------------------------------------------------------
# The forward-proxy signing designation
# ---------------------------------------------------------------------------

#: The two designation containers and the column each algorithm child feeds.
#:
#: THE PAYLOAD IS A NESTED DICT AND NOT A STRING, which is the one trap on this node and the
#: reason this table names the child explicitly: `{"forward-trust-certificate": {"rsa":
#: "oep-p1-cert"}}`, measured by stage 4. A consumer reading `forward-trust-certificate` as a
#: certificate name gets a dict, and `str()` of it stores something that looks like a name.
FORWARD_PROXY_SLOTS = (
    ("forward_trust_cert_rsa", "forward-trust-certificate", "rsa"),
    ("forward_trust_cert_ecdsa", "forward-trust-certificate", "ecdsa"),
    ("forward_untrust_cert_rsa", "forward-untrust-certificate", "rsa"),
    ("forward_untrust_cert_ecdsa", "forward-untrust-certificate", "ecdsa"),
)

TRUST_COLUMNS = ("forward_trust_cert_rsa", "forward_trust_cert_ecdsa")
UNTRUST_COLUMNS = ("forward_untrust_cert_rsa", "forward_untrust_cert_ecdsa")

#: An absent designation slot. `not_assumed` AND NOT A MATERIALISED DEFAULT, because there is no
#: value to materialise: stage 4 recorded the container's implicit as `not_applicable` with
#: `may_materialise: false` - it has no value of its own, and its absence asserts that no
#: forward-proxy CA is designated at all.
#:
#: THE FIREWALL STATES THAT ABSENCE IN WORDS, which is what makes it `measured` territory rather
#: than a guess even though nothing is stored: with `/config/shared/ssl-decrypt` absent,
#: `show system setting ssl-decrypt certificate` answers `No SSL Decryption CERT` and `NO
#: INBOUND CERT` - measured in BOTH directions on pan-fw-201, before the node existed, after a
#: designation was written and committed, and again after that delete was committed.
DESIGNATION_ABSENT = Implicit.not_assumed(
    "an absent forward-proxy designation slot has no value of its own - stage 4 recorded the "
    "container implicit as not_applicable with may_materialise false, and the firewall reports "
    "the absence in words through `show system setting ssl-decrypt certificate`")


def merged_shared_ssl_decrypt(payload: dict[str, Any]) -> dict[str, Any]:
    """The appliance's own shared `ssl-decrypt` node, or `{}`.

    SHARED SCOPE ONLY. Stage 4 completed both scopes: `/config/shared/ssl-decrypt` has six
    children and the vsys node has five, and the forward-proxy designations are device-wide. The
    owner is LOCAL here, unlike the decryption rule's shared scope, which is Panorama's.
    """
    shared = merged_shared(payload)
    node = shared.get("ssl-decrypt") if isinstance(shared, dict) else None
    return node if isinstance(node, dict) else {}


def forward_proxy_designations(
    node: dict[str, Any],
) -> tuple[dict[str, str], list[tuple[str, Any, str | None]]]:
    """The four designation columns and their provenance rows, from the shared `ssl-decrypt`.

    A CONTAINER THAT IS ABSENT AND ONE THAT IS PRESENT BUT HOLDS ONLY THE OTHER ALGORITHM GIVE
    THE SAME COLUMN, which is correct and is why each child is read on its own: the two slots are
    independent designations and one being filled says nothing about the other.
    """
    values: dict[str, str] = {}
    provenance: list[tuple[str, Any, str | None]] = []
    for column, container, child in FORWARD_PROXY_SLOTS:
        held = node.get(container)
        held = held if isinstance(held, dict) else {}
        value, raw_key, raw_value = parse_text_field(
            held.get(child), implicit=DESIGNATION_ABSENT)
        values[column] = value
        provenance.append((column, raw_key, raw_value))
    return values, provenance


def forward_proxy_verdicts(
    values: dict[str, str], local_authorities: dict[str, tuple[bool, bool]],
) -> dict[str, bool]:
    """The two verdicts over the four designation columns.

    `local_authorities` is {certificate name: (is_ca, is_self_signed)} for the certificates THIS
    APPLIANCE holds. Passed in rather than queried here so the inputs are visible at the call
    site and the derivation stays a pure function.

    A NAME THAT RESOLVES TO NO CERTIFICATE MAKES THE FIRST VERDICT FALSE rather than leaving it
    unknown, deliberately: a designation pointing at nothing is a worse state than no
    designation at all, not a better-evidenced one.

    THE QUANTIFIER ON THE FIRST IS `at least one filled AND every filled one qualifies`. An
    appliance with an RSA slot naming a local self-signed CA and an ECDSA slot naming a
    third-party certificate does NOT pass: the weaker of the two is what a session can end up
    negotiating, and nothing in the configuration says which it will be.
    """
    trust = [values[c] for c in TRUST_COLUMNS if values.get(c)]
    untrust = [values[c] for c in UNTRUST_COLUMNS if values.get(c)]
    designated_local_ca = bool(trust) and all(
        all(local_authorities.get(name, (False, False))) for name in trust)
    distinct = bool(untrust) and not (set(untrust) & set(trust))
    return {
        "forward_trust_is_designated_local_ca": designated_local_ca,
        "untrust_distinct_from_trust": distinct,
    }


def appliance_local_authorities(appliance: Appliance) -> dict[str, tuple[bool, bool]]:
    """{certificate name: (is_ca, is_self_signed)} for the certificates this appliance holds.

    READ FROM THE STORED ROWS and not from the payload, which is the one ordering dependency in
    this normalizer and is declared here rather than left implicit: the certificate pass must
    have run for this appliance first. It is already ordered that way in `flows.py`, where the
    certificate objects are normalized in the per-appliance list ahead of this one.
    AN EMPTY MAP MAKES THE FIRST VERDICT FALSE for any filled slot, which is the firing side: a
    designation whose target cannot be confirmed is not a designation that has been shown good.
    """
    from optivedge_integrations.integrations.models import Certificate
    return {
        name: (bool(is_ca), bool(self_signed))
        for name, is_ca, self_signed in Certificate.objects.filter(
            appliance=appliance).values_list("name", "is_ca", "is_self_signed")
    }


def normalize_decryption_settings(appliance: Appliance) -> dict[str, Any]:
    """Replace one appliance's forward-proxy signing designation. PAN-DCP-003, 004 and 006.

    ONE ROW PER APPLIANCE AND ALWAYS WRITTEN, including where the whole `ssl-decrypt` branch is
    absent - which is the state all four lab appliances were in before stage 6 built a
    designation on one of them. The row that says "nothing is designated" is the only thing that
    can carry PAN-DCP-006, whose subject is exactly that absence; a per-slot grain would have no
    row at all in the failing state.

    `write_node_row` is the shared writer and it deletes only the provenance rows for the fields
    it writes, so this and the two other normalizers over `ssl-decrypt` do not erase each
    other's - a missing provenance row means "nothing tracks this field", so an erasure would
    read as a deliberate statement.
    """
    snapshot = latest_appliance_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")

    node = merged_shared_ssl_decrypt(snapshot.payload)
    values, provenance = forward_proxy_designations(node)
    authorities = appliance_local_authorities(appliance)
    values = {**values, **forward_proxy_verdicts(values, authorities)}

    with transaction.atomic():
        write_node_row(DecryptionSettings, appliance, snapshot, {
            **values, "last_synced_at": snapshot.collected_at,
        }, provenance)

    return {
        "decryption_settings": 1,
        "node_present": bool(node),
        "designated_slots": sum(
            1 for column, _, _ in FORWARD_PROXY_SLOTS if values.get(column)),
        "local_authorities_seen": len(authorities),
    }
