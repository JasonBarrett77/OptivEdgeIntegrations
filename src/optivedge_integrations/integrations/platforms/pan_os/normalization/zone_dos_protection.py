"""Zone protection and DoS protection normalization - PAN-ZON-001 to PAN-ZON-008.

FOUR ENTRY POINTS AND NO NEW COLLECTION. Every column of every subject in this domain arrives
in reads a collector already issues:

    normalize_zone_protection_profiles(appliance)     one row per appliance per profile name
    normalize_dos_policy_rules(enforcement_point)     one row per rulebase per rule name
    dos_protection_profile_values(entry)              the DoS kind's two columns on SecurityProfile
    dos_profile_references(root, ...)                 the DoS rulebase's two profile slots

The first two read `show config merged`, which `collect_merged_config` already takes once per
device - the zone protection profile collection is a SIBLING KEY of the
`interface-management-profile` node `interface_management_profiles.py` already walks, and the
DoS rulebase is a sibling of the `security` node `security_rules.py` already walks. The second
two are called from `security_profiles.py`, out of the merged and pushed roots that module
already has in hand. Nothing in this module issues a read.

STAGE 5 NAMED THREE OPERATIONAL READS AND NO COLUMN RESTS ON ANY OF THEM, which it said in
terms three times: `show zone-protection`, `show zone-protection zone <NAME>` and
`show session info`. They are the reads that would let the flood verdicts, the resolved non-SYN
refusal and the zone attachment be MEASURED rather than derived, and they read RUNNING where the
merge view reads CANDIDATE. No collector issues any of them and none is built here.

THE MERGE VIEW IS CANDIDATE-DERIVED, which is the caveat over everything below and is worse on
the zone protection profile than on most objects: stage 4 measured that pressing OK on a bare
profile's dialog writes 21 KEYS with values identical to the ones the device already applies, so
an administrator who opened a profile and changed nothing leaves a candidate in which every
default has become an explicit key. Nothing looks wrong afterwards at any layer.

TWO JOINS, BOTH COMPUTED FROM ONE PAYLOAD IN ONE PASS, and that is deliberate. The zone-side
column `Zone.zone_protection_unresolved` and the profile-side columns `attached_zone_count`,
`is_in_force` and `is_unreferenced` are two directions of the same comparison. Re-walking the
merged payload in each pass - rather than reading the other model's rows back - is what makes
them unable to disagree and removes the ordering dependency that `interface_management_profiles.py`
had to check for and raise on. The price is that the zone walk runs twice per appliance; the
payload is already in memory and the walk is a dict traversal.

THE JOIN IS CASE-SENSITIVE IN BOTH DIRECTIONS. Profile names are case-sensitive and not
normalised (help p.663), so a case-folded comparison would call a profile in force that the
dataplane does not resolve - and the two verdicts fail in opposite directions, so there is no
single safe way to be wrong about it.

Measured against 6A9C0A9904E7D6E (PA-VM, 11.2.3-h3) and 691665AC334B458 (PA-VM, 11.2.5) on
2026-10-30, which are the two appliances stage 6 left subjects on - the first carrying 13 zone
protection profiles, 15 zones, 4 DoS protection profiles and 4 DoS rules, and the second
carrying the four absences. APPLIANCES ARE NAMED BY SERIAL throughout: 691665AC334B458 answers
to the factory-default hostname `PA-VM` while every artifact calls it `pan-fw-201`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    DosPolicyRule,
    EnforcementPoint,
    FieldProvenance,
    Snapshot,
    Zone,
    ZoneProtectionProfile,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ENTRY_PROVENANCE_ATTRIBUTES,
    entry_provenance_record,
    ABSENT,
    Implicit,
    choice_child,
    classify_prov_type,
    ensure_list,
    merged_vsys_entry,
    parse_integer_field,
    parse_text_field,
    parse_yes_no_field,
    provenance_raw_key,
    provenance_value,
    pushed_vsys_panorama,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot as latest_appliance_merged_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.network_hardening import (
    TCP_REJECT_NON_SYN_ABSENT,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    is_panorama_managed,
    latest_pushed_vsys_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    latest_merged_snapshot as latest_point_merged_snapshot,
)
# THE ZONE SIDE OF THE JOIN LIVES BESIDE THE ZONE NORMALIZER, imported here rather than defined
# here, for two reasons. A reader of `Zone` looks in `zones.py`; and this module imports
# `network_hardening.py`, which imports `zones.py` for `ZONE_NETWORK_TYPES` - so defining them
# here and importing them there would be a cycle. `network_hardening.py` already takes five of
# this domain's neighbours' pure functions out of `zones.py` the same way.
from optivedge_integrations.integrations.platforms.pan_os.normalization.zones import (
    zone_attachment_verdict,
    zone_protection_profile_names,
)

#: The entry-level provenance record, as `FieldProvenance` documents it: the `@ptpl` on a named
#: PAN-OS entry rather than on one of its fields.
ENTRY_FIELD = "__entry__"


#: The five flood types the ZONE protection profile meters, as the config spells them, paired
#: with the column each one fills. SIX CHILDREN EXIST AND `sctp-init` GETS NO COLUMN: no control
#: asserts it, and declaring one would manufacture an obligation rather than meet one.
#:
#: THIS IS NOT THE DOS PROTECTION PROFILE'S FLOOD NODE. Measured on three appliances: that
#: object's `flood` has FIVE children (no `sctp-init`, and `action=complete` at
#: `flood/sctp-init` answers code=6) and its `red` container has FIVE where this one's has THREE,
#: adding `block` and `block-probability`. Same two node names, two key sets - which is why no
#: constant is shared between the two readers below.
ZONE_FLOOD_COLUMNS = {
    "tcp-syn": "syn_flood_enabled",
    "udp": "udp_flood_enabled",
    "icmp": "icmp_flood_enabled",
    "icmpv6": "icmpv6_flood_enabled",
    "other-ip": "other_ip_flood_enabled",
}

#: The four volumetric types PAN-ZON-003's restatement is written over - the five above minus
#: the half-open connection flood, which is PAN-ZON-002's on its own.
VOLUMETRIC_FLOOD_COLUMNS = (
    "udp_flood_enabled", "icmp_flood_enabled", "icmpv6_flood_enabled", "other_ip_flood_enabled")

#: The three rate leaves under an action branch, as the config spells them.
ZONE_FLOOD_RATE_KEYS = ("alarm-rate", "activate-rate", "maximal-rate")

#: The eight packet drops that get a column, paired with their keys. FOUR OF THEM ARE
#: PAN-ZON-006's and the verdict is written over those four alone; `discard-ip-spoof` is
#: PAN-ZON-005's, and `strict-ip-check`, `discard-record-route` and `discard-timestamp` are
#: asserted by nothing and are declared for the reasons each column's own comment gives.
PACKET_DROP_COLUMNS = {
    "discard-ip-spoof": "discard_ip_spoof",
    "strict-ip-check": "strict_ip_check",
    "discard-strict-source-routing": "discard_strict_source_routing",
    "discard-loose-source-routing": "discard_loose_source_routing",
    "discard-malformed-option": "discard_malformed_option",
    "discard-overlapping-tcp-segment-mismatch": "discard_overlapping_tcp_segment_mismatch",
    "discard-record-route": "discard_record_route",
    "discard-timestamp": "discard_timestamp",
}

#: The four PAN-ZON-006 asserts. The other four in the map above are NOT in its verdict.
ASSERTED_PACKET_DROP_COLUMNS = (
    "discard_strict_source_routing", "discard_loose_source_routing",
    "discard_malformed_option", "discard_overlapping_tcp_segment_mismatch")

#: The two address leaves under a `scan-white-list` entry. A NORMALIZER MUST WALK BOTH: the Help
#: describes ONE address field with a type selector and the configuration holds TWO SEPARATE
#: LEAVES, so a reader checking only one sees half the list - and half a list on an exemption
#: surface is the direction that reports a blind spot as clean.
SCAN_WHITE_LIST_LEAVES = ("ipv4", "ipv6")

#: The DoS protection profile's own flood types - FIVE, not the zone profile's six.
DOS_FLOOD_TYPES = ("tcp-syn", "udp", "icmp", "icmpv6", "other-ip")
#: The five rate and block leaves under a DoS profile's `red` container.
DOS_RED_KEYS = ("alarm-rate", "activate-rate", "maximal-rate", "block-probability")


# ---------------------------------------------------------------------------
# What an absent key means. One declaration per key, with its measurement.
# ---------------------------------------------------------------------------

def _flood_absent(flood_type: str, dataplane_name: str) -> Implicit:
    """`flood/<type>/enable` absent means THIS FLOOD TYPE IS NOT METERED.

    One function rather than five constants because the measurement is one measurement: a
    profile created carrying only `description`, committed, and read back from
    `show config running` still carrying only `description`, with the dataplane confirming each
    type by name. The per-type argument is what keeps the citation checkable against the oracle's
    own output rather than naming a generality.
    """
    return Implicit.measured(
        False,
        f"stage4-zone-dos-protection.json, zone-protection-profile.flood/{flood_type}/enable: "
        f"measured 2026-10-25 on 691665AC334B458 (PA-VM 11.2.5) on a profile created carrying "
        f"only `description`, COMMITTED, and read back from `show config running` still carrying "
        f"only `description` - so the absence is a state a running device holds and not a "
        f"candidate artefact. Confirmed on a second and non-UI oracle, "
        f"`show zone-protection zone`, which reports `{dataplane_name}: False` by name. "
        f"`action=complete` answers code=2 on all six flood types, so there is no candidate "
        f"list to read instead.")


#: The five flood enables' declarations, keyed by config name. The dataplane spells two of them
#: differently from the configuration - `icmpv6` reports as `icmp6` and `tcp-syn` as `tcp` - and
#: the citation names the oracle's spelling rather than ours so a reader can grep the output.
ZONE_FLOOD_ABSENT = {
    "tcp-syn": _flood_absent("tcp-syn", "tcp"),
    "udp": _flood_absent("udp", "udp"),
    "icmp": _flood_absent("icmp", "icmp"),
    "icmpv6": _flood_absent("icmpv6", "icmp6"),
    "other-ip": _flood_absent("other-ip", "other-ip"),
}


def _drop_absent(key: str) -> Implicit:
    """A packet drop leaf absent means THE FIREWALL DOES NOT DISCARD THAT PACKET."""
    return Implicit.measured(
        False,
        f"stage4-zone-dos-protection.json, zone-protection-profile.{key}: measured 2026-10-25 "
        f"on 691665AC334B458 (PA-VM 11.2.5) on the keyless COMMITTED profile, with two oracles - "
        f"the dialog's checkbox read as a CSS class rather than as innerText, and the dataplane "
        f"report, which names `strict-ip-check: False` among them. `action=complete` answers "
        f"code=2 on every one of these bare <yes|no> leaves.")


PACKET_DROP_ABSENT = {key: _drop_absent(key) for key in PACKET_DROP_COLUMNS}

#: `tcp-reject-non-syn` ON THE PROFILE absent means DEFER TO THE DEVICE-WIDE SETTING. The
#: measured implicit is a POINTER rather than a value, which stage 4 called the first such case
#: in its tally - so agreeing with the schema's own `@default` settles less than it looks.
PROFILE_NON_SYN_ABSENT = Implicit.measured(
    ZoneProtectionProfile.NON_SYN_GLOBAL,
    "stage4-zone-dos-protection.json, zone-protection-profile.tcp-reject-non-syn: measured "
    "2026-10-25 on 691665AC334B458 (PA-VM 11.2.5) - the dialog renders the literal `global` on "
    "a keyless profile, `action=complete with_body=True` returns the same three values with the "
    "same @default on `global` on all three appliances asked (PA-VM 11.2.5, PA-VM 11.2.3-h3, "
    "PA-5220 11.1.13-h3), and the pointer's RESOLUTION was measured in both directions by "
    "moving the device-wide node and watching the dataplane follow.")

#: `scan/entry/action` absent, WHERE THE ENTRY EXISTS. THE TWO ABSENCES ARE DIFFERENT AND THIS
#: ONE IS THE GENTLER: an entry carrying no action child records the event. The other absence -
#: no entry of that type at all - is the empty-string sentinel and is NOT this declaration; it
#: is decided by the walk below, because an `Implicit` cannot express "the parent is missing".
SCAN_ACTION_ABSENT = Implicit.measured(
    ZoneProtectionProfile.SCAN_ACTION_ALERT,
    "stage4-zone-dos-protection.json, zone-protection-profile.scan/entry/action: measured "
    "2026-10-25 on 691665AC334B458 (PA-VM 11.2.5) on entry 8002 SEPARATELY from the "
    "missing-entry case - its action child was deleted and the entry committed carrying only "
    "`interval`, `show config running` returned {'@name': '8002', 'interval': '102'}, and the "
    "dialog then rendered `alert` while its three written siblings rendered `block`. The vendor "
    "agrees (help p.672 prints '(Default) Alert') and the vendor was not the evidence.")

#: `scan/entry/action/block-ip/track-by` absent: NOTHING IS STORED. Stage 4 did not reach it -
#: reaching it needs a scan entry whose action is block-ip, which that run did not build - and
#: help p.672 describes the choice and gives no default.
SCAN_TRACK_BY_ABSENT = Implicit.not_assumed(
    "NOT MEASURED. Reaching this leaf needs a scan entry whose action is block-ip and stage 4 "
    "built none; help p.672 describes the choice and gives no default. A wrong guess moves a "
    "finding between two of stage 3's severity bands, because the vendor calls the "
    "source-and-destination form the LESS stringent one and stage 3 grades them differently, so "
    "storing nothing is better than storing either. `scan_sensitivity_known` is what a control "
    "clauses on instead.")

#: `scan/entry/interval` absent: NOTHING IS STORED, and the reading that looked like a
#: measurement was REFUTED.
SCAN_INTERVAL_ABSENT = Implicit.not_assumed(
    "NOT MEASURED, and the reading that looked like a measurement was refuted: stage 4 found "
    "the dialog's inner grid rendering four fully-populated rows for entries that did not exist "
    "and proved them the form's new-row TEMPLATE rather than the device's answer - once the "
    "entries existed carrying no threshold, every cell rendered BLANK. No other oracle reports "
    "it: `show zone-protection zone` carries no scan entries at all and `show system state "
    "filter *scan*` answers NO_MATCHES. The vendor's documented defaults also differ PER SCAN "
    "TYPE - one value for the port and protocol scans and another for the host sweep - so there "
    "is not one number to materialise even if one were licensed.")

#: `scan/entry/threshold` absent: NOTHING IS STORED, and the two available leads DISAGREE.
SCAN_THRESHOLD_ABSENT = Implicit.not_assumed(
    "NOT MEASURED, and the two available leads disagree with each other: help p.672 gives 100 "
    "for every scan type with no exception printed, and the device's own form prefills 4 for IP "
    "Protocol Scan. Stage 4 recorded that as an unresolved disagreement, because the prefill is "
    "what the form WOULD write and was proved not to be the device's answer for an existing "
    "entry - so neither number is evidence about an absent key. The write that would settle it "
    "is an entry carrying an action and no threshold, committed, read through an oracle that "
    "reports the effective threshold, and that run found no such oracle.")

#: `type` on a DOS protection profile absent: NOTHING IS ASSUMED, because the key cannot be
#: absent on a committed profile.
DOS_PROFILE_TYPE_ABSENT = Implicit.not_assumed(
    "MANDATORY AT COMMIT VALIDATION, so there is no absent-key case on a running device and "
    "nothing for an absence to assert. Measured rather than inferred: stage 4 built a second "
    "bare profile for this question alone and the commit was refused with `Validation Error: "
    "profiles -> dos-protection -> oep-zdp-dosp2 is missing 'type'`. The merge view is "
    "candidate-derived, so a STAGED profile can reach a normalizer without it, and the blank "
    "this lands says exactly that rather than naming a default.")

#: `protection/aggregate/profile` absent means NO AGGREGATE THRESHOLDS ARE IN FORCE.
AGGREGATE_PROFILE_ABSENT = Implicit.measured(
    "",
    "stage4-zone-dos-protection.json, dos-policy-rule.protection/aggregate/profile: help p.205 "
    "- 'An Aggregate profile setting of None means there are no threshold settings in place for "
    "the aggregate traffic' - measured 2026-10-25 on 691665AC334B458 (PA-VM 11.2.5) on the bare "
    "COMMITTED rule and on the grid, where both the grid's Aggregate column and the dialog's "
    "combo render the UI's word for empty. Stage 4's note on this key is that a null here is a "
    "REAL measured implicit and not a missing reading.")

#: `protection/classified/profile` absent: NOTHING IS ASSUMED. The classified arm was never
#: written, so the symmetry with the aggregate arm is derived rather than measured.
CLASSIFIED_PROFILE_ABSENT = Implicit.not_assumed(
    "NOT MEASURED. Stage 4 did not write the classified arm at all and said so in terms - it is "
    "the half of PAN-ZON-007 that run did not exercise - and the one surface that renders an "
    "answer is a dialog measured to prefill. By the aggregate arm's measured behaviour this "
    "should mean 'no per-device thresholds in force', and that symmetry is DERIVED. A text "
    "column with a not_assumed implicit lands the empty string rather than a null, so the row "
    "is reachable and says nothing, and this provenance row is what says why.")

#: `protection/classified/classification-criteria/address` absent: NOTHING IS ASSUMED, and the
#: one reading available was refused as evidence.
CLASSIFICATION_ADDRESS_ABSENT = Implicit.not_assumed(
    "NOT MEASURED, and the one reading available was refused as evidence: stage 4 found the "
    "dialog rendering `source-ip-only` as a VALUE on a keyless rule, on a form it had already "
    "measured to prefill, and did not promote it. The vendor is DIRECTIONAL about this field and "
    "the prefill is the one it warns about - help p.206 says 'Don't use source-ip-only or "
    "src-dest-ip-both for internet-facing zones' - so storing a form's prefill would store the "
    "hazardous value as though the device held it.")

#: `disabled` on a DOS rule absent: NOTHING IS ASSUMED. The shipped `SecurityRule` and
#: `DecryptionRule` both store a boolean defaulting to false; on THIS object nobody measured it.
DOS_RULE_DISABLED_ABSENT = Implicit.not_assumed(
    "NOT MEASURED ON THIS OBJECT. Stage 4 reached state C only partially here - its writes went "
    "on the mandatory children and the profile slots - and no control was paid on this key, so "
    "what an absent `disabled` means on a DoS rule is not established even though the answer is "
    "almost certainly 'not disabled'. `SecurityRule` and `DecryptionRule` both materialise false "
    "for it on THEIR objects off their own measurements, and carrying that across would assume "
    "two rulebases sharing a leaf name share a default. One write and one read would settle it.")


# ---------------------------------------------------------------------------
# Small shared readers
# ---------------------------------------------------------------------------

def _dict(node: Any) -> dict[str, Any]:
    return node if isinstance(node, dict) else {}


def _entries(node: Any) -> list[dict[str, Any]]:
    """The `entry` children of a container that may be absent, null, one or many."""
    return [e for e in ensure_list(_dict(node).get("entry")) if isinstance(e, dict)]


def _text(node: Any) -> str:
    """A PAN-OS scalar's text, whether it is a bare string or a provenance-wrapped dict."""
    if isinstance(node, str):
        return node.strip()
    value, _raw_key, _raw_prov = scalar_value(node)
    return value.strip()


#: Attributes that state where an entry came from - the same pair
#: `interface_management_profiles.py` reads, and for the same reason: an unmarked entry is a
#: LOCALLY DEFINED object, and writing nothing for it would make absence mean both "defined on
#: the device" and "nothing tracks this".
#:
#: ON THIS OBJECT THE BASIS IS LOAD-BEARING AND NOT A STYLE RULE. Stage 4 measured
#: `network/profiles` itself carrying `@ptpl='shared-single-vsys'` while the profile collection
#: beneath it carried no attribute at all, so a normalizer inheriting the PARENT's mark would
#: label every locally-created profile on that appliance template-supplied AND name the wrong
#: template. The value's own marker, never an ancestor's.
def _entry_provenance(entry: dict) -> tuple[str, str, str]:
    return entry_provenance_record(entry)


# ---------------------------------------------------------------------------
# ZoneProtectionProfile
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class NormalizedZoneProtectionProfile:
    profile_name: str
    values: dict[str, Any]
    field_provenance_data: list[tuple[str, Any, str | None]] = field(default_factory=list)
    entry_provenance: tuple[str, str, str] = (FieldProvenance.ProvenanceType.LOCAL, "", "")


def _scan_entries_by_id(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """`scan/entry`, keyed by the entry name - WHICH IS THE SCAN TYPE.

    Nothing else identifies a scan entry: there is no `type` key on one, and
    `/config/predefined/threats/scan` returns the four entries keyed by @id carrying no other
    child, so there is no name in it to join to. The id-to-type mapping was measured by writing
    a distinct `interval` to each of the four and reading the dialog's inner grid back.
    """
    return {
        name: scan
        for scan in _entries(entry.get("scan"))
        if (name := str(scan.get("@name") or "").strip())
    }


def _scan_action(scan_entry: dict[str, Any] | None) -> tuple[str, Any, str | None]:
    """One scan type's action, and the provenance of the reading.

    THE TWO ABSENCES ARE DIFFERENT AND THIS IS WHERE THEY ARE SEPARATED - an `Implicit` cannot
    express "the parent is missing", so the missing-ENTRY case is decided here and the missing-
    ACTION case is declared in `SCAN_ACTION_ABSENT`:

    - NO ENTRY of this type: the empty string, and `raw_key` is ABSENT so no provenance row is
      written. The scan type is NOT DETECTED AT ALL, which stage 4 measured is the worst state
      available rather than the gentlest - with no entry present the outer grid's four scan
      columns render BLANK and the `scan` node is absent from the committed entry.
    - THE ENTRY EXISTS carrying no `action` child: `alert`, with a `pan_os_default` row. The
      event IS recorded.

    A normalizer that collapses the two reports a scan type nobody detects as one that records
    the event, which is the specific failure stage 4 wrote this measurement down to prevent.
    """
    if scan_entry is None:
        return "", ABSENT, None
    action, _content = choice_child(
        scan_entry.get("action"), ZoneProtectionProfile.SCAN_ACTIONS)
    if not action:
        return SCAN_ACTION_ABSENT.value, SCAN_ACTION_ABSENT, None
    return action, "action", action


def scan_weakest_action(actions: dict[str, str], track_by: str) -> str:
    """The least protective of the four scan types' actions, in `SCAN_WEAKEST_ORDER`.

    THE ORDERING IS NOT A LADDER, which is why the answer is stored rather than compared: stage
    3 grades `block` as acceptable and `block-ip` tracking the source-and-destination PAIR as
    low, because a scanner that moves to another destination is no longer blocked - so the pair
    form sorts BELOW the plain block despite being the more elaborate setting. No numeric or
    lexical comparison produces that order.

    A `block-ip` whose `track-by` was never read cannot be told apart from either form, and this
    resolves it to the GENTLER of the two - the plain `source` rank. That is the reassuring
    direction and is why it is named in stage 5's `not_measured` and why no clause and no
    baseline rests on this column: `scan_sensitivity_known` beside it is what says the reading
    was incomplete.
    """
    resolved: list[str] = []
    for action in actions.values():
        if action == ZoneProtectionProfile.SCAN_ACTION_BLOCK_IP:
            mode = track_by or ZoneProtectionProfile.TRACK_BY_SOURCE
            resolved.append(f"{action}-{mode}")
        else:
            resolved.append(action)
    order = ZoneProtectionProfile.SCAN_WEAKEST_ORDER
    # UNRECOGNISED SORTS WORST. A value outside the measured set is a reading nobody has
    # graded, and ranking it as the best available would grade a profile on a guess.
    return min(resolved, key=lambda value: order.index(value) if value in order else -1,
               default="")


def _scan_white_list(entry: dict[str, Any]) -> tuple[list[dict[str, str]], int]:
    """`scan-white-list`, and the count of exempted addresses.

    BOTH ADDRESS LEAVES ARE WALKED - `ipv4` and `ipv6` - because the configuration holds two
    separate leaves where the Help describes one field with a type selector. The count is of
    ADDRESSES rather than of entries, so an entry carrying both leaves counts twice: the column
    is what a control reads to ask how much of the detection surface is exempt, and an entry
    exempting two addresses exempts two.

    The vendor documents a maximum of 20 entries (help p.672) and the grammar expresses no
    limit, so a longer list is a question about the device rather than a finding against the
    customer. No column asserts the cap.
    """
    rows: list[dict[str, str]] = []
    count = 0
    for white in _entries(entry.get("scan-white-list")):
        row = {"name": str(white.get("@name") or "").strip()}
        for leaf in SCAN_WHITE_LIST_LEAVES:
            value = _text(white.get(leaf))
            if value:
                row[leaf] = value
                count += 1
        rows.append(row)
    return rows, count


def _zone_flood_rates(entry: dict[str, Any], syn_action: str) -> dict[str, Any] | None:
    """The rate keys the profile stores, keyed by flood type, with the branch each sat under.

    NULL WHERE THE PROFILE STORES NONE, because stage 4 recorded these implicits as a RELATION
    rather than a constant and set `merge_as: hold` - there is no value to put in the column for
    an absent key, and expanding a live reading unconditionally across six flood types and two
    branches would report a weak configuration as a hardened one.

    THE DIALOG'S RATE FIELDS ARE HINTS AND THIS READS THE CONFIG ONLY. ExtJS writes emptyText
    into the input's `value` and `x-form-empty-field` is the only discriminator, set on all nine
    of them - and the hint reads `10000 [0 - 2000000]`, the shipped number AND the range in one
    placeholder, so a scrape would store a number that is really a hint about a number.
    """
    rates: dict[str, Any] = {}
    flood = _dict(entry.get("flood"))
    for flood_type in ZONE_FLOOD_COLUMNS:
        branch_values: dict[str, Any] = {}
        for branch in ZoneProtectionProfile.SYN_FLOOD_ACTIONS:
            node = _dict(_dict(flood.get(flood_type)).get(branch))
            if not node:
                continue
            read = {key: _text(node.get(key)) for key in ZONE_FLOOD_RATE_KEYS
                    if _text(node.get(key))}
            duration = _text(_dict(node.get("block")).get("duration"))
            if duration:
                read["block/duration"] = duration
            if read:
                branch_values[branch] = read
        if branch_values:
            rates[flood_type] = branch_values
    if not rates:
        return None
    # The SYN branch is the one that can be either container, so the resolved branch travels
    # with the numbers: the same `activate-rate` means a different response under each.
    return {"syn_flood_action": syn_action, "rates": rates}


def normalize_zone_protection_profile(
    entry: dict[str, Any], *, device_non_syn_reject: bool,
) -> NormalizedZoneProtectionProfile:
    """One profile entry, with every provenance row it owes.

    `device_non_syn_reject` is this appliance's `deviceconfig/setting/session/tcp-reject-non-syn`
    reading, which is HALF OF PAN-ZON-006'S ANSWER and is not on the profile at all. It is
    passed in rather than read from `PanOsSessionSettings` so that the resolution and the
    session-settings row cannot disagree about one payload, and so that this pass does not
    depend on the network-hardening pass having run.
    """
    provenance: list[tuple[str, Any, str | None]] = []
    values: dict[str, Any] = {}

    flood = _dict(entry.get("flood"))
    for flood_type, column in ZONE_FLOOD_COLUMNS.items():
        value, raw_key, raw_prov = parse_yes_no_field(
            _dict(flood.get(flood_type)).get("enable"),
            implicit=ZONE_FLOOD_ABSENT[flood_type])
        values[column] = value
        provenance.append((column, raw_key, raw_prov))

    # PAN-ZON-003's verdict, over the FOUR volumetric types and not over all five. True where
    # any one of them is unmetered, which is what the four inputs' own defaults compute to.
    values["volumetric_flood_gap"] = not all(
        values[column] for column in VOLUMETRIC_FLOOD_COLUMNS)

    # THE ACTION IS NOT A VALUE: `flood/tcp-syn` has no `action` leaf and the response is which
    # of two sibling CONTAINERS exists. Blank for neither, and there is no third state.
    syn_action, _syn_content = choice_child(
        flood.get("tcp-syn"), ZoneProtectionProfile.SYN_FLOOD_ACTIONS)
    values["syn_flood_action"] = syn_action
    values["flood_rates"] = _zone_flood_rates(entry, syn_action)

    for key, column in PACKET_DROP_COLUMNS.items():
        value, raw_key, raw_prov = parse_yes_no_field(
            entry.get(key), implicit=PACKET_DROP_ABSENT[key])
        values[column] = value
        provenance.append((column, raw_key, raw_prov))

    values["packet_drop_gap"] = not all(
        values[column] for column in ASSERTED_PACKET_DROP_COLUMNS)

    configured, non_syn_rk, non_syn_rv = parse_text_field(
        entry.get("tcp-reject-non-syn"), implicit=PROFILE_NON_SYN_ABSENT)
    values["non_syn_reject_configured"] = configured
    provenance.append(("non_syn_reject_configured", non_syn_rk, non_syn_rv))
    # THE POINTER, RESOLVED. The profile's own literal where it is yes or no; the device-wide
    # setting where it is `global` or anything else - which includes a value nobody has seen,
    # because stage 4's `global` WRITE here was accepted and never committed, so the leaf's
    # committed value set is not closed. An unrecognised literal resolves through the device,
    # which is what `global` means and is the reading that cannot invent a refusal.
    if configured in ZoneProtectionProfile.NON_SYN_EFFECTIVE_VALUES:
        values["non_syn_reject_effective"] = configured
    else:
        values["non_syn_reject_effective"] = (
            ZoneProtectionProfile.NON_SYN_YES if device_non_syn_reject
            else ZoneProtectionProfile.NON_SYN_NO)

    scans = _scan_entries_by_id(entry)
    actions: dict[str, str] = {}
    for scan_id, column in ZoneProtectionProfile.SCAN_COLUMN_BY_ID.items():
        action, raw_key, raw_prov = _scan_action(scans.get(scan_id))
        values[column] = action
        actions[scan_id] = action
        provenance.append((column, raw_key, raw_prov))

    # ONE TRACK-BY, FOUR ENTRIES. Stage 5 declared one column, so the first entry that carries
    # the leaf speaks for the profile; the entries are read in the fixed id order above so the
    # answer does not depend on payload order. Where two entries disagree the column is wrong
    # about one of them and `scan_sensitivity_known` does not say so - recorded as a spec gap
    # rather than papered over with a second column nothing asserts.
    # THE DECLARATION IS THE STARTING STATE AND NOT `ABSENT`, which is a correction a test
    # found. A profile with NO SCAN NODE AT ALL has no `interval` key for the loop below to
    # reach, so these three started out untracked - and a missing `FieldProvenance` row means
    # "the field is not tracked", which is a different and weaker statement than "the key was
    # absent and nothing was assumed". Stage 5's provenance block for this subject is explicit
    # that an ABSENT key records a row typed `not_configured` where it declares no value, so
    # seeding the declaration is what makes the two absences - no scan node, and a scan entry
    # carrying no sensitivity keys - record the same honest row.
    track_by, track_rk, track_rv = "", SCAN_TRACK_BY_ABSENT, None
    interval, interval_rk, interval_rv = None, SCAN_INTERVAL_ABSENT, None
    threshold, threshold_rk, threshold_rv = None, SCAN_THRESHOLD_ABSENT, None
    for scan_id in ZoneProtectionProfile.SCAN_COLUMN_BY_ID:
        scan = scans.get(scan_id)
        if scan is None:
            continue
        if not track_by:
            block_ip = _dict(_dict(scan.get("action")).get(
                ZoneProtectionProfile.SCAN_ACTION_BLOCK_IP))
            track_by, track_rk, track_rv = parse_text_field(
                block_ip.get("track-by"), implicit=SCAN_TRACK_BY_ABSENT)
        if interval is None:
            interval, interval_rk, interval_rv = parse_integer_field(
                scan.get("interval"), implicit=SCAN_INTERVAL_ABSENT)
        if threshold is None:
            threshold, threshold_rk, threshold_rv = parse_integer_field(
                scan.get("threshold"), implicit=SCAN_THRESHOLD_ABSENT)
    # ONE TRACK-BY, FOUR ENTRIES, and `track_by` falsy after the loop is indistinguishable
    # from never having been read - which is the state the declaration above already covers.
    values["scan_block_ip_track_by"] = track_by
    values["scan_interval"] = interval
    values["scan_threshold"] = threshold
    provenance.extend([
        ("scan_block_ip_track_by", track_rk, track_rv),
        ("scan_interval", interval_rk, interval_rv),
        ("scan_threshold", threshold_rk, threshold_rv),
    ])

    values["scan_weakest_action"] = scan_weakest_action(actions, track_by)
    # PAN-ZON-004's first verdict: does every scan type RECORD the event it detects? `allow`
    # does not and neither does the empty string, which is the no-entry sentinel.
    values["scan_detection_gap"] = not all(
        action in ZoneProtectionProfile.SCAN_RECORDING_ACTIONS for action in actions.values())
    # AND THE COMPANION, which is what a control clauses on instead of the two nullable
    # integers: true only where the profile carries at least one scan entry AND both sensitivity
    # numbers were read. A profile with no scan entry at all has no sensitivity to know, and
    # false is the side that REPORTS it.
    values["scan_sensitivity_known"] = bool(
        scans and interval is not None and threshold is not None)

    white_list, white_count = _scan_white_list(entry)
    values["scan_white_list"] = white_list
    values["scan_white_list_count"] = white_count
    provenance.append(("scan_white_list", "scan-white-list" if "scan-white-list" in entry
                       else Implicit.measured(
                           [],
                           "stage4-zone-dos-protection.json, "
                           "zone-protection-profile.scan-white-list: an absent exclusion list "
                           "means NOTHING is exempt from reconnaissance detection, measured "
                           "2026-10-25 on 691665AC334B458 (PA-VM 11.2.5) - the dialog's Source "
                           "Address Exclusion grid rendered with no rows on the keyless "
                           "COMMITTED subject, `action=complete` on the container returned an "
                           "empty list, and four scan entries were written beside it while it "
                           "stayed empty. Stage 4 called this its WEAKEST promotion on this "
                           "object because the positive control was NOT paid - no exclusion "
                           "entry was ever written, so the empty grid was never shown to move - "
                           "and promoted it only because an empty entry-list has no other "
                           "reading: the node is a collection and its absence cannot assert "
                           "membership."), None))

    return NormalizedZoneProtectionProfile(
        profile_name=str(entry.get("@name") or "").strip(),
        values=values,
        field_provenance_data=provenance,
        entry_provenance=_entry_provenance(entry),
    )


def _zone_attachments(device_entry: dict[str, Any]) -> dict[str, int]:
    """How many zones name each profile, across every vsys of this appliance.

    WALKED OUT OF THE PAYLOAD rather than read back from `Zone` rows, so that this count and
    `Zone.zone_protection_unresolved` are two readings of one dict in one pass and cannot
    disagree - and so that neither normalizer has to have run before the other.

    THE KEY IS CASE-SENSITIVE and is not folded. A case-insensitive join would over-count the
    in-force set and under-count the unreferenced one, and those two errors are unsafe for
    different controls.
    """
    counts: dict[str, int] = {}
    for vsys in _entries(device_entry.get("vsys")):
        for zone in _entries(vsys.get("zone")):
            name = _text(_dict(zone.get("network")).get("zone-protection-profile"))
            if name:
                counts[name] = counts.get(name, 0) + 1
    return counts


def attachment_sweep_is_complete(device_entry: dict[str, Any]) -> bool:
    """Did the reverse lookup have EVERY reference surface available to it?

    TWO SURFACES CAN NAME A ZONE PROTECTION PROFILE and only one is modelled. A vsys zone's
    attachment leaf is measured and is walked above; a SHARED GATEWAY's own zone is derived from
    the grammar and was never exercised, because no appliance in the lab has one - a shared
    gateway needs multi-vsys with external zones. `Zone`'s only owner is an EnforcementPoint, so
    a shared-gateway zone has nowhere to be stored at all.

    SO THE QUESTION IS MEASURABLE RATHER THAN PERMANENTLY FALSE: if this appliance has no
    `shared-gateway` node, there is no second surface to have missed and the sweep IS complete.
    Where the node exists the sweep is incomplete, and saying so is what keeps PAN-ZON-008 from
    recommending the deletion of a profile a shared-gateway zone is using - the direction that
    removes configuration rather than wasting an hour.

    WHAT THIS CANNOT SEE: a zone in a vsys whose merged read never arrived. The whole device
    entry is one read, so a vsys missing from it is missing from the zone walk and from this
    check alike, and no column of either model can say so.
    """
    return not _dict(device_entry.get("shared-gateway"))


def normalize_zone_protection_profiles(appliance: Appliance) -> list[ZoneProtectionProfile]:
    """Replace every zone protection profile for one appliance. Returns what was written.

    Profiles are replaced wholesale rather than upserted, for the reason the zone normalizer
    gives: a profile deleted on the device has to disappear here too, and every field is derived
    from the snapshot.

    IT ALSO WRITES THE ZONE SIDE OF THE JOIN. `Zone.zone_protection_unresolved` is recomputed
    for every zone row of this appliance that was built from the SAME snapshot, as a targeted
    update rather than a rebuild - the zone normalizer sets the column's firing default when it
    creates a row, and this is the pass that resolves it. Doing it here is what makes the two
    directions of one comparison come out of one walk. A zone row from an OLDER snapshot is left
    alone: it describes a device state this payload does not.
    """
    snapshot = latest_appliance_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")
    device_entry = device_entry_from_snapshot(snapshot)

    setting = _dict(_dict(device_entry.get("deviceconfig")).get("setting"))
    device_non_syn_reject, _rk, _rv = parse_yes_no_field(
        _dict(setting.get("session")).get("tcp-reject-non-syn"),
        implicit=TCP_REJECT_NON_SYN_ABSENT)

    profiles_root = _dict(_dict(device_entry.get("network")).get("profiles"))
    attachments = _zone_attachments(device_entry)
    sweep_complete = attachment_sweep_is_complete(device_entry)

    normalized: list[NormalizedZoneProtectionProfile] = []
    seen: set[str] = set()
    for entry in _entries(profiles_root.get("zone-protection-profile")):
        name = str(entry.get("@name") or "").strip()
        if not name or name in seen:
            # A profile with no name cannot be referenced by anything, and a duplicate name is
            # not expressible in PAN-OS. Neither is invented into a row.
            continue
        seen.add(name)
        normalized.append(normalize_zone_protection_profile(
            entry, device_non_syn_reject=device_non_syn_reject))

    written: list[ZoneProtectionProfile] = []
    with transaction.atomic():
        content_type = ContentType.objects.get_for_model(ZoneProtectionProfile)
        FieldProvenance.objects.filter(
            content_type=content_type,
            object_id__in=list(
                ZoneProtectionProfile.objects.filter(appliance=appliance)
                .values_list("pk", flat=True)),
        ).delete()
        ZoneProtectionProfile.objects.filter(appliance=appliance).delete()

        for row in normalized:
            attached = attachments.get(row.profile_name, 0)
            profile = ZoneProtectionProfile.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                source_snapshot=snapshot,
                profile_name=row.profile_name,
                attached_zone_count=attached,
                attachment_sweep_complete=sweep_complete,
                # THE TWO VERDICTS ARE NOT EACH OTHER'S NEGATION. `is_in_force` is the
                # applicability gate five content controls rest on and errs INCLUSIVE;
                # `is_unreferenced` is a deletion candidate and errs SILENT, so it also
                # requires the sweep to have been complete. Both false is the real state of a
                # profile nothing references on an incomplete sweep - the undetermined group.
                is_in_force=attached > 0,
                is_unreferenced=attached == 0 and sweep_complete,
                **row.values,
            )
            FieldProvenance.objects.create(
                content_type=content_type, object_id=profile.pk,
                field_name=ENTRY_FIELD, provenance_type=row.entry_provenance[0],
                raw_key=row.entry_provenance[1], raw_value=row.entry_provenance[2][:128],
            )
            FieldProvenance.objects.bulk_create([
                FieldProvenance(
                    content_type=content_type, object_id=profile.pk, field_name=name,
                    provenance_type=classify_prov_type(raw_key),
                    raw_key=provenance_raw_key(raw_key),
                    raw_value=provenance_value(raw_key, raw_value)[:128])
                for name, raw_key, raw_value in row.field_provenance_data
                if raw_key is not ABSENT])
            written.append(profile)

        # THE ZONE SIDE, in the same transaction and off the same walk.
        profile_names = {row.profile_name for row in normalized}
        for zone in Zone.objects.filter(
                enforcement_point__appliance=appliance, source_snapshot=snapshot):
            unresolved = zone_attachment_verdict(zone.zone_protection_profile, profile_names)
            if zone.zone_protection_unresolved != unresolved:
                zone.zone_protection_unresolved = unresolved
                zone.save(update_fields=["zone_protection_unresolved", "updated_at"])

    return written


# ---------------------------------------------------------------------------
# DosPolicyRule
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class NormalizedDosPolicyRule:
    config_source: str
    rule_position: int
    rule_name: str
    source_snapshot: Snapshot
    values: dict[str, Any]
    field_provenance_data: list[tuple[str, Any, str | None]] = field(default_factory=list)
    entry_provenance: tuple[str | None, str | None] = (None, None)


def _dos_rules(rulebase: Any) -> list[dict[str, Any]]:
    """`<rulebase>/dos/rules/entry`, in ARRAY ORDER.

    The order is the evaluation order and no key holds it, so a reader that does not preserve
    array order loses the only statement the device makes about evaluation sequence.
    """
    return _entries(_dict(_dict(rulebase).get("dos")).get("rules"))


def normalize_dos_policy_rule(
    *, entry: dict[str, Any], config_source: str, rule_position: int, snapshot: Snapshot,
) -> NormalizedDosPolicyRule:
    """One DoS policy rule entry, with every provenance row it owes."""
    provenance: list[tuple[str, Any, str | None]] = []
    values: dict[str, Any] = {}

    # `action` IS A CHOICE ELEMENT: three child nodes, not three values, with the stored shape
    # `action: {'protect': None}`. Blank means no branch is present, which on a COMMITTED rule
    # cannot happen - and the provenance row records the key rather than a default, because a
    # mandatory key has no absent-key case to type as one.
    action, _content = choice_child(entry.get("action"), DosPolicyRule.ACTION_BRANCHES)
    values["rule_action"] = action
    provenance.append(("rule_action", "action" if action else ABSENT, action or None))

    protection = _dict(entry.get("protection"))
    aggregate, agg_rk, agg_rv = parse_text_field(
        _dict(protection.get("aggregate")).get("profile"), implicit=AGGREGATE_PROFILE_ABSENT)
    values["aggregate_profile"] = aggregate
    provenance.append(("aggregate_profile", agg_rk, agg_rv))

    classified_node = _dict(protection.get("classified"))
    classified, cls_rk, cls_rv = parse_text_field(
        classified_node.get("profile"), implicit=CLASSIFIED_PROFILE_ABSENT)
    values["classified_profile"] = classified
    provenance.append(("classified_profile", cls_rk, cls_rv))

    address, addr_rk, addr_rv = parse_text_field(
        _dict(classified_node.get("classification-criteria")).get("address"),
        implicit=CLASSIFICATION_ADDRESS_ABSENT)
    values["classification_address"] = address
    provenance.append(("classification_address", addr_rk, addr_rv))

    # BOTH SLOTS, which is the whole point: they are sibling nodes with no exclusivity the
    # grammar expresses - a rule may carry one of each, measured - and the catalogue row for
    # PAN-ZON-007 asserts the AGGREGATE slot alone, so a gate written from that row would call
    # every classified-only rule inapplicable.
    values["names_a_profile"] = bool(aggregate or classified)

    disabled, dis_rk, dis_rv = parse_text_field(
        entry.get("disabled"), implicit=DOS_RULE_DISABLED_ABSENT)
    values["rule_disabled"] = disabled
    provenance.append(("rule_disabled", dis_rk, dis_rv))

    raw_key, raw_value = None, None
    for key in ("@ptpl", "@loc"):
        if key in entry:
            raw_key, raw_value = key, str(entry[key] or "")
            break
    return NormalizedDosPolicyRule(
        config_source=config_source,
        rule_position=rule_position,
        rule_name=str(entry.get("@name") or "").strip(),
        source_snapshot=snapshot,
        values=values,
        field_provenance_data=provenance,
        entry_provenance=(raw_key, raw_value),
    )


def build_normalized_dos_policy_rules(
    enforcement_point: EnforcementPoint,
) -> list[NormalizedDosPolicyRule]:
    """Every DoS rule visible from this point: the vsys-local rulebase and both pushed ones.

    Raises only when a READ is unusable, as the security-rule build does: a missing merged
    snapshot, or a missing pushed snapshot on a Panorama-managed point. A point with no pushed
    read on an unmanaged firewall simply has no pushed rules.

    THE MERGED READ CARRIES THE LOCAL RULEBASE AND NOT THE PUSHED ONES, measured and recorded in
    the consumer's own CLAUDE.md, which is why both reads are required and neither alone is the
    rule set.
    """
    merged_snapshot = latest_point_merged_snapshot(enforcement_point)
    pushed_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    if merged_snapshot is None:
        raise ValueError(f"missing merged config snapshot for {enforcement_point}")
    if is_panorama_managed(enforcement_point) and pushed_snapshot is None:
        raise ValueError(f"missing pushed VSYS snapshot for {enforcement_point}")

    rows: list[NormalizedDosPolicyRule] = []
    merged_root = merged_vsys_entry(merged_snapshot.payload, enforcement_point.vsys_name)
    for position, entry in enumerate(_dos_rules(merged_root.get("rulebase")), start=1):
        rows.append(normalize_dos_policy_rule(
            entry=entry, config_source=DosPolicyRule.SOURCE_LOCAL,
            rule_position=position, snapshot=merged_snapshot))

    if pushed_snapshot is not None:
        panorama = _dict(pushed_vsys_panorama(pushed_snapshot.payload))
        for node, config_source in (("pre-rulebase", DosPolicyRule.SOURCE_PUSHED_PRE),
                                    ("post-rulebase", DosPolicyRule.SOURCE_PUSHED_POST)):
            for position, entry in enumerate(_dos_rules(panorama.get(node)), start=1):
                rows.append(normalize_dos_policy_rule(
                    entry=entry, config_source=config_source,
                    rule_position=position, snapshot=pushed_snapshot))
    return rows


def normalize_dos_policy_rules(enforcement_point: EnforcementPoint) -> list[DosPolicyRule]:
    """Replace every DoS rule for one enforcement point. Returns what was written."""
    rows = build_normalized_dos_policy_rules(enforcement_point)

    written: list[DosPolicyRule] = []
    with transaction.atomic():
        content_type = ContentType.objects.get_for_model(DosPolicyRule)
        FieldProvenance.objects.filter(
            content_type=content_type,
            object_id__in=list(
                DosPolicyRule.objects.filter(enforcement_point=enforcement_point)
                .values_list("pk", flat=True)),
        ).delete()
        DosPolicyRule.objects.filter(enforcement_point=enforcement_point).delete()

        seen: set[tuple[str, str]] = set()
        for row in rows:
            if not row.rule_name or (row.config_source, row.rule_name) in seen:
                # A rule with no name has no identity and cannot be reported; a duplicate name
                # within one rulebase is not expressible in PAN-OS.
                continue
            seen.add((row.config_source, row.rule_name))
            rule = DosPolicyRule.objects.create(
                management_station=enforcement_point.management_station,
                enforcement_point=enforcement_point,
                source_snapshot=row.source_snapshot,
                config_source=row.config_source,
                rule_position=row.rule_position,
                rule_name=row.rule_name,
                **row.values,
            )
            entry_rk, entry_rv = row.entry_provenance
            FieldProvenance.objects.create(
                content_type=content_type, object_id=rule.pk, field_name=ENTRY_FIELD,
                provenance_type=classify_prov_type(entry_rk),
                raw_key=provenance_raw_key(entry_rk),
                raw_value=provenance_value(entry_rk, entry_rv)[:128],
            )
            FieldProvenance.objects.bulk_create([
                FieldProvenance(
                    content_type=content_type, object_id=rule.pk, field_name=name,
                    provenance_type=classify_prov_type(raw_key),
                    raw_key=provenance_raw_key(raw_key),
                    raw_value=provenance_value(raw_key, raw_value)[:128])
                for name, raw_key, raw_value in row.field_provenance_data
                if raw_key is not ABSENT])
            written.append(rule)
    return written


# ---------------------------------------------------------------------------
# The DoS protection profile - a KIND on SecurityProfile, read from security_profiles.py
# ---------------------------------------------------------------------------

def dos_protection_profile_values(
    entry: dict[str, Any],
) -> tuple[dict[str, Any], list[tuple[str, Any, str | None]]]:
    """The DoS kind's two columns on `SecurityProfile`, and the provenance row `type` owes.

    Called from `normalize_security_profile` the way `decryption_profile_values` and
    `url_filtering_profile_values` are, and for the same reason: these are reads of the entry's
    own keys, so a reader is owed the difference between a value read and a value inferred.

    TWO COLUMNS AND NOT SIXTY. Stage 4 enumerated 58 key paths on this object and stage 5
    declared a scalar for none of them, because both halves of PAN-ZON-007 are discharged
    elsewhere - the first onto the customer's asset inventory and the second onto the RULE's
    action. The flood and resource numbers are held as ONE structure for a reader, with no
    reachable scalar beside them, and nothing clauses on it.
    """
    profile_type, type_rk, type_rv = parse_text_field(
        entry.get("type"), implicit=DOS_PROFILE_TYPE_ABSENT)
    return (
        {"profile_type": profile_type,
         "flood_and_resource_settings": dos_flood_and_resource_settings(entry, profile_type)},
        [("profile_type", type_rk, type_rv)],
    )


def dos_flood_and_resource_settings(
    entry: dict[str, Any], profile_type: str,
) -> dict[str, Any] | None:
    """The flood thresholds, block durations, block probabilities and session ceiling, as read.

    NULL WHERE THE PROFILE STORES NONE. Stage 4 measured NO implicit for any of these keys on
    THIS object and declined to carry the ZONE protection profile's measurements across, because
    that would assume two nodes sharing a leaf name share a default - which this very object
    disproves: its `flood` node has FIVE children where the zone profile's has six, and its
    `red` container has FIVE where the zone profile's has three, adding `block` and
    `block-probability`. So there is no value to put in the column for an absent key.

    THE PROFILE'S OWN TYPE TRAVELS WITH THE NUMBERS, because a threshold means two different
    things under `aggregate` and under `classified` - the whole matched group counted together,
    or each device in it individually - and a number read without it is ambiguous.
    """
    settings: dict[str, Any] = {}
    flood = _dict(entry.get("flood"))
    for flood_type in DOS_FLOOD_TYPES:
        node = _dict(flood.get(flood_type))
        if not node:
            continue
        read: dict[str, Any] = {}
        enable = _text(node.get("enable"))
        if enable:
            read["enable"] = enable
        red = _dict(node.get("red"))
        for key in DOS_RED_KEYS:
            value = _text(red.get(key))
            if value:
                read[key] = value
        duration = _text(_dict(red.get("block")).get("duration"))
        if duration:
            read["block/duration"] = duration
        if read:
            settings[flood_type] = read

    sessions = _dict(_dict(entry.get("resource")).get("sessions"))
    resource: dict[str, Any] = {}
    for key in ("enabled", "max-concurrent-limit"):
        value = _text(sessions.get(key))
        if value:
            resource[key] = value

    if not settings and not resource:
        return None
    return {"profile_type": profile_type, "flood": settings, "resource": resource}


def dos_profile_references(root: Any) -> list[tuple[str, str, str | None]]:
    """Every DoS rule in `root` naming a DoS protection profile, as (name, referrer, @loc).

    THE SHIPPED REFERRER WALK CANNOT FIND THESE AND WOULD NOT HAVE SAID SO.
    `collect_profile_and_group_references` matches on a payload key whose NAME is the profile
    kind carrying a member list - `{"spyware": {"member": ...}}` - and a DoS rule names its
    profile at `protection/aggregate/profile`, a text leaf under a key called `profile`. Adding
    `dos-protection` to `PROFILE_KINDS` makes that walk collect the DEFINITIONS and find no
    referrer at all, so `reference_reach` would read `unreferenced` on every DoS profile in
    every estate with nothing erroring. This function is the second surface.

    BOTH SLOTS, AT EVERY RULEBASE. A COUNT THAT READS ONE SLOT CALLS EVERY CLASSIFIED PROFILE
    UNREFERENCED, which stage 3 names as the specific error here: the catalogue row for
    PAN-ZON-007 asserts the AGGREGATE slot alone, and the two are sibling nodes with no
    exclusivity the grammar expresses. So the walk is two lookups and not one.

    The `@loc` of the owning rule is returned rather than interpreted, so the caller classifies
    scope the way it classifies every other pushed referrer's - from the marker and never from
    which query returned it.
    """
    found: list[tuple[str, str, str | None]] = []
    for node in ("rulebase", "pre-rulebase", "post-rulebase"):
        container = _dict(root).get(node)
        for entry in _dos_rules(container):
            name = str(entry.get("@name") or "").strip()
            if not name:
                continue
            loc = entry.get("@loc")
            protection = _dict(entry.get("protection"))
            for slot in ("aggregate", "classified"):
                profile = _text(_dict(protection.get(slot)).get("profile"))
                if profile:
                    found.append((profile, f"{node}/dos/{name}", loc))
    return found
