"""Normalize the IPSec crypto profiles, IPSec tunnels and monitor profiles on one appliance.

All three objects are DEVICE-WIDE, read from the merged config's single device entry at
`network/ike/crypto-profiles/ipsec-crypto-profiles`, `network/tunnel/ipsec` and
`network/profiles/monitor-profile`. None of them has a vsys or a shared scope, measured by stage 4
of the `ipsec-crypto` domain on two platforms and two vsys postures.

THE COLLECTION HAS THREE STATES AND NOT TWO, and all three occur in this lab at the same moment -
measured 2026-10-29 at `action=get` and again through the whole-config merged read:

    ipsec-crypto-profiles   ABSENT on both PA-5220s, POPULATED (13) on pan-fw-111, (3) on pan-fw-201
    tunnel/ipsec            EMPTY on both PA-5220s, POPULATED (4) on pan-fw-111, ABSENT on pan-fw-201
    monitor-profile         ABSENT on both PA-5220s, POPULATED (3) on pan-fw-111, (1) on pan-fw-201

`common.py::entry_container` is what tells them apart, and its own docstring says to import it
rather than write a third copy. A reader testing truthiness reports ABSENT and EMPTY identically
and they are different facts here: an absent `ipsec-crypto-profiles` is an appliance never
configured for site-to-site VPN, while an empty one is a collection somebody emptied - and both
PA-5220s hold `network/tunnel` present with three NULL children, so the tunnel container exists
there and holds nothing.

NO ROW IS WRITTEN FOR AN APPLIANCE THAT HOLDS NOTHING, which is the one wrong-direction limit in
this domain and it belongs to the GRAIN rather than to this module: every subject is per ENTRY, so
an appliance with no entries produces no rows and a query over no rows reports nothing - which in
a report reads as compliant. Stage 5 recorded it in `not_stored` and named what would close it: a
per-appliance coverage row, which is a fourth model at a different grain.

THE READ IS CANDIDATE-DERIVED. `action=get` and the collector's
`<show><config><merged/></config></show>` are both the merged view, which follows the CANDIDATE,
so an uncommitted edit is reported as configuration. On this domain that matters in exactly one
place and stage 4 measured it: a tunnel with `tunnel-monitor/enable: yes` and no
`destination-ip` is ACCEPTED at the write and REFUSED at commit validation, so
monitoring-enabled-with-nothing-to-probe is a state this module can collect and a running device
never holds.

EVERY CROSS-OBJECT RESOLUTION HERE READS THE SAME PAYLOAD AND NEVER THE OTHER MODEL'S ROWS. The
tunnel's crypto-profile binding, its monitor action and the profile's referrer count are all
computed from the device entry the caller is already holding, so no normalizer depends on another
having run first and the two sides cannot disagree. That is the shape `ike.py` established at the
sibling path, for the same reason.
"""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    FieldProvenance,
    IpsecCryptoProfile,
    IpsecTunnel,
    MonitorProfile,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    Implicit,
    classify_prov_type,
    entry_container,
    iter_member_values,
    offer_below_preferred,
    parse_text_field,
    parse_yes_no_field,
    provenance_raw_key,
    provenance_value,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)
# `_weakest` and `_lifetime` ARE IMPORTED RATHER THAN COPIED, and both are module-private to
# `ike.py`. That is not a liberty taken here for the first time: `security_profiles.py:86` already
# does `from ...ike import _weakest as weakest_member`, and OptivEdgeProbe's
# `reference/consumer-repo-notes.md` carries the entry that recorded it - "it belongs in
# `common.py` and this is its second caller", with the move declined because it would refactor
# code that domain did not add inside a concurrent wave. This is the third caller of `_weakest`
# and the second of `_lifetime`, and the same judgement applies for the same reason.
#
# `_lifetime` is the stronger case of the two: it reads the FOUR UNIT BRANCHES of a `lifetime`
# choice container, rounding UP, on the SIBLING object at
# `network/ike/crypto-profiles/ike-crypto-profiles` - the same container name, the same four
# children and the same silent-replacement behaviour at the write. Rounding up is forced here as
# well as there: stage 5 declares `lifetime_hours` with `minimum: 1`, so a sub-hour lifetime must
# store 1 and can never store 0. The tests below assert the hours for all four branches so that a
# change to the shared helper fails here rather than silently re-grading PAN-IPS-005.
from optivedge_integrations.integrations.platforms.pan_os.normalization.ike import (  # noqa: E501
    _lifetime as lifetime_in_hours,
    _weakest as weakest_member,
)

#: The entry-level provenance record - the entry's own marker rather than one of its fields.
ENTRY_FIELD = "__entry__"

#: Attributes that say an ENTRY came from somewhere other than this device.
#:
#: MEASURED AS ZERO AT ALL THREE PATHS ON ALL FOUR APPLIANCES, by stage 4 and again by this
#: stage's readback on 2026-10-29: no entry of any of the three collections carries any attribute
#: but `@name`. Five Panorama templates hold zero entries at these paths and `show config
#: pushed-template` holds each collection's name zero times, so every row collected on this estate
#: is `local` and the template mapping is for an estate that pushes these paths.
#:
#: `@src` IS MAPPED THOUGH STAGE 5's `provenance.types` HAS NO `panorama` MEMBER. Stage 5 lists
#: local, template, pan_os_default, assumed_default, not_configured and derived for all three
#: subjects, on the strength of the zero measurement above. An `@src`-marked entry would therefore
#: be a state no artifact in this domain accounts for - and recording it as `local`, which is what
#: leaving it out of this map would do, asserts "defined on this device" about an entry the device
#: did not define. Recorded truthfully instead.
ENTRY_PROVENANCE_ATTRIBUTES = {
    "@ptpl": FieldProvenance.ProvenanceType.TEMPLATE,
    "@src": FieldProvenance.ProvenanceType.PANORAMA,
}

# ---------------------------------------------------------------------------
# The paths. All three collections and BOTH referring leaves, as the merged payload spells them.
# ---------------------------------------------------------------------------

IPSEC_CRYPTO_PROFILE_PATH = ("network", "ike", "crypto-profiles", "ipsec-crypto-profiles")
IPSEC_TUNNEL_PATH = ("network", "tunnel", "ipsec")
MONITOR_PROFILE_PATH = ("network", "profiles", "monitor-profile")
#: The LSVPN satellite collection. Its `client/ipsec-crypto-profile` leaf draws from the SAME
#: crypto-profile collection as a site-to-site tunnel's `auto-key` leaf - stage 4 settled that by
#: enumeration rather than by name matching, and the enumeration pointing the other way is what
#: makes it mean anything: `action=complete` at this path returned exactly this collection's three
#: entries on pan-fw-201, two of which exist in no other collection there, while the same read at
#: `global-protect-gateway/entry/ipsec/ipsec-crypto-profile` returned exactly ONE name - the
#: GlobalProtect app crypto collection's only entry. So that third leaf does NOT reach this
#: object and is deliberately not counted.
SATELLITE_TUNNEL_PATH = ("network", "tunnel", "global-protect-site-to-site")

# ---------------------------------------------------------------------------
# The orderings. WEAKEST FIRST, because what a control grades is the weakest member a profile
# still OFFERS: the profile offers every member and a peer may insist on any of them, so a weak
# member left in place is a live option and not a lower preference. Stage 4 also measured that
# `action=set` with one `<member>` ADDS to the stored list rather than replacing it, so an offer
# set is cumulative and a remediation cannot shrink it by overwriting.
# ---------------------------------------------------------------------------

#: PAN-IPS-002's severity order over the eight members measured at `esp/encryption`.
#:
#: STAGE 5 GIVES A SEVERITY ORDER AND NOT A TOTAL ONE, so the ties are broken here and the
#: tie-breaks are deliberately inconsequential: `null` and `3des` share `high`, and the five AES
#: members between `aes-128-cbc` and `aes-128-gcm` share `medium`. `null` is placed first because
#: it carries the payload in CLEARTEXT inside what the estate reports as an encrypted tunnel,
#: which stage 5 calls the worst outcome available - and because the two share a severity, a
#: profile offering both reports at `high` whichever way the tie falls.
#:
#: THE SET IS A LOWER BOUND AND STAGE 4 SAYS WHY: `action=complete` answers a SUCCESSFUL EMPTY
#: list at this path on all four appliances, so the schema oracle enumerates nothing here and
#: every member came from a write probe or a stored row. `des` is NOT a member on either build
#: (code=12 "esp -> encryption 'des' is not an allowed keyword"), which is why PAN-IPS-002's
#: `des` rank can never fire at this path; `aes-128-ccm` was ACCEPTED on the PA-5220 and REFUSED
#: on the PA-VMs; `aes-256-cbc` is the vendor's and was not probed.
#:
#: A MEMBER THIS ORDER DOES NOT PLACE IS NOT DROPPED - `weakest_member` returns it as the device
#: gave it and the grading places it unranked, which is visible, where returning nothing would
#: read as "nobody collected this".
ENCRYPTION_ORDER = (
    "null", "3des", "aes-128-cbc", "aes-192-cbc", "aes-256-cbc", "aes-128-ccm",
    "aes-128-gcm", "aes-256-gcm",
)

#: Authenticated-encryption ciphers - the GCM and CCM families. PAN-IPS-003's applicability turns
#: on all of them authenticating, because the vendor states the separate hash is IGNORED for these
#: (gp p.877), so a weak hash beside AEAD-only ciphers is not an exposure the device will act on.
AEAD_CIPHERS = frozenset({"aes-128-ccm", "aes-128-gcm", "aes-256-gcm"})

#: PAN-IPS-003's severity order over the six members measured at `esp/authentication`. This one is
#: TOTAL rather than tied: critical, high, medium, medium, no_finding, no_finding, and `none`
#: first because unauthenticated encryption is the one rank above this control's baseline - the
#: payload is confidential and FORGEABLE.
#:
#: `none` IS A MEMBER HERE AND NOT AN ABSENCE, and the asymmetry is the device's: it is accepted
#: on `esp/authentication` and REFUSED on `ah/authentication` with code=12 "ah -> authentication
#: 'none' is not an allowed keyword". That is help p.656's conditional offer measured on the
#: device, and it is conditioned on the PROTOCOL BRANCH rather than on the cipher - so the AH
#: branch's set is these six minus `none`.
INTEGRITY_ORDER = ("none", "md5", "sha1", "sha256", "sha384", "sha512")

#: The family PAN-IPS-003 requires. `sha384` and `sha512` are the control's target; `sha256` meets
#: the floor at a lower severity.
SHA2_INTEGRITY = frozenset({"sha256", "sha384", "sha512"})

#: PAN-IPS-004's target: the three elliptic-curve groups. Every other value fails, including the
#: nineteen post-quantum members and the literal `none` - not because a post-quantum group is
#: weak, but because no ordering places it and the column is named for the target being MET.
DH_GROUP_TARGET = frozenset({"group19", "group20", "group21"})

#: PAN-IPS-005's target, in hours. The vendor names one hour as its own default.
LIFETIME_TARGET_HOURS = 1

#: The algorithm content PAN-OS ships, as `effective_crypto_profile_chosen` tests it. Read off the
#: shipped `default` entry on pan-fw-201, 2026-10-29: esp encryption {aes-128-cbc, 3des},
#: esp authentication {sha1}, dh-group group2, lifetime 1 hour.
#:
#: COMPARED AS SETS AND NOT AS LISTS, because the device keeps its own order and a reordered copy
#: of the shipped proposal is still the shipped proposal. Compared on CONTENT and not on the name
#: for the reason stage 3 changed the control: the factory entries are ordinary local config,
#: present on one of four lab appliances and deletable, so a renamed copy passes a name test, a
#: hand-made weak profile passes it too, and on an appliance where the shipped entry was deleted a
#: name test is vacuously satisfied.
SHIPPED_PROFILE_CONTENT = (
    frozenset({"aes-128-cbc", "3des"}),
    frozenset({"sha1"}),
    "group2",
    1,
)

# ---------------------------------------------------------------------------
# Absent-key declarations. Four are MEASURED vendor facts, three store nothing, and TWO are
# inferences - which is unusual for this pipeline and is why each of the two says in its own words
# why an inference is admissible there at all. The test
# `ImplicitDeclarationTests.ASSUMED_DEFAULTS` greps this module's TEXT for the inferred-default
# constructor and asserts the per-file count, so this module is listed there as 2. It counts the
# literal in a COMMENT as readily as in a call - this sentence was written naming the constructor
# and turned the suite red at 3 - which is why the two call sites below are the only places in
# this file where that name is spelled.
# ---------------------------------------------------------------------------

_LIST_ABSENT_MEANS_NOTHING_OFFERED = (
    "stage 4, pipeline/artifacts/stage4-ipsec-crypto.json "
    "objects.ipsec-crypto-profile.fields.{key}.implicit, measured 2026-10-26 on fw-core-tpa-a "
    "(PA-5220, 11.1.13-h3) off two COMMITTED profiles and licensed may_materialise: true - an "
    "absent list means NOTHING IS OFFERED and there is no implicit algorithm. The materialised "
    "value is null, which is the FIRING side: every verdict derived from this list reads its "
    "worst value from an empty list")

ESP_ENCRYPTION_ABSENT = Implicit.measured(
    None, _LIST_ABSENT_MEANS_NOTHING_OFFERED.format(key="esp/encryption"))
ESP_AUTHENTICATION_ABSENT = Implicit.measured(
    None, _LIST_ABSENT_MEANS_NOTHING_OFFERED.format(key="esp/authentication"))
AH_AUTHENTICATION_ABSENT = Implicit.measured(
    None, _LIST_ABSENT_MEANS_NOTHING_OFFERED.format(key="ah/authentication"))

#: THE SHARPEST MEASUREMENT IN THIS DOMAIN. An absent `dh-group` asserts `group2`, with the
#: positive control PAID IN BOTH DIRECTIONS over three grid reads in one lease - absent rendered
#: group2, group21 written rendered group21, the key deleted rendered group2 again.
#:
#: AND IT FIRES. PAN-IPS-004 ranks group2 HIGH, the key is optional at commit validation, and both
#: stage 4 and stage 6 committed profiles without it (`oep-ips6-p09` is standing in that state
#: now) - so a profile that simply omits the key behaves as a FAILING value and the omission is
#: committable. Materialising it is what makes that reportable; leaving the column null would have
#: made the commonest omission in the domain pass every threshold.
DH_GROUP_ABSENT = Implicit.measured(
    "group2",
    "stage 4, pipeline/artifacts/stage4-ipsec-crypto.json "
    "objects.ipsec-crypto-profile.fields.dh-group.implicit, measured 2026-10-26 on fw-core-tpa-a "
    "(PA-5220, 11.1.13-h3) with the positive control paid in both directions over three grid "
    "reads in one lease, licensed may_materialise: true")

#: Absent behaves identically to `no`, measured THROUGH THE COMMIT-VALIDATION GATE rather than
#: through a screen, with the positive control paid in both directions over three commits: key
#: ABSENT, job 498 failed the enabled-tunnel virtual-router check; `disabled: yes`, job 500
#: returned OK and the check vanished; `disabled: no`, job 503 failed the same check again.
#:
#: THIS DEFAULT REASSURES AND THAT IS CORRECT ONLY BECAUSE OF WHICH CONTROL READS IT. PAN-IPS-008
#: fires on a tunnel left switched OFF, so a materialised `false` reports an un-switched tunnel as
#: enabled - the compliant side of THAT control. It would not be safe for any control asserting
#: that a tunnel IS enabled, and no control in this domain does.
DISABLED_ABSENT = Implicit.measured(
    False,
    "stage 4, pipeline/artifacts/stage4-ipsec-crypto.json "
    "objects.ipsec-tunnel.fields.disabled.implicit, measured 2026-10-26 on fw-core-tpa-a through "
    "commit validation jobs 498, 500 and 503, licensed may_materialise: true")

ANTI_REPLAY_ABSENT = Implicit.not_assumed(
    "stage 4 recorded this implicit UNMEASURED with three leads and promoted none of them, "
    "setting may_materialise: false and consumer_disposition: not_assumed. The vendor's wording "
    "is a selection instruction stating no default (help p.614); the same two node names on the "
    "MACsec profile ARE documented disabled (guide p.544) and are a DIFFERENT OBJECT; and "
    "action=complete answers code=2 at this leaf. Materialising `false` would report a finding on "
    "behalf of a measurement nobody took and materialising `true` would report a clean estate for "
    "the same reason, so nothing is stored and the firing is moved to anti_replay_determined. The "
    "gap is an INSTRUMENT gap and not a device one: the field sits behind the IPSec Tunnel "
    "dialog's `Show Advanced Options` toggle and stage 4's UI oracle cannot tick a control before "
    "reading. ONE dialog read with the toggle ticked would settle this field, tunnel-monitor, "
    "tunnel-monitor/enable, anti-replay-window, ipsec-mode, copy-tos and copy-flow-label - seven "
    "unmeasured implicits behind one toggle")

TUNNEL_MONITOR_ENABLE_ABSENT = Implicit.not_assumed(
    "stage 4 recorded this implicit UNMEASURED with may_materialise: false and "
    "consumer_disposition: not_assumed, and calls it and the monitor branch above it the second "
    "most valuable unmeasured value in the domain because PAN-IPS-007's first record asserts "
    "exactly this field. The vendor's wording is a selection instruction ('Tunnel Monitor - "
    "Select to alert the device administrator of tunnel failures', help p.614). A materialised "
    "`false` would report a finding on an unmeasured basis and a `true` would clear every "
    "unmonitored tunnel in the estate - and an unmonitored tunnel is the COMMONEST shape of this "
    "control's failure, so the firing is moved to tunnel_monitor_enable_determined. Behind the "
    "same `Show Advanced Options` toggle as anti-replay")

#: Absent means NO PROBE TARGET, measured through the commit gate by MOVING the gate: with
#: `enable=yes` AND a target the candidate validated, and with the target deleted and `enable=yes`
#: left behind, commit job 505 refused naming this exact key ("tunnel-monitor constraints failed :
#: destination-ip is required to enable tunnel-monitor"). The materialised value is NULL and it
#: neither fires nor reassures on its own account - no control clauses on it. It is stored because
#: PAN-IPS-007's remediation needs it, and because the measurement is what retires half of stage
#: 3's assertion: monitoring-enabled-with-nothing-to-probe is a CANDIDATE-ONLY state.
TUNNEL_MONITOR_DESTINATION_ABSENT = Implicit.measured(
    None,
    "stage 4, pipeline/artifacts/stage4-ipsec-crypto.json "
    "objects.ipsec-tunnel.fields.tunnel-monitor/destination-ip.implicit, measured 2026-10-26 on "
    "fw-core-tpa-a through commit validation job 505, licensed may_materialise: true")

TUNNEL_MONITOR_PROFILE_ABSENT = Implicit.not_assumed(
    "stage 4 recorded this implicit UNMEASURED with may_materialise: false and "
    "consumer_disposition: not_assumed: the vendor calls monitor profiles optional (help p.660) "
    "and commit validation named only destination-ip when this key was present, so nothing says "
    "what an ABSENT profile reference means for a monitored tunnel. Storing nothing is the only "
    "honest column - a guessed profile name would resolve to a real profile's action and report "
    "what THAT profile does on a tunnel that names no profile at all")

IKE_GATEWAY_ABSENT = Implicit.not_assumed(
    "stage 4 records this implicit as `not_reached` with consumer_disposition: not_assumed - "
    "state B was not run and could not be, because the key is mandatory once the auto-key branch "
    "exists and satisfying it needs an IKE gateway, which that run declared out of scope before "
    "it wrote anything. `not_reached` is its own answer rather than 'no implicit value', and "
    "storing nothing is the only honest column for it")

#: AN INFERENCE AND NOT A MEASUREMENT, and stage 4 says so in terms: three leads pointing one way
#: and not one measurement. Stage 4 set `may_materialise: false`, which stage 5 read as refusing
#: the VENDOR-FACT claim rather than the storing - so this is `Implicit.assumed` and the report
#: renders it as not measured.
#:
#: THE REASON IT MAY BE STORED AT ALL IS NARROW AND IS THE ONLY REASON. PAN-IPS-009's first record
#: fires on a tunnel running on a profile nobody chose, and a materialised `default` is exactly
#: that - so the inference CANNOT reassure. Leaving the column null would have made a tunnel with
#: no reference pass PAN-IPS-009 silently, which is the one direction rules.md forbids. What would
#: settle it is a negotiating tunnel and `show vpn ipsec-sa`, which needs an IKE gateway and a
#: reachable peer.
CRYPTO_PROFILE_ABSENT = Implicit.assumed(
    "default",
    "three leads and no measurement, per stage 4's own record: the IPSec Tunnel dialog renders "
    "the literal `default` on a tunnel storing no reference; action=complete marks `default` with "
    "@default='yes' where such a profile exists; and help p.613 says 'Select an existing profile "
    "or keep the default profile'. Stage 4's consumer_disposition is `assumed`. The inference is "
    "admissible ONLY because it lands on the firing side of the single control that reads it - on "
    "both PA-5220s and on pan-fw-111 the literal `default` resolves to NOTHING, measured, so the "
    "commonest configuration in this lab reports rather than passes")

#: AN INFERENCE AND NOT A MEASUREMENT, off two leads: `action=complete` answers two values with
#: @default='yes' on `wait-recover` on all four appliances, and the vendor-shipped `default`
#: profile on pan-fw-201 stores `wait-recover` EXPLICITLY - which is a shipped configuration and
#: not an implicit value.
#:
#: IT FIRES, AND THAT IS THE WHOLE REASON IT MAY BE STORED. `wait-recover` is the value
#: PAN-IPS-007's second record treats as FAILING, and the vendor states the consequence plainly on
#: help p.614. Stage 4's own words: "an unmeasured implicit here must not be materialised as a
#: pass". Had the inferred value been `fail-over` this would have had to be a null column.
#:
#: Stage 4 could not reach the Monitor profile screen at all - three guessed hash routes all
#: landed silently on the Network > Interfaces grid - so this object's implicits are unmeasured
#: for a ROUTE reason rather than a device one, and ONE grid or dialog read would settle it.
MONITOR_ACTION_ABSENT = Implicit.assumed(
    "wait-recover",
    "two leads and no measurement, per stage 4's own record: action=complete answers "
    "wait-recover and fail-over with @default='yes' on wait-recover on all four appliances, and "
    "the vendor-shipped `default` profile on pan-fw-201 stores wait-recover EXPLICITLY, which is "
    "a shipped configuration rather than an implicit value. Stage 4 names the tally that makes "
    "the schema attribute a lead and not evidence: it agrees with the measured implicit on four "
    "fields and disagrees on three, and nothing in the answer says which kind you are holding. "
    "Admissible only because wait-recover is the FAILING value for the one record that reads it")


# ---------------------------------------------------------------------------
# Reading the payload
# ---------------------------------------------------------------------------

def _nullable_text(node: Any, *, implicit: Implicit) -> tuple[str | None, Any, str | None]:
    """A text leaf whose ABSENCE must store NULL rather than the empty string.

    `common.py::parse_text_field` CANNOT EXPRESS THIS and the coercion is in its body:
    `("" if implicit.value is None else str(implicit.value))`. So a column stage 5 declares as
    storing null for an absent key gets "" instead, which is a different row to a clause - and
    that exact substitution is the defect migration `0110_wildfire_rule_absence_is_null`
    corrected on another model after the stage 7 validator raised it. Two columns in this domain
    declare it (`tunnel_monitor_destination_ip`, `tunnel_monitor_profile_name`), so the
    declaration is honoured here rather than silently downgraded.

    Everything else is `parse_text_field`'s contract unchanged: on an ABSENT key the returned
    raw_key IS the `implicit` declaration, so `_write_provenance` writes a row saying WHY the
    stored value is what it is rather than skipping it. A present key carrying no text returns
    the empty string, which is the device holding an empty element and not an absence.

    This is NOT a bare `scalar_value` call site. `ike.py` records the rule it would break -
    "EVERY TRACKED LEAF GOES THROUGH A parse_* HELPER AND NEVER THROUGH BARE scalar_value",
    because the bare path receives the ABSENT sentinel and writes NO row - and this helper exists
    precisely so that rule holds for a nullable text column too.

    TWO NEAR MISSES EXIST AND NEITHER IS THE ANSWER, both found before this was written.
    `security_profiles.py::_text_or_none` is `_text(node) or None`: its own docstring says it
    cannot tell an absent key from an empty element, on a per-key licence that does not hold here,
    and it drops the provenance triple - so a TRACKED field read through it writes no row and then
    reads as a field nobody tracks. And `value or None` applied to `parse_text_field`'s own return,
    which another run in this wave recorded in OptivEdgeProbe's `reference/consumer-repo-notes.md`
    the same day, collapses the same two states for the same reason. Both are right where an empty
    element is unreachable at the leaf; neither says so from the store. The shape that belongs in
    `common.py` is `parse_text_field(..., coerce_null=False)`, which is this function.
    """
    raw_value, raw_key, raw_prov = scalar_value(node)
    if raw_key is ABSENT:
        return implicit.value, implicit, None
    return raw_value, raw_key, raw_prov


def _member_list(node: Any, *, implicit: Implicit) -> tuple[list[str] | None, Any, str | None]:
    """A PAN-OS member list as (values, raw key, raw provenance value), or None for an absence.

    NONE AND `[]` ARE DIFFERENT ANSWERS HERE. None is the key being absent, which stage 4
    measured to mean NOTHING IS OFFERED; `[]` would be a container present and holding no member.
    Stage 5 declares the materialised absent value as null and `empty_is_distinct: false`, so the
    absence stores NULL and the verdicts beside it read an empty offer either way.

    The values keep THE DEVICE'S OWN SPELLING AND THE DEVICE'S OWN ORDER, because these lists are
    offer sets rather than preferences. `scalar_value` reads only the node's provenance marker -
    it scans the marker keys and returns the one present, which is what is needed and is not
    available otherwise - while `iter_member_values` reads the members, including the
    single-member case that arrives as a bare string.

    `null` IS A CIPHER NAME AND NOT A MISSING VALUE at `esp/encryption`: the member list on
    `oep-ips6-p01` is `{"member": ["null"]}`, the string, and it is the cleartext cipher. Nothing
    here coerces a member to a Python None.
    """
    _, raw_key, raw_prov = scalar_value(node)
    if raw_key is ABSENT:
        return implicit.value, implicit, None
    return [value for value, _ in iter_member_values(node) if value], raw_key, raw_prov


def _entry_provenance(entry: dict) -> tuple[str, str, str]:
    """(type, raw key, raw value) for the entry's OWN provenance.

    An unmarked entry is LOCAL, which is a positive statement and not the absence of one: a
    missing row would mean only that nothing tracks the entry. Measured as unmarked on every entry
    of all three collections on all four appliances - the factory-named entries included, which
    are local writable config and NOT predefined, so they must never be given the PREDEFINED
    sentinel.
    """
    for attribute, provenance_type in ENTRY_PROVENANCE_ATTRIBUTES.items():
        value = entry.get(attribute)
        if value:
            return provenance_type, attribute, str(value)
    return FieldProvenance.ProvenanceType.LOCAL, "", ""


# ---------------------------------------------------------------------------
# The computations
# ---------------------------------------------------------------------------

def protocol_branch(entry: dict) -> str:
    """Which of the two mutually exclusive branch containers exists on the entry.

    `esp`, `ah`, or `none` where NEITHER does - which is a COMMITTED state and not a collection
    gap: `lifetime` is the only unconditionally mandatory key on this object, measured at commit
    validation, and both stage 4 and stage 6 committed a profile carrying nothing else.

    THREE TOKENS AND NOT FOUR. Stage 4 wrote `ah` onto a profile already carrying `esp`: the write
    was ACCEPTED and SILENTLY REMOVED `esp`, then `esp` was written back and `ah` vanished -
    measured in both directions with a read-back after each write. So "both branches present",
    which stage 3 ranks high, is a configuration no device can hold. An EMPTY branch is refused at
    commit validation in both directions as well, so stage 3's other high rank is a candidate-only
    state no running device holds.

    `esp` IS TESTED FIRST, which matters only for a payload holding both - a shape the device does
    not produce. Reported as `esp` there rather than as an error, because the ESP branch is the one
    that carries a cipher and understating the protection is the wrong direction.
    """
    if isinstance(entry.get("esp"), (dict, str)):
        return IpsecCryptoProfile.ProtocolBranch.ESP
    if isinstance(entry.get("ah"), (dict, str)):
        return IpsecCryptoProfile.ProtocolBranch.AH
    return IpsecCryptoProfile.ProtocolBranch.NONE


def integrity_offered(branch: str, esp_authentication: list[str] | None,
                      ah_authentication: list[str] | None) -> list[str]:
    """Whichever integrity list the EXISTING protocol branch carries.

    Two sibling lists, one of them chosen by the presence of a third node - which is why this is a
    column and not a clause: a predicate has one field slot, no way to compare two columns and no
    presence operator. Reading one key is not a shortcut either, because stage 4 measured that the
    single grid column serving both branches cannot say which list a value came from.

    An unknown branch token - which can only be a row nobody recomputed - reads as no list, which
    is the firing side of every verdict over it.
    """
    if branch == IpsecCryptoProfile.ProtocolBranch.ESP:
        return list(esp_authentication or [])
    if branch == IpsecCryptoProfile.ProtocolBranch.AH:
        return list(ah_authentication or [])
    return []


def all_offered_ciphers_authenticate(ciphers: list[str] | None) -> bool:
    """Every cipher offered is AEAD, and at least one is offered. False is the APPLICABLE side.

    PAN-IPS-003 clauses on this as APPLICABILITY rather than as an assertion, so the direction of
    an unknown is the whole point: false keeps the control applicable and lets the assertion
    clause decide. An applicability clause whose un-recomputed value read `true` would exclude
    every row from the control and the report would say nothing at all - which is the suppressing
    shape rules.md warns about, and it reads as careful.

    An empty offer is therefore False and not vacuously True: a profile offering no cipher has not
    been shown to authenticate anything.

    `offer_below_preferred` with the preferred and the allowed set identical is this computation
    exactly, and it is in `common.py` because the IKE normalizer needed the same shape for one of
    its own floors. Its own docstring records the move.
    """
    fires, _ = offer_below_preferred(list(ciphers or []), AEAD_CIPHERS, AEAD_CIPHERS)
    return not fires


def integrity_meets_sha2_floor(integrity: list[str]) -> bool:
    """Every integrity algorithm offered is in the SHA-2 family. False is the finding side.

    A UNIVERSAL QUANTIFIER OVER A LIST CHOSEN BY THE PRESENCE OF A SIBLING NODE, which the
    predicate has no operator for in any form - and the membership test a reader reaches for,
    `in`, is in no operator registry at all.

    An empty list is False rather than vacuously True, which is what makes PAN-IPS-003 fire on the
    branchless profile as well as on a weak one. The column is named for the floor being MET so
    that a boolean's own default of false is the reporting side.

    No exception is made for `none` here: the AEAD case is excluded by the applicability clause
    above rather than scored, so `none` reaching this function always means integrity declined
    beside a cipher that only encrypts.
    """
    fires, _ = offer_below_preferred(integrity, SHA2_INTEGRITY, SHA2_INTEGRITY)
    return not fires


def dh_group_meets_target(group: str) -> bool:
    """The key-agreement group is one of PAN-IPS-004's three elliptic-curve targets.

    False for every post-quantum member and for the literal `none` as well as for the weak
    classical groups - not because a post-quantum group is weak, but because no ordering places
    it, and false is how the nineteen values stage 3 leaves unranked reach the report at all.

    `no-pfs` is false and is a DIFFERENT fact from the key being absent: the absent key
    materialises `group2`, which is also false but is a profile re-keying on a 1024-bit group
    rather than one reusing the key already agreed.
    """
    return group in DH_GROUP_TARGET


def lifetime_within_target(hours: int | None) -> bool:
    """The written key lifetime is one hour or less. False is the finding side.

    A threshold on the CONVERSION and never on the raw number: the number and its unit are in
    different keys, and a threshold on the figure without its unit INVERTS the verdict - 240 is
    four hours in minutes and ten days in... the point is that the same figure is this control's
    best state in one unit and its worst in another.

    None is False, so a lifetime nobody could convert reports rather than passing.
    """
    return hours is not None and hours <= LIFETIME_TARGET_HOURS


def _profile_content(values: dict) -> tuple:
    """One profile's algorithm content, in the shape `SHIPPED_PROFILE_CONTENT` is written in."""
    return (
        frozenset(values.get("esp_encryption") or ()),
        frozenset(values.get("esp_authentication") or ()),
        values.get("dh_group") or "",
        values.get("lifetime_hours"),
    )


def effective_crypto_profile_chosen(reference_was_written: bool, found: bool,
                                    content: tuple | None) -> bool:
    """The tunnel runs on a profile somebody CHOSE AND HARDENED. False is the finding side.

    False in three states, and a finding from PAN-IPS-009 has to say which it found because the
    remediations differ:

    - the tunnel carries NO reference at all. False unconditionally, whatever a profile named
      `default` on that appliance happens to contain - because a proposal nobody chose is a
      proposal nobody owns, and because stage 4 measured that the dialog renders `default` on
      such a tunnel while nothing stored says the device agrees.
    - the name resolves to nothing. The MAJORITY state in this lab.
    - the resolved profile still carries the shipped algorithm set, whatever it is called.

    REACHING ACROSS A NAME RESOLUTION AND THEN COMPARING FOUR COLUMNS OF THE FAR ROW is why this
    is a column: there is no join the model does not define, no second field slot and no way to
    compare two columns. Stage 4 named the shape it needs - "The binding, the resolved entry and
    whether the name exists all have to be columns on one row before a comparison means anything."
    """
    if not reference_was_written or not found or content is None:
        return False
    return content != SHIPPED_PROFILE_CONTENT


def crypto_profile_reference_counts(device_entry: dict) -> dict[str, int]:
    """Per profile name, how many tunnel configurations on this appliance name it.

    COUNTED ACROSS BOTH REFERRING LEAVES, which stage 4 settled by enumeration:

        network/tunnel/ipsec/entry/auto-key/ipsec-crypto-profile
        network/tunnel/global-protect-site-to-site/entry/client/ipsec-crypto-profile

    A count over the first alone would report an LSVPN-only profile as UNUSED, and PAN-IPS-009's
    remediation for an unused profile is to delete it. The third candidate leaf,
    `global-protect-gateway/entry/ipsec/ipsec-crypto-profile`, draws from a different collection
    and is deliberately not counted.

    THE SITE-TO-SITE TUNNEL'S ABSENT REFERENCE IS MATERIALISED AND THE SATELLITE'S IS NOT. A
    tunnel entry with no `auto-key/ipsec-crypto-profile` is inferred to use the profile named
    `default` - the same `CRYPTO_PROFILE_ABSENT` inference the tunnel's own column stores, so the
    two sides cannot disagree - while nothing has been measured or inferred about an absent
    satellite reference, so an absent one counts for nothing. Carrying the inference into the
    count is what keeps `referencing_tunnel_count` consistent with `crypto_profile_name` on the
    rows it is counting.

    COMPUTED FROM THE SAME PAYLOAD AS THE PROFILES rather than read back from IpsecTunnel rows, so
    neither normalizer depends on the other having run and the two cannot disagree. With no tunnel
    container at all - pan-fw-201 - every profile correctly gets 0, which is what an absent
    container means and not a missing read.
    """
    counts: dict[str, int] = {}
    _, tunnels = entry_container(device_entry, *IPSEC_TUNNEL_PATH)
    for entry in tunnels:
        auto_key = entry.get("auto-key")
        auto_key = auto_key if isinstance(auto_key, dict) else {}
        name, raw_key, _ = parse_text_field(
            auto_key.get("ipsec-crypto-profile"), implicit=CRYPTO_PROFILE_ABSENT)
        if name:
            counts[name] = counts.get(name, 0) + 1
    _, satellites = entry_container(device_entry, *SATELLITE_TUNNEL_PATH)
    for entry in satellites:
        client = entry.get("client")
        client = client if isinstance(client, dict) else {}
        name, _, _ = scalar_value(client.get("ipsec-crypto-profile"))
        if name:
            counts[name] = counts.get(name, 0) + 1
    return counts


def monitor_profile_actions(device_entry: dict) -> dict[str, str]:
    """Per monitor profile name, the action it would take - INCLUDING the materialised default.

    "Including the monitor profile's own materialised default where the profile stores no action"
    is stage 5's wording and it is load-bearing: stage 4 measured that an entry with NO KEYS AT
    ALL is committable on this object, so "names a profile that stores no action" is a real state
    and not a hypothetical, and `oep-ips6-m03` is standing in it. Resolving such a name to the
    empty string would report a monitored tunnel as unresolvable when the device would in fact
    wait for the dead tunnel - the one answer PAN-IPS-007's second record treats as failing.

    Read from the same payload as the tunnels, for the same reason as the referrer count.
    """
    actions: dict[str, str] = {}
    _, entries = entry_container(device_entry, *MONITOR_PROFILE_PATH)
    for entry in entries:
        name = str(entry.get("@name") or "").strip()
        if not name:
            continue
        action, _, _ = parse_text_field(entry.get("action"), implicit=MONITOR_ACTION_ABSENT)
        actions[name] = action
    return actions


# ---------------------------------------------------------------------------
# Persisting
# ---------------------------------------------------------------------------

def _replace(model, appliance: Appliance):
    """Drop this appliance's rows and their provenance. Returns the content type.

    THE SIXTH PRIVATE COPY OF THIS IN THIS PACKAGE, and that is a defect in the shared layer
    rather than a decision taken here: `ike.py`, `decryption.py`, `network_hardening.py` and
    `user_id.py` each carry their own `_write_provenance`, `services_settings.py` carries
    `write_node_row` for the SINGLETON case, and nothing covers the collection-grained
    delete-and-recreate. Importing another domain's private copy was weighed and declined for one
    reason: `ike.py`'s version documents a claim that is FALSE of these rows - "NOT ONE ROW HERE
    WILL EVER CARRY A VENDOR FACT" - and four of this domain's nine declarations are measured
    vendor facts. Recorded in OptivEdgeProbe's `reference/consumer-repo-notes.md` with the
    signature a shared one would need.
    """
    content_type = ContentType.objects.get_for_model(model)
    FieldProvenance.objects.filter(
        content_type=content_type,
        object_id__in=list(
            model.objects.filter(appliance=appliance).values_list("pk", flat=True)),
    ).delete()
    model.objects.filter(appliance=appliance).delete()
    return content_type


def _write_provenance(content_type, obj, entry: dict,
                      rows: list[tuple[str, Any, str | None]]) -> None:
    """One row per tracked field, plus the entry's own.

    A row is written for a PRESENT key saying where it came from, AND for an ABSENT one saying what
    the absence means - skipping the absent ones is what left "PAN-OS supplied it", "we inferred
    it" and "nobody tracks it" sharing one blank. A missing row now means only that the field is
    not tracked.

    THIS DOMAIN USES FOUR OF THE SIX PROVENANCE TYPES AND THAT IS UNUSUAL HERE. Four absent keys
    record `pan_os_default` - the three algorithm lists and `dh-group`, every one of them a stage
    4 measurement with the positive control paid; three record `not_configured`; and TWO record
    `assumed_default`, which the report renders as not measured. Every entry collected on this
    estate records `local`.
    """
    provenance_type, raw_key, raw_value = _entry_provenance(entry)
    FieldProvenance.objects.create(
        content_type=content_type, object_id=obj.pk, field_name=ENTRY_FIELD,
        provenance_type=provenance_type, raw_key=raw_key[:32], raw_value=raw_value[:128])
    for field_name, key, value in rows:
        if key is ABSENT:
            continue
        FieldProvenance.objects.create(
            content_type=content_type, object_id=obj.pk, field_name=field_name,
            provenance_type=classify_prov_type(key),
            raw_key=provenance_raw_key(key)[:32],
            raw_value=provenance_value(key, value)[:128])


def profile_values(entry: dict) -> tuple[dict, list[tuple[str, Any, str | None]]]:
    """One IPSec crypto profile's columns and provenance rows, read out of its entry.

    Pure: no database, no appliance, no referrer count - which is what lets the readback run the
    real function against a real device payload and compare column by column.

    EVERY TRACKED LEAF GOES THROUGH A `parse_*` HELPER OR THROUGH `_member_list`, never through
    bare `scalar_value`: the bare path receives the ABSENT sentinel and writes NO row, which would
    make four measured absences read as untracked fields.
    """
    esp = entry.get("esp")
    esp = esp if isinstance(esp, dict) else {}
    ah = entry.get("ah")
    ah = ah if isinstance(ah, dict) else {}

    encryption, enc_key, enc_prov = _member_list(
        esp.get("encryption"), implicit=ESP_ENCRYPTION_ABSENT)
    esp_auth, espa_key, espa_prov = _member_list(
        esp.get("authentication"), implicit=ESP_AUTHENTICATION_ABSENT)
    ah_auth, aha_key, aha_prov = _member_list(
        ah.get("authentication"), implicit=AH_AUTHENTICATION_ABSENT)
    group, dh_key, dh_prov = parse_text_field(
        entry.get("dh-group"), implicit=DH_GROUP_ABSENT)

    branch = protocol_branch(entry)
    integrity = integrity_offered(branch, esp_auth, ah_auth)
    unit, hours = lifetime_in_hours(entry.get("lifetime"))

    return (
        {
            "protocol_branch": branch,
            "esp_encryption": encryption,
            "esp_authentication": esp_auth,
            "ah_authentication": ah_auth,
            # Sliced to the column's own length: stage 4 measured no maxLength at this leaf, so a
            # member longer than the column is a value the device could return and the database
            # would refuse. The unranked passthrough is the only way one could arrive.
            "weakest_encryption_offered": (
                weakest_member(list(encryption or []), ENCRYPTION_ORDER) or "")[:16],
            "weakest_integrity_offered": (
                weakest_member(integrity, INTEGRITY_ORDER) or "")[:16],
            "all_offered_ciphers_authenticate": all_offered_ciphers_authenticate(encryption),
            "integrity_meets_sha2_floor": integrity_meets_sha2_floor(integrity),
            "dh_group": group[:32],
            "dh_group_meets_target": dh_group_meets_target(group),
            "lifetime_hours": hours,
            "lifetime_unit": unit or "",
            "lifetime_within_target": lifetime_within_target(hours),
        },
        [("esp_encryption", enc_key, enc_prov),
         ("esp_authentication", espa_key, espa_prov),
         ("ah_authentication", aha_key, aha_prov),
         ("dh_group", dh_key, dh_prov)],
    )


def tunnel_values(entry: dict, *, profile_content: dict[str, tuple],
                  monitor_actions: dict[str, str],
                  ) -> tuple[dict, list[tuple[str, Any, str | None]]]:
    """One IPSec tunnel's columns and provenance rows, read out of its entry.

    `profile_content` and `monitor_actions` come from the SAME device entry, so the two sides of
    every binding are read in one pass and cannot disagree with the rows the other normalizer
    writes.
    """
    monitor = entry.get("tunnel-monitor")
    monitor = monitor if isinstance(monitor, dict) else {}
    auto_key = entry.get("auto-key")
    auto_key = auto_key if isinstance(auto_key, dict) else {}

    disabled, dis_key, dis_prov = parse_yes_no_field(
        entry.get("disabled"), implicit=DISABLED_ABSENT)
    anti_replay, ar_key, ar_prov = parse_yes_no_field(
        entry.get("anti-replay"), implicit=ANTI_REPLAY_ABSENT)
    monitor_enable, me_key, me_prov = parse_yes_no_field(
        monitor.get("enable"), implicit=TUNNEL_MONITOR_ENABLE_ABSENT)
    destination, dest_key, dest_prov = _nullable_text(
        monitor.get("destination-ip"), implicit=TUNNEL_MONITOR_DESTINATION_ABSENT)
    monitor_profile, mp_key, mp_prov = _nullable_text(
        monitor.get("tunnel-monitor-profile"), implicit=TUNNEL_MONITOR_PROFILE_ABSENT)
    gateways, gw_key, gw_prov = _member_list(
        auto_key.get("ike-gateway"), implicit=IKE_GATEWAY_ABSENT)
    profile_name, cp_key, cp_prov = parse_text_field(
        auto_key.get("ipsec-crypto-profile"), implicit=CRYPTO_PROFILE_ABSENT)

    # Whether the reference was WRITTEN, as against inferred. `parse_text_field` hands back the
    # `Implicit` itself as the raw key for an absent one, which is the only place this is
    # knowable - by the time the column holds `default` the two states are identical.
    reference_was_written = not isinstance(cp_key, Implicit) and cp_key is not ABSENT
    found = profile_name in profile_content

    return (
        {
            "is_disabled": disabled,
            "anti_replay": anti_replay,
            # The ANSWER TO "is this unknown", which the clause grammar has no operator for -
            # there is no is-null operator, and by the time a query runs every absent key has
            # already been collapsed into a column value. False FIRES.
            "anti_replay_determined": anti_replay is not None,
            "tunnel_monitor_enable": monitor_enable,
            "tunnel_monitor_enable_determined": monitor_enable is not None,
            "tunnel_monitor_destination_ip": destination,
            "tunnel_monitor_profile_name": monitor_profile,
            # Blank where the tunnel names no profile AND where the name resolves to nothing. A
            # resolved profile that stores no action still answers, with its own materialised
            # default - see `monitor_profile_actions`.
            "monitor_action_effective": monitor_actions.get(monitor_profile or "", "")[:16],
            "ike_gateway_names": gateways,
            "crypto_profile_name": profile_name[:64],
            "crypto_profile_found": found,
            "effective_crypto_profile_chosen": effective_crypto_profile_chosen(
                reference_was_written, found, profile_content.get(profile_name)),
        },
        [("is_disabled", dis_key, dis_prov),
         ("anti_replay", ar_key, ar_prov),
         ("tunnel_monitor_enable", me_key, me_prov),
         ("tunnel_monitor_destination_ip", dest_key, dest_prov),
         ("tunnel_monitor_profile_name", mp_key, mp_prov),
         ("ike_gateway_names", gw_key, gw_prov),
         ("crypto_profile_name", cp_key, cp_prov)],
    )


def monitor_profile_values(entry: dict) -> tuple[dict, list[tuple[str, Any, str | None]]]:
    """One monitor profile's columns and provenance rows.

    `interval` and `threshold` are read by nothing here on purpose - stage 5 declared three
    columns for this subject and no control in this domain asserts over how often the probe is
    sent or how many losses it tolerates. The device holds both and this stage read both, so a
    later domain that wants them is adding a column rather than a read.
    """
    action, action_key, action_prov = parse_text_field(
        entry.get("action"), implicit=MONITOR_ACTION_ABSENT)
    return ({"action": action[:16]}, [("action", action_key, action_prov)])


def _device_entry(appliance: Appliance):
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")
    return snapshot, device_entry_from_snapshot(snapshot)


def _named_entries(entries: list[dict]) -> list[tuple[str, dict]]:
    """(name, entry) for each entry that can be keyed, in payload order.

    An entry with no name is not an entry, and a duplicate name is not expressible in PAN-OS.
    Neither can satisfy the uniqueness constraint, so neither is written.
    """
    out: list[tuple[str, dict]] = []
    seen: set[str] = set()
    for entry in entries:
        name = str(entry.get("@name") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append((name, entry))
    return out


def normalize_ipsec_crypto_profiles(appliance: Appliance) -> list[IpsecCryptoProfile]:
    """Replace every IPSec crypto profile for one appliance. Returns what was written.

    An appliance whose collection is ABSENT or EMPTY writes no row and raises nothing: there is no
    profile to describe, which is a reading and not a failure. The entry grain has no row for "no
    IPSec crypto profile is defined on this appliance" - the committed state of both PA-5220s -
    and the consequence is in the module docstring.
    """
    snapshot, device_entry = _device_entry(appliance)
    _, entries = entry_container(device_entry, *IPSEC_CRYPTO_PROFILE_PATH)
    counts = crypto_profile_reference_counts(device_entry)

    written: list[IpsecCryptoProfile] = []
    with transaction.atomic():
        content_type = _replace(IpsecCryptoProfile, appliance)
        for name, entry in _named_entries(entries):
            values, provenance_rows = profile_values(entry)
            profile = IpsecCryptoProfile.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                source_snapshot=snapshot,
                profile_name=name,
                referencing_tunnel_count=counts.get(name, 0),
                **values,
            )
            _write_provenance(content_type, profile, entry, provenance_rows)
            written.append(profile)
    return written


def normalize_ipsec_tunnels(appliance: Appliance) -> list[IpsecTunnel]:
    """Replace every IPSec tunnel for one appliance. Returns what was written.

    An appliance with no tunnel container writes no row and raises nothing. That is the state of
    three of the four lab appliances, and the shape rules.md warns about applies: PAN-IPS-006 to
    -008 are written over every tunnel the firewall terminates, so an appliance with none has
    those controls VACUOUSLY satisfied. Unlike the gateway case at the sibling path that is not
    even a suppression - there is no applicability clause doing it, just no row - which is why
    stage 5 recorded it as this domain's one wrong-direction limit.
    """
    snapshot, device_entry = _device_entry(appliance)
    _, entries = entry_container(device_entry, *IPSEC_TUNNEL_PATH)
    _, profile_entries = entry_container(device_entry, *IPSEC_CRYPTO_PROFILE_PATH)
    profile_content = {
        name: _profile_content(profile_values(entry)[0])
        for name, entry in _named_entries(profile_entries)
    }
    actions = monitor_profile_actions(device_entry)

    written: list[IpsecTunnel] = []
    with transaction.atomic():
        content_type = _replace(IpsecTunnel, appliance)
        for name, entry in _named_entries(entries):
            values, provenance_rows = tunnel_values(
                entry, profile_content=profile_content, monitor_actions=actions)
            tunnel = IpsecTunnel.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                source_snapshot=snapshot,
                tunnel_name=name,
                **values,
            )
            _write_provenance(content_type, tunnel, entry, provenance_rows)
            written.append(tunnel)
    return written


def normalize_monitor_profiles(appliance: Appliance) -> list[MonitorProfile]:
    """Replace every monitor profile for one appliance. Returns what was written.

    A COLLECTOR THAT SKIPS THIS OBJECT LEAVES PAN-IPS-007's SECOND RECORD UNANSWERABLE, in stage
    4's words: the tunnel's row says monitoring is on and names a profile while the action it
    would take lives only here.
    """
    snapshot, device_entry = _device_entry(appliance)
    _, entries = entry_container(device_entry, *MONITOR_PROFILE_PATH)

    written: list[MonitorProfile] = []
    with transaction.atomic():
        content_type = _replace(MonitorProfile, appliance)
        for name, entry in _named_entries(entries):
            values, provenance_rows = monitor_profile_values(entry)
            profile = MonitorProfile.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                source_snapshot=snapshot,
                profile_name=name,
                **values,
            )
            _write_provenance(content_type, profile, entry, provenance_rows)
            written.append(profile)
    return written
