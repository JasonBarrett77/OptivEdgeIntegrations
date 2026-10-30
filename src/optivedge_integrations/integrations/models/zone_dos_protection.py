"""Zone protection profiles and the DoS rulebase - PAN-ZON-001 to PAN-ZON-008's subjects.

TWO MODELS HERE AND TWO MORE ELSEWHERE, and which node goes where is the decision this file
records. Stage 5 declared four models for this domain; two of them already existed under
other names and are extended in place rather than duplicated:

- `ZoneProtectionProfile` is NEW. `network/profiles/zone-protection-profile` is covered by
  nothing: the only thing in OEI that knew the object existed was `Zone.zone_protection_profile`,
  which holds the NAME a zone points at and not the object.
- `DosPolicyRule` is NEW. `rulebase/dos/rules` is covered by nothing: `security_rules.py`
  takes the whole `rulebase` dict out of the merged vsys entry and reads `security` and
  `default-security-rules` from it, and `dos` is their unread sibling.
- the DoS PROTECTION PROFILE is a kind on `policy.SecurityProfile`, not a model of its own.
  It is a `ScopedPolicyObject` in shape - vsys and shared scopes, a device-group push, and a
  rule names it - and stage 5 proposed the kind for exactly that reason.
- the device-wide `tcp-reject-non-syn` leaf is a column on
  `network_hardening.PanOsSessionSettings`, not a `SessionSettings` model of its own. That
  class already owns `deviceconfig/setting/session` for PAN-NET-005's `ipv6-firewalling`, and
  ruling P374a is one model per PAN-OS node.

THREE GRAINS, and they are the identity decisions:

`ZoneProtectionProfile` is ONE ROW PER APPLIANCE PER NAME - not per enforcement point. The
collection lives under `network/profiles`, which has exactly one scope on a firewall:
`action=complete` is refused code=6 Invalid sequence at both the shared and the vsys
spellings, measured by stage 4. `InterfaceManagementProfile` is the one network profile
already modelled and is unique on (appliance, name) for the same reason; this copies it.

`DosPolicyRule` is ONE ROW PER RULEBASE PER NAME within one enforcement point. The rulebase
is part of the key because one rule name can exist in the vsys-local rulebase and in a pushed
pre- and post-rulebase at once, and those are three different objects at three evaluation
positions. `DecryptionRule` keys the same way and for the same reason.

BOTH PRODUCE A ROW PER HA NODE, not per pair. The merged configuration is read per appliance
and the pair is synchronised, so two rows describe one real configuration and nothing
downstream deduplicates them - the convention `Interface`, `ManagementInterface` and all five
network-hardening models already follow.

WHICH COLUMNS CARRY A `FieldProvenance` ROW. Only the ones that read a payload key. On the
profile that is the five flood enables, the eight drops, `tcp-reject-non-syn`, the four scan
actions, `track-by`, `interval`, `threshold` and the exemption list; on the rule it is
`action`, both profile slots, the classification address and `disabled`. Everything else is
computed and is DECLARED in `DERIVED_FIELDS`, which is what `provenance_for()` answers from.

NULLABILITY IS NOT UNIFORM AND THE RULE IS THE ONE `network_hardening.py` STATES: a text or
integer column whose absence a control compares is non-nullable, because the search layer has
no is-null operator and SQL answers every positive comparison over a NULL with no match - a
reading that must FIRE would silently pass. `null=True` is used only on `scan_interval`,
`scan_threshold` and `flood_rates`, where stage 5 declared that NOTHING is to be stored for an
absent key and its own `when_unknown` records that no clause rests on the column. Stage 5 is
explicit about what that costs: a threshold comparison over those two integers passes every
profile whose key is absent, which is every unedited profile in the estate, and
`scan_sensitivity_known` beside them is what a control clauses on instead.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel
from .policy.base import CONFIG_SOURCE_CHOICES
from .provenance import ProvenancedMixin


class ZoneProtectionProfile(ProvenancedMixin, SyncTrackedModel):
    """One zone protection profile as it exists on one appliance.

    Provenance is recorded the way every other normalized object records it - a
    `FieldProvenance` row with field_name `__entry__` carrying the entry's `@ptpl` - and on
    THIS object the entry-level mark is load-bearing for a different reason than usual.
    Measured by stage 4: `network/profiles` is itself `@ptpl='shared-single-vsys'` while the
    profile collection beneath it carries no mark at all, so a normalizer inheriting the
    parent's mark would label every locally-created profile on the appliance as
    template-supplied AND name the wrong template while doing it. The basis is the value's own
    marker, never an ancestor's.

    THE READ IS CANDIDATE-DERIVED AND ON THIS OBJECT THAT IS WORSE THAN USUAL. Stage 4
    measured that pressing OK on a bare profile's dialog writes 21 KEYS - `enable: no` plus
    three rates for all five rendered flood types, plus `net-inspection: {rule: {}}` - with
    values identical to the ones the device already applies. So an administrator who opened a
    profile and changed nothing leaves a candidate in which every default has become an
    explicit key, and this model reports it as configured. Nothing looks wrong at any layer.
    """

    #: Computed here: the four gap verdicts, the weakest scan action, the resolved non-SYN
    #: refusal, the exemption count, the attachment sweep and the two reference verdicts.
    #: See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "volumetric_flood_gap",
        "syn_flood_action",
        "flood_rates",
        "packet_drop_gap",
        "non_syn_reject_effective",
        "scan_weakest_action",
        "scan_detection_gap",
        "scan_sensitivity_known",
        "scan_white_list_count",
        "attached_zone_count",
        "attachment_sweep_complete",
        "is_in_force",
        "is_unreferenced",
    )

    #: The two sibling CONTAINERS under `flood/tcp-syn`. THE ACTION IS NOT A VALUE: stage 4
    #: measured that `flood/tcp-syn` has no `action` leaf and the response is which of these
    #: two children exists. The empty string for neither is stage 5's own third token, not a
    #: device value, and there is no third state the configuration expresses.
    SYN_ACTION_RED = "red"
    SYN_ACTION_SYN_COOKIES = "syn-cookies"
    SYN_FLOOD_ACTIONS = (SYN_ACTION_RED, SYN_ACTION_SYN_COOKIES)

    #: `tcp-reject-non-syn` ON THE PROFILE answers with THREE values and an `@default` on
    #: `global`, measured identically on PA-VM 11.2.5, PA-VM 11.2.3-h3 and PA-5220 11.1.13-h3.
    #: The device-wide leaf of the SAME NAME is a bare <yes|no> - same name, two shapes, one
    #: hop apart on a pointer, where the three-valued field points at the two-valued one.
    NON_SYN_GLOBAL = "global"
    NON_SYN_YES = "yes"
    NON_SYN_NO = "no"
    NON_SYN_CONFIGURED_VALUES = (NON_SYN_GLOBAL, NON_SYN_YES, NON_SYN_NO)
    #: The RESOLVED form, which no single device read returns: the profile's own literal where
    #: it is yes or no, and the device-wide setting's value where it is `global` or absent.
    NON_SYN_EFFECTIVE_VALUES = (NON_SYN_YES, NON_SYN_NO)

    #: THE ENTRY NAME IS THE SCAN TYPE and nothing else identifies it - there is no `type` key
    #: on a scan entry. The id-to-type mapping was MEASURED by stage 4 by writing a distinct
    #: `interval` to each of the four and reading the dialog's inner grid back;
    #: `/config/predefined/threats/scan` returns the four entries keyed by @id carrying no
    #: other child, so there is no name in it to join to.
    #:
    #: THE SET IS CLOSED, which is what makes four columns the right shape rather than a child
    #: table: the id is a reference and `scan/entry[@name='8004']` is refused `'8004' is not a
    #: valid reference`.
    SCAN_TCP_PORT = "8001"
    SCAN_HOST_SWEEP = "8002"
    SCAN_UDP_PORT = "8003"
    SCAN_IP_PROTOCOL = "8006"
    SCAN_COLUMN_BY_ID = {
        SCAN_TCP_PORT: "scan_tcp_port_action",
        SCAN_HOST_SWEEP: "scan_host_sweep_action",
        SCAN_UDP_PORT: "scan_udp_port_action",
        SCAN_IP_PROTOCOL: "scan_ip_protocol_action",
    }

    #: FOUR CHILD NODES, NOT FOUR VALUES - stage 4 measured the stored shape as
    #: `{'block': None}`, so the chosen action is the child element that exists and the column
    #: stores that element's name. `block-ip` is the one that carries children of its own.
    SCAN_ACTION_ALERT = "alert"
    SCAN_ACTION_ALLOW = "allow"
    SCAN_ACTION_BLOCK = "block"
    SCAN_ACTION_BLOCK_IP = "block-ip"
    SCAN_ACTIONS = (SCAN_ACTION_BLOCK_IP, SCAN_ACTION_BLOCK, SCAN_ACTION_ALERT,
                    SCAN_ACTION_ALLOW)

    #: The two tracking modes under `block-ip`, measured from the grammar's own token
    #: `<source|source-and-destination>` and from `action=complete` on the container.
    TRACK_BY_SOURCE = "source"
    TRACK_BY_SOURCE_AND_DESTINATION = "source-and-destination"

    #: WORST FIRST, and THE ORDERING IS NOT A LADDER - which is why it is stored rather than
    #: compared. Stage 3 grades `block` as acceptable and `block-ip` tracking the
    #: source-and-destination PAIR as low, because a scanner that moves to another destination
    #: is no longer blocked, so the pair form sorts BELOW the plain block despite being the
    #: more elaborate setting. No numeric or lexical comparison produces that order.
    #:
    #: The empty string is first because a scan type with NO ENTRY is not detected at all,
    #: which stage 4 measured is a different absence from an entry carrying no action and is
    #: the worst state available rather than the gentlest.
    SCAN_WEAKEST_ORDER = (
        "",
        SCAN_ACTION_ALLOW,
        SCAN_ACTION_ALERT,
        f"{SCAN_ACTION_BLOCK_IP}-{TRACK_BY_SOURCE_AND_DESTINATION}",
        SCAN_ACTION_BLOCK,
        f"{SCAN_ACTION_BLOCK_IP}-{TRACK_BY_SOURCE}",
    )

    #: What counts as recording the event a scan type detects. `allow` does not, and neither
    #: does the empty string - the two states PAN-ZON-004 fires on.
    SCAN_RECORDING_ACTIONS = (SCAN_ACTION_ALERT, SCAN_ACTION_BLOCK, SCAN_ACTION_BLOCK_IP)

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="zone_protection_profiles")
    #: THE OWNER. The shipped `InterfaceManagementProfile` carries `appliance` as a required FK
    #: and carries NO `enforcement_point`, because there is no vsys in a network profile's
    #: world. That is the FK set this model copies.
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="zone_protection_profiles")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="zone_protection_profiles", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="zone_protection_profiles")

    #: `@name`. WIDER THAN THE VENDOR'S LIMIT ON PURPOSE: stage 4 recorded maxLength 31 from
    #: help p.663 - "up to 31 characters", case-sensitive, unique - and said the length and the
    #: character class were NOT TESTED. 64 gives headroom against an untested documented limit,
    #: because a column narrower than the device's real limit loses the tail of a real value
    #: and the direction of that error is a finding naming a profile that does not exist.
    #:
    #: THE CASE SENSITIVITY IS LOAD-BEARING. The subtraction that decides whether a zone's
    #: attachment resolves is a case-sensitive string comparison, so this must never be stored
    #: or compared case-folded.
    profile_name = models.CharField(max_length=64)

    # ----------------------------------------------------------------- flood protection
    #
    # PAN-ZON-002 (SYN) and PAN-ZON-003 (the other four). Five measured booleans off
    # `flood/<type>/enable`, each non-nullable with a MEASURED default of false: stage 4,
    # 2026-10-25 on pan-fw-201, on a profile created carrying only `description`, committed,
    # and read back from `show config running` still carrying only `description`; confirmed on
    # a second and non-UI oracle, `show zone-protection zone`, which reports the type false by
    # name. A nullable spelling would put the row beyond every operator the compiler has -
    # `eq false` compiles to a plain equality and three-valued logic drops nulls - and the
    # unknown would then read as compliant with nothing erroring.

    #: `flood/tcp-syn/enable`. True is the protected state - the vendor's own polarity.
    syn_flood_enabled = models.BooleanField(default=False)
    #: `flood/udp/enable`. The one flood enable whose positive control was paid DIRECTLY: the
    #: grid's UDP Flood check column moved unticked to ticked, read from the
    #: `x-grid3-check-col-on` class. The other four were read under the same conditions and
    #: held while fourteen siblings moved around them.
    udp_flood_enabled = models.BooleanField(default=False)
    #: `flood/icmp/enable`. The dataplane reports `icmp: False` by name.
    icmp_flood_enabled = models.BooleanField(default=False)
    #: `flood/icmpv6/enable`. The dataplane reports `icmp6: False` by name.
    icmpv6_flood_enabled = models.BooleanField(default=False)
    #: `flood/other-ip/enable`.
    other_ip_flood_enabled = models.BooleanField(default=False)

    #: PAN-ZON-003's verdict over the four non-SYN enables. TRUE IS THE FIRING SIDE and is the
    #: migration default, which is also what the four inputs' own defaults compute to - a
    #: profile storing none of these keys meters none of these flood types.
    volumetric_flood_gap = models.BooleanField(default=True)

    #: Which of the two sibling action containers exists under the SYN flood branch. BLANK
    #: MEANS NEITHER, and there is no third state the configuration expresses.
    #:
    #: Nothing clauses on this column and nothing may: stage 3 discharged the response onto a
    #: question for a person, because the vendor contradicts itself about which response to
    #: prefer and the fact that decides it - whether a dedicated scrubbing appliance sits
    #: upstream of this zone - is not in the configuration. Stage 4 held both containers
    #: `unmeasured` for a reason worth carrying: the one surface that renders an answer is a
    #: dialog combo whose own OK-press was measured to write `red`, so the combo shows what the
    #: form WOULD write rather than what the device applies.
    syn_flood_action = models.CharField(max_length=32, blank=True, default="")

    #: The rate keys the profile stores, as read, with the flood type and the action branch
    #: each one sat under. NULL where the profile stores none, because stage 4 recorded these
    #: implicits as a RELATION rather than a constant and set `merge_as: hold` - there is no
    #: value to put in the column for an absent key.
    #:
    #: THE DIALOG'S RATE FIELDS ARE HINTS, NOT VALUES, and a normalizer must never fill this
    #: from a screen: ExtJS writes emptyText into the input's `value` and the class
    #: `x-form-empty-field` is the only discriminator, set on all nine of them - and the hint
    #: reads `10000 [0 - 2000000]`, the shipped number AND the range in one placeholder. The
    #: only honest source is the config read.
    #:
    #: Nothing clauses on it and nothing may - a consumer test refuses to register a JSON
    #: column as searchable at all.
    flood_rates = models.JSONField(null=True, blank=True, default=None)

    # ----------------------------------------------------------------- packet based attacks
    #
    # PAN-ZON-005 (`discard-ip-spoof`) and PAN-ZON-006 (four of the option and segment drops).
    # Eight measured booleans, all non-nullable with a measured default of false - stage 4,
    # 2026-10-25 on pan-fw-201, keyless committed profile, two oracles including
    # `strict-ip-check: False` by name from the dataplane.

    #: `discard-ip-spoof`. PAN-ZON-005's leaf.
    discard_ip_spoof = models.BooleanField(default=False)
    #: `strict-ip-check`. DECLARED AS A TRAP THAT HAS BEEN DISARMED, and NO CLAUSE NAMES IT.
    #: Stage 4 records `asserted_by: [PAN-ZON-005]` for this key and STAGE 3 SAYS THE OPPOSITE
    #: in terms - "neither control reaches the Strict IP Address Check ... which no control in
    #: the 234 asserts". Stage 5 took stage 3, because an assertion is control prose and stage
    #: 4's own account calls `asserted_by` an index and explicitly not identity. The column
    #: exists only because stage 2 and stage 3 both recorded the specific failure it prevents:
    #: a later stage that reads THIS leaf instead of `discard-ip-spoof` answers a different
    #: question and nothing downstream would notice. Two columns side by side, each named for
    #: its own key, is what makes that visible.
    strict_ip_check = models.BooleanField(default=False)
    #: `discard-strict-source-routing`. PAN-ZON-006.
    discard_strict_source_routing = models.BooleanField(default=False)
    #: `discard-loose-source-routing`. PAN-ZON-006.
    discard_loose_source_routing = models.BooleanField(default=False)
    #: `discard-malformed-option`. PAN-ZON-006.
    discard_malformed_option = models.BooleanField(default=False)
    #: `discard-overlapping-tcp-segment-mismatch`. PAN-ZON-006.
    discard_overlapping_tcp_segment_mismatch = models.BooleanField(default=False)
    #: `discard-record-route`. Asserted by nothing; declared because stage 5 did, and carried
    #: beside its siblings so a reader can see which drop is which.
    discard_record_route = models.BooleanField(default=False)
    #: `discard-timestamp`. Asserted by nothing, as above.
    discard_timestamp = models.BooleanField(default=False)

    #: PAN-ZON-006's verdict over the four ASSERTED drops - not over all eight. TRUE IS THE
    #: FIRING SIDE and is what the four inputs' own defaults compute to.
    packet_drop_gap = models.BooleanField(default=True)

    #: `tcp-reject-non-syn` AS THE PROFILE SPELLS IT. A PRESENT LITERAL THAT IS A POINTER -
    #: the shape stage 4 named as one a consumer gets wrong. `global` is NEITHER the asserted
    #: `yes` NOR a readable `no`: a query comparing this column to `yes` reports a profile at
    #: `global` as non-compliant on a device whose global setting rejects non-SYN TCP, and a
    #: query treating `global` as satisfied reports it as compliant on a device whose global
    #: setting is `no`. Wrong in both directions, measured. So the assertion clauses on
    #: `non_syn_reject_effective` beside it and this column carries the grading.
    #:
    #: THE MODEL DEFAULT IS BLANK AND THE ABSENT-KEY VALUE IS `global`, and the two are
    #: different facts. An absent key stores `global` with a `pan_os_default` provenance row -
    #: stage 4 measured the dialog rendering the literal on a keyless profile and the schema's
    #: own @default agreeing. A row nobody has normalized holds the blank, which is neither the
    #: asserted value nor the measured implicit, so every comparison this control makes reports
    #: it: it fires rather than reassures.
    #:
    #: Its two siblings on the same tab, `asymmetric-path` and `strip-mptcp-option`, have the
    #: SAME three-valued shape with the same @default and render `global` the same way - so the
    #: pointer pattern is three fields on this object and not one. Neither is asserted by any
    #: control and neither gets a column.
    non_syn_reject_configured = models.CharField(max_length=16, blank=True, default="")

    #: WHAT THE FIREWALL ACTUALLY ENFORCES for this profile, resolved across the pointer: the
    #: profile's own literal where it is `yes` or `no`, and
    #: `PanOsSessionSettings.tcp_reject_non_syn` where it is `global` or absent. HALF OF
    #: PAN-ZON-006'S ANSWER IS NOT ON THE PROFILE AT ALL - stage 3 said so in terms, and a
    #: later stage that reads the profile alone has not answered this control.
    #:
    #: `no` IS THE DEFAULT AND IT FIRES, chosen against the arithmetic of the commonest real
    #: state. This is the column that keeps the reassuring default on the session-settings node
    #: from ever reaching a finding: `tcp_reject_non_syn` materialises the measured vendor fact
    #: TRUE, which is correct about an appliance that WAS read and wrong about one that was
    #: not, and this resolution is where the difference is turned into a finding.
    non_syn_reject_effective = models.CharField(max_length=16, default=NON_SYN_NO)

    # ----------------------------------------------------------------- reconnaissance
    #
    # PAN-ZON-004. Four action columns keyed to the four closed scan ids, their sensitivity
    # keys, the exemption list, and three verdicts.

    #: `scan/entry[@name='8001']/action`, as the name of the child element that exists.
    #:
    #: THE TWO ABSENCES ARE DIFFERENT AND THIS ONE COLUMN HOLDS BOTH. The normalizer stores the
    #: EMPTY STRING where no entry of this type exists - measured: with no entry present the
    #: outer grid's four scan columns render BLANK and the `scan` node is absent from the
    #: committed entry - and `alert` where the entry EXISTS and carries no `action` child,
    #: measured separately on entry 8002 after deleting its action child and committing, with
    #: `show config running` returning `{'@name': '8002', 'interval': '102'}` and the dialog
    #: rendering `alert`. The vendor agrees (help p.672 prints "(Default) Alert") and the
    #: vendor was not the evidence. A normalizer that collapses the two reports a scan type
    #: nobody detects as one that records the event.
    scan_tcp_port_action = models.CharField(max_length=16, blank=True, default="")
    #: `scan/entry[@name='8003']/action`.
    scan_udp_port_action = models.CharField(max_length=16, blank=True, default="")
    #: `scan/entry[@name='8002']/action`. The host sweep is the one scan type whose documented
    #: detection INTERVAL differs from the other three - one leaf with two documented defaults
    #: depending on which entry it is (help p.672). Stage 4 measured neither.
    scan_host_sweep_action = models.CharField(max_length=16, blank=True, default="")
    #: `scan/entry[@name='8006']/action`. THE FOURTH SCAN TYPE, AND THE REASON PAN-ZON-004 IS
    #: WRITTEN OVER EVERY SCAN TYPE THE PROFILE CAN CARRY: the catalogue row names three scan
    #: entries and the device offers four, measured identically on three appliances, and an
    #: assertion written over the row's three leaves this entry unaudited.
    scan_ip_protocol_action = models.CharField(max_length=16, blank=True, default="")

    #: The least protective of the four actions, in `SCAN_WEAKEST_ORDER`. The empty string is
    #: the worst token and the migration default, so a profile nobody has recomputed grades at
    #: the assertion's severity rather than escaping the grading.
    scan_weakest_action = models.CharField(max_length=32, blank=True, default="")

    #: Whether at least one scan type fails to RECORD the event it detects. TRUE IS THE FIRING
    #: SIDE and is what the four inputs' own empty strings compute to.
    scan_detection_gap = models.BooleanField(default=True)

    #: `scan/entry/action/block-ip/track-by`. STORES NOTHING for an absent key, and the blank
    #: is what a text column lands: stage 4 did not reach this - reaching it needs a scan entry
    #: whose action is block-ip, which that run did not build - and help p.672 describes the
    #: choice and gives no default. A wrong guess here moves a finding between two of stage 3's
    #: severity bands, so storing nothing is better than storing either. The grading column
    #: beside it then cannot tell the vendor's two tracking modes apart and grades at the
    #: gentler of the two, which is why `scan_sensitivity_known` exists.
    scan_block_ip_track_by = models.CharField(max_length=32, blank=True, default="")

    #: `scan/entry/interval`, in seconds. NULL AND NOT BLANK, because `parse_integer_field`
    #: returns a genuine None for a `not_assumed` implicit - and NO OPERATOR REACHES A NULL:
    #: there is no is-null operator and `is_empty` compiles to a comparison against the empty
    #: string. So a threshold comparison on this column silently passes every profile whose key
    #: is absent, which is every unedited profile in the estate, and `scan_sensitivity_known`
    #: is what a control clauses on instead.
    #:
    #: NOT MEASURED, AND THE READING THAT LOOKED LIKE A MEASUREMENT WAS REFUTED: stage 4 found
    #: the dialog's inner grid rendering four fully-populated rows for entries that did not
    #: exist and proved them the form's new-row template - once the entries existed carrying no
    #: threshold, every Threshold cell rendered BLANK.
    scan_interval = models.PositiveIntegerField(null=True, blank=True)
    #: `scan/entry/threshold`. NULL for the same reason, and the two available leads DISAGREE
    #: WITH EACH OTHER: help p.672 gives 100 for every scan type with no exception printed, and
    #: the device's own form prefills 4 for IP Protocol Scan. Stage 4 recorded that as a
    #: disagreement and did not resolve it.
    scan_threshold = models.PositiveIntegerField(null=True, blank=True)

    #: Whether the interval and the threshold are present for every scan entry this profile
    #: carries. FALSE REPORTS rather than excludes: a profile nobody has recomputed reads as
    #: having unknown sensitivity, and PAN-ZON-004's undetermined group fires on it.
    scan_sensitivity_known = models.BooleanField(default=False)

    #: `scan-white-list`. A NORMALIZER MUST WALK BOTH LEAVES: the Help describes ONE address
    #: field with a type selector and the configuration holds TWO SEPARATE LEAVES, so a reader
    #: checking only one sees half the list - and half a list on an exemption surface is the
    #: direction that reports a blind spot as clean.
    #:
    #: An absent list means NOTHING is exempt, which is the safe direction. Stage 4 called this
    #: its weakest promotion on this object and said why: the positive control was NOT paid,
    #: because no exclusion entry was ever written, so the empty grid was never shown to move.
    #: It is promoted only because an empty entry-list has no other reading.
    scan_white_list = models.JSONField(default=list, blank=True)
    #: How many exclusion entries the profile carries, counting BOTH address leaves. The
    #: reachable form of the column above, which no query can read.
    scan_white_list_count = models.PositiveIntegerField(default=0)

    # ----------------------------------------------------------------- the attachment sweep
    #
    # PAN-ZON-008 from the profile end, and the applicability gate the five content controls
    # rest on. The arithmetic is in `attached_zone_count` and NOTHING CLAUSES ON IT: the two
    # verdicts below carry the firing decision, each with the default its own control needs.

    #: How many zones on this appliance name this profile in their attachment leaf,
    #: case-sensitively. Stored rather than joined at query time for the reason the shipped
    #: `InterfaceManagementProfile.bound_interface_count` is: there is no count operator and no
    #: aggregation in a predicate.
    attached_zone_count = models.PositiveIntegerField(default=0)

    #: Whether the reverse lookup had EVERY reference surface available to it. THE COUNT MUST
    #: SWEEP THREE SURFACES AND STAGE 4 CONFIRMED ONLY ONE: a zone protection profile is named
    #: by a vsys zone's attachment leaf (measured) and ALSO by a shared gateway's own zone
    #: (derived from the grammar, never exercised - no appliance in the lab has a shared
    #: gateway). A count that reads the vsys surface alone calls a shared-gateway-attached
    #: profile unreferenced, which for PAN-ZON-008 ends in a profile deleted out from under the
    #: zone using it.
    #:
    #: FALSE SUPPRESSES the unreferenced finding rather than letting it fire, which is
    #: deliberate and is the opposite of this file's usual direction: that control's remediation
    #: is a DELETION, and a false "nothing references this" removes configuration rather than
    #: wasting an hour. The suppressed rows are picked up by PAN-ZON-008's undetermined group,
    #: which fires on this column being false.
    attachment_sweep_complete = models.BooleanField(default=False)

    #: Whether at least one zone names this profile. TRUE IS THE DEFAULT AND IT INCLUDES THE
    #: ROW, chosen against the arithmetic of the column it is computed from: `attached_zone_count`
    #: defaults to zero, which would compute FALSE and silently drop every profile out of five
    #: content controls between the migration and the recompute.
    #:
    #: THIS AND `is_unreferenced` ARE NOT EACH OTHER'S NEGATION AND THAT IS DELIBERATE. They
    #: answer the same join and carry OPPOSITE defaults, because the two controls that read
    #: them fail in opposite directions: a content control that falls silent hides a real
    #: exposure, and a hygiene control that fires wrongly gets a profile deleted. One column
    #: with one default cannot be safe for both.
    is_in_force = models.BooleanField(default=True)

    #: Whether NO zone names this profile AND the sweep had every surface. True is the finding.
    #: FALSE does not fire - the only column in this model whose window is deliberately silent,
    #: and the reason is that the remediation is a deletion.
    #:
    #: THE JOIN IS CASE-SENSITIVE. Profile names are case-sensitive and not normalised (help
    #: p.663), so a case-insensitive join UNDER-COUNTS the unreferenced set - the safe direction
    #: for this control and the unsafe one for `is_in_force`, since a profile whose name differs
    #: only in case from an attachment is not in force and a case-folded join would say it was.
    is_unreferenced = models.BooleanField(default=False)

    class Meta:
        ordering = ["appliance__hostname", "profile_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "profile_name"],
                name="integrations_unique_zone_protection_profile_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance", "profile_name"]),
            models.Index(fields=["appliance", "is_in_force"]),
            models.Index(fields=["appliance", "is_unreferenced"]),
            models.Index(fields=["management_station"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.profile_name}"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError(
                "A zone protection profile must belong to the same management station as its "
                "appliance.")
        # THE TWO VERDICTS MAY BOTH BE FALSE and may never both be TRUE: false/false is the
        # real state of a profile nothing references on a sweep that was incomplete, which is
        # the undetermined group. True/true would say a profile is both in force and
        # referenced by nothing.
        if self.is_in_force and self.is_unreferenced:
            raise ValidationError(
                "is_in_force and is_unreferenced cannot both be true: the first says a zone "
                "names this profile and the second says nothing does.")
        if self.scan_white_list_count != len(self.scan_white_list or []):
            raise ValidationError(
                "scan_white_list_count must match scan_white_list.")


class DosPolicyRule(ProvenancedMixin, SyncTrackedModel):
    """One DoS Protection policy rule within one rulebase of one vsys of one appliance.

    PAN-ZON-007's second half is about a rule that READS AS PROTECTION AND CONSULTS NOTHING:
    only `protect` consults the profile the rule names, and a rule set to `deny` or `allow`
    carrying a profile in either slot never evaluates it.

    SEVEN OF THIS OBJECT'S SIXTEEN CHILDREN ARE MANDATORY AT COMMIT VALIDATION - `from`, `to`,
    `source`, `destination`, `service`, `action` and `protection`, enumerated by stage 4's
    commit-iteration one refusal at a time. It is the most mandatory node in this domain. So on
    a running device `action` and `protection` are always present - but the read this model
    normalizes is CANDIDATE-DERIVED, so a staged rule can reach it without them.

    `pan_os_default` IS THEREFORE NOT A REACHABLE PROVENANCE TYPE for the mandatory keys this
    model stores: there is no absent-key case to type as a vendor default.

    FIVE MATCH CRITERIA ARE DELIBERATELY NOT STORED. PAN-ZON-007's first half - which services
    deserve a connection ceiling - is discharged onto the customer's asset inventory, so a
    column holding the rule's destination addresses answers nothing a finding can say. One
    asymmetry in those five is worth recording even though neither end is stored: writing `any`
    as the from-zone gave TWO refusal lines and the identical value on `to` gave THREE, because
    the `to` leaf is checked against a keyword list AND against the reference pool while `from`
    is checked against the pool only - so a DoS rule cannot be written zone-agnostically at
    either end.

    WORTH CARRYING FOR ANYONE WHO GOES LOOKING: the UI routes `policies/dos` and
    `policies/dos-protection` both land SILENTLY on the Security rulebase - same chrome,
    different object - and the real route is `policies/dos-rulebase`.
    """

    #: Computed here: the array position, and whether either profile slot holds a name.
    #: See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = ("is_missing", "rule_position", "names_a_profile")

    #: THREE CHILD NODES, NOT THREE VALUES - measured by stage 4 with `action=complete` on
    #: fw201, with the stored shape `action: {'protect': None}`. A later stage reading the
    #: parent's path expecting a string gets an ELEMENT instead.
    ACTION_DENY = "deny"
    ACTION_ALLOW = "allow"
    ACTION_PROTECT = "protect"
    ACTION_BRANCHES = (ACTION_DENY, ACTION_ALLOW, ACTION_PROTECT)
    #: The ONE action that consults the profile the rule names. PAN-ZON-007's second half.
    ACTIONS_CONSULTING_A_PROFILE = (ACTION_PROTECT,)

    #: Which rulebase a row came from, in `CONFIG_SOURCE_CHOICES`' own token set - which is
    #: `SecurityRule.config_source`'s and `DecryptionRule.config_source`'s. Stage 5 named this
    #: column `rulebase` and declared its value set as exactly these three tokens; the shipped
    #: name is used instead, because two rule models already carry this vocabulary under it and
    #: `RuleFinding.subject_scope` is built from it, so a third spelling would be a third name
    #: for one concept. `default` is inherited from the shared vocabulary and is NOT reachable
    #: here: PAN-OS ships no default DoS rule.
    SOURCE_LOCAL = "local"
    SOURCE_PUSHED_PRE = "pushed_pre"
    SOURCE_PUSHED_POST = "pushed_post"

    CONFIG_SOURCE_CHOICES = CONFIG_SOURCE_CHOICES

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="dos_policy_rules")
    #: THE OWNER, and what carries both appliance and vsys: an EnforcementPoint IS one vsys of
    #: one appliance. `SecurityRule` and `DecryptionRule` anchor their rulebases the same way.
    enforcement_point = models.ForeignKey(
        "integrations.EnforcementPoint", on_delete=models.CASCADE,
        related_name="dos_policy_rules")
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="dos_policy_rules")

    config_source = models.CharField(max_length=32, choices=CONFIG_SOURCE_CHOICES)

    #: 1-based rank in the `rules` array as the config read returned it. STAGE 5 DECLARED NO
    #: SUCH COLUMN and its `one_row_per` says the evaluation position "is part of what a row IS
    #: even though the name is what a finding prints" - so the identity it describes is not
    #: representable from the columns it declares. Stored as plumbing, declared derived, and
    #: recorded as a spec gap rather than left out: no configuration key holds the order, so a
    #: normalizer that does not preserve array order loses the only statement the device makes
    #: about evaluation sequence, and it cannot be recovered later.
    #:
    #: It is NOT part of the identity constraint, for the reason `DecryptionRule` gives: a rule
    #: keeps its name across an `action=move`, so keying on position makes a reorder look like
    #: a delete and an insert.
    rule_position = models.PositiveIntegerField()

    #: `@name`. 255 rather than 64 because no length was measured for this key and
    #: `SecurityRule.name` is 255. `ObjectFindingBase.subject_name` is 64, so a longer name is
    #: truncated in the FINDING even where this column holds it whole.
    rule_name = models.CharField(max_length=255)

    #: `action`, as the name of the child element that exists. BLANK means no branch is present,
    #: which on a COMMITTED rule cannot happen - the key is mandatory at commit validation, so
    #: a blank here is a candidate-only rule and not a default anybody applied.
    #:
    #: THE SECOND GRID-VERSUS-DIALOG DISAGREEMENT THAT DISSOLVED, carried because a normalizer
    #: author reading a screen would take the wrong answer: on a bare rule the DoS rulebase
    #: grid's Action cell rendered `none` and the dialog's Action combo rendered `Deny`, at the
    #: same moment on the same rule. Since the key cannot be absent on a committed rule,
    #: NEITHER surface was describing a real state.
    rule_action = models.CharField(max_length=16, blank=True, default="")

    #: `protection/aggregate/profile`. The empty string means NO AGGREGATE THRESHOLDS ARE IN
    #: FORCE - help p.205, "An Aggregate profile setting of None means there are no threshold
    #: settings in place for the aggregate traffic", measured by stage 4 on the bare committed
    #: rule and on the grid.
    #:
    #: ELIGIBILITY IS GATED ON THE REFERENT'S OWN `type` AT THE WRITE AND NOT AT THE READ,
    #: measured in both directions: `action=complete` here returned ZERO candidates while a
    #: DoS profile existed in the same vsys carrying no `type`, and writing that profile's name
    #: was refused `not a valid reference`; setting `type=aggregate` on the profile and
    #: repeating the identical write got it ACCEPTED. So a rule whose referent's type was
    #: changed afterwards names a profile it cannot use, and nothing in the configuration says
    #: so.
    aggregate_profile = models.CharField(max_length=64, blank=True, default="")

    #: `protection/classified/profile`. THE SLOT THE CATALOGUE ROW FOR THIS CONTROL DOES NOT
    #: ASSERT, and the two slots are sibling nodes with no exclusivity the grammar expresses -
    #: a rule may carry one of each, measured - so a walk written from the row's asserted path
    #: misses this one entirely.
    #:
    #: BLANK AND NOT MATERIALISED: stage 4 did not write the classified arm at all, and the one
    #: surface that renders an answer is a dialog measured to prefill. Stage 5 declared `stores:
    #: null` with `rests_on: not_assumed`; a text column with a `not_assumed` implicit lands the
    #: empty string rather than a null, and the provenance row beside it is what says the key
    #: was absent and nothing was assumed.
    classified_profile = models.CharField(max_length=64, blank=True, default="")

    #: `protection/classified/classification-criteria/address`. NOT MEASURED, and the one
    #: reading available was refused as evidence: the dialog renders `source-ip-only` as a VALUE
    #: on a keyless rule, on a form already measured to prefill.
    #:
    #: THE VENDOR IS DIRECTIONAL ABOUT THIS FIELD AND THE PREFILL IS THE ONE IT WARNS ABOUT. A
    #: classified rule must count on the destination address only where the zone faces the
    #: internet, "because the firewall can't store counters for all possible internet IP
    #: addresses. Use destination-ip-only in perimeter zones" (help p.206, repeated at guide
    #: p.1251) - and help p.206 says "Don't use source-ip-only or src-dest-ip-both for
    #: internet-facing zones", which is exactly what the form prefills. No control asserts it,
    #: because deciding it needs a zone-exposure fact no configuration holds.
    classification_address = models.CharField(max_length=32, blank=True, default="")

    #: Whether EITHER profile slot holds a name - the applicability gate for the assertion that
    #: a rule naming a profile must be set to enforce it. TRUE IS THE DEFAULT AND IT INCLUDES
    #: THE ROW: an applicability gate that excludes on an unknown silences exactly the rows
    #: nobody measured.
    names_a_profile = models.BooleanField(default=True)

    #: `disabled`. A STRING AND NOT A BOOLEAN, which is a departure from `SecurityRule` and
    #: `DecryptionRule` and is stage 5's decision rather than this model's taste: what an
    #: absent `disabled` means on a DoS rule IS NOT MEASURED - stage 4's writes went on the
    #: mandatory children and the profile slots, and no control was paid on this key - so a
    #: boolean defaulting to false would materialise a guess. The honest declaration is
    #: `not_assumed`, a nullable boolean is unreachable by every operator the compiler has, and
    #: a text column lands the empty string, which is reachable and says nothing.
    #:
    #: NOTHING CLAUSES ON IT, and the argument is the direction of a wrong guess: if an absent
    #: key were read as "disabled" the control would suppress every rule in the estate,
    #: silently. Leaving it unclaused and firing on the action regardless means the control may
    #: name a rule that is switched off, which is a false finding checkable in seconds.
    rule_disabled = models.CharField(max_length=8, blank=True, default="")

    class Meta:
        ordering = ["enforcement_point", "config_source", "rule_position", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "config_source", "rule_name"],
                name="integrations_unique_dos_policy_rule_per_rulebase"),
        ]
        indexes = [
            models.Index(fields=["enforcement_point", "config_source", "rule_position"]),
            models.Index(fields=["enforcement_point", "rule_action"]),
            models.Index(fields=["enforcement_point", "names_a_profile"]),
            models.Index(fields=["management_station"]),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} / {self.config_source} / {self.rule_name}"

    def clean(self) -> None:
        if self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError(
                "A DoS policy rule must belong to the same management station as its "
                "enforcement point.")
