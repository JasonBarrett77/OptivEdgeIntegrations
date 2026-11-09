"""IPSec crypto profiles, IPSec tunnels and monitor profiles, as they exist on one appliance.

All three objects are DEVICE-WIDE. Stage 4 of the `ipsec-crypto` pipeline domain measured exactly
one firewall-local scope for each - neither shared nor under a vsys, and one collection for the
whole appliance even on the multi-vsys PA-5220:

    /config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='...']
    /config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry[@name='...']
    /config/devices/entry[@name='localhost.localdomain']/network/profiles/monitor-profile/entry[@name='...']

WHY THESE CARRY NO `scope` AND NO `vsys_name` COLUMN, where `IkeCryptoProfile` at the SIBLING
path carries both. Stage 5 declared the identity of all three subjects as `unique(appliance,
<name>)` and named the shipped precedent it copied - `integrations.Interface` and
`integrations_unique_interface_per_appliance`, which is also a `network/` collection with no vsys
axis. The identity columns are the authoritative half of that artifact (they are about the
device), so the constraint is the two columns stage 5 declared. `IkeScopedObject` reaches the same
conclusion about the DEVICE and then carries `scope`/`vsys_name` anyway so that its constraint
matches `ApplianceScopedObject`'s four columns; this domain was told two, and inheriting that base
would have put two extra columns into the uniqueness key stage 5 specified. That is the whole of
the difference and it is recorded here so the next reader does not take the divergence for an
oversight.

WHAT AN ENTRY-ONLY SCOPE COSTS, recorded because it is a real limit rather than a safe
simplification: an entry that exists ONLY in a pushed Panorama template is stored as though the
appliance defined it. Nothing is lost on this estate today and that is measured rather than
assumed - five Panorama templates hold ZERO entries at all three paths, `show config
pushed-template` holds each collection's name zero times on all four appliances, and this stage's
own readback found no @ptpl and no @src on any entry of any of the three collections on any of the
four appliances, 2026-10-29. A value SUPPLIED by a template does survive, as the `template`
provenance type on that field; an ENTRY that exists only there has nowhere to go.

THE FACTORY-NAMED ENTRIES ARE NOT PREDEFINED OBJECTS. `default`, `Suite-B-GCM-128` and
`Suite-B-GCM-256` at the IPSec crypto profile path, and `default` at the monitor profile path, are
ORDINARY WRITABLE, DELETABLE local entries - stage 4 measured `/config/predefined/ipsec-crypto-profiles`
answering None (code=7) on all four appliances while `/config/predefined` itself answers 24 MB. So
a normalizer must NOT give them the PREDEFINED entry-provenance sentinel, which asserts "shipped
in the release and not editable here". That they are deletable is what makes PAN-IPS-009's
removal remedy possible at all, and it is why PAN-IPS-009's own expression tests algorithm CONTENT
rather than the entry's name.

ON AN HA PAIR each of these subjects yields TWO ROWS FOR ONE REAL CONFIGURATION and nothing
downstream deduplicates them. On the lab's PA-5220 pair the collections are absent or empty on
both members, so the duplication is not exercised here; where it is, a difference between the two
rows is not by itself a configuration finding.

WHAT NO ROW CAN SAY, recorded because it is the one wrong-direction limit stage 5 named for this
domain: an appliance holding NO IPSec crypto profile and NO IPSec tunnel produces NO ROWS, and
every one of PAN-IPS-001 to -008 is written over "every profile the firewall holds" or "every
tunnel it terminates" - so on such an appliance the predicate is VACUOUSLY TRUE. Both PA-5220s are
in exactly that state. Closing it needs a per-APPLIANCE row carrying a profile count, a tunnel
count and whether each collection was reached, which is a fourth model at a different grain and
not a column here; stage 5 recorded it in `not_stored` rather than specifying it, and the
catalog already has the shape in PAN-COV-001 and PAN-COV-002.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class IpsecNetworkObject(ProvenancedMixin, SyncTrackedModel):
    """The owning anchors all three objects of this domain share.

    Abstract, so three models that are keyed the same way cannot drift apart on the plumbing.
    The NAME column is deliberately NOT here: stage 5 named it per subject - `profile_name` on
    two of them and `tunnel_name` on the third - and those are the names every clause, every
    artifact column and every readback comparison uses.
    """

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="%(class)ss")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="%(class)ss")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="%(class)ss", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="%(class)ss")

    class Meta:
        abstract = True

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError("Object appliance must belong to the same station.")


class IpsecCryptoProfile(IpsecNetworkObject):
    """One named IPSec crypto profile on one appliance. PAN-IPS-001 to 005 and 009.

    THE PHASE-2 PROPOSAL, AND THE ALGORITHM LISTS ARE OFFER SETS AND NOT CHOICES: the profile
    offers every member and a peer may insist on any of them, so what a control grades is the
    WEAKEST member still on offer. That is why each list has a `weakest_*` column beside it and a
    verdict over the whole set, rather than a single value column. Stage 4 also measured that
    `action=set` with one `<member>` ADDS to the stored list rather than replacing it, so a
    remediation cannot shrink an offer set by overwriting it.

    The three lists are JSON and are deliberately NOT reachable from a query - the consumer's
    convention is that values are reachable and lists are not, and stage 5 marks all three
    `not_searchable`. They are here because a reader of the finding has to see the actual
    proposal, and because the per-field provenance rows hang on them. The shipped precedent is
    `ManagementSshSettings`, whose `ciphers`/`kex`/`macs` lists carry the provenance while the
    derived verdicts beside them are what the controls query.

    ONLY ONE KEY ON THIS OBJECT IS UNCONDITIONALLY MANDATORY - the lifetime - which stage 4
    measured at commit validation (`... -> oep-ips-s4-bare is missing 'lifetime'`). So a profile
    carrying no protocol branch, no cipher, no integrity algorithm and no key-agreement group is a
    COMMITTABLE state, stage 4 committed two of them and stage 6 left one standing
    (`oep-ips6-p09`). That state is `protocol_branch = none`, and it is the state stage 3's
    grading had no rank for.

    THE PROTOCOL BRANCHES ARE EXCLUSIVE AND THE EXCLUSION IS ENFORCED BY SILENT REPLACEMENT.
    Stage 4 wrote `ah` onto a profile already carrying `esp`: the write was ACCEPTED and `esp`
    vanished, then `esp` was written back and `ah` vanished - measured in both directions with a
    read-back after each write. So "both branches present", which stage 3 ranks high, is a
    configuration no device can hold, and `protocol_branch` can safely be one of three tokens.
    """

    #: Computed here: the branch classification, the two weakest-member readings, the three
    #: floor verdicts, the lifetime coalesced across four unit branches and its verdict, and the
    #: cross-object referrer count. The three member lists and `dh_group` are NOT here - they are
    #: payload keys and carry provenance rows. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "protocol_branch",
        "weakest_encryption_offered",
        "weakest_integrity_offered",
        "all_offered_ciphers_authenticate",
        "integrity_meets_sha2_floor",
        "dh_group_meets_target",
        "lifetime_hours",
        "lifetime_unit",
        "lifetime_within_target",
        "referencing_tunnel_count",
    )

    class ProtocolBranch(models.TextChoices):
        NONE = "none", "Neither branch"
        ESP = "esp", "ESP"
        AH = "ah", "AH"

    class LifetimeUnit(models.TextChoices):
        SECONDS = "seconds", "Seconds"
        MINUTES = "minutes", "Minutes"
        HOURS = "hours", "Hours"
        DAYS = "days", "Days"

    #: The profile's own name on the device: what a finding prints as its subject and what a
    #: tunnel's reference resolves against. 64 characters is the CONSUMER's limit and not the
    #: device's - it matches the finding model's own `subject_name = CharField(max_length=64)`.
    #: The vendor documents 31 for a profile (help p.656) and stage 4 measured neither.
    profile_name = models.CharField(max_length=64)

    #: WHICH protocol branch the profile carries. `none` is a committed state and not a
    #: collection gap - see the class docstring.
    #:
    #: THERE IS NO `protocol` KEY AT THIS PATH AT ALL: stage 4's `action=complete` lists five
    #: children on 11.1 and six on 11.2 and none of them is a protocol. The grid column is
    #: rendered FROM WHICH BRANCH EXISTS, so this is a presence test over two sibling containers.
    #:
    #: THE TWO SURFACES DISAGREE FOR THE KEYLESS CASE and stage 4 believed the GRID: the edit
    #: dialog renders `IPSec Protocol: ESP` for a profile with no branch, because a dialog renders
    #: what OK would write, while the grid renders blank. A consumer that materialised the
    #: dialog's reading would report a profile with no cipher and no integrity algorithm as an ESP
    #: profile. Blank here - the pre-renormalisation value - is the FIRING side of both clauses
    #: written on this column.
    protocol_branch = models.CharField(
        max_length=8, choices=ProtocolBranch.choices, blank=True, default="")

    #: The cipher proposals offered on the ESP branch, in the device's own order and spelling.
    #: NULL - not `[]` - where the key is absent, which stage 4 measured to mean NOTHING IS
    #: OFFERED with no implicit algorithm behind it. The distinction is deliberate: stage 5
    #: declares the materialised value as null and `empty_is_distinct: false`, and storing `[]`
    #: for an absence is the defect migration 0110 corrected on another model.
    esp_encryption = models.JSONField(null=True, blank=True)
    #: The integrity algorithms offered on the ESP branch. THE LITERAL `none` IS A MEMBER HERE
    #: AND NOT AN ABSENCE - both shipped Suite-B profiles store it - so it is a value whose
    #: meaning depends on the ciphers beside it, which is what `all_offered_ciphers_authenticate`
    #: is for. `none` is accepted here and REFUSED on the AH branch, measured in both directions.
    esp_authentication = models.JSONField(null=True, blank=True)
    #: The integrity algorithms offered on the integrity-only AH branch. A SEPARATE COLUMN AND
    #: NOT FOLDED INTO THE ONE ABOVE, because stage 4 measured that ONE grid column serves both
    #: branches - so a reading taken off the screen cannot say which branch's list it came from.
    ah_authentication = models.JSONField(null=True, blank=True)

    #: The weakest cipher still offered on the ESP branch, by PAN-IPS-002's severity order.
    #: BLANK AND NOT NULL, because stage 5 declares the un-renormalised and no-branch states as
    #: the empty string and the clause on this column is a NEGATED equality against
    #: `aes-256-gcm`: on a text column `NOT(col = 'aes-256-gcm')` over `''` is TRUE and the row is
    #: REPORTED, where a NULL would make SQL answer NULL and silently drop it.
    weakest_encryption_offered = models.CharField(max_length=16, blank=True, default="")
    #: The weakest integrity algorithm still offered, read from whichever branch exists.
    #: `none` here always means integrity DECLINED beside a cipher that only encrypts, because
    #: the AEAD case is excluded by PAN-IPS-003's applicability clause rather than scored.
    #: THIS COLUMN CARRIES THE SEVERITY AND NOT THE FINDING: the assertion is on
    #: `integrity_meets_sha2_floor` beside it, so a row nobody recomputed reports at the baseline
    #: severity rather than silently - which is why stage 5 could declare its unknown state
    #: `passes` and have that be safe.
    weakest_integrity_offered = models.CharField(max_length=16, blank=True, default="")

    #: Whether EVERY cipher offered authenticates as it encrypts - the AEAD case, in which the
    #: vendor states the separate hash is IGNORED (gp p.877: "the SHA1 authentication algorithm
    #: is ignored for these ciphers even though it is required during configuration"). False
    #: where any offered cipher only encrypts, and false where no cipher is offered at all.
    #:
    #: PAN-IPS-003 CLAUSES ON THIS AS APPLICABILITY, so the direction of the default is the whole
    #: point: false keeps the control APPLICABLE. An applicability clause whose unread value read
    #: `true` would exclude every row from the control and the report would say nothing at all.
    all_offered_ciphers_authenticate = models.BooleanField(default=False)
    #: PAN-IPS-003's assertion: every offered integrity algorithm is in the SHA-2 family, with no
    #: md5, no sha1 and no `none`. False is the finding side and is also the migration default,
    #: so a profile nobody has recomputed is reported rather than passing.
    integrity_meets_sha2_floor = models.BooleanField(default=False)

    #: The key-agreement group for the payload phase, as ONE BARE STRING and not a member list.
    #:
    #: THE STORED SHAPE IS THE TRAP AND IT IS SILENT. The IKE crypto profile's `dh-group` at the
    #: SIBLING path `network/ike/crypto-profiles/ike-crypto-profiles` stores `{"member": [...]}`;
    #: this one stores a bare string, measured both ways on pan-fw-201, and writing the member
    #: shape here is REFUSED. A reader who reuses the phase-1 shape at this path reads nothing and
    #: reads it silently.
    #:
    #: `no-pfs` is a real writable value meaning the key already agreed is reused, and it is a
    #: DIFFERENT fact from the key being absent. The absent key materialises `group2` - see the
    #: normalizer's DH_GROUP_ABSENT, which carries the measurement - so a profile with no
    #: dh-group is not a profile with no forward secrecy, it is one re-keying on a 1024-bit group.
    #: Ten values are offered on 11.1 and twenty-nine on 11.2, measured, and the build difference
    #: is why no choices tuple constrains this column: `kyber-768` and the literal `none` were
    #: accepted on a PA-VM at 11.2 and refused on a PA-5220 at 11.1, so a choices list would
    #: either refuse a value one build stores or admit one another build refuses.
    dh_group = models.CharField(max_length=32)
    #: PAN-IPS-004's assertion: the group is one of the three elliptic-curve groups the control
    #: targets - group19, group20, group21. False is the finding side, and it is false for every
    #: post-quantum member and for `none` as well as for the weak classical groups, which is how
    #: the nineteen values stage 3 leaves UNRANKED reach the report at all.
    dh_group_meets_target = models.BooleanField(default=False)

    #: The written key lifetime CONVERTED TO HOURS, from whichever one of the four unit branches
    #: the profile used, rounded UP so a sub-hour lifetime stores 1 and never 0. The number alone
    #: is meaningless - the same figure is this control's best state in one unit and its worst in
    #: another - which is why `lifetime_unit` is stored beside it.
    #:
    #: NULL IS REACHABLE BY EXACTLY ONE ROUTE and it is a normalizer defect rather than a device
    #: state: a FIFTH unit branch a later release adds. Stage 4 measured four on both builds, and
    #: the mandatory `lifetime` key means a committed profile always carries one of them.
    #: `lifetime_unit` holding a token nothing maps is how that would show.
    lifetime_hours = models.PositiveIntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(8760000)])
    #: WHICH unit branch the lifetime was written in. The unit is WHICH CHILD ELEMENT EXISTS and
    #: is not a value anywhere on the device.
    #:
    #: THE CHOICE CONTAINER IS NOT ENFORCED AT THE WRITE, measured: an element naming several
    #: units is ACCEPTED and only the LAST one lands - `<hours>1</hours><minutes>30</minutes>`
    #: stored `{minutes: 30}`. So a configuration tool that sends two units gets no error and a
    #: value it did not choose, and a normalizer must read all four children.
    lifetime_unit = models.CharField(
        max_length=8, choices=LifetimeUnit.choices, blank=True, default="")
    #: PAN-IPS-005's assertion: the lifetime is one hour or less, which is the figure the vendor
    #: names as its own default. False is the finding side and the migration default.
    lifetime_within_target = models.BooleanField(default=False)

    #: HOW MANY tunnel configurations on this appliance name this profile, counted across BOTH
    #: referring leaves stage 4 confirmed by enumeration:
    #:
    #:     network/tunnel/ipsec/entry/auto-key/ipsec-crypto-profile
    #:     network/tunnel/global-protect-site-to-site/entry/client/ipsec-crypto-profile
    #:
    #: The second is the LSVPN satellite reference and it is not optional: stage 4 measured
    #: `action=complete` at that path returning exactly this collection's entries - two of which
    #: exist in no other collection on that appliance - so a count over the auto-key leaf alone
    #: would report an LSVPN-only profile as unused. A third candidate,
    #: `network/tunnel/global-protect-gateway/entry/ipsec/ipsec-crypto-profile`, draws from a
    #: DIFFERENT collection (the GlobalProtect app crypto profiles) and is deliberately not
    #: counted; the same read pointing both ways is what makes either result mean anything.
    #:
    #: ZERO IS THE FINDING SIDE AND THAT IS LUCK RATHER THAN DESIGN - an integer column's own
    #: default of zero happens to be the alarming value for a reference count, and would be the
    #: reassuring one for a count of weak algorithms.
    #:
    #: A FIREWALL-SIDE COUNT CANNOT SAY AN OBJECT IS UNUSED and this column does not claim to: a
    #: profile nothing on the device names may still be named by configuration held at the
    #: management station, and the two states look identical from here. That qualification lives
    #: in PAN-IPS-009's finding text because no column holds it. Stage 4 also measured that
    #: referential integrity is enforced AT THE WRITE while DELETING a referenced profile is
    #: accepted with no complaint, so a dangling reference is reachable by that route alone.
    referencing_tunnel_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["appliance__hostname", "profile_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "profile_name"],
                name="integrations_unique_ipsec_crypto_profile_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance", "profile_name"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["appliance", "integrity_meets_sha2_floor"]),
            models.Index(fields=["appliance", "dh_group_meets_target"]),
            models.Index(fields=["appliance", "lifetime_within_target"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.profile_name}"


class IpsecTunnel(IpsecNetworkObject):
    """One named IPSec tunnel configuration on one appliance. PAN-IPS-006 to 009.

    NOTHING OF THIS OBJECT EXISTED ANYWHERE ON THIS ESTATE before stage 6 built it - zero entries
    on all four appliances in all three views and zero negotiated SAs - so every reading behind
    these columns comes from a subject a pipeline stage constructed. Only `tunnel-interface` is
    mandatory, and a tunnel is committable with nothing else only when it is switched OFF,
    because the virtual-router validation its enabled self fails is SKIPPED while it is off. That
    is a finding with a security edge in its own right: a switched-off tunnel can be committed in
    a state that would refuse to commit the moment somebody switches it on.

    THE RUNTIME IS OUTSIDE EVERY COLUMN HERE. `show vpn flow` num_ipsec and `show vpn ipsec-sa`
    ntun are COUNTS - which is what lets them tell zero from unknown - and no configuration read
    carries either, so whether a tunnel is negotiating is not a question any row of this model
    answers. PAN-IPS-002 asks "and above all one a live tunnel uses" and nothing here can rank by
    that; stage 5 recorded it in `not_stored`.

    NO COLUMN REACHES THE `manual-key` BRANCH, and the gap is in the catalog rather than in
    this model: a hand-keyed tunnel has its own protocol choice and its own algorithm list -
    including the 56-bit `des`, which stage 4 measured as OFFERED at
    `manual-key/esp/encryption/algorithm` and REFUSED at the crypto profile's `esp/encryption` on
    both builds - and no control in this domain asserts over it. So such a tunnel is stored with
    its name, its switch and its monitoring and with NOTHING about the cryptography it uses, while
    every algorithm control here stays silent about it and reports its auto-key siblings. Stage 3
    records it as its first uncovered subject.
    """

    #: Computed here: the two did-we-read-it companions, the monitor action resolved across a name
    #: reference, and the two crypto-profile binding verdicts. The payload keys beside them carry
    #: provenance rows. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "anti_replay_determined",
        "tunnel_monitor_enable_determined",
        "monitor_action_effective",
        "crypto_profile_found",
        "effective_crypto_profile_chosen",
    )

    class MonitorAction(models.TextChoices):
        WAIT_RECOVER = "wait-recover", "Wait for recovery"
        FAIL_OVER = "fail-over", "Fail over"

    #: The tunnel's own name on the device. 64 characters is the consumer's limit - the vendor
    #: documents 63 INCLUDING the proxy ID (help p.613), so this has one character of margin and
    #: the device figure was not measured.
    tunnel_name = models.CharField(max_length=64)

    #: The device's own `disabled` key and the device's own POLARITY: `true` means the tunnel is
    #: switched OFF. The column is named for the KEY and not for the question, so the direction
    #: has to be faced in the clause - a column named `enabled` here would invert every row in
    #: silence.
    #:
    #: NON-NULLABLE, because the absent state IS measured: stage 4 paid the positive control in
    #: both directions through the commit-validation gate rather than through a screen - key
    #: absent, the enabled-tunnel virtual-router check FAILED; `disabled: yes`, it vanished and
    #: the commit returned OK; `disabled: no`, it failed again. So absent behaves identically to
    #: `no` and the materialised `false` is a vendor fact.
    #:
    #: THAT DEFAULT REASSURES, WHICH IS CORRECT ONLY BECAUSE OF WHICH CONTROL READS IT.
    #: PAN-IPS-008 fires on a tunnel left switched OFF, so `false` is this control's compliant
    #: side; it would NOT be safe for a control asserting that a tunnel is enabled, and no
    #: control in this domain does.
    is_disabled = models.BooleanField(default=False)

    #: The `anti-replay` key as the device spells it: `true` where replay protection is on,
    #: `false` where it is explicitly off, and NULL where the key is absent.
    #:
    #: NULL IS THE HONEST ANSWER AND NOT A CONVENIENCE. Stage 4 recorded this implicit as
    #: UNMEASURED with three leads and promoted none: the vendor's wording is a selection
    #: instruction stating no default (help p.614), the same two node names on the MACsec profile
    #: ARE documented disabled (guide p.544) and are a different object, and `action=complete`
    #: gives nothing. Materialising `false` would report a finding on behalf of a measurement
    #: nobody took; materialising `true` would report a clean estate for the same reason.
    #:
    #: A NULL BOOLEAN MATCHES NO POSITIVE COMPARISON, so `anti_replay equals false` does not match
    #: a tunnel whose key is simply absent and the row would pass PAN-IPS-006 in silence. The
    #: firing is moved to `anti_replay_determined`, which the control clauses on as a second query
    #: at the same severity.
    anti_replay = models.BooleanField(null=True, blank=True)
    #: Whether `anti-replay` was actually READ for this tunnel. The answer to "is this unknown",
    #: which the consumer's clause grammar has NO OPERATOR FOR - there is no is-null operator, and
    #: by the time a query runs every absent key has been collapsed into a column value, so the
    #: only way to ask is to have answered it at normalization time. False FIRES.
    anti_replay_determined = models.BooleanField(default=False)

    #: The `tunnel-monitor/enable` key as the device spells it, NULL where the branch or the key
    #: is absent. Same unmeasured implicit and same companion arrangement as `anti_replay`, and
    #: the stake here is larger: an absent monitor branch is the COMMONEST shape of the failure
    #: PAN-IPS-007 is about, so a `false` matching nothing would pass exactly the unmonitored
    #: tunnels the control exists to find.
    tunnel_monitor_enable = models.BooleanField(null=True, blank=True)
    #: Whether `tunnel-monitor/enable` was actually READ. A tunnel with no monitor branch at all
    #: and a tunnel whose branch exists with the key absent are BOTH false here, deliberately:
    #: stage 4 measured no implicit for either.
    tunnel_monitor_enable_determined = models.BooleanField(default=False)

    #: The address the monitor probes. NULL means NO PROBE TARGET, measured through the commit
    #: gate: with `enable=yes` and a target the candidate validated, and with the target deleted
    #: and `enable=yes` left behind, commit job 505 refused naming this exact key.
    #:
    #: NULLABLE RATHER THAN BLANK, because stage 5 declares the materialised value as null and
    #: `is_empty` compiles to a filter on the empty string which does NOT match NULL - so a
    #: clause written against the declaration and one written against a blank column find
    #: different rows. Migration 0110 on another model is the correction that established this.
    #:
    #: STAGE 4 CONTRADICTS STAGE 3 HERE: stage 3 asserts monitoring "with a target for the probe
    #: to reach", and monitoring-enabled-with-nothing-to-probe turns out to be a CANDIDATE-ONLY
    #: state - accepted at the write, refused at commit validation. The merged view is
    #: candidate-derived, so this column can still hold that state for an uncommitted edit, which
    #: is the one case where a clause on it would mean something. No control writes one.
    tunnel_monitor_destination_ip = models.CharField(max_length=64, null=True, blank=True)
    #: The monitor profile this tunnel's monitoring names, where it names one. NULL where none is
    #: named - which stage 4 records as the case PAN-IPS-007's second record cannot answer, since
    #: a null name matches no comparison and would silently skip exactly the tunnels that name
    #: nothing. The day a clause IS written here it owes a companion that fires, exactly as
    #: `anti_replay` does.
    #:
    #: An unresolvable name means the profile was DELETED after the tunnel was pointed at it:
    #: stage 4 measured that a name which does not exist is refused AT THE WRITE while deleting a
    #: profile a live tunnel-monitor names is ACCEPTED with no complaint.
    tunnel_monitor_profile_name = models.CharField(max_length=64, null=True, blank=True)
    #: What this tunnel's monitoring WOULD DO when probing fails - the `action` of the monitor
    #: profile it names, resolved on the same appliance and INCLUDING that profile's own
    #: materialised default where it stores no action. Blank in three different states: the tunnel
    #: names no profile, the name resolves to nothing, or the row has not been recomputed.
    #:
    #: Stage 4 measured all three and said what the shape has to be: "The binding, the resolved
    #: entry and whether the name exists all have to be columns on one row before a comparison
    #: means anything." Nothing clauses on this column today - PAN-IPS-007's second record is
    #: discharged to an engineer's question - and the day one does, the three blank states have to
    #: be told apart by a companion that fires. `tunnel_monitor_profile_name` and
    #: `tunnel_monitor_enable_determined` are already stored for that purpose.
    monitor_action_effective = models.CharField(
        max_length=16, choices=MonitorAction.choices, blank=True, default="")

    #: The key-exchange gateways this tunnel's auto-key branch names. AN ENTRY LIST AND NOT A
    #: SINGLE VALUE, so a tunnel can name more than one and PAN-IPS-008's reconciliation is a set
    #: problem rather than a lookup.
    #:
    #: STORED FOR ONE REASON, stated so a reviewer can judge it: PAN-IPS-008's first record
    #: asserts that a retired tunnel's gateway is retired with it, and the GATEWAY OBJECT was not
    #: measured by this domain's stage 4 - so the reconciliation cannot be restated at all today.
    #: Holding the tunnel side of the join means that the day the gateway collection is measured
    #: the other half is already here. Until then the assertion's gateway clause does not exist
    #: and stage 5's `not_measured` says so rather than this column pretending to cover it.
    #: `not_searchable`: a finding must not rest on a JSON field.
    ike_gateway_names = models.JSONField(null=True, blank=True)

    #: The IPSec crypto profile this tunnel's auto-key branch names - A POINTER AND NOT A VALUE.
    #:
    #: WHERE THE KEY IS ABSENT THIS HOLDS THE LITERAL `default`, AND THAT IS AN INFERENCE RATHER
    #: THAN A MEASUREMENT. Stage 4 set `may_materialise: false` on three leads and not one
    #: measurement - the dialog renders `default` on a tunnel storing no reference,
    #: `action=complete` marks `default` with `@default='yes'` where such a profile exists, and
    #: help p.613 says "Select an existing profile or keep the default profile" - so the
    #: declaration is `Implicit.assumed` and the report renders it as not measured. What would
    #: settle it is a negotiating tunnel and `show vpn ipsec-sa`, which needs an IKE gateway and a
    #: reachable peer.
    #:
    #: THE REASON IT MAY BE STORED AT ALL IS NARROW: PAN-IPS-009's first record fires on a tunnel
    #: running on a profile nobody chose, and a materialised `default` is exactly that, so the
    #: inference cannot reassure. Leaving the column null would have made a tunnel with no
    #: reference PASS silently, which is the one direction rules.md forbids. The danger stage 4
    #: names - that a reader would infer the profile's CONTENT from the name - is answered by the
    #: two columns beside it, which is the three-column shape stage 4 asked for.
    #:
    #: ON BOTH PA-5220s AND ON pan-fw-111 THE LITERAL `default` RESOLVES TO NOTHING, measured. So
    #: an unresolvable name is the COMMONEST configuration in this lab and not an edge case.
    crypto_profile_name = models.CharField(max_length=64)
    #: Whether the crypto profile name this tunnel carries - stored or inferred - RESOLVES to an
    #: entry in this appliance's own collection. False with a name set is a dangling binding, and
    #: on this lab it is the majority state. The shipped precedent is
    #: `ManagementSshSettings.profile_found`, whose docstring says exactly that.
    crypto_profile_found = models.BooleanField(default=False)
    #: Whether the profile this tunnel actually runs on is one somebody CHOSE AND HARDENED. False
    #: where the tunnel carries no reference at all, where the name resolves to nothing, and where
    #: the profile it resolves to still carries the shipped algorithm set - WHATEVER THAT PROFILE
    #: IS CALLED.
    #:
    #: THE TEST IS ON CONTENT AND NOT ON THE NAME, and a measurement is why: the factory profiles
    #: are ordinary local config, present on one of four lab devices and deletable, so a renamed
    #: copy of the shipped profile passes a name test, a hand-made weak profile passes it too, and
    #: on a device where the shipped profile was deleted a name test is vacuously satisfied. The
    #: naive test passes exactly the configuration this one fails.
    effective_crypto_profile_chosen = models.BooleanField(default=False)

    class Meta:
        ordering = ["appliance__hostname", "tunnel_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "tunnel_name"],
                name="integrations_unique_ipsec_tunnel_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance", "tunnel_name"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["appliance", "is_disabled"]),
            models.Index(fields=["appliance", "crypto_profile_found"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.tunnel_name}"


class MonitorProfile(IpsecNetworkObject):
    """One named monitor profile on one appliance - the far end of a tunnel's monitoring binding.

    A COLLECTOR THAT SKIPS THIS OBJECT LEAVES PAN-IPS-007's SECOND RECORD UNANSWERABLE, in stage
    4's words: the tunnel's row says monitoring is on and names a profile, while the action it
    would take lives only here. The subject is modeled even though that record is discharged to
    an engineer's question, because the column is owed either way and the derived column that
    resolves it lives on the tunnel.

    THIS OBJECT WAS NEVER SHOWN TO BE ON A SCREEN, and that is a statement about the instrument
    rather than about the device: stage 4 records `ui_rendered: false` because three candidate
    hash routes all landed silently on the Network > Interfaces grid and `--walk` merged zero
    routes on that host. The vendor documents a control for all three keys at help p.660. So no
    value in this model is read off a rendering, and the one implicit it carries is an inference.

    NO KEY ON THIS OBJECT IS MANDATORY: stage 4 committed an entry carrying zero children and
    read it back as `{'@name': 'oep-ips-s4-mon'}`, and stage 6 left one standing
    (`oep-ips6-m03`). So all three keys have a genuine absent state on a running device.

    `interval` AND `threshold` ARE DELIBERATELY NOT COLUMNS. Stage 5 declared this subject with
    three columns and no control in this domain asserts over how often the probe is sent or how
    many losses it tolerates - the vendor's own range for the interval is itself a recorded
    vendor contradiction (2-10 against 2-100). Adding them would be a column nobody needs; the
    device holds both and this stage read both, so a later domain that wants them is adding a
    column and not a read.
    """

    #: Computed here: nothing but the shipped missing-tracking flag. The only other non-identity
    #: column is a payload key and carries a provenance row - through `ProvenancedMixin`, which
    #: all three models in this file inherit from `IpsecNetworkObject` rather than declaring for
    #: themselves. Named here because `probe.model_brief` decides whether a class carries the
    #: mixin by searching the CLASS's own source text, so a model that inherits it through a base
    #: and never mentions it reads as `ProvenancedMixin: no` - which this class did.
    DERIVED_FIELDS = ("is_missing",)

    class Action(models.TextChoices):
        WAIT_RECOVER = "wait-recover", "Wait for recovery"
        FAIL_OVER = "fail-over", "Fail over"

    #: The profile's own name: what a tunnel's monitoring reference resolves against and what a
    #: remediation has to name.
    profile_name = models.CharField(max_length=64)

    #: What the firewall does when a monitored tunnel stops answering. Where the key is absent
    #: this holds the INFERRED `wait-recover`.
    #:
    #: THAT INFERENCE FIRES, AND THAT IS THE WHOLE REASON IT MAY BE STORED. `wait-recover` is the
    #: value PAN-IPS-007's second record treats as FAILING - the vendor states the consequence
    #: plainly on help p.614, "if the action specified in the monitor profile is wait-recover, the
    #: firewall will wait for the tunnel to become functional and will NOT seek an alternate path
    #: with the route table" - so a profile that stores no action is reported rather than cleared.
    #: Stage 4's own words: "an unmeasured implicit here must not be materialised as a pass". Had
    #: the inferred value been `fail-over` this would have had to be a null column.
    #:
    #: THE TWO LEADS BEHIND THE INFERENCE, neither of them a measurement: `action=complete`
    #: answers two values with `@default='yes'` on `wait-recover` on all four appliances, and the
    #: vendor-shipped `default` profile on pan-fw-201 stores `wait-recover` EXPLICITLY - which is
    #: a shipped configuration and not an implicit value. Stage 4 names the tally that makes the
    #: schema attribute a lead rather than evidence: it agrees with the measured implicit on four
    #: fields and disagrees on three, and nothing in the answer says which kind you are holding.
    #:
    #: THE WIRE SHAPE IS A BARE STRING AND THE DEVICE IS EXPLICIT ABOUT IT: stage 4 measured
    #: `<action><fail-over/></action>` REFUSED with code=12 "oep-ips-s4-mon -> action is invalid"
    #: while `<action>fail-over</action>` is accepted - and the refusal names the KEY and not the
    #: shape, which is the least informative of the code=12 message classes.
    action = models.CharField(max_length=16, choices=Action.choices)

    class Meta:
        ordering = ["appliance__hostname", "profile_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "profile_name"],
                name="integrations_unique_monitor_profile_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance", "profile_name"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["appliance", "action"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.profile_name}"
