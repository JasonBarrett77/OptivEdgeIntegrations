"""The four `decryption-policy` models: the rulebase, its rules, and the SSL exclusions.

PAN-DEC-001 to 010. Two grains and two objects:

    DecryptionPolicyRule                one ordered entry of one decryption rulebase
    DecryptionRulebaseVerdict           a verdict over ALL of one enforcement point's rules
    SslDecryptionExclusion              one exclusion the organization added itself
    SslDecryptionVendorExclusionOptOut  which VENDOR exclusions somebody switched off here

WHY THERE ARE TWO RULE MODELS AND NOT ONE. Stage 4 measured the commonest state of this domain
as NO DECRYPTION RULEBASE AT ALL - all four lab appliances, all twenty vsys, both Panorama
Shared rulebases and all ten device groups, twice. The per-entry grain has no row for that, so
the three coverage assertions (PAN-DEC-001, 009 and the outbound half of 010) cannot be raised
from it: a predicate cannot compare against a row that is not there. The verdict model is the
row that reports the absence, and every one of its columns defaults to its FIRING value for
exactly that reason.

THE TWO LOG FLAGS ON A DECRYPTION RULE DEFAULT OPPOSITE WAYS, two keys apart - `log-fail`
absent means YES and `log-success` absent means NO, both measured by stage 4 on pan-fw-201's
Policies > Decryption grid by flipping each in both directions. A consumer that assumes a
rulebase entry's log flags share a default gets one of them backwards.

EVERY NEW COLUMN A CONTROL COMPARES IS NON-NULLABLE AND HOLDS ITS FIRING VALUE AS ITS DEFAULT.
The search layer has no is-null operator, so a positive comparison over NULL matches nothing and
the control silently stops firing - the unsafe direction. `is_empty`, the one operator that is
about absence, compiles to `filter(field="")` in every per-model compiler, so a text column
whose emptiness a control asserts is `blank=True, default=""` and never `null=True`. That
applies to `profile_name`, `description` and `log_setting` here, each of which stage 5 declares
as storing `null` for the absent key: the SIDE of the assertion that declaration picks is
preserved exactly - absence still fires - and the empty string is what makes the declared clause
satisfiable at all.

ON AN HA PAIR, a vsys-scoped row is owned by the ENFORCEMENT POINT, which a Panorama-managed
pair holds once for the pair rather than once per member. So the two TPA members' synchronised
copies of one rulebase produce ONE row here, not two. Stage 5's identity note predicted two and
that is a claim about this schema rather than about the device; `SecurityRule` has keyed on the
enforcement point since it was written and `RuleFinding.subject_scope` is built from it.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import ApplianceScopedObject, SyncTrackedModel
from .collected import EnforcementPoint, ManagementStation
from .policy.base import CONFIG_SOURCE_CHOICES
from .provenance import ProvenancedMixin


class DecryptionPolicyRule(ProvenancedMixin, SyncTrackedModel):
    """One named decryption policy rule, in one rulebase of one enforcement point.

    PAN-DEC-002, 003, 005, 006, 007, 008 and 010. The grain is the entry an engineer would open
    and edit, which is what every EXEMPTION assertion in this domain is about: the offending
    rule EXISTS - it leaves traffic encrypted with a criterion at `any`, or with no description,
    or with no profile, or with the match inverted - and the remediation is to edit that rule.

    `config_source` IS PART OF THE IDENTITY and not decoration: the same rule NAME may exist in
    a device-group pre-rulebase and a post-rulebase at the same scope, and those are two
    different objects a reader must tell apart. `rule_position` deliberately is NOT: a rule
    keeps its name and its uuid across an `action=move` - stage 4 moved a pair twice and both
    uuids were unchanged - so keying on position would make a reorder look like a delete and an
    insert.

    SIX KEYS ARE MANDATORY AT COMMIT VALIDATION, measured by stage 4 as `validate full` job 217
    on a rule carrying none of them: `from`, `to`, `source`, `destination`, `action` and `type`.
    A seventh, `certificates`, is mandatory CONDITIONAL on the inbound-inspection branch (job
    224). So on a running device `action`, `type_branch`, `source` and `destination` are always
    present - but the read this model normalizes is CANDIDATE-DERIVED, so a staged rule can
    reach it without them, and each column carries the blank that says so.
    """

    #: Which rulebase a row came from, in `CONFIG_SOURCE_CHOICES`' own token set. `SecurityRule`
    #: declares the same four and `RuleFinding.subject_scope` is built from them, so the two
    #: rulebases print alike - values like `local:vsys1` and `pushed_pre:vsys3`. `default` is
    #: inherited from the shared vocabulary and is NOT reachable on this object: PAN-OS ships no
    #: default decryption rule, measured as an absent `default-security-rules` sibling under
    #: every decryption rulebase this estate holds.
    SOURCE_LOCAL = "local"
    SOURCE_PUSHED_PRE = "pushed_pre"
    SOURCE_PUSHED_POST = "pushed_post"

    CONFIG_SOURCE_CHOICES = CONFIG_SOURCE_CHOICES

    #: What the rule does with a session it matches. `no-decrypt` is the value that leaves
    #: traffic UNINSPECTED, which is the direction the name does not carry.
    ACTION_NO_DECRYPT = "no-decrypt"
    ACTION_DECRYPT = "decrypt"
    ACTION_DECRYPT_AND_FORWARD = "decrypt-and-forward"
    #: The two that OPEN the session. `decrypt-and-forward` is accepted only at device-group
    #: scope - the firewall vsys path refuses the write with code=12, measured - so a lab with
    #: no pushed decryption rule cannot exercise it.
    SESSION_OPENING_ACTIONS = (ACTION_DECRYPT, ACTION_DECRYPT_AND_FORWARD)

    #: The three mutually exclusive `type` branches. PAN-OS stores the selection as WHICH EMPTY
    #: CHILD EXISTS, so this column holds the present child's NAME and is read with
    #: `common.choice_child` rather than as a text value. Writing two branches in one element
    #: was ACCEPTED with status=success and no message and the read-back carried only the LAST,
    #: measured - so a consumer must read which branch is present and must never assume a write
    #: of one left the others alone.
    TYPE_SSL_FORWARD_PROXY = "ssl-forward-proxy"
    TYPE_SSL_INBOUND_INSPECTION = "ssl-inbound-inspection"
    TYPE_SSH_PROXY = "ssh-proxy"
    TYPE_BRANCHES = (TYPE_SSL_FORWARD_PROXY, TYPE_SSL_INBOUND_INSPECTION, TYPE_SSH_PROXY)

    #: The four device KEYWORDS the user criterion may hold instead of a principal name. A
    #: member outside this set is a free string that may be a directory group or one individual,
    #: and this node cannot tell those apart.
    USER_KEYWORDS = frozenset({"any", "known-user", "pre-logon", "unknown"})

    #: What this rule does with the record of a SUCCESSFUL session, as one value. A VOCABULARY
    #: THIS LAYER INVENTS: the device offers no such set. It is one column rather than two
    #: clauses because PAN-DEC-010's second half is graded at two severities, a grading holds
    #: exactly ONE column, and the two states differ by two columns at once.
    RECORD_NONE = "no-record"
    RECORD_KEPT_NOT_FORWARDED = "kept-not-forwarded"
    RECORD_KEPT_AND_FORWARDED = "kept-and-forwarded"

    #: Computed here. `rule_position` is the entry's index in the `rules` array - the ORDER IS
    #: THE EVALUATION ORDER and no key holds it, so a normalizer that does not preserve array
    #: order loses the only statement the device makes about evaluation sequence.
    #: See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "rule_position",
        "source_user_is_keyword_population",
        "success_record_disposition",
        "opens_session",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE, related_name="decryption_policy_rules")
    #: THE OWNER, and what carries both `appliance` and `vsys_name`: an EnforcementPoint IS one
    #: vsys of one appliance (or of one HA pair). `SecurityRule` anchors the other rulebase the
    #: same way and `RuleFinding.subject_scope` is built as `config_source:vsys_name` off it.
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE, related_name="decryption_policy_rules")
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="decryption_policy_rules")

    #: Which rulebase the entry was read from. Collapses the scope token and the pre/post
    #: SECTION into one value, which is `SecurityRule.config_source`'s own token set.
    config_source = models.CharField(max_length=32, choices=CONFIG_SOURCE_CHOICES)
    #: 1-based rank in the `rules` array as the config read returned it. Declared though no
    #: control asserts it: no configuration key holds the order, so the rank has to be stored for
    #: a later shadowing question to be askable at all.
    #:
    #: THIS IS THE CONFIGURATION RANK AND NOT THE EVALUATION INDEX, and the two diverge. Measured
    #: 2026-10-29 on fw-core-tpa-a/vsys2: `show running decryption-policy` (with the API's `vsys`
    #: parameter) SKIPS the disabled rule, so `oep-dec6-r09` has no index at all and every rule
    #: after it renders one lower than its array position - r10 is `index: 9` and is stored here
    #: as 10. Stage 5 declared this column's `derived_from` as "the order of the entries in the
    #: rules container", which is the array position, so that is what is stored; its prose calls
    #: the column "the evaluation order, which decides which rule wins", and that is false from
    #: the first disabled rule onward. `SecurityRule` carries BOTH numbers - `rule_position` and
    #: `effective_order` - and stage 5 declared one. The second is what a shadowing control would
    #: need and it is recorded as a gap rather than invented here.
    rule_position = models.PositiveIntegerField()

    #: `@name`. The entry key - a rule has no identity without it, and `action=set` with an
    #: existing name MERGES into that entry rather than creating a second one, measured. 255
    #: rather than 64: no length was measured for this key, and `SecurityRule.name` is 255.
    #: `ObjectFindingBase.subject_name` is 64, so a longer name is truncated in the FINDING even
    #: where this column holds it whole.
    rule_name = models.CharField(max_length=255)
    #: `@uuid`. The firewall's own identifier, which survives a rename, a key deletion, a
    #: same-name merge and two `action=move` calls - measured on pan-fw-201 across commit job
    #: 219. BLANK AND NOT NULL, and blank is never materialised: a uuid we invented would be a
    #: fiction, and a device-created rule always carries one.
    rule_uuid = models.CharField(max_length=64, blank=True, default="")

    #: `action`. Mandatory at commit validation, so blank means a CANDIDATE-only rule and not a
    #: default anybody applied. The schema's own @default=yes on `no-decrypt` is NOT an implicit
    #: value for the same reason.
    action = models.CharField(max_length=32, blank=True, default="")
    #: Which of `TYPE_BRANCHES` is present under `type`. Blank means no branch is, which on a
    #: committed rule cannot happen.
    type_branch = models.CharField(max_length=32, blank=True, default="")

    #: `source-user` is drawn ENTIRELY from `USER_KEYWORDS`. TRUE is the firing side and is the
    #: migration default deliberately: PAN-DEC-006 fires where the exempt population is a
    #: keyword rather than a reviewable group, so an unrecomputed row reports itself. The
    #: framework's boolean default of False is the REASSURING side here and would pass every
    #: people-keyed exemption in the estate until the recompute ran, with nothing erroring.
    #: WHAT IT CANNOT DO: tell a directory GROUP from a single individual. False means only
    #: "at least one member is a principal of unknown kind".
    source_user_is_keyword_population = models.BooleanField(default=True)

    #: `negate-source` / `negate-destination`, stored with THE VENDOR'S OWN POLARITY: true means
    #: the device's key is `yes`, which means the match is INVERTED. The column name reads
    #: negative and the value does not negate anything - `SecurityRule` stores the same two keys
    #: the same way. ASSUMED and not measured: stage 4 found no oracle that renders either key,
    #: and `no` is inferred from the security rulebase's measured ABSENT MEANS NO plus the
    #: commit-validation refusal "Negate cannot be enabled ... with source address as 'any'",
    #: which only makes sense if absence means no.
    negate_source = models.BooleanField(default=False)
    negate_destination = models.BooleanField(default=False)

    #: `disabled`. True means the rule is in the configuration and NOT in force. Absent means IN
    #: FORCE, measured by the sharpest control stage 4 ran: a rule committed without the key
    #: appears in `show running decryption-policy` and in `show running rule-use hit-count`,
    #: while the same rule with `disabled: yes` (job 231) is absent from both. Used as an
    #: APPLICABILITY clause, so the default must keep an unread rule INSIDE the population - an
    #: applicability clause that drops a row suppresses the control on exactly the rows nobody
    #: read, which is rules.md's named trap.
    disabled = models.BooleanField(default=False)

    #: `log-fail`. True is the failed-handshake record being kept. ABSENT MEANS YES, measured on
    #: the Policies > Decryption grid at pan-fw-201 in both directions (job 230), and the vendor
    #: agrees twice (Help p.175 "Enabled by default", p.70 from the log-type end).
    log_fail = models.BooleanField(default=True)
    #: `log-success`. True is the successful-handshake record being kept. ABSENT MEANS NO, and
    #: THE PAIR WAS THE DISCRIMINATOR rather than the confirmation: the two grid cells are
    #: adjacent and unlabelled, so writing yes to one and no to the other is what attached each
    #: reading to its key - under the reverse mapping the pair would have read `false | true`
    #: unchanged, and it read `true | false`.
    log_success = models.BooleanField(default=False)

    #: `profile`. EMPTY DOES NOT MEAN NOTHING IS APPLIED. Stage 4 promoted this to measured and
    #: then refuted itself: with the key still absent, the same read printed `decryption-profile
    #: default` once `action` was moved to `decrypt` and `type` to the inbound branch. So the
    #: device resolves an absent profile to the predefined profile named `default` under some
    #: conditions and to nothing under others, and NOTHING IS MATERIALISED here. PAN-DEC-008
    #: confines itself with an applicability clause on `action equals no-decrypt`, which is one
    #: of the conditions under which the absent profile was measured resolving to nothing.
    profile_name = models.CharField(max_length=128, blank=True, default="")
    #: `description`. The only place on the rule that can hold why the rule exists and when
    #: somebody is due to revisit it, and the device checks neither. TextField and not a bounded
    #: CharField: the device refuses 1025 characters and returned 1024 whole, and normalizers
    #: elsewhere in this package truncate inbound text by hand at 32, 64, 128 and 255 - a column
    #: narrower than 1024 would lose the tail of the very justification PAN-DEC-003 asserts.
    description = models.TextField(blank=True, default="")
    #: `log-setting`. The forwarding profile that would carry this rulebase's records off the
    #: firewall. THE ATTACHMENT IS NOT THE DELIVERY and this column can only ever answer the
    #: first; whether an attachment on an ordinary decryption rule forwards anything at all is
    #: unsettled in the vendor's own documentation and is recorded in
    #: OptivEdgeProbe reference/known-vendor-contradictions.md.
    log_setting = models.CharField(max_length=128, blank=True, default="")

    #: One of `RECORD_NONE` / `RECORD_KEPT_NOT_FORWARDED` / `RECORD_KEPT_AND_FORWARDED`, over
    #: `log_success` and `log_setting` together. `no-record` is the worst of the three AND the
    #: migration default explicitly: a CharField migrated with an empty default would match no
    #: placement at all and the control would report nothing on every row until the recompute
    #: ran, with nothing erroring and no page rendering empty.
    success_record_disposition = models.CharField(max_length=32, default=RECORD_NONE)
    #: Whether the rule opens the session it matches - true for either of `SESSION_OPENING
    #: ACTIONS`. A DISJUNCTION the query grammar cannot write: `clauses` is one conjunction with
    #: no OR and there is no `in` operator. Used as an APPLICABILITY clause, so TRUE is the
    #: migration default deliberately - a boolean migrated False would exclude EVERY rule in the
    #: estate from PAN-DEC-010's second half and the control would report nothing.
    opens_session = models.BooleanField(default=True)

    class Meta:
        ordering = ["enforcement_point", "config_source", "rule_position", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "config_source", "rule_name"],
                name="integrations_unique_decryption_rule_per_rulebase"),
        ]
        indexes = [
            models.Index(fields=["enforcement_point", "config_source", "rule_position"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["enforcement_point", "action"]),
            models.Index(fields=["enforcement_point", "disabled"]),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} / {self.config_source} / {self.rule_name}"

    def clean(self) -> None:
        if self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError(
                "A decryption rule must belong to the same management station as its "
                "enforcement point.")


class DecryptionPolicyRuleValue(models.Model):
    """One member of one of a decryption rule's five member-list criteria.

    SATELLITE ROWS AND NOT A JSON COLUMN, and the reason is read in the consumer rather than
    assumed: `SecurityRuleValue` is the shipped shape for a rule's member lists and its
    subclasses ARE registered and reachable with `matches`, `includes`, `exactly` and
    `intersects`, while a JSONField is refused outright by two tests in OptivEdgeAssessments.
    PAN-DEC-002's structural half needs `includes 'any'` over five criteria at once, so a blob
    would have put the whole control out of reach.

    `prov` is a plain CharField rather than a FieldProvenance row, which is the documented
    exception for member and tag models. The LIST NODE's own provenance is recorded as a
    FieldProvenance row on the rule, because for three of these five an ABSENT key carries a
    measured vendor meaning and nothing else could tell "the rule says any" from "the key was
    absent and PAN-OS means any".
    """

    decryption_rule = models.ForeignKey(
        DecryptionPolicyRule, on_delete=models.CASCADE, related_name="%(class)ss")
    value = models.CharField(max_length=255)
    prov = models.CharField(max_length=128, blank=True)
    position = models.PositiveIntegerField()

    class Meta:
        abstract = True
        ordering = ["position", "id"]

    def __str__(self) -> str:
        return self.value


class DecryptionPolicyRuleCategory(DecryptionPolicyRuleValue):
    """`category`. AN ABSENT KEY MEANS EVERY URL CATEGORY, so the empty state is the most
    permissive one and not the narrowest, and the normalizer materialises `any` for it. A member
    may also be a custom-url-category object whose own members are other categories, and that
    object is an INTERSECTION rather than a union - so coverage read off the member NAMES
    OVERSTATES what is opened."""


class DecryptionPolicyRuleSource(DecryptionPolicyRuleValue):
    """`source`. MANDATORY at commit validation, so the literal `any` is a written value here
    and not a default - the opposite of `category` on the same object. A member may be an address
    object, an address group, a region or an external dynamic list and the device offers no
    @type to tell them apart."""


class DecryptionPolicyRuleDestination(DecryptionPolicyRuleValue):
    """`destination`. Mandatory, in the same four member kinds as `source`."""


class DecryptionPolicyRuleSourceUser(DecryptionPolicyRuleValue):
    """`source-user`. An absent key means EVERY user, materialised as `any`. A member is either
    one of `DecryptionPolicyRule.USER_KEYWORDS` or a free principal string. THE LEAF NAME IS ONE
    OF THE MOST REUSED IN THE PRODUCT - 85 objects in the grammar carry it, and the SECURITY
    rulebase's copy decides whether traffic is ALLOWED rather than whether it is INSPECTED."""


class DecryptionPolicyRuleService(DecryptionPolicyRuleValue):
    """`service`. An absent key means every port, materialised as `any`. No control asserts a
    service criterion; it is stored because PAN-DEC-002's structural half needs `keyed on nothing
    at all` to be a conjunction over EVERY criterion, and a criterion left out of that
    conjunction is a rule bounded by a port that reads as bounded by nothing."""


class DecryptionRulebaseVerdict(ProvenancedMixin, SyncTrackedModel):
    """One enforcement point's decryption rulebase, as a verdict over all of its rules.

    PAN-DEC-001 and 009, and the row that answers for every `passes` the per-rule subject
    declares. A rule nobody collected produces NO rule row, and a predicate cannot compare
    against a row that is not there - so the silence is reported here, where every column's
    uncollected and unrecomputed value is the FIRING one.

    NO PROVENANCE ROW IS WRITTEN FOR ANY COLUMN. A verdict is computed rather than read: no key
    supplies it, so there is no marker to store. The rule rows it is computed from carry their
    own. The consequence is stated rather than hidden - a control whose finding turned on whether
    a value was PUSHED cannot be written against this subject.

    AND THE VERDICT IS RIGHT BUT UNATTRIBUTABLE. A decryption rule pushed from a device-group or
    Shared pre/post-rulebase CONTRIBUTES to these counts - it is in force on this enforcement
    point - and this row has no scope column, so a finding saying "this enforcement point opens
    no outbound web session" cannot say whether the gap is in the firewall's own rulebase or in
    the device group. The per-rule model answers that with `config_source`; this one cannot.
    """

    #: What the enforcement point does with an outbound web session, as the STRONGEST thing any
    #: in-force forward-proxy rule on it does. `no-rule-opens-outbound-web` is the measured state
    #: of every vsys in this lab before stage 6 wrote one, and it is the firing value.
    OUTBOUND_NO_RULE = "no-rule-opens-outbound-web"
    OUTBOUND_NO_DECRYPT = "no-decrypt"
    OUTBOUND_DECRYPT = "decrypt"
    OUTBOUND_DECRYPT_AND_FORWARD = "decrypt-and-forward"

    #: Whether anything inspects inbound TLS on the organisation's own published servers.
    INBOUND_NONE = "no-inbound-inspection-rule"
    INBOUND_PRESENT = "inbound-inspection-present"

    #: Every column but the anchors. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "rule_count",
        "outbound_web_disposition",
        "inbound_inspection_posture",
        "opens_outbound_web",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE, related_name="decryption_rulebase_verdicts")
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE,
        related_name="decryption_rulebase_verdicts")
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="decryption_rulebase_verdicts")

    #: How many rules are IN FORCE here - every scope that reaches this enforcement point,
    #: excluding the disabled ones. ZERO IS THE FIRING VALUE: zero means no session is opened
    #: anywhere on this enforcement point, which is the finding PAN-DEC-001 exists to raise, so
    #: an unrecomputed row reports itself. It is also what makes a measured truthiness trap
    #: harmless - `show running decryption-policy` answers `{"member": [null]}`, TRUTHY, on an
    #: appliance with NO rulebase, so the count is taken from the CONFIG read instead, where
    #: absent (None) and empty-but-present (a truthy dict) are distinguishable.
    rule_count = models.PositiveIntegerField(default=0)
    #: One of the four OUTBOUND_* values. The firing value must be the explicit migration
    #: default: a CharField migrated empty would match no placement and the control would report
    #: nothing on every enforcement point in the estate until the recompute ran.
    outbound_web_disposition = models.CharField(max_length=32, default=OUTBOUND_NO_RULE)
    #: INBOUND_NONE or INBOUND_PRESENT. NO RANK OF PAN-DEC-009 HAS BEEN SEEN IN A POPULATED
    #: ESTATE: there was no inbound-inspection rule and no inbound certificate anywhere in the
    #: lab before stage 6 built one.
    inbound_inspection_posture = models.CharField(max_length=32, default=INBOUND_NONE)
    #: PAN-DEC-001's BASELINE column, kept separate from `outbound_web_disposition` so the
    #: baseline fires on BOTH failing states - no rule at all, and rules that all leave traffic
    #: encrypted - in one conjunction, while the disposition carries the severity. Splitting them
    #: is what lets `decrypt-and-forward` sit outside the baseline: the session IS opened, so
    #: that value meets the assertion and must not be reported as a coverage failure.
    opens_outbound_web = models.BooleanField(default=False)

    class Meta:
        ordering = ["enforcement_point", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point"],
                name="integrations_unique_decryption_rulebase_verdict_per_point"),
        ]
        indexes = [
            models.Index(fields=["enforcement_point"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["opens_outbound_web"]),
            models.Index(fields=["inbound_inspection_posture"]),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} decryption rulebase"

    def clean(self) -> None:
        if self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError(
                "A decryption rulebase verdict must belong to the same management station as "
                "its enforcement point.")


class SslDecryptionExclusion(ApplianceScopedObject):
    """One SSL decryption exclusion THE ORGANIZATION ADDED ITSELF, in one scope of one appliance.

    PAN-DEC-004's first half. `ssl-decrypt/ssl-exclude-cert`, at the vsys scope and at the
    appliance's own shared scope - both LOCAL owners, which is where this differs from the
    decryption rule's shared scope, which is Panorama's. A collector reading only the vsys scope
    would report no exclusions on a firewall whose operator added them through the interface.

    WHAT THIS MODEL DOES NOT HOLD IS THE VENDOR'S 330 OR 385 ENTRIES. They live at
    /config/predefined/ssl-exclude-cert, are a separate object, and are invisible to the read
    this model normalizes. The web interface renders BOTH collections in ONE grid distinguished
    only by a Location column, so a consumer reading this path sees only the organization's own
    exclusions while an operator looking at the screen sees both.

    `ApplianceScopedObject` IS THE RIGHT BASE and is inherited rather than reimplemented: shared
    plus vsys with a local owner is exactly what that base documents itself for, its `clean()`
    already enforces the vsys rule this object needs, and its four anchors are the uniqueness
    constraint every appliance-scoped model keys on. The one edge it brings is `name`'s 64
    characters, which is the base's limit and not a measurement - the longest name the vendor
    ships is 59 characters, measured on all four lab appliances, and a customer FQDN longer than
    64 is a question about the shared base rather than about this domain.
    """

    #: Computed: nothing but the inherited missing flag. Both real columns read a real key.
    DERIVED_FIELDS = ("is_missing",)

    #: `exclude`. True means the firewall will NOT open sessions to the named server. MANDATORY
    #: at commit validation, measured by building a bare entry at EACH scope and being refused -
    #: `ssl-decrypt -> ssl-exclude-cert -> oep-dcp-excl-vsys is missing 'exclude'`, job 236 - so
    #: no committed exclusion is observed without it. False where the key is absent means a BARE
    #: UNCOMMITTED entry, which returns only @name plus the staging attributes.
    exclude = models.BooleanField(default=False)
    #: `description`. The only place on the entry that can say which application it protects and
    #: when it is next due to be rechecked. NO LENGTH WAS MEASURED for this key, so it is not
    #: narrowed on the decryption rule's measured 1024 by analogy.
    description = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["appliance", "scope", "vsys_name", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "name"],
                name="integrations_unique_ssl_decryption_exclusion_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance", "name"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["appliance", "exclude"]),
        ]

    @property
    def exclusion_name(self) -> str:
        """The server name this exclusion is written against, under the name stage 5 gave it.

        A PROPERTY RATHER THAN A SECOND COLUMN. The stored column is the base class's `name`,
        and the findings sheet resolves a tested field against the subject model and refuses a
        name the model can neither store nor compute - `SecurityRule.source_breadth_known` is
        the precedent and records the page it broke when it was missing. Nothing clauses on this
        name, so a property is enough; a clause would need the column itself.
        """
        return self.name


class SslDecryptionVendorExclusionOptOut(ProvenancedMixin, SyncTrackedModel):
    """One appliance's departures from the VENDOR-SUPPLIED SSL decryption exclusion list.

    PAN-DEC-004's second half. `/config/shared/ssl-decrypt/disabled-ssl-exclude-cert-from-
    predefined` is a bare member list and not a collection, so there is no entry to be one row
    per and the row is a conclusion about the VENDOR's entries: which of them are switched off
    here. SHARED SCOPE ONLY - stage 4 completed both scopes and this node is the one the vsys
    scope is missing, so on a multi-vsys firewall the decision cannot be taken per vsys.

    SWITCHING ONE OFF IS A HARDENING ACT AND NOT A WEAKENING ONE, which is the direction the
    obvious reading gets backwards: the vendor's own screen says the option effectively removes
    support for applications that break decryption, and is there to ensure certain encrypted
    applications do not enter your network. So a non-empty list is a REVIEW ITEM and not a gap.

    THE ONE CLEAN FINDING IS THE STALE RESIDUE, and the vendor supplies the mechanic that makes
    it accumulate: an entry left switched OFF stays on the list even after a content update stops
    defining it, while a switched-ON one is removed automatically. So the residue gathers on
    exactly the entries an administrator touched.

    NO PROVENANCE ROW IS WRITTEN FOR THE TWO COUNTS: both are derived. The member list itself
    does record one, because its ABSENT state is an assumption and a reader is owed the fact
    that the empty list they are relying on was inferred rather than read.

    THERE IS NO "DID ANYBODY READ THE VENDOR'S LIST" COLUMN AND THERE SHOULD BE. Stage 5
    declared none, and a column this stage invented would sit beyond every check stage 5 makes,
    so `stale_disabled_vendor_exclusion_count` of zero means BOTH "no departure is stale" and
    "the `show predefined` snapshot did not exist when this row was written". Stage 5 took that
    concession deliberately, with the reasons written into the column's `when_unknown`, and this
    layer implements it as declared; the gap is recorded in the stage 7 artifact's `spec_gaps`
    and what would close it is a `*_collected` companion boolean on stage 5's own declaration,
    the way `LoggingSettings.central_store_status_collected` carries it for PAN-LOG-010.
    `normalize_ssl_decryption_vendor_exclusion_optout`'s return value says whether the vendor
    read was present, so a caller can see what a row cannot.
    """

    #: Computed. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "disabled_vendor_exclusion_count",
        "stale_disabled_vendor_exclusion_count",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE,
        related_name="ssl_decryption_vendor_exclusion_optouts")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="ssl_decryption_vendor_exclusion_optouts")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="ssl_decryption_vendor_exclusion_optouts", null=True, blank=True)
    #: The MERGED CONFIG snapshot the member list came from. The vendor list is a second
    #: snapshot and is not referenced here; `predefined_list_collected` is what records whether
    #: it existed, which is what any reader of the stale count needs.
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="ssl_decryption_vendor_exclusion_optouts")

    #: The server names somebody switched off here, in the device's own order. NOT SEARCHABLE
    #: and deliberately so: it is the list a reader needs beside the reachable count, and it is
    #: what PAN-DEC-004's second half is DELIVERED as. An absent node is taken to mean the EMPTY
    #: LIST, which is an ASSUMPTION - the absence itself is measured on all four lab appliances,
    #: what is assumed is the reading of it.
    disabled_vendor_exclusions = models.JSONField(default=list, blank=True)
    #: The reachable form of the list beside it. Zero is the REASSURING side and it is accepted
    #: with the reason stated: the recompute is a read of a column the same row already carries
    #: rather than a new collection, and no finding rests on this column alone.
    disabled_vendor_exclusion_count = models.PositiveIntegerField(default=0)
    #: How many switched-off entries the vendor NO LONGER SHIPS - a member with no matching
    #: @name in the predefined collection. A SET DIFFERENCE BETWEEN TWO NODES, and the
    #: right-hand side is invisible to `action=get` and to `show config merged`: the config read
    #: a collector naturally reaches for answers a well-formed, TRUTHY, EMPTY count envelope
    #: (`{"@total-count": "0", "@count": "0"}`) for a populated vendor list on every appliance,
    #: so only the `show predefined` op read can supply it. Zero where the op read did not
    #: happen, which `predefined_list_collected` is what separates.
    stale_disabled_vendor_exclusion_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["appliance", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="integrations_unique_ssl_vendor_exclusion_optout_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["stale_disabled_vendor_exclusion_count"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} vendor decryption exclusion opt-outs"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError("Object appliance must belong to the same station.")


class DecryptionSettings(ProvenancedMixin, SyncTrackedModel):
    """One appliance's FORWARD-PROXY SIGNING designation. PAN-DCP-003, 004 and 006's subject.

    `/config/shared/ssl-decrypt` holds which certificate the firewall signs with when it stands
    in for a destination. A fifth model over a node three others already touch, and the split is
    by CHILD rather than arbitrary: `SslDecryptionExclusion` owns `ssl-exclude-cert`,
    `SslDecryptionVendorExclusionOptOut` owns `disabled-ssl-exclude-cert-from-predefined`, and
    this owns the two `forward-*-certificate` containers. `trusted-root-CA` and
    `root-ca-exclude-list` are owned by NOTHING and are named in this stage's artifact as the
    gap: `trusted-root-CA` is the predicate PAN-DCP-004 rests on, so that control is exactly as
    good as a list nothing checks.

    THE GRAIN IS THE APPLIANCE AND NOT THE DESIGNATION SLOT, and the commonest failing state
    decides it: NO certificate designated at all. `/config/shared/ssl-decrypt` was absent on all
    four lab appliances before stage 6 built a designation on one of them, and the firewall says
    so in its own words - `show system setting ssl-decrypt certificate` answers `No SSL
    Decryption CERT`. A per-slot grain has NO ROW AT ALL in that state, so it could not report
    the finding. A row per appliance always exists and can say "nothing is designated".

    ON AN HA PAIR THIS YIELDS TWO ROWS FOR ONE REAL CONFIGURATION, and that is the opposite of
    the decryption profile's shared scope, which anchors to the appliance GROUP. The designation
    is device-wide - one node per firewall - so it takes an appliance directly, the same way
    `SnmpSettings` does; writing to either peer writes to both and nothing here deduplicates
    them.

    THE DESIGNATION IS MADE ON A SCREEN THIS NODE IS NOT ON. The vendor's interface presents it
    as something you select while editing the CERTIFICATE (Administrator's Guide p.323 step 8,
    p.399 step 4) and stores it here, so an engineer looking for "where is the forward trust
    certificate set" finds the certificate and not this node. The name stored here is the join
    into `Certificate`, by name within the appliance.

    THE TWO VERDICTS FOLLOW A REFERENCE AND THAT IS WHY THEY ARE COLUMNS. A clause compares one
    field to one literal: it cannot follow `forward_trust_cert_rsa` into the certificate store
    to ask whether the target is a CA, and it cannot compare two columns of this row to each
    other. Both default FALSE, which fires, and on this estate false is also the true answer.
    """

    #: Computed here: both are quantifiers over the four designation columns, one of them
    #: following the name into `Certificate`. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "forward_trust_is_designated_local_ca",
        "untrust_distinct_from_trust",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE, related_name="decryption_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="decryption_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="decryption_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="decryption_settings")

    #: THE FOUR DESIGNATION SLOTS. Each container has an `rsa` and an `ecdsa` child, so the
    #: payload is a NESTED DICT and not a string - `{"forward-trust-certificate": {"rsa":
    #: "oep-p1-cert"}}` - and a consumer reading `forward-trust-certificate` as a certificate
    #: name gets a dict. Stage 4 measured that shape and it is the one trap on this node.
    #:
    #: EMPTY MEANS NO CERTIFICATE IS DESIGNATED IN THAT SLOT, which on its own is NOT the same
    #: as none being designated at all - the other algorithm slot has to be read too, which is
    #: what the two verdicts below do. `blank=True, default=""` and never `null=True`: the
    #: search layer's `is_empty` compiles to `filter(field="")`, so emptiness is only assertable
    #: on an empty string.
    #:
    #: Trust is what the firewall signs with for a destination it COULD validate; untrust is for
    #: one it could NOT. The pair matters: a firewall using one certificate for both gives a
    #: user no way to tell a trustworthy site from an untrustworthy one.
    forward_trust_cert_rsa = models.CharField(max_length=64, blank=True, default="")
    forward_trust_cert_ecdsa = models.CharField(max_length=64, blank=True, default="")
    forward_untrust_cert_rsa = models.CharField(max_length=64, blank=True, default="")
    forward_untrust_cert_ecdsa = models.CharField(max_length=64, blank=True, default="")

    #: Whether this appliance has designated a forward-trust signing certificate AT ALL and
    #: every slot it fills resolves to a certificate THIS APPLIANCE HOLDS that is marked a
    #: certificate authority and is self-signed - the on-device PROXY for "the organisation
    #: issued it", in the direction that PASSES only when all of that is in evidence.
    #:
    #: A name that resolves to no certificate row makes this FALSE rather than leaving it
    #: unknown, deliberately: a designation pointing at nothing is a worse state than no
    #: designation, not a better-evidenced one.
    forward_trust_is_designated_local_ca = models.BooleanField(default=False)

    #: Whether a forward-UNTRUST authority is designated and is a DIFFERENT certificate from
    #: every forward-trust one. FALSE where no untrust authority is designated at all, and FALSE
    #: where any untrust slot names a certificate a trust slot also names. Compared across BOTH
    #: algorithm slots of each, which is four columns rather than two.
    untrust_distinct_from_trust = models.BooleanField(default=False)

    class Meta:
        ordering = ["appliance", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="integrations_unique_decryption_settings_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["forward_trust_is_designated_local_ca"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} decryption settings"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError("Object appliance must belong to the same station.")
