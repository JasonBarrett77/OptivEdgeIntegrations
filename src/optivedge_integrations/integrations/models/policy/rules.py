"""Security rule and rule-adjacent policy models."""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from ..base import SyncTrackedModel
from ..collected import EnforcementPoint, ManagementStation
from ..provenance import ProvenancedMixin
from .base import CONFIG_SOURCE_CHOICES


class SecurityRule(ProvenancedMixin, SyncTrackedModel):

    #: Computed here: the position the dataplane evaluates this rule at, which no key carries. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "effective_order",
        # How many IPv4 addresses each side permits, AFTER negation. Worked out by walking the
        # side's address refs and merging their intervals; no payload key carries it.
        "source_num_hosts",
        "destination_num_hosts",
        "has_antivirus_profile",
        "has_spyware_profile",
        "has_vulnerability_profile",
        "spyware_profile_resolved",
        "wildfire_analysis_submits_all",
        "wildfire_analysis_detail",
        # --- security-policy domain (PAN-POL). Every one is worked out at normalization from
        # other stored rows or from the rule's own satellites; no payload key carries any of
        # them, so none can have a provenance row. `group_tag` and `schedule` are deliberately
        # NOT here - both read a real key on the rule and record one.
        "threat_profile_kinds_in_force",
        "has_url_filtering_profile",
        "url_inspection_posture",
        "permitted_port_count",
        "permits_high_risk_application",
        "high_risk_application_characteristic",
        "open_zone_side_count",
        "is_shadowed_by_earlier_rule",
        "shadow_relation_computed",
        "has_exact_duplicate",
        "duplicate_comparison_computed",
        "days_since_last_hit",
        "hit_count_reading_known",
        "busy_rule_placed_late",
        "schedule_kind",
        "schedule_window_expired",
        # --- vulnerability-protection domain (PAN-VLN). Both are worked out by the
        # profile-coverage pass from other stored rows - the rule's profile-setting, the one
        # profile group it may name, and the resolved profile - so neither has a payload key and
        # neither can carry a provenance row. They are the vulnerability siblings of
        # `spyware_profile_resolved` and of `shadow_relation_computed`.
        "vulnerability_profile_resolved",
        "vulnerability_verdict_written",
    )
    #: The three site-inspection states PAN-POL-020 grades, and the reason a boolean is not
    #: enough: `exception_unrecorded` is the middle state - a URL filtering profile IS in force
    #: and the rule's own `category` list excuses something from it - and it is the state the
    #: control's severity turns on. EMPTY is a fourth value and is not a state: it means no pass
    #: has run, matches none of the three literals, and leaves `has_url_filtering_profile` to
    #: carry the finding. None of the three is a device value: PAN-OS holds a profile binding
    #: and a category list and nothing that says whether an exception was recorded, so these are
    #: this assessment's reading and `exception_unrecorded` CANNOT be told from a deliberate,
    #: bounded exception - the device has no field for a reason or a date.
    URL_POSTURE_NONE = "none"
    URL_POSTURE_EXCEPTION_UNRECORDED = "exception_unrecorded"
    URL_POSTURE_IN_FORCE = "in_force"
    URL_INSPECTION_POSTURE_CHOICES = [
        (URL_POSTURE_NONE, "No site inspection in force"),
        (URL_POSTURE_EXCEPTION_UNRECORDED, "In force, with an unrecorded exception"),
        (URL_POSTURE_IN_FORCE, "In force"),
    ]

    #: Which of the schedule object's two mutually exclusive branches the rule's named schedule
    #: carries, plus `none` for a rule that names no schedule at all. `none` is a REAL and
    #: reportable state - the rule is permanent, which is PAN-POL-022's finding - so the empty
    #: string is kept distinct from it and means "no pass has resolved this rule's schedule".
    #: Defaulting to `none` would report every unresolved rule as permanent, which is a finding
    #: raised on no evidence.
    SCHEDULE_KIND_NONE = "none"
    SCHEDULE_KIND_NON_RECURRING = "non_recurring"
    SCHEDULE_KIND_RECURRING = "recurring"
    SCHEDULE_KIND_CHOICES = [
        (SCHEDULE_KIND_NONE, "No schedule - always in force"),
        (SCHEDULE_KIND_NON_RECURRING, "Non-recurring date range"),
        (SCHEDULE_KIND_RECURRING, "Recurring weekly or daily window"),
    ]

    SOURCE_LOCAL = "local"
    SOURCE_PUSHED_PRE = "pushed_pre"
    SOURCE_PUSHED_POST = "pushed_post"
    SOURCE_DEFAULT = "default"

    CONFIG_SOURCE_CHOICES = CONFIG_SOURCE_CHOICES

    #: How many IPv4 addresses this side permits once negation is applied. NULL means
    #: INDETERMINATE, never zero: a side is unknowable when it names a dynamic address group or
    #: a region, when an EDL or FQDN on it has no resolved content, or when that content was
    #: truncated and is a known under-count. Zero would be the narrowest possible value, so a
    #: rule nobody could measure would score as the tightest rule on the device - which is the
    #: failure direction a breadth control exists to prevent.
    source_num_hosts = models.BigIntegerField(null=True, blank=True)
    destination_num_hosts = models.BigIntegerField(null=True, blank=True)

    #: Which threat profile types are IN FORCE on this rule, after resolving its profile group.
    #:
    #: A rule names either individual profiles or ONE profile group, and the group is the common
    #: case - on the lab 113 rules reach their protection that way and none names a profile
    #: directly. Resolving it is the whole point: the lab's `default` group NAMES NO PROFILES AT
    #: ALL, so 113 rules that look protected inspect nothing. A control reading "does the rule
    #: carry a profile group" would pass every one of them.
    #:
    #: Columns rather than a query, for the reason the breadth columns are columns: the search
    #: layer compares a field to a literal and cannot follow a rule's group reference into that
    #: group's member list, resolving the name by scope on the way.
    has_antivirus_profile = models.BooleanField(default=False)
    has_spyware_profile = models.BooleanField(default=False)
    has_vulnerability_profile = models.BooleanField(default=False)

    #: THE THIRD ATTACHMENT STATE, and the only thing that separates it from the first.
    #:
    #: `has_spyware_profile` is true as soon as something names a spyware profile - the rule's own
    #: `profile-setting/profiles/spyware` slot, or a profile group whose `spyware` key exists. It
    #: says nothing about whether that NAME resolves. This column is the resolution: true only
    #: where a spyware profile row was found by name AND scope. So:
    #:
    #:   has_spyware_profile False                      nothing binds. Attach a profile.
    #:   has_spyware_profile True, resolved False       a name is bound and resolves to nothing.
    #:                                                  Repair the profile, or repair the group.
    #:   both True                                      a definition is in force.
    #:
    #: Three states, three different repairs, and the existing finding sentence renders the middle
    #: one as protected by a profile it then says does not exist. The data was already in the
    #: store - `SecurityRuleProfileVerdict.profile_name` is non-blank with `satisfied` NULL for
    #: exactly that case - and no query could reach it, because `profile_name` is in no field
    #: registry. This column is that question answered where a clause can see it.
    #:
    #: FALSE IS THE FIRING SIDE and the default, so a rule nobody has recomputed reports as
    #: unresolved rather than passing. The cost of that direction is that the migration window is
    #: indistinguishable from the real middle state until the recompute runs, which is why it is a
    #: separate column rather than folded into `has_spyware_profile`.
    spyware_profile_resolved = models.BooleanField(default=False)

    #: THE SAME THIRD ATTACHMENT STATE FOR VULNERABILITY PROTECTION, read the same way and for the
    #: same three repairs - see `spyware_profile_resolved` directly above, whose comment is the
    #: argument and is not repeated. True only where a vulnerability profile row was found by name
    #: AND scope, taken vsys first, then shared, then predefined.
    #:
    #: ITS ONE CONTROL CLAUSES IT AS AN APPLICABILITY TEST, which is the opposite polarity to the
    #: spyware column's use and is worth stating here because the suppressing form reads as
    #: careful: PAN-VLN-004 asks whether exemptions are minimal and applies only where a profile
    #: is in force, so `equals true` is the clause and a rule nobody could resolve holds FALSE and
    #: is excluded rather than reported.
    #:
    #: WHAT MAKES THAT SAFE is that the exclusion cannot hide an unassessed rule. The gap on a
    #: rule reaching no profile is asserted by the other three controls in this domain, none of
    #: which carries an applicability clause, and a rule the coverage pass never ran over is
    #: reported by `vulnerability_verdict_written` below.
    #:
    #: FALSE IS THE DEFAULT, and on this column that is the SILENT side rather than the firing
    #: one. Deliberate, and the reason the column beside it exists.
    vulnerability_profile_resolved = models.BooleanField(default=False)

    #: WHETHER THE PROFILE-COVERAGE PASS HAS WRITTEN THIS RULE'S VERDICT ROWS AT ALL. False means
    #: NOBODY HAS LOOKED, as against a reading that found nothing, and it is the undetermined
    #: group of all four PAN-VLN controls.
    #:
    #: THERE IS NO IS-NULL OPERATOR AND NO QUANTIFIER OVER ROWS, and the absence this answers is
    #: of a ROW and not of a value. Every shipped verdict compiler filters
    #: `profile_verdicts__assertion = <assertion>` before it looks at the verdict, so a rule whose
    #: rows were never written matches no clause of any of those controls and is SILENT in all of
    #: them while looking compliant. A query cannot ask for a row that is not there; this column
    #: is that question moved somewhere a clause can see it.
    #:
    #: FALSE IS THE FIRING SIDE AND THE DEFAULT, so the window between a migration and the next
    #: pass announces itself instead of reporting a clean estate. The sibling of
    #: `shadow_relation_computed` and `duplicate_comparison_computed`, which answer the same
    #: question for the security-policy domain's own computed pairs.
    #:
    #: IT IS WRITTEN FOR EVERY RULE THE PASS TOUCHES, not only for rules a vulnerability profile
    #: reaches: the pass writes a row for every assertion including the no-profile case, so "this
    #: rule makes no claim" is a stored fact and "nobody computed this rule" is this column.
    vulnerability_verdict_written = models.BooleanField(default=False)

    #: Does the WildFire analysis profile in force on this rule send EVERY file type for
    #: sandbox analysis? PAN-AVW-003 asks this per RULE rather than per profile, because a
    #: profile nothing uses endangers nothing and a rule is what carries traffic.
    #:
    #: THREE STATES, and the middle one is why this is nullable rather than a boolean:
    #:
    #:   True   a profile is in force and some rule in it covers `any` file type
    #:   False  a profile is in force and none of its rules does - including a profile with
    #:          no rules at all, which is valid configuration and submits nothing
    #:   NULL   no WildFire analysis profile reaches this rule, or this row predates the
    #:          column and nothing has re-normalized it
    #:
    #: NULL and False both produce a finding and `wildfire_analysis_detail` says which. Null
    #: is the firing side deliberately: a new column on an already-populated model defaults
    #: to its empty value, and a column whose empty value meant "fine" would report a clean
    #: estate for the whole window between migrating and re-normalizing.
    wildfire_analysis_submits_all = models.BooleanField(null=True)
    #: Why, in words, for the finding and the row. Empty only when the answer is True.
    wildfire_analysis_detail = models.CharField(max_length=255, blank=True)

    def profile_verdict(self, assertion):
        """The verdict row for one assertion, or None when nothing has normalized yet.

        Walks the prefetched set rather than filtering, so one `prefetch_related` covers every
        property below - the finding sentence reads several per rule.
        """
        for row in self.profile_verdicts.all():
            if row.assertion == assertion:
                return row
        return None

    def _verdict_value(self, assertion):
        row = self.profile_verdict(assertion)
        return row.satisfied if row else None

    def _verdict_detail(self, assertion):
        row = self.profile_verdict(assertion)
        return row.detail if row else ""

    def _verdict_grading(self, assertion):
        """The GRADED VALUE beside one assertion's verdict, or "" where there is no row.

        A verdict says WHETHER; a severity grading needs WHICH, and the value it needs sits on a
        collection one model away from the rule the finding names. See
        `SecurityRuleProfileVerdict.grading_value` for why it is one column and not three.

        EMPTY where no row exists, which matches no severity placement - so a rule nobody has
        recomputed reports at its control's BASELINE severity rather than being handed a value.
        """
        row = self.profile_verdict(assertion)
        return row.grading_value if row else ""

    #: THE NINE PER-RULE THREAT-PROFILE VERDICTS, named exactly as the control queries name
    #: them. Each reads a `SecurityRuleProfileVerdict` row; see that model for why they are a
    #: satellite and why None does not fire.
    #:
    #: They exist as PROPERTIES, not only as search fields, because the artifact layer resolves
    #: a control's tested fields against the subject model and accepts a name the model either
    #: stores or COMPUTES - so a search field with no matching attribute fails the workbook
    #: build for the whole domain. The security-profile verdicts are properties for the same
    #: reason.
    @property
    def antivirus_blocks_malware(self):
        return self._verdict_value("antivirus_blocks_malware")

    @property
    def antivirus_blocks_malware_detail(self):
        return self._verdict_detail("antivirus_blocks_malware")

    @property
    def antivirus_inline_ml_blocks(self):
        return self._verdict_value("antivirus_inline_ml_blocks")

    @property
    def antivirus_inline_ml_blocks_detail(self):
        return self._verdict_detail("antivirus_inline_ml_blocks")

    @property
    def spyware_blocks_critical_high(self):
        return self._verdict_value("spyware_blocks_critical_high")

    @property
    def spyware_blocks_critical_high_detail(self):
        return self._verdict_detail("spyware_blocks_critical_high")

    @property
    def spyware_dns_sinkholes(self):
        return self._verdict_value("spyware_dns_sinkholes")

    @property
    def spyware_dns_sinkholes_detail(self):
        return self._verdict_detail("spyware_dns_sinkholes")

    @property
    def spyware_dns_categories_enforced(self):
        return self._verdict_value("spyware_dns_categories_enforced")

    @property
    def spyware_dns_categories_enforced_detail(self):
        return self._verdict_detail("spyware_dns_categories_enforced")

    @property
    def spyware_inline_analysis_blocks(self):
        return self._verdict_value("spyware_inline_analysis_blocks")

    @property
    def spyware_inline_analysis_blocks_detail(self):
        return self._verdict_detail("spyware_inline_analysis_blocks")

    @property
    def spyware_exceptions_minimal(self):
        return self._verdict_value("spyware_exceptions_minimal")

    @property
    def spyware_exceptions_minimal_detail(self):
        return self._verdict_detail("spyware_exceptions_minimal")

    #: THE THREE GRADED VALUES PAN-SPY-001, -002 and -004 CALIBRATE THEIR SEVERITY WITH. Each
    #: reads the `grading_value` of the assertion it belongs to, so each is the WHICH beside that
    #: assertion's WHETHER. None of them may be clausedon alone: an empty string matches no
    #: placement, so a row nobody recomputed loses the ESCALATION and keeps the finding, which the
    #: boolean verdict beside it raises because its `false` clause also matches a NULL row.
    @property
    def spyware_worst_unstopped_severity(self):
        return self._verdict_grading("spyware_blocks_critical_high")

    @property
    def spyware_dns_content_list_action(self):
        return self._verdict_grading("spyware_dns_sinkholes")

    @property
    def spyware_worst_engine_action(self):
        return self._verdict_grading("spyware_inline_analysis_blocks")

    @property
    def vulnerability_blocks_critical_high(self):
        return self._verdict_value("vulnerability_blocks_critical_high")

    @property
    def vulnerability_blocks_critical_high_detail(self):
        return self._verdict_detail("vulnerability_blocks_critical_high")

    @property
    def vulnerability_blocks_brute_force(self):
        return self._verdict_value("vulnerability_blocks_brute_force")

    @property
    def vulnerability_blocks_brute_force_detail(self):
        return self._verdict_detail("vulnerability_blocks_brute_force")

    @property
    def vulnerability_inline_analysis_blocks(self):
        return self._verdict_value("vulnerability_inline_analysis_blocks")

    @property
    def vulnerability_inline_analysis_blocks_detail(self):
        return self._verdict_detail("vulnerability_inline_analysis_blocks")

    @property
    def vulnerability_exceptions_minimal(self):
        return self._verdict_value("vulnerability_exceptions_minimal")

    @property
    def vulnerability_exceptions_minimal_detail(self):
        return self._verdict_detail("vulnerability_exceptions_minimal")

    @property
    def vulnerability_inline_analysis_enabled(self):
        """PAN-VLN-003's FIRST HALF: is the profile-wide real-time analysis switch on at all?

        A fifth vulnerability assertion rather than a column, so NULL - no vulnerability profile
        reaches this rule - is carried by the same satellite mechanism the other four use. The
        detector verdict beside it grades what each engine DOES; this says whether any of it runs.
        """
        return self._verdict_value("vulnerability_inline_analysis_enabled")

    @property
    def vulnerability_inline_analysis_enabled_detail(self):
        return self._verdict_detail("vulnerability_inline_analysis_enabled")

    #: THE PROFILE A FINDING IN THIS DOMAIN TELLS AN ENGINEER TO OPEN, and what makes one profile
    #: behind forty rules recognisable as one object. Read off the satellite's own `profile_name`,
    #: which has been stored per assertion since the per-rule migration - so this is the shipped
    #: value surfaced flat, not a new column. The four vulnerability assertions resolve from one
    #: per-kind resolution and so always agree; the severity assertion is read as the canonical
    #: one rather than any of them in turn.
    #:
    #: BLANK where no profile reaches the rule AND where the name it asks for resolves to
    #: nothing - the two are told apart by `vulnerability_profile_resolved` and by the detail
    #: columns, never by this one, which is why it is carried for the sentence and claused by
    #: nothing.
    @property
    def vulnerability_profile_name(self):
        row = self.profile_verdict("vulnerability_blocks_critical_high")
        return row.profile_name if row else ""

    #: THE THREE GRADED VALUES PAN-VLN-001, -003 and -004 CALIBRATE THEIR SEVERITY WITH, each the
    #: WHICH beside one assertion's WHETHER, read exactly as the three spyware gradings above are.
    #: None may be claused on alone: an empty string matches no placement, so a rule nobody
    #: recomputed loses the ESCALATION and keeps the finding, which the boolean verdict beside it
    #: raises because its `false` clause also matches a NULL row.
    @property
    def vulnerability_severity_weakest_action(self):
        return self._verdict_grading("vulnerability_blocks_critical_high")

    @property
    def vulnerability_inline_weakest_action(self):
        return self._verdict_grading("vulnerability_inline_analysis_blocks")

    @property
    def vulnerability_widest_exemption_surface(self):
        return self._verdict_grading("vulnerability_exceptions_minimal")

    @property
    def threat_profile_in_force(self) -> dict:
        """{assertion: profile name} for the rules a finding has to name."""
        return {row.assertion: row.profile_name
                for row in self.profile_verdicts.all() if row.profile_name}

    @property
    def source_breadth_known(self) -> bool:
        """Whether the source side's breadth was established at all.

        The search layer filters this with an inverted `__isnull` on the column, because a
        property cannot appear in a WHERE clause. It is here as well so that a control TESTING
        the field has somewhere to read it from when presenting a finding: the findings sheet
        resolves a tested field against the subject model and refuses a name the model can
        neither store nor compute. Without this, PAN-POL-002 broke the security-rules findings
        page while every test passed.
        """
        return self.source_num_hosts is not None

    @property
    def destination_breadth_known(self) -> bool:
        return self.destination_num_hosts is not None

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="security_rules",
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="security_rules",
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="security_rules",
    )
    config_source = models.CharField(max_length=32, choices=CONFIG_SOURCE_CHOICES)
    effective_order = models.PositiveIntegerField()
    rule_position = models.PositiveIntegerField()
    name = models.CharField(max_length=255)
    uuid = models.CharField(max_length=64, blank=True)
    action = models.CharField(max_length=32, blank=True)
    disabled = models.BooleanField(default=False)
    rule_type = models.CharField(max_length=64, blank=True)
    description = models.TextField(blank=True)
    log_start = models.BooleanField(null=True, blank=True)
    log_end = models.BooleanField(null=True, blank=True)
    log_setting = models.CharField(max_length=128, blank=True)
    negate_source = models.BooleanField(default=False)
    negate_destination = models.BooleanField(default=False)
    raw_rule = models.JSONField(default=dict, blank=True)

    # ======================================================================================
    # THE SECURITY-POLICY DOMAIN'S COLUMNS (PAN-POL-003, 006, 008, 011, 012, 013, 015, 020,
    # 021, 022, 024). Two read a key; the rest are worked out at normalization.
    #
    # EVERY DEFAULT BELOW IS CHOSEN BY THE DIRECTION OF THE ERROR, not by what reads tidily:
    # a row nobody has recomputed must not look like a row somebody checked and found fine.
    # Where a default lands on the reassuring side anyway, the comment says so and names the
    # companion column that fires on the same rows - because a reassuring default with no
    # companion is a clean estate reported on the strength of nothing.
    # ======================================================================================

    #: The single tag the rule is GROUPED BY in the policy list. A DIFFERENT KEY from the tag
    #: list beside it (`securityruletags`), and a consumer joining tags to rules has to read
    #: both or it drops the grouping. MEASURED on 013201001475: absent from all 666 firewall
    #: rules, no group header in the grid, and a positive control wrote it, committed, and read
    #: back the BARE SCALAR `'group-tag': 'Production'`. Empty is the reportable state for
    #: PAN-POL-021's third clause, so an unfilled column raises rather than hides.
    group_tag = models.CharField(max_length=255, blank=True, default="")

    #: The name of the time window attached to the rule, or empty for a rule that is always in
    #: force. MEASURED on 013201001475: absent from all 666 firewall rules and all 630 Panorama
    #: rules, with the dialog rendering Schedule as `None` - which is RENDERED TEXT and not a
    #: placeholder, so a normalizer must never store a schedule object named `None`. Empty is
    #: PAN-POL-022's FINDING rather than its pass: a permanent rule is the thing it reports.
    schedule = models.CharField(max_length=255, blank=True, default="")

    #: How many of the three inspection kinds PAN-POL-008 names are in force on this rule, 0-3.
    #: A count rather than three clauses because the control's GRADING turns on how many are
    #: missing, and a predicate has no arithmetic over three booleans of one row. ZERO on an
    #: unrecomputed row, which is both the worst real configuration and the firing side.
    threat_profile_kinds_in_force = models.PositiveSmallIntegerField(default=0)

    #: The fourth profile kind, which `PROFILE_COVERAGE_COLUMNS` did not carry: PAN-POL-008
    #: excludes URL filtering by name and PAN-POL-020 asserts it. Same resolution as the three
    #: beside it - the rule's own `profile-setting/profiles/url-filtering` member OR the
    #: `url-filtering` member of the profile GROUP it names, resolved by name and scope. FALSE
    #: on an unrecomputed row, which means no site inspection and therefore fires.
    has_url_filtering_profile = models.BooleanField(default=False)

    #: Which of three site-inspection states this rule is in. See URL_INSPECTION_POSTURE_CHOICES
    #: for why empty is not one of them.
    url_inspection_posture = models.CharField(
        max_length=32, choices=URL_INSPECTION_POSTURE_CHOICES, blank=True, default="")

    #: How many distinct TCP and UDP ports this rule opens, over the UNION of both transport
    #: branches after expanding every service object and group it names, recursively.
    #:
    #: NULL MEANS INDETERMINATE AND NEVER ZERO - zero ports is the narrowest rule there is, so a
    #: rule whose services could not be expanded must not score as the tightest on the device.
    #: It is null for a member this pass cannot resolve to ports: `application-default`, whose
    #: ports are the ports of whatever applications the rule names and are vendor content rather
    #: than configuration; a service name that resolves to nothing; and a group this pass could
    #: not walk. `permitted_port_count_known` is the companion that fires on exactly those rows.
    permitted_port_count = models.BigIntegerField(null=True, blank=True)

    #: Whether any application this rule permits carries a published characteristic the control
    #: treats as hostile.
    #:
    #: NULL RATHER THAN FALSE, because FALSE HERE MEANS CHECKED AND CLEAN. Nothing computes this
    #: today: it needs `/config/predefined/application`, which no collector reads, and an
    #: application FILTER is a PREDICATE evaluated against a content release rather than a
    #: property of the rule - so the same rule can pass and then fail with no configuration
    #: change. Null is the state of every row in the estate and it is on the REASSURING side of
    #: PAN-POL-006's clause; what makes the gap visible is the characteristic column below being
    #: empty and placed as UNRANKED, not a companion boolean. See the stage 7 artifact.
    permits_high_risk_application = models.BooleanField(null=True, blank=True)

    #: Which published characteristic the finding turns on, as the vendor's own leaf name - the
    #: axis PAN-POL-006's severity varies with. EMPTY on an unrecomputed row, and empty is
    #: graded as UNRANKED rather than acceptable, so a rule whose applications nobody resolved
    #: produces a finding with no severity band rather than no finding.
    high_risk_application_characteristic = models.CharField(
        max_length=64, blank=True, default="")

    #: How many of this rule's two zone sides are left open - a side is open when its member
    #: list is exactly the keyword `any`. TWO on an unrecomputed row, which is the worst band: a
    #: zero would report every rule in the estate as correctly zoned before anything looked.
    open_zone_side_count = models.PositiveSmallIntegerField(default=2)

    #: Whether some rule evaluated BEFORE this one matches everything this one matches with the
    #: same decision, so this rule can never match traffic.
    #:
    #: NULL IS NOT `NOT SHADOWED`: a false here is a claim that the whole rulebase was compared.
    #: The device's own answer is unreachable - the firewall's shadow-rule warning comes only
    #: from pre-commit validation, which is a COMMIT GATE and not a view, so no collector can
    #: issue it. This column is therefore a DIFFERENT CLAIM made against a different definition
    #: of shadowing, computed from the stored rules, and `shadow_relation_computed` beside it is
    #: what says whether the comparison ran at all.
    is_shadowed_by_earlier_rule = models.BooleanField(null=True, blank=True)

    #: Whether the per-vsys shadowing pass completed for this rule's rulebase. FALSE until it
    #: has, which fires.
    shadow_relation_computed = models.BooleanField(default=False)

    #: Whether another rule reaching the same vsys has the same resolved match tuple AND the
    #: same action.
    #:
    #: FALSE IS THE REASSURING SIDE AND IT IS THE DEFAULT, which is stated here rather than
    #: hidden: a rulebase nobody compared reports as duplicate-free. A boolean has no third
    #: state and the search layer has no is-null operator, so the containment is entirely
    #: `duplicate_comparison_computed`, which fires on exactly the same rows.
    has_exact_duplicate = models.BooleanField(default=False)

    #: Whether the per-vsys duplicate pass completed for this rule's rulebase. FALSE until it
    #: has, which fires.
    duplicate_comparison_computed = models.BooleanField(default=False)

    #: How many days since this rule last matched traffic, from `show rule-hit-count`.
    #:
    #: NULL IS `NOT ESTABLISHED` AND NEVER ZERO: a rule nobody counted is not a rule that
    #: matched traffic today. MEASURED 2026-10-29 on 013201001475 and 691665AC334B458: the read
    #: answers `last-hit-timestamp: 0` for a rule that has never matched, so an epoch of 0 is
    #: parsed as NULL rather than as 1970 - which would read as the oldest rule on the device.
    days_since_last_hit = models.IntegerField(null=True, blank=True)

    #: Whether a hit-count reading for this rule can be believed at all.
    #:
    #: THIS IS WHERE A ZERO THAT IS REALLY AN UNKNOWN IS CAUGHT, and it is measured rather than
    #: argued. On 691665AC334B458, whose `rule-hit-count` key reads `no`, the hit-count read
    #: SUCCEEDS and returns `hit-count: 0, last-hit-timestamp: 0, latest: yes` for every rule -
    #: byte-identical to a counting appliance whose rules have never matched. So the reading
    #: alone cannot tell "nothing matched" from "nothing is counting", and this column is false
    #: wherever `PolicyRuleSettings.rule_hit_count_enabled` is not TRUE, wherever no reading was
    #: taken, and wherever the counter was reset inside the window being judged. FALSE fires.
    hit_count_reading_known = models.BooleanField(default=False)

    #: Whether this rule carries enough traffic to belong nearer the top of its rulebase while
    #: sitting near the bottom. NULL IS `NOT ESTABLISHED`: false would claim the ranking was run
    #: over every rule in the rulebase and found nothing out of place. A decile over all-zero
    #: hit counts is no answer rather than a weak one, so this stays null wherever
    #: `hit_count_reading_known` is false - which is every rule in this lab.
    busy_rule_placed_late = models.BooleanField(null=True, blank=True)

    #: Which kind of time window the rule's schedule carries. See SCHEDULE_KIND_CHOICES for why
    #: empty and `none` are different values.
    schedule_kind = models.CharField(
        max_length=32, choices=SCHEDULE_KIND_CHOICES, blank=True, default="")

    #: Whether the end of the schedule's date range is in the past. NULL IS `NO WINDOW, OR NOT
    #: COMPARED`; false would claim the window is still open, which is a claim about a date
    #: nobody parsed. Only the non-recurring branch has an end, so a RECURRING schedule is null
    #: here on purpose - and that is the false pass to watch for: a temporary rule carrying a
    #: repeating daily window looks time-bounded and never expires.
    schedule_window_expired = models.BooleanField(null=True, blank=True)

    @property
    def permitted_port_count_known(self) -> bool:
        """Whether this rule's open-port count was established at all.

        The same shape as `source_breadth_known` and for the same two reasons: the search layer
        filters it with an inverted `__isnull` on the column because a property cannot appear in
        a WHERE clause, and it has to exist as an ATTRIBUTE as well because the findings sheet
        resolves a tested field against the subject model and refuses a name the model can
        neither store nor compute. Not a stored column: the count's NULL *is* this false, and a
        second stored copy could disagree with it.
        """
        return self.permitted_port_count is not None

    class Meta:
        ordering = ["effective_order", "name", "id"]
        indexes = [
            models.Index(
                fields=["management_station", "enforcement_point", "effective_order", "name", "id"],
            ),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name"],
                name="integrations_unique_security_rule_name_per_point",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} / {self.name}"

    def clean(self) -> None:
        if self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError("Security rule must belong to the same management station as the enforcement point.")
        if self.source_snapshot.enforcement_point_id != self.enforcement_point_id and self.source_snapshot.appliance_id is None:
            raise ValidationError("Security rule source snapshot must belong to the enforcement point or a related appliance.")
        snapshot_station_id = (
            self.source_snapshot.management_station_id
            or getattr(self.source_snapshot.appliance, "management_station_id", None)
            or getattr(self.source_snapshot.enforcement_point, "management_station_id", None)
        )
        if snapshot_station_id != self.management_station_id:
            raise ValidationError("Security rule source snapshot must belong to the same management station.")


class SecurityRuleProfileVerdict(models.Model):
    """Whether the threat profile in force on ONE RULE satisfies ONE assertion.

    The anti-spyware and vulnerability-protection controls were profile-based until
    2026-10-12: one finding per SecurityProfile. Jason asked them to report per rule, the way
    PAN-AVW-003 already does, and for the same reason that control gives - "a profile nothing
    uses endangers nothing and a rule is what carries traffic".

    **A SATELLITE RATHER THAN COLUMNS**, which is where this diverges from PAN-AVW-003's
    `wildfire_analysis_submits_all`. Nine assertions need a verdict and a reason each, and
    eighteen columns on the busiest model in the schema - growing by two every time a profile
    control is added - is not a shape to commit to. The severity verdicts moved from columns
    to a satellite for the same reason and kept their search field names, which is the
    precedent being followed.
    
    That leaves TWO mechanisms for one idea, with PAN-AVW-003 still on columns. Recorded as an
    open question rather than fixed here: it belongs to the av-wildfire domain and this change
    was scoped to the other two.

    **THE THREE STATES ARE THE POINT, and `satisfied` is nullable to carry them:**

        True   a profile of the right kind is in force on this rule and it satisfies the
               assertion
        False  one is in force and it does NOT
        NULL   no profile of that kind reaches this rule at all

    **BOTH False AND NULL FIRE.** Jason, 2026-10-12: "The absence of a profile should create the
    finding for that profile. This is a rule across all rule security profiles."

    These shipped the other way for a few hours, on the argument that eleven controls matching
    NULL would raise roughly 8,600 findings on the lab and duplicate PAN-POL-008. That argued
    VOLUME, which is not the same thing as correctness: a rule with no anti-spyware profile is
    not getting anti-spyware inspection, so the absence is each control's own finding.
    PAN-AVW-003 had it this way from the day it was built, and was right.

    So the overlap with PAN-POL-008 is deliberate and the two say different things. PAN-POL-008
    says "this allow rule carries no security profiles at all", once. Each of these says "this
    rule gets no antivirus / anti-spyware / vulnerability inspection", and `detail` carries
    which case it is - `no <kind> profile is in force on this rule`, or the specific gap in the
    profile that IS there. They are different fixes: attach a profile, or repair one.

    NULL is still kept distinct from False rather than collapsed into it, because that
    distinction is the only thing telling a reader which fix applies.
    """

    #: One per assertion, and STABLE - a control's query names these, so they are a contract.
    #: Keyed by the control that asks, in the comment, because the name alone does not say.
    ANTIVIRUS_BLOCKS_MALWARE = "antivirus_blocks_malware"            # PAN-AVW-001
    ANTIVIRUS_INLINE_ML = "antivirus_inline_ml_blocks"               # PAN-AVW-002
    SPYWARE_SEVERITIES = "spyware_blocks_critical_high"              # PAN-SPY-001
    SPYWARE_DNS_SINKHOLE = "spyware_dns_sinkholes"                   # PAN-SPY-002
    SPYWARE_DNS_CATEGORIES = "spyware_dns_categories_enforced"       # PAN-SPY-003
    SPYWARE_INLINE = "spyware_inline_analysis_blocks"                # PAN-SPY-004
    SPYWARE_EXCEPTIONS = "spyware_exceptions_minimal"                # PAN-SPY-005
    VULNERABILITY_SEVERITIES = "vulnerability_blocks_critical_high"  # PAN-VLN-001
    VULNERABILITY_BRUTE_FORCE = "vulnerability_blocks_brute_force"   # PAN-VLN-002
    VULNERABILITY_INLINE = "vulnerability_inline_analysis_blocks"    # PAN-VLN-003
    VULNERABILITY_EXCEPTIONS = "vulnerability_exceptions_minimal"    # PAN-VLN-004
    #: PAN-VLN-003's FIRST HALF, and a twelfth assertion rather than a column on the rule, so it
    #: inherits the three-state NULL this satellite already has: NULL where no vulnerability
    #: profile reaches the rule, which the shipped compiler matches on `equals false`.
    #:
    #: Stage 3 splits that control in two - the analysis is SWITCHED ON, and each detector ENDS
    #: what it catches - and `VULNERABILITY_INLINE` above answers only the second: it reads
    #: `mica-engine-vulnerability-enabled` and not `cloud-inline-analysis`. So a profile with
    #: every detector at reset-both and the profile-wide switch off satisfied that assertion and
    #: inspected nothing in real time.
    VULNERABILITY_INLINE_ENABLED = "vulnerability_inline_analysis_enabled"  # PAN-VLN-003

    ASSERTION_CHOICES = [
        (ANTIVIRUS_BLOCKS_MALWARE, "Antivirus blocks malware on every decoder"),
        (ANTIVIRUS_INLINE_ML, "Antivirus WildFire inline ML blocks"),
        (SPYWARE_SEVERITIES, "Anti-spyware blocks critical and high severity"),
        (SPYWARE_DNS_SINKHOLE, "Anti-spyware sinkholes malicious DNS"),
        (SPYWARE_DNS_CATEGORIES, "Anti-spyware enforces malicious DNS Security categories"),
        (SPYWARE_INLINE, "Anti-spyware inline cloud analysis blocks"),
        (SPYWARE_EXCEPTIONS, "Anti-spyware threat exceptions minimal"),
        (VULNERABILITY_SEVERITIES, "Vulnerability protection blocks critical and high severity"),
        (VULNERABILITY_BRUTE_FORCE, "Vulnerability protection blocks brute-force sources"),
        (VULNERABILITY_INLINE, "Vulnerability protection inline cloud analysis blocks"),
        (VULNERABILITY_EXCEPTIONS, "Vulnerability protection exceptions minimal"),
        (VULNERABILITY_INLINE_ENABLED,
         "Vulnerability protection inline cloud analysis switched on"),
    ]

    #: Which profile kind each assertion reads, so the normalizer resolves once per kind.
    ANTIVIRUS_ASSERTIONS = (ANTIVIRUS_BLOCKS_MALWARE, ANTIVIRUS_INLINE_ML)
    SPYWARE_ASSERTIONS = (SPYWARE_SEVERITIES, SPYWARE_DNS_SINKHOLE, SPYWARE_DNS_CATEGORIES,
                          SPYWARE_INLINE, SPYWARE_EXCEPTIONS)
    VULNERABILITY_ASSERTIONS = (VULNERABILITY_SEVERITIES, VULNERABILITY_BRUTE_FORCE,
                                VULNERABILITY_INLINE, VULNERABILITY_EXCEPTIONS,
                                VULNERABILITY_INLINE_ENABLED)

    security_rule = models.ForeignKey(
        SecurityRule, on_delete=models.CASCADE, related_name="profile_verdicts")
    assertion = models.CharField(max_length=64, choices=ASSERTION_CHOICES)
    #: The profile the verdict was read from, resolved by name AND scope - blank when none
    #: reaches this rule. Carried so a finding can name what to go and fix, and so the same
    #: profile appearing behind forty rules is recognisable as one object.
    profile_name = models.CharField(max_length=128, blank=True)
    satisfied = models.BooleanField(null=True)
    #: Why, in words. Empty only when `satisfied` is True.
    detail = models.CharField(max_length=255, blank=True)
    #: THE GRADED VALUE beside this verdict - the one the control's severity grading varies with.
    #: `critical` for a severity band, `alert` for a DNS action, `drop` for an engine action: a
    #: different vocabulary per assertion, which is why it is ONE column and not three.
    #:
    #: Three named columns on this model would be three nulls on every row of the other eight
    #: assertions, growing by one every time a graded control is added - the same argument that
    #: made the verdict a satellite rather than eighteen columns on SecurityRule. It follows
    #: `detail`, which is one column on this model read through nine named properties on the rule,
    #: and which the search layer already reaches per assertion as `<field>_detail`.
    #:
    #: BLANK AND NOT NULL, deliberately. The search layer has no is-null operator, so a positive
    #: clause over a nullable column never matches and the control reports a clean estate - and
    #: `is_empty`, the one operator that is ABOUT absence, compiles to `filter(field="")` in every
    #: per-model compiler and reaches no NULL. A blank matches no severity placement either way,
    #: which is the direction this field's own absence has to point.
    #:
    #: EMPTY ON EVERY ASSERTION THAT HAS NO GRADING, which is most of them, and empty on a verdict
    #: whose profile could not be resolved - there is no value to name, and naming one would hand
    #: a grading a severity it has not earned.
    grading_value = models.CharField(max_length=32, blank=True)

    class Meta:
        ordering = ["security_rule", "assertion"]
        indexes = [models.Index(fields=["assertion", "satisfied"])]
        constraints = [
            models.UniqueConstraint(
                fields=["security_rule", "assertion"],
                name="integrations_unique_profile_verdict_per_rule"),
        ]

    def __str__(self) -> str:
        state = {True: "satisfied", False: "FAILED", None: "no claim"}[self.satisfied]
        return f"{self.security_rule} / {self.assertion}: {state}"


class SecurityRuleValue(models.Model):
    security_rule = models.ForeignKey(
        SecurityRule,
        on_delete=models.CASCADE,
        related_name="%(class)ss",
    )
    value = models.CharField(max_length=255)
    prov = models.CharField(max_length=128, blank=True)
    position = models.PositiveIntegerField()

    class Meta:
        abstract = True
        ordering = ["position", "id"]

    def __str__(self) -> str:
        return self.value


class SecurityRuleFromZone(SecurityRuleValue):
    pass


class SecurityRuleToZone(SecurityRuleValue):
    pass


class SecurityRuleAddressRef(models.Model):
    class RefType(models.TextChoices):
        ADDRESS_OBJECT = "address_object", "Address Object"
        STATIC_ADDRESS_GROUP = "static_address_group", "Static Address Group"
        DYNAMIC_ADDRESS_GROUP = "dynamic_address_group", "Dynamic Address Group"
        ANY = "any", "Any"
        REGION = "region", "Region"

    raw_value = models.CharField(max_length=255)
    position = models.PositiveIntegerField()
    ref_type = models.CharField(max_length=32, choices=RefType.choices)
    address_object = models.ForeignKey(
        "integrations.AddressObject",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    address_group = models.ForeignKey(
        "integrations.AddressGroup",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    region = models.ForeignKey(
        "integrations.Region",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )

    class Meta:
        abstract = True
        ordering = ["position", "id"]

    def clean(self) -> None:
        if self.ref_type == self.RefType.ADDRESS_OBJECT:
            if self.address_object is None or self.address_group is not None:
                raise ValidationError(
                    "Address-object refs require address_object and must not set address_group."
                )
            return

        if self.ref_type == self.RefType.STATIC_ADDRESS_GROUP:
            if self.address_object is None or self.address_group is None:
                raise ValidationError(
                    "Static-address-group refs require both address_object and address_group."
                )
            return

        if self.ref_type == self.RefType.DYNAMIC_ADDRESS_GROUP:
            if self.address_object is not None or self.address_group is None:
                raise ValidationError(
                    "Dynamic-address-group refs require address_group and must not set address_object."
                )
            return

        if self.ref_type == self.RefType.ANY:
            if self.address_object is None or self.address_group is not None:
                raise ValidationError(
                    "Any refs require address_object and must not set address_group."
                )
            if not self.address_object.is_any:
                raise ValidationError("Any refs must point to an address object marked is_any.")
            return

        if self.ref_type == self.RefType.REGION:
            if self.address_object is not None or self.address_group is not None:
                raise ValidationError(
                    "Region refs must not set address_object or address_group. "
                    "region may be null (builtin country/region code) or set (custom region object)."
                )
            return

        raise ValidationError("Unsupported address ref type.")

    def __str__(self) -> str:
        target = self.address_group or self.address_object or self.region or self.raw_value
        return f"{self.raw_value} -> {target}"


class SecurityRuleSourceAddressRef(SecurityRuleAddressRef):
    security_rule = models.ForeignKey(
        SecurityRule,
        on_delete=models.CASCADE,
        related_name="source_address_refs",
    )

    class Meta(SecurityRuleAddressRef.Meta):
        indexes = [
            models.Index(fields=["security_rule", "ref_type"]),
            models.Index(fields=["address_object"]),
            models.Index(fields=["address_group"]),
            models.Index(fields=["region"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                        address_object__isnull=False,
                        address_group__isnull=True,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.STATIC_ADDRESS_GROUP,
                        address_object__isnull=False,
                        address_group__isnull=False,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.DYNAMIC_ADDRESS_GROUP,
                        address_object__isnull=True,
                        address_group__isnull=False,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.ANY,
                        address_object__isnull=False,
                        address_group__isnull=True,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.REGION,
                        address_object__isnull=True,
                        address_group__isnull=True,
                    )
                ),
                name="integrations_valid_source_address_ref_shape",
            ),
        ]


class SecurityRuleDestinationAddressRef(SecurityRuleAddressRef):
    security_rule = models.ForeignKey(
        SecurityRule,
        on_delete=models.CASCADE,
        related_name="destination_address_refs",
    )

    class Meta(SecurityRuleAddressRef.Meta):
        indexes = [
            models.Index(fields=["security_rule", "ref_type"]),
            models.Index(fields=["address_object"]),
            models.Index(fields=["address_group"]),
            models.Index(fields=["region"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                        address_object__isnull=False,
                        address_group__isnull=True,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.STATIC_ADDRESS_GROUP,
                        address_object__isnull=False,
                        address_group__isnull=False,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.DYNAMIC_ADDRESS_GROUP,
                        address_object__isnull=True,
                        address_group__isnull=False,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.ANY,
                        address_object__isnull=False,
                        address_group__isnull=True,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.REGION,
                        address_object__isnull=True,
                        address_group__isnull=True,
                    )
                ),
                name="integrations_valid_destination_address_ref_shape",
            ),
        ]


class SecurityRuleTag(SecurityRuleValue):
    """The tags on one rule, one row per member - PAN-POL-021 and PAN-POL-022.

    A MEMBER SATELLITE rather than a column, because the key is a member list and that is how
    every other member list on this model is stored. It carries the plain `prov = CharField` the
    member models use, per CLAUDE.md's provenance section, not a `FieldProvenance` row.

    AN EMPTY SET IS THE STATE PAN-POL-021 REPORTS, so a rule nobody tagged and a rule nobody
    normalized read the same way and the finding is raised either way. MEASURED on 013201001475:
    `tag` is absent from all 666 firewall rules with the grid's Tags cell empty for every one,
    and a positive control wrote `tag=Production`, committed, read it back and deleted it.

    WHAT THE TAG ITSELF CARRIES IS NOT HERE AND IS THE DOMAIN'S REAL GAP: five of this domain's
    controls ask for a business reason, an approver or an expiry, and the tag ENTRY has two
    fields and none of them is an owner, an expiry or a type. So a bypass and a deliberate,
    bounded exception are the same configuration, and every finding on those controls is
    qualified rather than decided.
    """


class SecurityRuleSourceUser(SecurityRuleValue):
    pass


class SecurityRuleApplication(SecurityRuleValue):
    pass


class SecurityRuleService(SecurityRuleValue):
    pass


class SecurityRuleCategory(SecurityRuleValue):
    pass


class SecurityRuleSourceHip(SecurityRuleValue):
    pass


class SecurityRuleDestinationHip(SecurityRuleValue):
    pass


class SecurityRuleSaasUser(SecurityRuleValue):
    pass


class SecurityRuleSaasTenant(SecurityRuleValue):
    pass


class SecurityRuleProfileGroup(SecurityRuleValue):
    pass


class SecurityRuleProfile(SecurityRuleValue):
    profile_type = models.CharField(max_length=64)

    class Meta(SecurityRuleValue.Meta):
        ordering = ["profile_type", "position", "id"]

    def __str__(self) -> str:
        return f"{self.profile_type}: {self.value}"
