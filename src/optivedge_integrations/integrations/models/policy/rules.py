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
        "wildfire_analysis_submits_all",
        "wildfire_analysis_detail",
    )
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
    ]

    #: Which profile kind each assertion reads, so the normalizer resolves once per kind.
    ANTIVIRUS_ASSERTIONS = (ANTIVIRUS_BLOCKS_MALWARE, ANTIVIRUS_INLINE_ML)
    SPYWARE_ASSERTIONS = (SPYWARE_SEVERITIES, SPYWARE_DNS_SINKHOLE, SPYWARE_DNS_CATEGORIES,
                          SPYWARE_INLINE, SPYWARE_EXCEPTIONS)
    VULNERABILITY_ASSERTIONS = (VULNERABILITY_SEVERITIES, VULNERABILITY_BRUTE_FORCE,
                                VULNERABILITY_INLINE, VULNERABILITY_EXCEPTIONS)

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
