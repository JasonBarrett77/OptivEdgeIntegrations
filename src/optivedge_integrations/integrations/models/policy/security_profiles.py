"""Objects > Security Profiles (Anti-Spyware, Vulnerability Protection) and Security Profile Groups.

Subjects of PAN-SPY-001 and PAN-VLN-001. Both are policy objects in the PAN-OS sense - they live
under `vsys/entry/profiles` or `shared/profiles`, arrive from Panorama through the pushed reads,
and a rule names them - so they scope exactly like address objects: vsys scope on the
enforcement point, shared scope on the appliance group, vendor scope synthesized per point. See
`ScopedPolicyObject`.

ONE MODEL FOR BOTH PROFILE TYPES, with `kind`. They are one shape - an ordered rule list whose
entries match on severity and carry an action - and one verdict, computed the same way. The
vulnerability rule adds `host`, `cve` and `vendor-id`, which only change which rules can match,
and that is decided in normalization, not stored as columns.

THE VERDICT IS ORDER-INDEPENDENT (Jason, 2026-09-11). A severity is blocked only when a
catch-all rule covers it - client AND server, for vulnerability - and every rule that can match
it takes a blocking action. No document says whether profile rules are first-match, and this
reading does not need to know: it cannot pass a weak profile. Its cost is that a non-blocking rule
sitting BELOW a broad blocking one still fails the severity, where first-match would never reach
it. `blocking` is drop, reset-client, reset-server, reset-both and block-ip - a deviation from the
corpus minimum, which names reset-both alone.

PREDEFINED PROFILES ARE ROWS TOO. `default` and `strict` ship with the device, live under
`/config/predefined/profiles` rather than in the merged config, and are what a rule uses when
nobody built a custom profile. They are assessed only when something USES them - a rule or a
profile group names them - which is what `is_used` records. An unused `default` is not a finding
about the estate; a rule protected by it is.
"""

from __future__ import annotations

from django.db import models

from ..collected import ApplianceGroup, EnforcementPoint, ManagementStation
from .objects import ScopedPolicyObject


class SecurityProfile(ScopedPolicyObject):

    #: Computed here: severity verdicts over the rule list, and the referrer walk. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "is_predefined",
        "rule_count",
        "threat_exception_count",
        "critical_blocked",
        "critical_detail",
        "high_blocked",
        "high_detail",
        "medium_blocked",
        "medium_detail",
        "referrer_count",
        "is_used",
    )
    KIND_SPYWARE = "spyware"
    KIND_VULNERABILITY = "vulnerability"
    KIND_CHOICES = [
        (KIND_SPYWARE, "Anti-Spyware"),
        (KIND_VULNERABILITY, "Vulnerability Protection"),
    ]

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE, related_name="security_profiles")
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE, related_name="security_profiles",
        null=True, blank=True)
    appliance_group = models.ForeignKey(
        ApplianceGroup, on_delete=models.CASCADE, related_name="security_profiles",
        null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="security_profiles")

    kind = models.CharField(max_length=16, choices=KIND_CHOICES)
    description = models.TextField(blank=True)
    is_predefined = models.BooleanField(default=False)
    rule_count = models.PositiveIntegerField(default=0)
    threat_exception_count = models.PositiveIntegerField(default=0)

    #: One verdict per severity the controls read, and the reason beside it - the tab has to be
    #: able to say WHY a severity is not blocked, because two profiles failing the same severity
    #: can fail it for different reasons (an alert rule, or no catch-all rule at all).
    critical_blocked = models.BooleanField(default=False)
    critical_detail = models.CharField(max_length=255, blank=True)
    high_blocked = models.BooleanField(default=False)
    high_detail = models.CharField(max_length=255, blank=True)
    #: Medium is the corpus PREFERRED value, not its minimum. Carried for the tab and for an
    #: assessor's own query; no control fires on it.
    medium_blocked = models.BooleanField(default=False)
    medium_detail = models.CharField(max_length=255, blank=True)

    #: Rules and profile groups that name this definition, resolved within their own scope
    #: first (vsys, then shared, then predefined). A count and a flag rather than the list,
    #: because a finding rests on a column; `referrers` is for the tab.
    referrer_count = models.PositiveIntegerField(default=0)
    is_used = models.BooleanField(default=False)
    referrers = models.JSONField(default=list, blank=True)

    raw_profile = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["kind", "name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "kind", "name", "precedence_rank"]),
            models.Index(fields=["appliance_group", "kind", "name", "precedence_rank"]),
            models.Index(fields=["enforcement_point", "namespace_type", "namespace_value"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "kind", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_per_point_namespace",
            ),
            models.UniqueConstraint(
                fields=["appliance_group", "kind", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_per_group_namespace",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.owner} / {self.kind} / {self.namespace_key} / {self.name}"


class SecurityProfileGroup(ScopedPolicyObject):
    """Objects > Security Profile Groups. Modelled because it is how profiles reach rules: on the
    lab every Panorama-shared rule protection arrives through a group, and a predefined profile
    counts as used when a group names it. Not assessed itself."""

    #: Computed here: referenced but never defined. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE, related_name="security_profile_groups")
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE, related_name="security_profile_groups",
        null=True, blank=True)
    appliance_group = models.ForeignKey(
        ApplianceGroup, on_delete=models.CASCADE, related_name="security_profile_groups",
        null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="security_profile_groups")

    spyware_profile = models.CharField(max_length=255, blank=True)
    vulnerability_profile = models.CharField(max_length=255, blank=True)
    #: Every profile type the group names, `{type: [names]}` - antivirus, URL filtering and the
    #: rest are read here so their controls do not need a second walk. Not searchable.
    members = models.JSONField(default=dict, blank=True)
    raw_group = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "name", "precedence_rank"]),
            models.Index(fields=["appliance_group", "name", "precedence_rank"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_group_per_point_namespace",
            ),
            models.UniqueConstraint(
                fields=["appliance_group", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_group_per_group_namespace",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.owner} / {self.namespace_key} / {self.name}"
