"""Password profiles - PAN-AUTH-026's subject.

Lives ONLY at `/config/mgt-config/password-profile`, so this is appliance-anchored with NO scope
column, unlike authentication profiles and the certificate objects. Measured 2026-09-04:
`shared/password-profile` and `vsys/entry/password-profile` are both rejected outright, and
`mgt-config` itself does not exist under a vsys.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class PasswordProfile(ProvenancedMixin, SyncTrackedModel):
    """One password profile, with the global policy it would override.

    A password profile OVERRIDES the global Minimum Password Complexity settings for the
    accounts it is applied to - Web Interface Help p.822 - so a profile is not merely another
    place the same values live. It is an exemption, and the question PAN-AUTH-026 asks is
    whether the exemption is weaker than what it replaces.

    That question cannot be answered from this row alone, so the global values in force on the
    same appliance at the same collection are recorded ALONGSIDE the profile's own. They are
    facts, not verdicts: what the global policy was. Whether being weaker is a FINDING, and how
    bad, stays in OptivEdgeAssessments where every other verdict lives.

    `weakens_global_expiration` is the comparison itself, and it is stored because it cannot be
    expressed as a query over one row - the search layer compares a field to a LITERAL, and only
    this control in the whole corpus needs field-to-field. Building a general capability for one
    control would be the more expensive mistake.

    THE COMPARISON IS NOT `profile > global`. Zero is a sentinel on BOTH sides: 0 means the
    password never expires, which is the weakest possible setting rather than the strictest. The
    lab holds exactly the case that breaks the naive reading - a profile with expiration-period
    365 on a device whose global is 0. Numerically larger, semantically STRONGER, and the corpus
    note "flag any larger value" would report it wrongly.
    """

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="password_profiles")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="password_profiles")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="password_profiles", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="password_profiles")

    #: Up to 31 characters, per the Help. The other named objects allow 64.
    name = models.CharField(max_length=64)

    #: The profile's own four keys - the same four the global policy carries, which is what
    #: makes it an override rather than a different setting. Ranges from the CLI grammar:
    #: expiration-period 0-365, warning 0-30, post-expiration login count 0-3.
    expiration_period = models.PositiveIntegerField(default=0)
    expiration_warning_period = models.PositiveIntegerField(default=0)
    post_expiration_admin_login_count = models.PositiveIntegerField(default=0)
    post_expiration_grace_period = models.PositiveIntegerField(default=0)

    #: The global policy in force on this appliance at the same collection. A fact about the
    #: device, recorded here because the profile's own values mean nothing without it.
    global_expiration_period = models.PositiveIntegerField(default=0)

    #: True when this profile's expiration is EFFECTIVELY longer than the global one, with 0
    #: treated as "never expires" on both sides:
    #:     profile 0, global non-zero   -> weaker  (this profile never expires; the global did)
    #:     both non-zero, profile larger -> weaker
    #:     global 0                      -> NOT weaker (nothing can be weaker than never)
    weakens_global_expiration = models.BooleanField(default=False)

    class Meta:
        ordering = ["management_station__hostname", "appliance__hostname", "name"]
        indexes = [
            models.Index(fields=["appliance"]),
            models.Index(fields=["name"]),
            models.Index(fields=["weakens_global_expiration"]),
        ]
        constraints = [
            models.UniqueConstraint(fields=["appliance", "name"],
                                    name="unique_password_profile_per_appliance"),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.name}"


def expiration_weakens(profile_period: int, global_period: int) -> bool:
    """Does `profile_period` weaken `global_period`? Zero means NEVER EXPIRES on both sides.

    Free function so the rule has one home and can be tested without a database.
    """
    if global_period == 0:
        # The global policy already never expires. No profile can be weaker than that.
        return False
    if profile_period == 0:
        return True
    return profile_period > global_period
