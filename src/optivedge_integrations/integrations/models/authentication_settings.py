"""Device > Setup > Management > Authentication Settings - PAN-AUTH-014 to 017's subject.

The second cluster cut out of `DeviceConfigurationProfile`, which is being retired in favour of
one model per control cluster. See `password_complexity.py` for why the cut follows the control
line rather than the PAN-OS screen: Device > Setup is ten sub-tabs and Management alone has
thirteen sections, so a model per screen would be nearly as coarse as the aggregate.

FOUR OF THE SCREEN'S ELEVEN FIELDS. The section also carries Authentication Profile,
Authentication Profile (Non-UI), Certificate Profile, API Keys Last Expired, API Key
Certificate, Max Session Count and Max Session Time. The three profile bindings are read
elsewhere - the authentication-profile referrer walk uses them to decide which profiles are
administrator-bound - and the rest are not normalized at all. They are absent here rather than
nulled: nothing has read them, so a column would assert a fact nobody has measured.

EVERY ZERO MEANS SOMETHING DIFFERENT, and none of them mean "strict":

    lockout_failed_attempts    0 is UNLIMITED ATTEMPTS, the worst value available
    lockout_time_minutes       0 is locked until an administrator releases it - the STRICTEST
    api_key_lifetime_minutes   0 is a key that never expires
    idle_timeout_minutes       0 is no idle timeout; the vendor default is 60, not 0

A page or a query that treats these four alike gets two of them backwards. PAN-AUTH-014 and 015
are the pair that proves it - `failed-attempts 2` with `lockout-time 0` locks the account and
holds it, which the Help denies on two separate pages and which was measured false on both.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class AuthenticationSettings(ProvenancedMixin, SyncTrackedModel):
    """The device-wide administrator authentication settings on one appliance."""

    #: Computed here: the lockout-duration absence flag, read off whether the parse stored a
    #: value. It has no payload key of its own. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "lockout_time_minutes_unknown",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="authentication_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="authentication_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="authentication_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="authentication_settings")

    #: PAN-AUTH-016. Vendor default 60, and 0 means no timeout at all.
    idle_timeout_minutes = models.PositiveIntegerField(default=60)
    #: PAN-AUTH-014. Named without the `admin_` prefix the aggregate needed: on a model that IS
    #: the administrator settings the prefix says nothing, and `AuthenticationProfile` carries
    #: the same two names for the per-profile lockout - which is the right parallel, because a
    #: query always names its model and the two settings really are the same idea at two scopes.
    lockout_failed_attempts = models.PositiveIntegerField(default=0)
    #: PAN-AUTH-015, and the one field on this model whose 0 is the STRICTEST value rather
    #: than the weakest - so an absent key expanded to 0 would store the compliant answer
    #: about a setting nobody read. NULLABLE for that reason: `Implicit.not_assumed` stores
    #: nothing and records `not_configured`, and the companion flag below carries the
    #: reporting. The shipped clause is `greater than 0 AND less than 30`, which a stored 0
    #: and a NULL both fail, so the nullability changes no verdict - it stops the row
    #: asserting a value nobody measured.
    #:
    #: THE VENDOR CONTRADICTS ITSELF ABOUT WHICH END OF THE RANGE 0 SITS AT - Help p.707 says
    #: both, two lines apart - and the project measured the strict reading on 2026-09-04.
    #: Neither this model nor the control ranks the two readings.
    lockout_time_minutes = models.PositiveIntegerField(null=True, blank=True)
    #: True when nothing was stored for `lockout_time_minutes`. DEFAULT TRUE, the firing side:
    #: a row written before the recompute declares itself unread rather than compliant.
    lockout_time_minutes_unknown = models.BooleanField(default=True)
    #: PAN-AUTH-017. 0 is a key that never expires.
    api_key_lifetime_minutes = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_authentication_settings_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} authentication settings"
