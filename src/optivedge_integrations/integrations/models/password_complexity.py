"""Device > Setup > Management > Minimum Password Complexity - PAN-AUTH-001 to 013's subject.

THE FIRST CUT OUT OF `DeviceConfigurationProfile`, deleted on 2026-09-11 after the last. It held one
row per appliance spanning three different PAN-OS screens - Setup > Management, Setup > Services
and High Availability - and the split follows the CONTROL line rather than the screen, because
Device > Setup is ten sub-tabs deep and a model per screen would be nearly as coarse. Jason,
2026-09-10: "the cleaner cut is along the control line, because that part of the UI is very
large."

Sixteen fields, thirteen of which a completed control reads. The other three -
`block_repeated_characters`, `change_on_first_login`, `change_period_block` - are kept even
though no query names them, on the same principle that keeps `ssl_tls_max_version`: they are
part of the section this model renders, and a row that shows two thirds of a screen invites the
reader to conclude the rest is unset. A CLUSTER earns a model by having a control; inside one,
the section is what the row is.

Appliance-anchored with no scope column: `mgt-config/password-complexity` sits at the TOP of the
merged config beside `devices` and `shared`, and `mgt-config` does not exist under a vsys -
measured 2026-09-04 while building `PasswordProfile`, which lives one node away at
`mgt-config/password-profile` and OVERRIDES these values for the accounts it is applied to.

EVERY DEFAULT IS THE INSECURE ONE - flag off, every number 0 - and absent is expanded to it
rather than left null. PAN-OS never writes these keys: the UI stores only the flag when an
administrator enables complexity, and a commit does not materialise the rest. So there is no
state where a null would mean something a 0 does not, and a nullable column would only invite a
query that treats NULL as satisfied.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class PasswordComplexityPolicy(ProvenancedMixin, SyncTrackedModel):
    """The global minimum password complexity in force on one appliance."""

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="password_complexity_policies")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="password_complexity_policies")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="password_complexity_policies", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="password_complexity_policies")

    #: The master switch. Off means none of the rest is enforced, whatever it says - so a
    #: control reading a minimum in isolation reports a policy the device is not applying.
    #: PAN-AUTH-001.
    enabled = models.BooleanField(default=False)

    #: PAN-AUTH-002 to 006. Zero is "no minimum", the weakest value, on every one of them.
    minimum_length = models.PositiveIntegerField(default=0)
    minimum_uppercase = models.PositiveIntegerField(default=0)
    minimum_lowercase = models.PositiveIntegerField(default=0)
    minimum_numeric = models.PositiveIntegerField(default=0)
    minimum_special = models.PositiveIntegerField(default=0)

    #: PAN-AUTH-007 and 008.
    block_username_inclusion = models.BooleanField(default=False)
    new_differs_by_characters = models.PositiveIntegerField(default=0)

    #: PAN-AUTH-009. "Prevent Password Reuse Limit" on the screen.
    history_count = models.PositiveIntegerField(default=0)

    #: PAN-AUTH-010 to 013, nested under `password-change` in the configuration. Zero means
    #: the password NEVER EXPIRES on `expiration_period`, which is the weakest setting and not
    #: the strictest - the same sentinel PasswordProfile records for the override case.
    expiration_period = models.PositiveIntegerField(default=0)
    expiration_warning_period = models.PositiveIntegerField(default=0)
    post_expiration_admin_login_count = models.PositiveIntegerField(default=0)
    post_expiration_grace_period = models.PositiveIntegerField(default=0)

    #: On the screen, read by no control yet. Kept so the row is the section.
    block_repeated_characters = models.PositiveIntegerField(default=0)
    change_on_first_login = models.BooleanField(default=False)
    change_period_block = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_password_complexity_policy_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} minimum password complexity"
