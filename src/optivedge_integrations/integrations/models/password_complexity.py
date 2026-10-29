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

ELEVEN OF THE THIRTEEN DEFAULTS ARE THE INSECURE ONE - flag off, every number 0 - and absent is
expanded to it rather than left null. PAN-OS never writes these keys: the UI stores only the flag
when an administrator enables complexity, and a commit does not materialise the rest. On those
eleven a 0 is the FINDING value, so materialising it is what makes an unknown fire, and a
nullable column would only invite a query that treats NULL as satisfied.

THE TWO POST-EXPIRATION KEYS RUN THE OTHER WAY AND ARE THEREFORE NULLABLE. On
`post_expiration_admin_login_count` (PAN-AUTH-012) and `post_expiration_grace_period`
(PAN-AUTH-013) the COMPLIANT value is 0, so expanding an absent key to 0 stores the reassuring
answer about a key nobody has measured - "we never asked" rendered as "we asked and it was
fine". Both shipped clauses are `is greater than 0`, which a stored 0 and a NULL both fail, so
the nullability changes no verdict; what it changes is that the row no longer asserts a value
nobody read. The absence is REPORTED by the `*_unknown` companion beside each one, which
defaults True and fires on its own. An earlier version of this docstring said there was "no
state where a null would mean something a 0 does not", which is true of the eleven and false of
these two.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class PasswordComplexityPolicy(ProvenancedMixin, SyncTrackedModel):
    """The global minimum password complexity in force on one appliance."""

    #: Computed here: the two absence flags, which are read off whether the parse stored a
    #: value and have no payload key of their own. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "post_expiration_admin_login_count_unknown",
        "post_expiration_grace_period_unknown",
    )

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

    #: PAN-AUTH-012 and 013, and the two keys on this node whose STRICTEST value is 0. NULL
    #: means the key was absent and nothing was inferred - `Implicit.not_assumed`, which
    #: records `not_configured` provenance rather than a vendor default nobody measured.
    #: Read the companion flag beside each, never the null: the query layer has no is-null
    #: operator, so a clause cannot tell a NULL from an unsatisfied comparison.
    post_expiration_admin_login_count = models.PositiveIntegerField(null=True, blank=True)
    post_expiration_grace_period = models.PositiveIntegerField(null=True, blank=True)

    #: The companion for each of the two above: True when nothing was stored for it, so the
    #: appliance reports "we did not read this" instead of passing on a null. DEFAULT TRUE,
    #: which is the firing side: a row written before the recompute declares itself unread.
    post_expiration_admin_login_count_unknown = models.BooleanField(default=True)
    post_expiration_grace_period_unknown = models.BooleanField(default=True)

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
