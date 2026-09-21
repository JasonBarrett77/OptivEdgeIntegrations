"""Administrator accounts - PAN-AUTH-019, 021, 022.

Lives ONLY at `/config/mgt-config/users`, so this is appliance-anchored with NO scope column,
the same shape as `PasswordProfile` and for the same reason: `mgt-config` sits at the top of
the merged config beside `devices` and `shared`, and does not exist under a vsys.

Measured 2026-09-08 on fw-core-tpa-a, and the measurements are why several fields look the way
they do:

**The role is not one shape, it is three.** `permissions/role-based` offers seven children and
they take three different forms - a yes/no leaf (`superuser`, `superreader`), a member list of
device names (`deviceadmin`, `devicereader`), and an entry per device carrying a vsys member
list (`vsysadmin`, `vsysreader`) - plus `custom`, which carries `vsys` and `profile`. One enum
column cannot hold that, so `role_type` names the branch and `role_scope` carries whatever the
branch was qualified by. *`__telemetryuser` reads `{"deviceadmin": {"member":
["localhost.localdomain"]}}` while `oep-authtest` reads `{"devicereader": null}` - same shape,
one populated and one bare, and both are valid.*

**`@ptpl` on the users CONTAINER says nothing about the entries.** It names A template that
contributes to the container and does not partition what is inside it. fw-core-tpa-a and -b
report `{"@ptpl": "shared-multi-vsys"}` over entries that carry no marker at all - that template
holds an EMPTY `users` node, which is enough to mark the container. pan-fw-111 reports
`{"@ptpl": "creds_tpl"}` over nine entries of which exactly two are marked. Either way, read the
ENTRY. This is a general template-provenance rule rather than anything about administrators; see
OptivEdgeIntegrations' `read-template-provenance.md`.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class AdminUser(ProvenancedMixin, SyncTrackedModel):
    """One administrator account under `mgt-config/users`."""

    #: Computed here: verdicts over the account, and a cohort counted across the appliance. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "is_superuser",
        "superuser_cohort_size",
        "has_password",
        "has_public_key",
        "authentication_is_external",
        "centrally_authenticated",
    )

    class AuthenticationBinding(models.TextChoices):
        #: `mgt-config/users/entry/authentication-profile`.
        USER = "user", "Per-account"
        #: `deviceconfig/system/authentication-profile` - covers every account without its own.
        DEVICE = "device", "Device-wide"
        NONE = "none", "Local database"

    class RoleType(models.TextChoices):
        SUPERUSER = "superuser", "Superuser"
        SUPERREADER = "superreader", "Superuser (read-only)"
        DEVICEADMIN = "deviceadmin", "Device administrator"
        DEVICEREADER = "devicereader", "Device administrator (read-only)"
        VSYSADMIN = "vsysadmin", "Virtual system administrator"
        VSYSREADER = "vsysreader", "Virtual system administrator (read-only)"
        CUSTOM = "custom", "Role based"
        NONE = "none", "No role"

    #: Most privileged first. An account carries one role in the UI; the order exists so a
    #: payload holding two never resolves to the weaker of them.
    ROLE_PRECEDENCE = (
        RoleType.SUPERUSER, RoleType.DEVICEADMIN, RoleType.VSYSADMIN,
        RoleType.SUPERREADER, RoleType.DEVICEREADER, RoleType.VSYSREADER,
        RoleType.CUSTOM,
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE, related_name="admin_users")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="admin_users")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="admin_users", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="admin_users")

    name = models.CharField(max_length=64)
    description = models.CharField(max_length=255, blank=True)

    role_type = models.CharField(max_length=16, choices=RoleType.choices, default=RoleType.NONE)
    #: What the role was qualified BY, as the device stated it: the device names a
    #: deviceadmin covers, the vsys list a vsysadmin covers, or the vsys list on a custom
    #: role. Empty for the roles that take no qualifier. Display only - no control reads it.
    role_scope = models.CharField(max_length=255, blank=True)
    #: The admin-role profile a `custom` role points at. May name a PREDEFINED role rather
    #: than one under `shared/admin-role`: completing the field on a device with no custom
    #: roles at all returned `auditadmin`, `securityadmin` and `cryptoadmin`.
    custom_role_profile = models.CharField(max_length=64, blank=True)

    #: PAN-AUTH-022 counts these. A column rather than a query over role_type because the
    #: control grades on the COUNT, and a count is not a property of any one row.
    is_superuser = models.BooleanField(default=False)
    #: How many superuser accounts this account is one of - the appliance's superuser total
    #: for a superuser, and 0 for an account holding any other role. Zero is literally
    #: correct there: a devicereader belongs to no superuser cohort.
    #:
    #: Stored on the row, like `PasswordProfile.global_expiration_period`, because the search
    #: layer compares a field to a LITERAL and PAN-AUTH-022's assertion is about a total.
    #: Defined to be 0 off-cohort so every query on that control reads this one field and a
    #: threshold is the only number in play - the graded severities are non-baseline queries
    #: over the same column (3 to 5 low, 6 to 10 medium).
    superuser_cohort_size = models.PositiveIntegerField(default=0)

    #: The PER-USER binding, straight off the entry. Empty means the entry names no profile -
    #: which is not the same as the account having none; see `effective_authentication_profile`.
    authentication_profile_name = models.CharField(max_length=64, blank=True)

    #: The profile that actually governs this account: the per-user binding when the entry
    #: names one, otherwise the device-wide `deviceconfig/system/authentication-profile`.
    #: Empty when neither is set.
    effective_authentication_profile = models.CharField(max_length=64, blank=True)
    authentication_binding = models.CharField(
        max_length=8, choices=AuthenticationBinding.choices, default=AuthenticationBinding.NONE)

    #: PAN-AUTH-020's whole assertion, resolved through whichever profile governs this account.
    #:
    #: FALSE WHEN NO PROFILE GOVERNS IT AT ALL, and that is the point rather than a default
    #: standing in for missing data: an administrator authenticating against the local database
    #: has no second factor, so a stolen password alone reaches the management plane. That is
    #: what the control asserts, and it is true whether the reason is a profile without MFA or
    #: no profile at all.
    #:
    #: It is a column on the USER because the finding is about the user. Two administrators on
    #: one appliance can sit behind different profiles, and one row per profile cannot say which
    #: people are exposed - Jason, 2026-09-08: "A row is a specific user, and its values are the
    #: value checks."
    admin_mfa_enabled = models.BooleanField(default=False)
    #: Display only. No control queries this - a finding rests on a column.
    admin_mfa_factors = models.JSONField(default=list, blank=True)
    #: True when a profile is bound and no row for it could be found on this appliance. The
    #: control still reports (nothing proves MFA is on), and the tab says so rather than
    #: rendering "no MFA" as though it had been read.
    authentication_profile_unresolved = models.BooleanField(default=False)
    #: The effective binding names an authentication SEQUENCE rather than a profile. Every
    #: administrative binding accepts one (measured 2026-09-11); `authentication_is_external`
    #: is then true only when every member is external.
    authentication_sequence = models.BooleanField(default=False)
    password_profile_name = models.CharField(max_length=64, blank=True)
    #: WEB INTERFACE ONLY - Help p.825, "Use only client certificate authentication (web)". It
    #: does not govern the CLI, so it neither replaces a stored credential nor centralizes the
    #: account, and it clears nothing.
    client_certificate_only = models.BooleanField(default=False)

    #: `phash` present - a local password exists. `public-key` present - an SSH key does.
    has_password = models.BooleanField(default=False)
    has_public_key = models.BooleanField(default=False)

    #: The effective profile exists AND its method is one of RADIUS, TACACS+, LDAP, Kerberos,
    #: SAML or Cloud. A profile whose method is `local-database` or `none` authenticates against
    #: the device, so binding one is not centralization - it only looks like it from the
    #: account's row.
    authentication_is_external = models.BooleanField(default=False)

    #: PAN-AUTH-019's whole assertion, and it takes BOTH halves: authentication reaches an
    #: external service, and no credential is stored on the device.
    #:
    #: The first half was missing until 2026-09-08. The control checked only whether a profile
    #: was BOUND, and three of the four accounts that passed it on the lab were reaching the
    #: device's own local user database through one - `oep-auth-lockout` and `oep-auth-hardened`
    #: are method `local-database`, and `aegis_auth_prof` names no method at all. A control
    #: titled "External Authentication for Administrator Accounts" was passing accounts that do
    #: not use external authentication.
    #:
    #: The second half is Jason's, 2026-09-08: "mfa/external=yes and local phash=no". A stored
    #: password on a profile-bound account is UNREACHABLE while the binding holds - measured the
    #: same day as an A/B on ONE account: `oep-fallback-test` with its profile unbound
    #: authenticated, and the same account with the same password, profile bound back a minute
    #: later, was refused, logging the profile and its dead RADIUS server. A failure with a
    #: password the previous step just proved correct is not a wrong password.
    #:
    #: So the credential is not a live way in - it is a secret that leaves with a configuration
    #: backup and becomes live the moment somebody removes the profile. Latent, the same way a
    #: password profile that weakens the global policy is a latent exemption whether or not
    #: anyone holds it today.
    #:
    #: The DEVICE-WIDE binding is a different mechanism, measured the same day with both leaves
    #: pushed at a dead RADIUS server and two attempts two seconds apart: an account with NO
    #: credential was sent to the profile and timed out, and an account WITH a stored password
    #: authenticated locally with the profile never consulted. So it covers only accounts that
    #: have no local credential of their own.
    #:
    #: That is why resolving `authentication_is_external` through it is correct rather than
    #: generous - it really does govern those accounts - and why the credential half still has
    #: to be here: an account holding a password is outside its reach entirely.
    #:
    #: One column because the query grades on one field, and because an account failing both
    #: halves has one thing wrong with it from an operator's point of view: it is not on the
    #: identity system. The summary sentence says which half failed.
    centrally_authenticated = models.BooleanField(default=False)

    class Meta:
        ordering = ["management_station__hostname", "appliance__hostname", "name"]
        indexes = [
            models.Index(fields=["appliance"]),
            models.Index(fields=["name"]),
            models.Index(fields=["is_superuser"]),
            models.Index(fields=["centrally_authenticated"]),
            models.Index(fields=["admin_mfa_enabled"]),
        ]
        constraints = [
            models.UniqueConstraint(fields=["appliance", "name"],
                                    name="unique_admin_user_per_appliance"),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.name}"


#: The seven children of `permissions/role-based`, measured with `action=complete`, paired with
#: how each one carries its qualifier. Order is the payload's, not a precedence.
ROLE_KEYS = (
    ("superuser", "flag"),
    ("superreader", "flag"),
    ("deviceadmin", "members"),
    ("devicereader", "members"),
    ("vsysadmin", "device-entries"),
    ("vsysreader", "device-entries"),
    ("custom", "custom"),
)
