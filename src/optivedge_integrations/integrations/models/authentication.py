"""Authentication profiles - PAN-AUTH-018, 020 and 025's subject.

Definable in `shared` AND under a vsys, measured 2026-09-04, so this carries the same scope
column as the certificate objects rather than being appliance-flat. The first measurement said
shared-only and was wrong: it completed the CONTAINER, which returns nothing for any node whose
children are `entry` elements, valid or not.
"""

from __future__ import annotations

from django.db import models

from .base import ApplianceScopedObject


class AuthenticationProfile(ApplianceScopedObject):
    """One authentication profile, in the scope it was defined in.

    `method` is the field that carries the meaning. PAN-OS offers eight, and two of them are not
    external authentication at all: `none` performs no authentication, and `local-database`
    checks the firewall's own user store. A control asserting that administrators authenticate
    externally cannot be satisfied by the presence of a profile - all four profiles on the lab's
    PA-VM are `none`, and a naive check would pass every user pointing at them.

    The device enforces a narrower rule than this model records, and it is worth knowing rather
    than encoding: only RADIUS, TACACS+ and SAML may be bound as the device-wide administrator
    authentication profile, and SAML cannot authenticate the CLI at all. Both are properties of
    the BINDING rather than of the profile, so they belong to whatever reads the binding.
    """

    METHOD_NONE = "none"
    METHOD_LOCAL_DATABASE = "local-database"
    METHOD_CLOUD = "cloud"
    METHOD_RADIUS = "radius"
    METHOD_TACPLUS = "tacplus"
    METHOD_LDAP = "ldap"
    METHOD_KERBEROS = "kerberos"
    METHOD_SAML = "saml-idp"
    METHOD_CHOICES = [
        (METHOD_NONE, "None"),
        (METHOD_LOCAL_DATABASE, "Local database"),
        (METHOD_CLOUD, "Cloud Authentication Service"),
        (METHOD_RADIUS, "RADIUS"),
        (METHOD_TACPLUS, "TACACS+"),
        (METHOD_LDAP, "LDAP"),
        (METHOD_KERBEROS, "Kerberos"),
        (METHOD_SAML, "SAML"),
    ]
    #: The six that reach an authority off the box. `none` and `local-database` do not.
    EXTERNAL_METHODS = (METHOD_CLOUD, METHOD_RADIUS, METHOD_TACPLUS, METHOD_LDAP,
                        METHOD_KERBEROS, METHOD_SAML)

    #: Blank when the profile has no `method` node at all, which is distinct from `none`: one
    #: is a profile nobody finished and the other is a deliberate choice to authenticate nothing.
    method = models.CharField(max_length=32, choices=METHOD_CHOICES, blank=True)

    #: PAN-AUTH-018. Range 0-10, and 0 means UNLIMITED ATTEMPTS - the worst value, not the
    #: strictest. Default 0 in normal operational mode and 10 in FIPS-CC mode, which this model
    #: does not distinguish; see AGENTS.md "Operating modes are not assessed".
    lockout_failed_attempts = models.PositiveIntegerField(default=0)
    #: Range 0-60. A 0 means the lockout holds until an administrator releases it, which is
    #: STRONGER than any duration - MEASURED 2026-09-04, three failed logins against a profile
    #: with failed-attempts 2 and lockout-time 0 locked the account. The Web Interface Help
    #: claims the opposite on p.840 and is wrong, as it is about the device-admin lockout on
    #: p.707. Neither field disables the other.
    lockout_time_minutes = models.PositiveIntegerField(default=0)

    #: PAN-AUTH-020. The device REFUSES mfa-enable unless a factor already exists, so an
    #: enabled profile always has at least one factor and the two are not independent.
    mfa_enabled = models.BooleanField(default=False)
    mfa_factor_count = models.PositiveIntegerField(default=0)
    #: Names only, for display. Nothing asserts on this - see "A control queries columns".
    mfa_factor_names = models.JSONField(default=list, blank=True)

    #: Who may authenticate through this profile. `all` is the common value and is not itself a
    #: finding; recorded because a profile is not fully described without it.
    #: Every place on this appliance that names this profile - PAN-AUTH-025's subject.
    #:
    #: THE LIST IS BUILT BY WALKING THE WHOLE MERGED PAYLOAD, not by visiting the eight paths
    #: the CLI grammar lists. A hygiene control that says "nobody references this" is only as
    #: good as its list of hiding places, and a path the grammar missed would make the control
    #: report an in-use profile as unused - the worst direction for it to fail in. Walking
    #: everything cannot miss a path; the grammar list is kept as a cross-check on the walk.
    #:
    #: Four of the eight paths have been seen carrying a real reference and are readable from
    #: merged config: `mgt-config/users/<name>`, `deviceconfig/system/authentication-profile`,
    #: a vsys leaf (`captive-portal`) and a leaf nested in a vsys ENTRY
    #: (`authentication-object/<name>`). Those are all four structural shapes, and the four
    #: unseen paths - GlobalProtect portal and gateway, secure-web-gateway - reuse them.
    referrer_paths = models.JSONField(default=list, blank=True)
    #: Zero is the whole point of this pair. Stored rather than derived so "unused" is a scalar
    #: a control query can filter on without a join - the same shape as
    #: `InterfaceManagementProfile.bound_interface_count`.
    referrer_count = models.PositiveIntegerField(default=0)

    allow_list_members = models.JSONField(default=list, blank=True)
    #: PAN-AAA-010's first half. `all` means every user the method can reach may authenticate
    #: through this profile, so a directory-wide phishing success reaches whatever the profile
    #: is bound to. A column rather than a JSON lookup into the members list, for the reason
    #: `allows_sha1` is one: a JSON lookup is unindexed and matches NOTHING the day the vendor
    #: renames a key, so the control quietly stops finding anything rather than failing.
    allow_list_is_all = models.BooleanField(default=False)
    #: PAN-AAA-010's second half. The corpus scopes the assertion to profiles used for
    #: ADMINISTRATIVE access - Jason, 2026-09-04, on the same question for PAN-AUTH-020:
    #: "GlobalProtect, Captive Portal, and even unused authentication profiles are very much
    #: separate controls."
    #:
    #: Derived from `referrer_paths`, which PAN-AUTH-025 already collects: a profile is
    #: administrative when something under `mgt-config/users` or `deviceconfig/system` names it.
    #: That is the question PAN-AUTH-020 was blocked on for days, now a column.
    is_administrative = models.BooleanField(default=False)
    allow_list_count = models.PositiveIntegerField(default=0)

    user_domain = models.CharField(max_length=64, blank=True)
    username_modifier = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["management_station__hostname", "appliance__hostname", "scope",
                    "vsys_name", "name"]
        indexes = [
            models.Index(fields=["appliance", "scope"]),
            models.Index(fields=["name"]),
            models.Index(fields=["referrer_count"]),
            models.Index(fields=["is_administrative"]),
            models.Index(fields=["method"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "name"],
                name="unique_authentication_profile_per_scope"),
        ]

    @property
    def method_is_external(self) -> bool:
        """Display only. A control queries `method` with `in` / `not-in` rather than this."""
        return self.method in self.EXTERNAL_METHODS
