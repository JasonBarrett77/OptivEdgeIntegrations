"""AAA server profiles - the auth-servers domain, PAN-AAA-001 through 013.

Six kinds live side by side under `server-profile`, and eleven of the domain's thirteen controls
read one of them. One model rather than six: the kinds share a name, a scope, a server list and a
referrer count, and the per-kind settings are a handful of columns each. Six models would repeat
the shared half six times and give every consumer a union to write.

WHAT AN ABSENT KEY MEANS WAS MEASURED, AND TWO OF THE THREE INVERT THE OBVIOUS READING.
`ldap/ssl`, `saml-idp/validate-idp-certificate` and `saml-idp/want-auth-requests-signed` are all
implicit YES; `ldap/verify-server-certificate`, four lines from `ssl` in the same dialog, is
implicit NO. Settled 2026-09-09 by writing key-less profiles and opening them in the UI, after
the Help, the write/read oracle and the Add form had each failed to answer it. Reading these as
"absent means off" would report every unconfigured SAML profile in an estate as unvalidated and
unsigned.
"""

from __future__ import annotations

from django.db import models

from .base import ApplianceScopedObject


class ServerProfile(ApplianceScopedObject):
    """One AAA server profile, in whichever scope defines it."""

    #: Computed here: counts and the referrer walk - `server_addresses` is the payload's. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "server_count",
        "referrer_paths",
        "referrer_count",
    )

    class Kind(models.TextChoices):
        LDAP = "ldap", "LDAP"
        RADIUS = "radius", "RADIUS"
        TACPLUS = "tacplus", "TACACS+"
        KERBEROS = "kerberos", "Kerberos"
        SAML_IDP = "saml-idp", "SAML Identity Provider"
        MFA = "mfa-server-profile", "MFA"
        #: A kind PAN-OS grew that this enum has not. The row is still written - an unfamiliar
        #: profile is still a profile, and dropping it is how a list looks complete and is not.
        UNKNOWN = "unknown", "Unknown"

    name = models.CharField(max_length=64)
    kind = models.CharField(max_length=24, choices=Kind.choices, default=Kind.UNKNOWN)
    #: The key PAN-OS used, kept verbatim when `kind` is UNKNOWN so the row names itself.
    raw_kind = models.CharField(max_length=64, blank=True)

    #: SHARED SCOPE ONLY. `admin-use-only` is the single key whose presence differs between
    #: shared and a vsys - confirmed three ways: `action=complete` returns one fewer key under a
    #: vsys, Help p.933 says the option "appears only if the Location is Shared", and the Add
    #: dialog renders the checkbox under Shared and omits it under a vsys.
    #:
    #: It is a cleaner "this AAA path is administrative" signal than walking referrers.
    admin_use_only = models.BooleanField(default=False)

    #: The server list. THE ADDRESS KEY HAS THREE NAMES - `address` on ldap and tacplus,
    #: `ip-address` on radius, `host` on kerberos - so a normalizer reading one loses two kinds
    #: silently. Normalized to one list here so no consumer repeats that.
    server_addresses = models.JSONField(default=list, blank=True)
    #: Searchable; the names are not. A finding rests on a column.
    server_count = models.PositiveIntegerField(default=0)

    # --- LDAP ---------------------------------------------------------------------------
    #: IMPLICIT YES. PAN-AAA-001 fires only on an explicit `no`.
    ldap_ssl = models.BooleanField(default=True)
    #: IMPLICIT NO, and the Help says so outright: "Select this option (cleared by default)".
    #: PAN-AAA-002 fires on absence.
    ldap_verify_server_certificate = models.BooleanField(default=False)
    #: PAN-AAA-003 asks whether the bind account is least-privilege, which no config states.
    #: The DN is carried so an assessor can answer it; the control enumerates rather than judges.
    ldap_bind_dn = models.CharField(max_length=255, blank=True)
    ldap_type = models.CharField(max_length=32, blank=True)

    # --- RADIUS and TACACS+ -------------------------------------------------------------
    #: MANDATORY AT COMMIT on both kinds, so a profile that exists always states one and neither
    #: PAN-AAA-004 nor 006 needs an implicit value.
    #:
    #: The two store it DIFFERENTLY and `action=complete` cannot tell them apart: radius keeps
    #: `{"PAP": null}` - an element - and tacplus keeps the string `"PAP"`. Both complete to the
    #: same value list, and writing the radius form into tacplus is refused at the write.
    #: Normalized to the plain string here.
    protocol = models.CharField(max_length=32, blank=True)

    # --- SAML ---------------------------------------------------------------------------
    #: BOTH IMPLICIT YES. PAN-AAA-008 and 009 fire only on an explicit `no`.
    saml_validate_idp_certificate = models.BooleanField(default=True)
    saml_want_auth_requests_signed = models.BooleanField(default=True)

    # --- MFA ----------------------------------------------------------------------------
    mfa_vendor_type = models.CharField(max_length=64, blank=True)

    #: A certificate or certificate-profile this profile points at - saml-idp `certificate`,
    #: mfa `mfa-cert-profile`. Recorded because the certificate reference map counts these
    #: places, and PAN-CRT-001/008 stop being deferred as each one gains a model.
    certificate_reference = models.CharField(max_length=64, blank=True)

    #: PAN-AAA-013, the same shape as PAN-AUTH-025: everywhere on this appliance that names this
    #: profile, found by walking the whole payload rather than a list of known paths.
    referrer_paths = models.JSONField(default=list, blank=True)
    referrer_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["management_station__hostname", "appliance__hostname", "kind", "name"]
        indexes = [
            models.Index(fields=["appliance", "scope"]),
            models.Index(fields=["kind"]),
            models.Index(fields=["name"]),
            models.Index(fields=["referrer_count"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "kind", "name"],
                name="unique_server_profile_per_scope"),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.get_kind_display()} / {self.name}"
