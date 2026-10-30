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

from django.core.exceptions import ValidationError
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
        "secret_shortest_stored_length",
        "secret_weakness",
        "message_signing_effective",
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

    class SecretWeakness(models.TextChoices):
        """PAN-AAA-005's three states, worst first. The ORDER here is the verdict's order.

        Two weaknesses are visible in a configuration export and one is not: whether the same
        secret is used on more than one appliance, and how long the plaintext was. The third
        token says neither was found, which is not the same as "the secret is strong" - a
        configuration cannot show whether the plaintext is guessable.
        """

        REUSED_ACROSS_APPLIANCES = "reused_across_appliances", "Reused across appliances"
        BELOW_SIXTEEN_CHARACTERS = "below_sixteen_characters", "Below sixteen characters"
        MEETS_FLOOR = "meets_floor", "Meets the floor"

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

    #: PAN-AAA-005. AN EQUALITY-GROUP ID PER SERVER ENTRY - never the secret, and never the
    #: form the device stores it in.
    #:
    #: Each id is `HMAC-SHA256(station key, the stored form)` truncated to 32 hex characters, one
    #: per server entry that carries a secret, in the entries' own order. Two entries hold the
    #: same secret exactly when their ids match, anywhere in one management station; the id says
    #: nothing else and cannot be turned back into anything. The key is
    #: `SecretFingerprintKey.key_for(station)` - see that model for why a KEYED digest and not a
    #: bare one, and for what it does and does not protect.
    #:
    #: THE VALUE IS NEVER STORED, which is Jason's standing ruling and the shipped reading of
    #: every other secret-shaped column here: `ike.py::IkeGateway` keeps `uses_pre_shared_key` as
    #: a presence test and says "No column holds the ciphertext", and
    #: `device_services.py::SnmpSettings` keeps `community_is_default` and lets the community
    #: string stay in the snapshot it came from. The only question PAN-AAA-005 asks of this
    #: column is whether two entries are identical, which an id answers exactly as well as a
    #: value does - so the per-entry evidence of WHICH entries share a secret is kept and the
    #: secret is not.
    #:
    #: WHERE THIS CANNOT FOLLOW ike.py. That precedent keeps its column MEASURED so the
    #: FieldProvenance row exists, because with no value stored the row is the only record of
    #: whether a template or the local device set the credential. A FieldProvenance row is per
    #: FIELD and a secret is per SERVER ENTRY, so one row here would have to pick an entry and
    #: speak for the rest. None is written, exactly as for `server_addresses`, and who set a
    #: secret stays unrecorded - which is a real gap and is named in this domain's stage 7
    #: artifact rather than papered over with a row that picks.
    secret_digests = models.JSONField(default=list, blank=True)
    #: The shortest stored form's LENGTH, measured on the way past and before the id is computed
    #: - a character count of the stored form rather than of the plaintext, which is not
    #: recoverable. `SECRET_STORED_LENGTH_FOR_ONE_BLOCK` in the normalizer maps one to the other
    #: and says what was measured.
    #:
    #: ike.py's objection to a length comparison is that it "would measure the ENCODING and pass
    #: a four-character key". It is answered rather than ignored: the encoding's step was measured
    #: at the BOUNDARY on committed objects, so a stored length of one cipher block is a
    #: plaintext of fifteen characters or fewer and a four-character key lands in that band with
    #: everything else short. The band is all this column claims; it does not claim a length.
    secret_shortest_stored_length = models.PositiveIntegerField(default=0)
    #: The single verdict PAN-AAA-005's severity grading reads. Blank where no secret was seen -
    #: every other kind, and a radius profile whose server entries carry none.
    #:
    #: WRITTEN OVER THE WHOLE MANAGEMENT STATION rather than per appliance, because
    #: `reused_across_appliances` is a comparison between two rows on different appliances and
    #: one appliance's rows cannot answer it. See the normalizer.
    secret_weakness = models.CharField(
        max_length=32, choices=SecretWeakness.choices, blank=True)

    # --- SAML ---------------------------------------------------------------------------
    #: BOTH IMPLICIT YES. PAN-AAA-008 and 009 fire only on an explicit `no`.
    saml_validate_idp_certificate = models.BooleanField(default=True)
    saml_want_auth_requests_signed = models.BooleanField(default=True)
    #: PAN-AAA-009, and it spans TWO objects. `want-auth-requests-signed` asks the firewall to
    #: sign; the certificate it signs WITH is named on the authentication profile, as
    #: `method/saml-idp/request-signing-certificate`. Help p.939: the firewall signs "using the
    #: Certificate for Signing Requests that you specify in an authentication profile", so the
    #: flag on with no certificate named is a request to sign with nothing.
    #:
    #: False where no authentication profile reaches this IdP profile at all: nothing sends a
    #: message, so nothing is signed, and the firing side is the safe one for an unreferenced
    #: profile. A query on the flag alone reports the first state as compliant.
    message_signing_effective = models.BooleanField(default=False)

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

    #: Every equality-group id is exactly this wide. The invariant below is what keeps a STORED
    #: FORM out of the column: one is 57 or 77 characters and fails this on sight.
    EQUALITY_GROUP_HEX_LENGTH = 32

    def clean(self) -> None:
        """What the row can still cross-check once the value is gone.

        THE OLD INVARIANT IS NOT AVAILABLE AND ITS ABSENCE IS THE POINT. This used to assert
        `secret_shortest_stored_length == min(len(d) for d in secret_digests)`, which only holds
        while the column carries the stored forms - a fixed-width id cannot reproduce a length it
        was computed from, and a column that could would be a column still holding the secret's
        shape. What is left is the pair's presence, which catches the two states a reader would
        misread, and the id's WIDTH, which is what refuses a stored form.
        """
        digests = [str(d) for d in (self.secret_digests or [])]
        if bool(digests) != bool(self.secret_shortest_stored_length):
            raise ValidationError(
                "secret_shortest_stored_length and secret_digests must both be set or "
                "both be empty.")
        if any(len(d) != self.EQUALITY_GROUP_HEX_LENGTH for d in digests):
            raise ValidationError(
                "secret_digests holds an entry that is not an equality-group id. A stored "
                "secret must never reach this column.")

    def __str__(self) -> str:
        return f"{self.appliance} / {self.get_kind_display()} / {self.name}"
