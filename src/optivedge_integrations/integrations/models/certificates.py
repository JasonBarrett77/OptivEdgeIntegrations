"""Certificate-domain objects: certificates, SSL/TLS service, certificate and SCEP profiles.

Both are assessed as OBJECTS here, which is the difference from PAN-MGT-010. That control
asks what the management interface has BOUND, and the answer is resolved onto
`DeviceConfigurationProfile` as scalars because the question is about the surface. PAN-CRT-005
asks whether every profile on the device sets a TLS 1.2 floor, whether or not anything uses
it — a question about the objects themselves, which only rows can answer. That is the same
reason `InterfaceManagementProfile` exists, arrived at from the same direction.

SCOPING: appliance, with the scope recorded on the row.

Both object types can live in `/config/shared` OR under `vsys/entry/{vsys}`, which straddles
the usual rule that vsys/entry means EnforcementPoint and everything else means Appliance.
The codebase has two precedents and they disagree, so this is a decision rather than a lookup:

    ScopedPolicyObject          shared -> appliance_group, vsys -> enforcement_point.
                                Because the group holds ONE /config/shared, and storing a
                                shared object per enforcement point turned 264 objects into
                                1,320 rows on a five-vsys PA-5220.

    InterfaceManagementProfile  appliance, always. Because a Panorama template push lands in
                                each firewall's merged config separately, so a profile present
                                on one peer and not the other is two rows telling the truth
                                about two devices.

InterfaceManagementProfile wins here, for two reasons. The row explosion that drove the policy
objects to `appliance_group` is multiplication by VSYS COUNT, and appliance scoping does not
cause it — it multiplies by HA members, which is two, and which the interface profiles
accepted deliberately. And PAN-CRT-008, the hygiene control these lead to, has to be able to
say a profile exists on one peer and not the other; an appliance-group row cannot express
that. These are also not policy objects: nothing resolves them through the precedence ladder
in `policy/base.py`, and its PREDEFINED rank is measured wrong for this object type anyway.

Revisit if a multi-vsys device ever carries per-vsys certificate profiles in volume. The lab
has none: every instance on both platforms is shared.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import ApplianceScopedObject
from .provenance import ProvenancedMixin


class Certificate(ApplianceScopedObject):
    """One certificate as an object. PAN-CRT-001, 002, 003 and 008's subject.

    Three fields here exist in NO PAN-OS configuration field and are decoded from the X.509
    blob PAN-OS stores under the misleadingly named `public-key`, which holds the whole
    certificate. Four oracles were tried before concluding this: the config `algorithm` field
    reports RSA or EC - the KEY algorithm, not its size - `request certificate show` returns
    FEWER fields than the config and no algorithm at all, `request certificate bulk-certs-show`
    does not exist on a PA-5220, and `show system state` returns NO_MATCHES for *cert*.
    """

    #: Computed here: decoded from the public key blob - `is_ca` reads the `ca` KEY and has a row of its own. See ProvenancedMixin.DERIVED_FIELDS.
    #:
    #: `not_valid_before` and `not_valid_after` were MISSING from this tuple while being
    #: computed from the PEM, so `provenance_for('not_valid_after')` answered None - which
    #: since 2026-09-21 means "nothing tracks this field" and not "we worked it out". The
    #: report therefore had no way to say the date was decoded rather than read, on the one
    #: column PAN-CRT-001 rests on. Added 2026-10-29 with the five verdict columns below.
    DERIVED_FIELDS = (
        "is_missing",
        "is_self_signed",
        "key_algorithm",
        "key_size_bits",
        "signature_algorithm",
        "parse_error",
        "not_valid_before",
        "not_valid_after",
        "key_strength_band",
        "signature_hash",
        "weak_signature_hash",
        "is_expired",
        "not_relied_on",
        "relied_on_by",
    )

    #: Where this key sits against the floor for ITS OWN algorithm. The VERDICT, and the column
    #: a control clauses on - `key_size_bits` is the evidence beside it and must not be
    #: clauseed: measured by stage 0, a certificate whose algorithm matches none of a query's
    #: paired literals has a NULL size, the integer compiler excludes nulls from both sides of
    #: an inequality explicitly, its parse error is empty, and it PASSES every threshold.
    #:
    #: Five members, and the two that exist to stop that happening are `algorithm_has_no_floor`
    #: - an algorithm this assessment carries no floor for, which an Ed25519 certificate is -
    #: and `undecodable`. Both are on the FIRING side of `is not at_or_above_floor`.
    BAND_AT_OR_ABOVE = "at_or_above_floor"
    BAND_BELOW = "below_floor"
    BAND_FAR_BELOW = "far_below_floor"
    BAND_NO_FLOOR = "algorithm_has_no_floor"
    BAND_UNDECODABLE = "undecodable"
    BAND_CHOICES = [
        (BAND_AT_OR_ABOVE, "At or above the floor for its algorithm"),
        (BAND_BELOW, "Below the floor"),
        (BAND_FAR_BELOW, "Far below the floor"),
        (BAND_NO_FLOOR, "No floor is carried for this algorithm"),
        (BAND_UNDECODABLE, "Could not be decoded"),
    ]

    #: As PAN-OS reports them. `subject` and `issuer` are stored because an engineer reads
    #: them, and are NEVER compared: they are formatted three ways depending on where they are
    #: read - "/CN=x" in shared, a bare "x" in predefined, and "CN = x" in subject-int and from
    #: the op command. Self-signed is decided by hash equality instead.
    common_name = models.CharField(max_length=255, blank=True)
    subject = models.CharField(max_length=512, blank=True)
    issuer = models.CharField(max_length=512, blank=True)
    subject_hash = models.CharField(max_length=64, blank=True)
    issuer_hash = models.CharField(max_length=64, blank=True)

    #: Equality of the two hashes, computed once here rather than at every call site. WITHIN a
    #: surface the hashes also chain - a certificate's issuer_hash equals its issuer's
    #: subject_hash - which is how a chain is built without parsing anything. Across surfaces
    #: the literal values differ and only the relationships hold.
    is_self_signed = models.BooleanField(default=False)
    is_ca = models.BooleanField(default=False)

    #: PAN-DCP-006's third fact: whether this certificate's private key is held on a separate
    #: signing module rather than on the firewall. The `private-key-on-hsm` key with the
    #: vendor's polarity, so TRUE means external custody.
    #:
    #: THE ABSENT VALUE IS ASSUMED AND NOT MEASURED, and the assumption is recorded rather than
    #: hidden: the only certificate on the lab appliance lacks this key and carries
    #: `private-key`, which is the on-device form, so an absent key most plausibly asserts local
    #: custody. No positive control was paid for it because that means writing the key, and the
    #: one certificate present is another run's standing object. FALSE is the direction that
    #: RAISES PAN-DCP-006 rather than passing it, so the unsettled case is the loud one. The
    #: value is stored non-null deliberately: `provenance_for` computes the type from the
    #: citation AND the value, so an assumed default holding null would persist as
    #: `not_configured` and the declaration and the row would disagree with nothing noticing.
    private_key_on_hsm = models.BooleanField(default=False)

    not_valid_before = models.DateTimeField(null=True, blank=True)
    not_valid_after = models.DateTimeField(null=True, blank=True)

    #: DECODED from the certificate, not read from a field.
    #:
    #: key_size_bits must always be read WITH key_algorithm. 256-bit EC is strong and 256-bit
    #: RSA is broken, so a bare minimum-bits comparison would pass the broken one and fail the
    #: good one - which is why PAN-CRT-002's query cannot be a single numeric threshold.
    key_algorithm = models.CharField(max_length=32, blank=True)
    key_size_bits = models.PositiveIntegerField(null=True, blank=True)
    signature_algorithm = models.CharField(max_length=64, blank=True)
    #: Set when the blob could not be decoded. The three fields above are then blank, and a
    #: control must report rather than pass - an unreadable certificate is not a compliant one.
    parse_error = models.CharField(max_length=255, blank=True)

    #: PAN-CRT-002's column. Default UNDECODABLE, which is the FIRING side: a certificate
    #: nobody has decoded has not been shown to meet any floor, so a row written before the
    #: decode pass reports itself instead of passing.
    key_strength_band = models.CharField(
        max_length=32, choices=BAND_CHOICES, default=BAND_UNDECODABLE)

    #: The hash the signature ACTUALLY uses, resolved to a bare name. Not recoverable from
    #: `signature_algorithm`: measured, an RSASSA-PSS certificate stores the identifier
    #: `rsassaPss`, which names NO hash - for PSS the hash lives in the signature parameters -
    #: so a PSS certificate signed with SHA-1 matches neither `contains md5` nor `contains
    #: sha1`, carries an empty parse error, and passes. Every SHA-3 variant has the same shape.
    #: Empty means the hash could not be resolved, which `weak_signature_hash` reads as weak.
    signature_hash = models.CharField(max_length=16, blank=True)
    #: PAN-CRT-003's column: md5, sha1, or unresolved. Default True - the firing side - for the
    #: same reason `SslTlsServiceProfile.allows_sha1` defaults True.
    weak_signature_hash = models.BooleanField(default=True)

    #: PAN-CRT-001's column, and a SNAPSHOT of a comparison against a clock: it goes stale
    #: between passes, which is why `not_valid_after` is kept beside it as the evidence a
    #: reader checks. Default True, the firing side: a certificate whose validity nobody has
    #: checked has not been shown to be current.
    is_expired = models.BooleanField(default=True)

    #: True ONLY where the reference walk completed and found nothing. False covers both
    #: "something names it" and "the walk could not be completed", and that is deliberate in
    #: BOTH directions at once, which is why this is one column and not two:
    #: PAN-CRT-001 clauses on `equals false`, so an expired certificate whose reliance is
    #: unknown FIRES; PAN-CRT-008 clauses on `equals true`, so it is SILENT until the walk has
    #: run - and the finding it would produce is "delete this authority", whose remediation is
    #: irreversible. The map is a FLOOR and not a census: 65 of 69 known reference locations
    #: are covered by no model at all.
    not_relied_on = models.BooleanField(default=False)
    #: The referrers the walk found, by kind and name - the evidence a deletion decision rests
    #: on. NOTHING MAY CLAUSE ON IT: a JSON lookup is unindexed and silently matches nothing
    #: when a key is renamed, so the control would stop finding anything instead of breaking.
    relied_on_by = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["appliance__hostname", "scope", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "name"],
                name="integrations_unique_certificate_per_scope"),
        ]
        indexes = [
            models.Index(fields=["appliance", "not_valid_after"]),
            models.Index(fields=["appliance", "key_algorithm", "key_size_bits"]),
            models.Index(fields=["appliance", "signature_algorithm"]),
            models.Index(fields=["management_station"]),
        ]

    def clean(self) -> None:
        super().clean()
        if self.subject_hash and self.issuer_hash:
            expected = self.subject_hash == self.issuer_hash
            if expected != self.is_self_signed:
                raise ValidationError(
                    "is_self_signed must match subject_hash == issuer_hash.")


class SslTlsServiceProfile(ApplianceScopedObject):
    """One SSL/TLS service profile as an object. PAN-CRT-005's subject."""

    #: Computed here: the effective algorithm set, which expands absent keys to enabled, and the column over it. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "allows_sha1",
        "explicit_algorithms",
        "protocol_algorithms",
        "min_version_rank",
        # Added by the `globalprotect-gateway` domain for PAN-GPG-001.
        "has_explicit_protocol_settings",
    )

    #: The ORDER of the four version tokens the device offers, measured identical on all four
    #: lab appliances by `action=complete`. `max` is NOT a member here - it is real PAN-OS and
    #: belongs to the decryption profile's ceiling and the GlobalProtect portal's; writing it
    #: to this leaf is refused, code=12, "'max' is not an allowed keyword".
    VERSION_ORDER = ("tls1-0", "tls1-1", "tls1-2", "tls1-3")
    #: A stored token that is none of the four. It sorts BELOW tls1-0 so every "the floor is
    #: too low" comparison FIRES on it - which is the direction stage 0 measured the enumerated
    #: query gets wrong: a list of the forbidden values reads an unrecognised token as
    #: compliant. The magnitude is not the meaning here; the meaning is the firing side.
    RANK_UNRECOGNISED = -1

    certificate_name = models.CharField(max_length=255, blank=True)
    min_version = models.CharField(max_length=16, blank=True)
    max_version = models.CharField(max_length=16, blank=True)

    #: The EFFECTIVE algorithm settings, absent keys expanded to enabled.
    #:
    #: Measured 2026-09-02 and the reason this field exists at all: ABSENT MEANS ENABLED. A
    #: profile carrying only a version range renders with every algorithm box ticked in the
    #: UI, so it permits SHA-1 authentication and CBC encryption. Storing only what the config
    #: contains would make such a profile look restrictive when it is the most permissive
    #: state available.
    protocol_algorithms = models.JSONField(default=dict, blank=True)
    #: The one algorithm a control asserts, promoted to a real column.
    #:
    #: PAN-CRT-009 originally queried into `protocol_algorithms` with a JSON lookup, which was
    #: wrong for the reason `bound_interface_count` exists on InterfaceManagementProfile: a
    #: finding must rest on a column, not on a key inside a blob. A JSON lookup is unindexed,
    #: silently returns nothing when the key is renamed, and puts the shape of a vendor payload
    #: into a control definition where no schema protects it.
    #:
    #: Default True because ABSENT MEANS ENABLED - a profile that writes no algorithm key
    #: permits SHA-1. Only this one is promoted: it is the only algorithm any control asserts,
    #: and a column per key would be eleven migrations ahead of a requirement. The rest stay
    #: readable in `protocol_algorithms` for display and inspection.
    allows_sha1 = models.BooleanField(default=True)

    #: The floor as an ORDERED number, which is the only shape the assertion can be written in
    #: at all: the grammar has no ordering over text, no `in` and no `between`, and a clause
    #: list is ONE conjunction. -1 is the sentinel and the migration default, so a profile
    #: nobody has ranked fires.
    min_version_rank = models.IntegerField(default=RANK_UNRECOGNISED)

    #: Which of those keys the configuration actually WROTE. The difference matters and is not
    #: recoverable from the effective values: tpa-b's profile omits every algorithm key and
    #: pan-fw-111's writes all of them as `yes`, and the two are identical once expanded.
    #: An engineer remediating them does different work in each case.
    explicit_algorithms = models.JSONField(default=list, blank=True)

    #: Whether this profile states a protocol RANGE of its own at all - true where a
    #: `protocol-settings` node is present carrying at least one version bound, false where the
    #: profile leaves the range to whatever the platform asserts.
    #:
    #: PAN-GPG-001's input, and the question it answers is not the one `min_version` answers. An
    #: ABSENT FLOOR IS NOT A LOW FLOOR: an absent `protocol-settings` node asserts a TLS 1.2 floor
    #: on a profile that exists, measured with a positive control in both directions - so a
    #: gateway binding such a profile is not insecure, it is UNDECIDED, and the gateway's own
    #: verdict column needs to tell "somebody chose a floor" from "nobody did". `min_version`
    #: cannot: it stores the empty string for both an unwritten key and an uncollected profile,
    #: and there is no is-not-empty operator to ask with.
    #:
    #: NOT A DUPLICATE OF `explicit_algorithms` BESIDE IT, which records which ALGORITHM keys the
    #: configuration wrote; this records whether the node holding the VERSION bounds exists. That
    #: one is a JSON column and deliberately unsearchable, so it could not carry this either way.
    #:
    #: False is the migration default and the side a gateway control fires on. The CONTAINER is
    #: mandatory on a committed profile, measured twice by two domains - so false on a collected
    #: profile means the two version children are both absent, not that the node is.
    has_explicit_protocol_settings = models.BooleanField(default=False)

    class Meta:
        ordering = ["appliance__hostname", "scope", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "name"],
                name="integrations_unique_ssl_tls_profile_per_scope"),
        ]
        indexes = [
            models.Index(fields=["appliance", "min_version"]),
            models.Index(fields=["appliance", "allows_sha1"]),
            models.Index(fields=["management_station"]),
        ]

    def clean(self) -> None:
        super().clean()
        # The column is derived from the JSON, so they cannot be allowed to disagree - the
        # same guard bound_interface_count carries against its name list.
        effective = (self.protocol_algorithms or {}).get("auth-algo-sha1")
        if effective is not None and bool(effective) != self.allows_sha1:
            raise ValidationError(
                "allows_sha1 must match protocol_algorithms['auth-algo-sha1'].")
        # The rank is derived from the token, so they cannot be allowed to disagree either.
        expected = (self.VERSION_ORDER.index(self.min_version)
                    if self.min_version in self.VERSION_ORDER else self.RANK_UNRECOGNISED)
        if expected != self.min_version_rank:
            raise ValidationError("min_version_rank must be min_version's position in VERSION_ORDER.")


class CertificateProfile(ApplianceScopedObject):
    """One certificate profile as an object. PAN-CRT-004's subject.

    Every boolean defaults False, measured 2026-09-02 from the blank Add Certificate Profile
    form. That uniformity is worth stating because the management plane is the counterexample:
    `server-verification` absent means ENABLED while `enable-log-high-dp-load` absent means
    DISABLED, so one assumption across neighbouring keys would have been wrong for one of
    them. Here a profile that sets nothing performs no revocation checking and blocks nothing.
    """

    #: Computed here: `ca_certificate_names` is the payload's CA list rather than a verdict. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "checks_revocation",
        "fail_open_mode",
    )

    #: Which of the two INCONCLUSIVE revocation outcomes this profile still lets through. One
    #: column over two measured booleans, because stage 3 grades the two outcomes SEPARATELY
    #: and a grading names ONE column - the severity cannot vary with which of two columns is
    #: false. `both_allowed` is the worst value and the migration default.
    FAIL_OPEN_NONE = "none"
    FAIL_OPEN_UNKNOWN = "unknown_allowed"
    FAIL_OPEN_TIMEOUT = "timeout_allowed"
    FAIL_OPEN_BOTH = "both_allowed"
    FAIL_OPEN_CHOICES = [
        (FAIL_OPEN_NONE, "Neither outcome is allowed through"),
        (FAIL_OPEN_UNKNOWN, "An unknown status is allowed through"),
        (FAIL_OPEN_TIMEOUT, "A timed-out status is allowed through"),
        (FAIL_OPEN_BOTH, "Both inconclusive outcomes are allowed through"),
    ]

    use_crl = models.BooleanField(default=False)
    use_ocsp = models.BooleanField(default=False)
    block_expired_cert = models.BooleanField(default=False)
    block_unknown_cert = models.BooleanField(default=False)
    block_timeout_cert = models.BooleanField(default=False)
    block_unauthenticated_cert = models.BooleanField(default=False)

    #: Revocation checked by EITHER method - the disjunction, computed once so a clause can
    #: name it. The ASSERTION half of PAN-CRT-004 survives without it (the failing condition is
    #: the conjunction of both negations, which is what the shipped baseline writes), but its
    #: APPLICABILITY half is the disjunction in its POSITIVE sense and a one-conjunction clause
    #: list cannot hold that at all. Default False: a profile whose keys nobody read has not
    #: been shown to check revocation.
    checks_revocation = models.BooleanField(default=False)
    fail_open_mode = models.CharField(
        max_length=16, choices=FAIL_OPEN_CHOICES, default=FAIL_OPEN_BOTH)

    #: All three default to 5 seconds, measured from the same form.
    crl_receive_timeout = models.PositiveIntegerField(default=5)
    ocsp_receive_timeout = models.PositiveIntegerField(default=5)
    cert_status_timeout = models.PositiveIntegerField(default=5)

    #: The CA certificates the profile trusts, by name. A profile with an empty list validates
    #: against nothing.
    ca_certificate_names = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["appliance__hostname", "scope", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "name"],
                name="integrations_unique_certificate_profile_per_scope"),
        ]
        indexes = [
            models.Index(fields=["appliance", "use_crl", "use_ocsp"]),
            models.Index(fields=["appliance", "fail_open_mode"]),
            models.Index(fields=["management_station"]),
        ]

    def clean(self) -> None:
        super().clean()
        # Both verdicts are derived from the booleans beside them, so they cannot be allowed to
        # disagree - the same guard `SslTlsServiceProfile.allows_sha1` carries.
        if self.checks_revocation != (self.use_crl or self.use_ocsp):
            raise ValidationError("checks_revocation must match use_crl or use_ocsp.")
        expected = {
            (True, True): self.FAIL_OPEN_NONE,
            (False, True): self.FAIL_OPEN_UNKNOWN,
            (True, False): self.FAIL_OPEN_TIMEOUT,
            (False, False): self.FAIL_OPEN_BOTH,
        }[(bool(self.block_unknown_cert), bool(self.block_timeout_cert))]
        if self.fail_open_mode != expected:
            raise ValidationError(
                "fail_open_mode must follow block_unknown_cert and block_timeout_cert.")


class ScepProfile(ApplianceScopedObject):
    """One SCEP enrolment profile as an object. PAN-CRT-002 and PAN-CRT-003's second subject.

    What it names is the profile that will mint the NEXT certificate, not any certificate
    already on the box - so the two halves of those controls sit on two models on purpose.

    NOTHING NAMED `scep` EXISTED ANYWHERE IN EITHER CONSUMER REPO before this, and no SCEP
    profile existed anywhere in the lab before stage 6 built one. So every reading behind the
    declarations below is from objects that run created and deleted, and the scope-collision
    behaviour was never measured on this object type - it is inherited from
    `ApplianceScopedObject` as the shape the store already keys on, which is a decision and not
    a measurement. There is also no predefined SCEP namespace and no template-contributed SCEP
    profile sighted on any of the four appliances, which is an absence of SIGHTINGS and not a
    demonstration that a template cannot supply one.

    The config key is `scep` and the screen is `SCEP`. Six of the fourteen settable keys are
    MANDATORY at commit validation, enumerated one commit at a time, so a committed profile
    carries all six and an absence asserts nothing about any of them.

    SCOPING: appliance, with the scope recorded on the row - the same answer
    `InterfaceManagementProfile` and the three classes above it reached, for the same reasons.
    Measured: a vsys-scoped enrolment profile RENDERS on a single-vsys firewall in the same
    grid as a shared one with LOCATION empty, which is the certificate-profile screen's answer
    and the OPPOSITE of the SSL/TLS profile screen's. Which way a screen goes is not
    predictable from the platform, the tab or the config path, so the scope is stored.
    """

    #: Computed here: the two verdicts. The two literals beside them are read keys. See
    #: ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "enrolment_key_below_floor",
        "csr_digest_weak",
    )

    #: The RSA key length the profile asks the authority for, nested two containers down at
    #: `algorithm/rsa/rsa-nbits`.
    #:
    #: NULL where the key is absent, which is this model's one nullable column and is
    #: deliberate against the convention: nothing clauses on it - the clause names
    #: `enrolment_key_below_floor` - so it is an input to a verdict and a literal a finding
    #: prints, which is the case `null=True` is reserved for. The exposure is bounded by a
    #: measurement rather than an argument: `algorithm` is mandatory at commit on all four
    #: appliances, so no committed profile in the lab can reach the null state.
    #:
    #: A STRING and not an integer, because the DEVICE WILL OFFER THREE VALUES AND ACCEPT MORE:
    #: `action=complete` returns exactly 2048, 1024 and 3072 on all four appliances with no
    #: @default, and stage 4 WROTE AND COMMITTED 512 here. The literal is stored as the device
    #: spells it and the verdict is computed from it with no assumption that it is in the
    #: completion set.
    rsa_key_bits = models.CharField(max_length=8, null=True, blank=True)
    #: True for any stored literal under the floor AND for a literal this assessment carries no
    #: floor for. Default True - the firing side - because a profile nobody has evaluated has
    #: not been shown to ask for a compliant key.
    enrolment_key_below_floor = models.BooleanField(default=True)

    #: The signing hash the profile asks for. MANDATORY at commit validation - "Validation
    #: Error: scep -> ... is missing digest" - so no committed profile lacks it and an absence
    #: asserts nothing; blank here means the read did not carry the key.
    #:
    #: MD5 IS ABSENT FROM THE COMPLETION SET ON ALL FOUR APPLIANCES AND IS STILL WRITABLE:
    #: stage 4 wrote `digest: md5`, committed it in job 149, and `show config running` returns
    #: it. The mirror image of `username-field` on the sibling object, where completion offers a
    #: value the write refuses - so neither direction can be inferred from the other.
    csr_digest = models.CharField(max_length=16, blank=True)
    #: True for sha1 and md5 and for any literal this assessment does not recognise. Default
    #: True, the firing side.
    csr_digest_weak = models.BooleanField(default=True)

    class Meta:
        ordering = ["appliance__hostname", "scope", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "name"],
                name="integrations_unique_scep_profile_per_scope"),
        ]
        indexes = [
            models.Index(fields=["appliance", "enrolment_key_below_floor"]),
            models.Index(fields=["appliance", "csr_digest"]),
            models.Index(fields=["management_station"]),
        ]
