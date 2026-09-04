"""Certificate-domain objects: SSL/TLS service profiles and certificate profiles.

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

    #: Which of those keys the configuration actually WROTE. The difference matters and is not
    #: recoverable from the effective values: tpa-b's profile omits every algorithm key and
    #: pan-fw-111's writes all of them as `yes`, and the two are identical once expanded.
    #: An engineer remediating them does different work in each case.
    explicit_algorithms = models.JSONField(default=list, blank=True)

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


class CertificateProfile(ApplianceScopedObject):
    """One certificate profile as an object. PAN-CRT-004's subject.

    Every boolean defaults False, measured 2026-09-02 from the blank Add Certificate Profile
    form. That uniformity is worth stating because the management plane is the counterexample:
    `server-verification` absent means ENABLED while `enable-log-high-dp-load` absent means
    DISABLED, so one assumption across neighbouring keys would have been wrong for one of
    them. Here a profile that sets nothing performs no revocation checking and blocks nothing.
    """

    use_crl = models.BooleanField(default=False)
    use_ocsp = models.BooleanField(default=False)
    block_expired_cert = models.BooleanField(default=False)
    block_unknown_cert = models.BooleanField(default=False)
    block_timeout_cert = models.BooleanField(default=False)
    block_unauthenticated_cert = models.BooleanField(default=False)

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
            models.Index(fields=["management_station"]),
        ]
