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

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class CertificateScopedModel(ProvenancedMixin, SyncTrackedModel):
    """Shared anchoring for the two certificate-domain object types."""

    #: Where the definition was found. `predefined` is vendor-shipped and read-only; it beats
    #: a same-named shared entry, measured 2026-09-02 — the opposite of the assumption encoded
    #: in policy/base.py, which governs a different object type and is left alone.
    SCOPE_SHARED = "shared"
    SCOPE_VSYS = "vsys"
    SCOPE_PREDEFINED = "predefined"
    SCOPE_CHOICES = [
        (SCOPE_SHARED, "Shared"),
        (SCOPE_VSYS, "Vsys"),
        (SCOPE_PREDEFINED, "Predefined"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="%(class)ss")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="%(class)ss")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="%(class)ss", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="%(class)ss")

    name = models.CharField(max_length=64)
    scope = models.CharField(max_length=16, choices=SCOPE_CHOICES, default=SCOPE_SHARED)
    #: Blank unless scope is vsys. Not a foreign key: the object is anchored to the appliance,
    #: and the vsys is a property of where the definition sits rather than a second owner.
    vsys_name = models.CharField(max_length=64, blank=True)

    class Meta:
        abstract = True

    def __str__(self) -> str:
        where = f"{self.scope}:{self.vsys_name}" if self.vsys_name else self.scope
        return f"{self.appliance} / {where} / {self.name}"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError("Object appliance must belong to the same station.")
        if self.scope == self.SCOPE_VSYS and not self.vsys_name:
            raise ValidationError("A vsys-scoped object must name its vsys.")
        if self.scope != self.SCOPE_VSYS and self.vsys_name:
            raise ValidationError("Only a vsys-scoped object may name a vsys.")


class SslTlsServiceProfile(CertificateScopedModel):
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
            models.Index(fields=["management_station"]),
        ]


class CertificateProfile(CertificateScopedModel):
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
