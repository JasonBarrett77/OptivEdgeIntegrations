"""Device > Setup > Management > General Settings > SSL/TLS Service Profile - the binding.

PAN-MGT-010 and PAN-CRT-006's subject, and the LAST cluster cut out of `DeviceConfigurationProfile`.
It is last because it is the one that was actually wrong, not merely coarse: the aggregate stored
the bound profile's protocol floor and certificate as RESOLVED COPIES, and they drifted - measured
2026-09-10, the aggregate said the bound profile's certificate was `oep-tls-test` while the
`SslTlsServiceProfile` row for the same profile on the same appliance said `oep-mgmt-server`.
Neither normalizer was wrong; they ran at different times and nothing kept them in step.

So this model does not copy. It holds what is genuinely the DEVICE'S - the name it binds and which
definition that name resolved to - and a foreign key to the profile ROW. `min_version`,
`max_version` and `certificate_name` are read through that key, so the binding and the profile
cannot disagree about them: there is only one place the values live.

THE CERTIFICATE IS NOT A FOREIGN KEY, and deliberately. The shipped `TLSv1.3_Default` profile
presents a PREDEFINED certificate - the device's own factory certificate - and predefined
certificates are not `Certificate` rows. A key that is null for the single most important case
(see PAN-CRT-006's test "the shipped profile passes the floor and fails the certificate") would
be worse than none. What is stored instead is the TRUST VERDICT and the evidence it rests on,
computed from the certificate name the profile row names - so the name still comes from one place.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class ManagementTlsBinding(ProvenancedMixin, SyncTrackedModel):
    """The SSL/TLS service profile the management interface serves, on one appliance."""

    #: Computed here: resolved through the profile this binding names, which carries no marker of its own. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "profile_scope",
        "certificate_trust",
        "certificate_scope",
        "certificate_issuer",
    )

    #: Which definition the bound name resolved to. PREDEFINED BEATS SHARED - measured
    #: 2026-09-02, a shared entry written under a predefined name was accepted, committed and
    #: ignored whole - and a vsys profile can never be bound here at all. The string values are
    #: the ones `resolve_ssl_tls_profile` and `resolve_certificate` return.
    SCOPE_PREDEFINED = "predefined"
    SCOPE_SHARED = "shared"
    #: Bound to a name no collected scope defines. Distinct from blank, which means nothing is
    #: bound: one is a dangling reference, the other a deliberate absence.
    SCOPE_UNRESOLVED = "unresolved"
    SCOPE_CHOICES = [
        (SCOPE_PREDEFINED, "Predefined"),
        (SCOPE_SHARED, "Shared"),
        (SCOPE_UNRESOLVED, "Unresolved"),
    ]

    #: Classified rather than a boolean: the fourth state is a real answer. See
    #: `_issuer_chain_trust` for why PRIVATE_CA and CA_ISSUED are kept apart.
    TRUST_SELF_SIGNED = "self_signed"
    TRUST_PRIVATE_CA = "private_ca"
    TRUST_CA_ISSUED = "ca_issued"
    TRUST_UNDETERMINED = "undetermined"
    TRUST_CHOICES = [
        (TRUST_SELF_SIGNED, "Self-signed"),
        (TRUST_PRIVATE_CA, "Issued by a private CA on this device"),
        (TRUST_CA_ISSUED, "CA-issued"),
        (TRUST_UNDETERMINED, "Undetermined"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="management_tls_bindings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="management_tls_bindings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="management_tls_bindings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="management_tls_bindings")

    #: The name `deviceconfig/system/ssl-tls-service-profile` binds. Empty means NOTHING is
    #: bound, which is not benign: measured 2026-09-02, an unbound management interface accepts
    #: TLS 1.1. PAN-MGT-010.
    profile_name = models.CharField(max_length=64, blank=True)
    profile_scope = models.CharField(max_length=16, blank=True, choices=SCOPE_CHOICES)
    #: The profile row the name resolved to. Null when nothing is bound or the name resolves
    #: nowhere. SET_NULL rather than CASCADE: a profile row disappearing must leave the binding
    #: recorded as dangling, which is a finding, not delete the evidence that there was one.
    ssl_tls_service_profile = models.ForeignKey(
        "integrations.SslTlsServiceProfile", on_delete=models.SET_NULL,
        related_name="management_bindings", null=True, blank=True)

    #: PAN-CRT-006. Blank when nothing is bound or the profile names no certificate.
    certificate_trust = models.CharField(max_length=16, blank=True, choices=TRUST_CHOICES)
    #: The evidence the verdict rests on, kept for the same reason `MasterKey.expires_at` is:
    #: a classification an assessor cannot check is a classification they must take on trust.
    certificate_scope = models.CharField(max_length=16, blank=True, choices=SCOPE_CHOICES)
    certificate_issuer = models.CharField(max_length=255, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_management_tls_binding_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} management TLS binding"

    # Read THROUGH the profile row, never stored. These three are the values that drifted.
    @property
    def min_version(self) -> str:
        return self.ssl_tls_service_profile.min_version if self.ssl_tls_service_profile else ""

    @property
    def max_version(self) -> str:
        return self.ssl_tls_service_profile.max_version if self.ssl_tls_service_profile else ""

    @property
    def certificate_name(self) -> str:
        return (self.ssl_tls_service_profile.certificate_name
                if self.ssl_tls_service_profile else "")
