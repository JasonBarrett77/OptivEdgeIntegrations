"""Normalized device configuration models."""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel
from .collected import Appliance, ApplianceGroup, ManagementStation
from .policy.base import CONFIG_SOURCE_CHOICES
from .provenance import ProvenancedMixin


class DeviceConfigurationProfile(ProvenancedMixin, SyncTrackedModel):
    """Appliance-scoped normalized device configuration settings."""

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="device_configuration_profiles",
    )
    appliance = models.ForeignKey(
        Appliance,
        on_delete=models.CASCADE,
        related_name="device_configuration_profiles",
    )
    appliance_group = models.ForeignKey(
        ApplianceGroup,
        on_delete=models.CASCADE,
        related_name="device_configuration_profiles",
        null=True,
        blank=True,
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="device_configuration_profiles",
    )
    config_source = models.CharField(max_length=32, choices=CONFIG_SOURCE_CHOICES)

    ha_required = models.BooleanField(default=False)
    ha_enabled = models.BooleanField(default=False)
    ha_state_sync_enabled = models.BooleanField(default=False)
    ha_link_monitoring_enabled = models.BooleanField(default=False)

    #: Whether an administrator must acknowledge the login banner. Implicit `no` - the
    #: checkbox reads unticked with the key absent, and is GREYED OUT until a banner exists,
    #: so this cannot be required without one. Measured 2026-09-01.
    ack_login_banner = models.BooleanField(default=False)
    #: Whether the update server's TLS identity is verified. Implicit `yes` - the checkbox
    #: reads ticked with the key absent. Measured 2026-09-01, and deliberately the opposite
    #: default to `log_on_high_dp_load` below: these are neighbouring management settings
    #: with opposite defaults, so one assumption for both would be wrong for one of them.
    server_verification_enabled = models.BooleanField(default=True)
    #: Implicit `no` - unticked with the key absent AND with the whole
    #: deviceconfig/setting/management node absent, which is the state on both PA-5220s.
    log_on_high_dp_load = models.BooleanField(default=False)

    #: The SSL/TLS service profile bound to the management interface, and the definition it
    #: resolves to. PAN-MGT-010's subject.
    #:
    #: Stored as resolved scalars rather than a foreign key to a profile model, because the
    #: only question asked of an SSL/TLS profile so far is asked of the SURFACE - what does
    #: this appliance's management interface enforce - and that is answerable without the
    #: profile ever becoming a row. `InterfaceManagementProfile` records the opposite case
    #: and the reason it is opposite: an UNUSED profile leaves no surface, so it could only
    #: be found by modelling the object. When a control asks something of SSL/TLS profiles as
    #: objects, the model is additive and these fields become its denormalization.
    #:
    #: Empty name means NOTHING is bound, which is not benign: measured 2026-09-02, an unbound
    #: management interface accepts TLS 1.1, so absence fails the control rather than passing
    #: it by default.
    ssl_tls_service_profile_name = models.CharField(max_length=64, blank=True)

    #: Which definition won. PAN-OS resolves this name over the predefined and shared scopes
    #: only - a vsys profile never becomes referenceable here, measured 2026-09-02 via
    #: `action=complete` on the binding field - and PREDEFINED BEATS SHARED. That order is
    #: measured, not assumed, and it is the opposite of `region`, where a custom definition
    #: extends its predefined namesake. Recorded per row because a name alone cannot say which
    #: settings are in force when both scopes define it.
    SSL_TLS_SCOPE_PREDEFINED = "predefined"
    SSL_TLS_SCOPE_SHARED = "shared"
    #: Bound to a name with no definition in either scope. Distinct from blank, which means
    #: nothing is bound at all: one is a dangling reference, the other a deliberate absence,
    #: and a control must not report them the same way.
    SSL_TLS_SCOPE_UNRESOLVED = "unresolved"
    SSL_TLS_SCOPE_CHOICES = [
        (SSL_TLS_SCOPE_PREDEFINED, "Predefined"),
        (SSL_TLS_SCOPE_SHARED, "Shared"),
        (SSL_TLS_SCOPE_UNRESOLVED, "Unresolved"),
    ]
    ssl_tls_profile_scope = models.CharField(
        max_length=16, blank=True, choices=SSL_TLS_SCOPE_CHOICES)

    #: The resolved profile's protocol floor and ceiling. Blank when nothing is bound or the
    #: name does not resolve. `protocol-settings` absent on a profile that DOES exist has not
    #: been measured, so blank must not be read as "PAN-OS defaulted it".
    ssl_tls_min_version = models.CharField(max_length=16, blank=True)
    ssl_tls_max_version = models.CharField(max_length=16, blank=True)
    #: The certificate the resolved profile presents. A name only. Whether the CA behind it is
    #: organisation-trusted is not a configuration fact and is deliberately not decided here.
    ssl_tls_certificate_name = models.CharField(max_length=255, blank=True)

    #: The certificate's own properties, resolved from the certificate object the profile
    #: names. PAN-CRT-006's subject, kept separate from PAN-MGT-010's protocol floor because
    #: the two are independent: the SHIPPED TLSv1.3_Default profile satisfies the floor and
    #: still serves the device's self-signed factory certificate, so one control passing tells
    #: you nothing about the other.
    #:
    #: Self-signed is decided by `subject-hash == issuer-hash`, which PAN-OS computes and
    #: exposes on the certificate entry - not by parsing the DN strings, which are formatted
    #: differently between scopes ("/CN=x" in shared, bare "x" in predefined) and would make
    #: a string comparison scope-dependent.
    #:
    #: Classified rather than stored as a raw boolean, following the same shape as
    #: `exposure.classify` on the management-interface side: the third state is a real answer
    #: and a nullable boolean invites a query that treats NULL as false. UNDETERMINED covers
    #: nothing bound, a profile that did not resolve, a certificate name that resolved
    #: nowhere, and a certificate present but carrying no hashes - all of which mean "an
    #: engineer must look", never "satisfied".
    TRUST_SELF_SIGNED = "self_signed"
    TRUST_CA_ISSUED = "ca_issued"
    TRUST_UNDETERMINED = "undetermined"
    TRUST_CHOICES = [
        (TRUST_SELF_SIGNED, "Self-signed"),
        (TRUST_CA_ISSUED, "CA-issued"),
        (TRUST_UNDETERMINED, "Undetermined"),
    ]
    #: CA_ISSUED means only that something other than the certificate itself signed it. It
    #: does NOT mean the signer is the organisation's own CA - that is not decidable from
    #: configuration, and PAN-CRT-006 says so rather than pretending otherwise.
    ssl_tls_certificate_trust = models.CharField(
        max_length=16, blank=True, choices=TRUST_CHOICES)
    #: The issuing authority as PAN-OS reports it. Recorded so an engineer can see WHICH CA
    #: signed it; whether that CA is the organisation's own is not decidable from config and
    #: is deliberately not decided here.
    ssl_tls_certificate_issuer = models.CharField(max_length=255, blank=True)
    #: Which scope the certificate object was found in - the profile and its certificate can
    #: come from different scopes, so this is not a duplicate of ssl_tls_profile_scope.
    ssl_tls_certificate_scope = models.CharField(
        max_length=16, blank=True, choices=SSL_TLS_SCOPE_CHOICES)

    #: PAN-CRT-007. The master key encrypts every private key and secret on the device, and
    #: the factory default is a PUBLICLY KNOWN value - so a device that never set one is
    #: protecting its key material with a shared secret anybody can look up.
    #:
    #: Classified, like ssl_tls_certificate_trust, because the third state is a real answer:
    #: UNDETERMINED means the properties were never collected, which is different from
    #: "collected and found to be default" and must not be read as either a pass or a fail.
    MASTER_KEY_DEFAULT = "default"
    MASTER_KEY_SET = "set"
    MASTER_KEY_UNDETERMINED = "undetermined"
    MASTER_KEY_CHOICES = [
        (MASTER_KEY_DEFAULT, "Factory default"),
        (MASTER_KEY_SET, "Set"),
        (MASTER_KEY_UNDETERMINED, "Undetermined"),
    ]
    #: DEFAULT is derived from `expire-at` being 0 - what the CLI renders as "unspecified".
    #: The inference is that a lifetime is MANDATORY when setting a key, in both the CLI and
    #: the GUI, so a key that has been set always carries a concrete expiry and an absent one
    #: cannot mean "set without a lifetime". That is vendor-documented, not measured here:
    #: nobody has set a master key on a lab device and watched these fields change. The
    #: payload contract's master-key node records it as an inference and says what would
    #: close it.
    master_key_state = models.CharField(
        max_length=16, blank=True, choices=MASTER_KEY_CHOICES)
    #: Raw, as reported. Kept because the derivation above rests on it and a reader checking
    #: the control should be able to see the value it was derived from.
    master_key_expires_at = models.CharField(max_length=32, blank=True)
    #: Non-zero moves the expiry WITHOUT the key value changing, which is why "when was it
    #: changed" cannot be computed as expire-at minus lifetime.
    master_key_auto_renew_hours = models.PositiveIntegerField(default=0)
    master_key_on_hsm = models.BooleanField(default=False)

    ntp_primary_server = models.CharField(max_length=255, blank=True)
    ntp_secondary_server = models.CharField(max_length=255, blank=True)

    #: Which services the MGT plane runs is NOT here. It was - six booleans reading
    #: deviceconfig/system/service - and ManagementService superseded them: same values, plus
    #: the four keys these omitted, on every management plane rather than only MGT. Two
    #: representations of one fact drift, and the per-appliance one cannot answer the
    #: question a services finding asks, which is always about a surface.

    #: The MGT plane's permitted-source list as collected. Whether that list is acceptable
    #: is a verdict, and verdicts belong to the consumer - see ManagementInterface /
    #: PermittedSource for the per-surface model OptivEdgeAssessments assesses.
    permitted_ip_values = models.JSONField(default=list, blank=True)
    permitted_ip_count = models.PositiveIntegerField(default=0)

    login_banner = models.TextField(blank=True)
    idle_timeout_minutes = models.PositiveIntegerField(default=60)

    raw_profile = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["management_station__hostname", "appliance__hostname", "appliance__serial_number"]
        indexes = [
            models.Index(fields=["management_station"]),
            models.Index(fields=["appliance_group"]),
            models.Index(fields=["ha_required"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="integrations_unique_device_configuration_profile_per_appliance",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} device configuration profile"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError(
                "Device configuration profile appliance must belong to the same management station."
            )
        if self.appliance_group_id is not None:
            if self.appliance_group.management_station_id != self.management_station_id:
                raise ValidationError(
                    "Device configuration profile appliance group must belong to the same management station."
                )
            if self.appliance.appliance_group_id != self.appliance_group_id:
                raise ValidationError(
                    "Device configuration profile appliance must belong to the same appliance group."
                )
        elif self.appliance.appliance_group_id is not None:
            raise ValidationError(
                "Device configuration profile should record the appliance group when the appliance belongs to one."
            )

        if self.source_snapshot.appliance_id != self.appliance_id:
            raise ValidationError(
                "Device configuration profile source snapshot must belong to the same appliance."
            )
        if self.source_snapshot.management_station_id != self.management_station_id:
            raise ValidationError(
                "Device configuration profile snapshot must belong to the same management station."
            )
