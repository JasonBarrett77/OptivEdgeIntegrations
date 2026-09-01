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
