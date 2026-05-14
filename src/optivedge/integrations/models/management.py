"""Normalized management-plane configuration models."""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel
from .collected import Appliance, ApplianceGroup, ManagementStation
from .policy.base import CONFIG_SOURCE_CHOICES


class ManagementPlaneProfile(SyncTrackedModel):
    """Appliance-scoped normalized management-plane settings."""

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="management_plane_profiles",
    )
    appliance = models.ForeignKey(
        Appliance,
        on_delete=models.CASCADE,
        related_name="management_plane_profiles",
    )
    appliance_group = models.ForeignKey(
        ApplianceGroup,
        on_delete=models.CASCADE,
        related_name="management_plane_profiles",
        null=True,
        blank=True,
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="management_plane_profiles",
    )
    config_source = models.CharField(max_length=32, choices=CONFIG_SOURCE_CHOICES)
    provenance = models.CharField(max_length=128, blank=True)

    ha_required = models.BooleanField(default=False)
    ha_enabled = models.BooleanField(default=False)
    ha_enabled_explicit = models.BooleanField(default=False)
    ha_enabled_prov = models.CharField(max_length=128, blank=True)
    ha_state_sync_enabled = models.BooleanField(default=False)
    ha_state_sync_explicit = models.BooleanField(default=False)
    ha_state_sync_prov = models.CharField(max_length=128, blank=True)
    ha_link_monitoring_enabled = models.BooleanField(default=False)
    ha_link_monitoring_explicit = models.BooleanField(default=False)
    ha_link_monitoring_prov = models.CharField(max_length=128, blank=True)

    ntp_primary_server = models.CharField(max_length=255, blank=True)
    ntp_primary_server_prov = models.CharField(max_length=128, blank=True)
    ntp_secondary_server = models.CharField(max_length=255, blank=True)
    ntp_secondary_server_prov = models.CharField(max_length=128, blank=True)

    http_disabled = models.BooleanField(default=True)
    http_disabled_explicit = models.BooleanField(default=False)
    http_disabled_prov = models.CharField(max_length=128, blank=True)
    https_disabled = models.BooleanField(default=False)
    https_disabled_explicit = models.BooleanField(default=False)
    https_disabled_prov = models.CharField(max_length=128, blank=True)
    telnet_disabled = models.BooleanField(default=True)
    telnet_disabled_explicit = models.BooleanField(default=False)
    telnet_disabled_prov = models.CharField(max_length=128, blank=True)
    ssh_disabled = models.BooleanField(default=False)
    ssh_disabled_explicit = models.BooleanField(default=False)
    ssh_disabled_prov = models.CharField(max_length=128, blank=True)
    icmp_disabled = models.BooleanField(default=False)
    icmp_disabled_explicit = models.BooleanField(default=False)
    icmp_disabled_prov = models.CharField(max_length=128, blank=True)
    snmp_disabled = models.BooleanField(default=True)
    snmp_disabled_explicit = models.BooleanField(default=False)
    snmp_disabled_prov = models.CharField(max_length=128, blank=True)

    permitted_ip_values = models.JSONField(default=list, blank=True)
    permitted_ip_count = models.PositiveIntegerField(default=0)
    has_permitted_ip_restrictions = models.BooleanField(default=False)
    has_unrestricted_permitted_ips = models.BooleanField(default=False)

    login_banner = models.TextField(blank=True)
    login_banner_prov = models.CharField(max_length=128, blank=True)
    idle_timeout_minutes = models.PositiveIntegerField(default=60)
    idle_timeout_explicit = models.BooleanField(default=False)
    idle_timeout_prov = models.CharField(max_length=128, blank=True)

    raw_profile = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["management_station__hostname", "appliance__hostname", "appliance__serial_number"]
        indexes = [
            models.Index(fields=["management_station"]),
            models.Index(fields=["appliance_group"]),
            models.Index(fields=["ha_required"]),
            models.Index(fields=["has_permitted_ip_restrictions"]),
            models.Index(fields=["has_unrestricted_permitted_ips"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="integrations_unique_management_plane_profile_per_appliance",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} management profile"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError(
                "Management plane profile appliance must belong to the same management station."
            )
        if self.appliance_group_id is not None:
            if self.appliance_group.management_station_id != self.management_station_id:
                raise ValidationError(
                    "Management plane profile appliance group must belong to the same management station."
                )
            if self.appliance.appliance_group_id != self.appliance_group_id:
                raise ValidationError(
                    "Management plane profile appliance must belong to the same appliance group."
                )
        elif self.appliance.appliance_group_id is not None:
            raise ValidationError(
                "Management plane profile should record the appliance group when the appliance belongs to one."
            )

        if self.source_snapshot.appliance_id != self.appliance_id:
            raise ValidationError(
                "Management plane profile source snapshot must belong to the same appliance."
            )
        if self.source_snapshot.management_station_id != self.management_station_id:
            raise ValidationError(
                "Management plane profile snapshot must belong to the same management station."
            )
