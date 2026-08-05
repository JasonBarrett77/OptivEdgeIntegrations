"""Collected and topology models for the integrations app."""

from __future__ import annotations

from django.contrib.contenttypes.fields import GenericRelation
from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel, TimestampedModel


class ManagementStation(TimestampedModel):
    class StationType(models.TextChoices):
        PAN_PANORAMA = "pan_panorama", "Palo Alto Networks - Panorama"
        PAN_FIREWALL = "pan_firewall", "Palo Alto Networks - Firewall"

    station_type = models.CharField(max_length=32, choices=StationType.choices)
    name = models.CharField(max_length=128, blank=True)
    hostname = models.CharField(max_length=255)
    port = models.PositiveIntegerField(default=443)
    username = models.TextField(blank=True)
    password = models.TextField(blank=True)
    api_key = models.TextField(blank=True, null=True)
    verify_tls = models.BooleanField(default=True)
    ca_bundle_path = models.CharField(max_length=512, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["hostname"]
        constraints = [
            models.UniqueConstraint(
                fields=["hostname"],
                name="integrations_unique_management_station",
            ),
        ]

    def __str__(self) -> str:
        return self.name or self.hostname


class ApplianceGroup(SyncTrackedModel):
    TYPE_STANDALONE = "standalone"
    TYPE_HA_PAIR = "ha_pair"
    TYPE_CLUSTER = "cluster"

    GROUP_TYPE_CHOICES = [
        (TYPE_STANDALONE, "Standalone"),
        (TYPE_HA_PAIR, "HA Pair"),
        (TYPE_CLUSTER, "Cluster"),
    ]

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="appliance_groups",
    )
    name = models.CharField(max_length=128)
    group_type = models.CharField(max_length=32, choices=GROUP_TYPE_CHOICES, default=TYPE_STANDALONE)
    discovery_key = models.CharField(max_length=256, blank=True)
    active_appliance = models.ForeignKey(
        "integrations.Appliance",
        on_delete=models.SET_NULL,
        related_name="active_in_groups",
        null=True,
        blank=True,
    )
    notes = models.TextField(blank=True)
    # User-authored Note records (the Notes feature). Distinct from the scalar `notes`
    # field above; the GenericRelation gives cascade cleanup if the group is deleted.
    note_entries = GenericRelation("integrations.Note", related_query_name="appliance_group")

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["management_station", "name"],
                name="integrations_unique_appliance_group_name_per_station",
            ),
        ]

    def __str__(self) -> str:
        return self.name

    def clean(self) -> None:
        if self.active_appliance is None:
            return
        if self.active_appliance.management_station_id != self.management_station_id:
            raise ValidationError("Active appliance must belong to the same management station.")
        if self.pk is None:
            raise ValidationError("Save the appliance group before assigning an active appliance.")
        if self.active_appliance.appliance_group_id != self.pk:
            raise ValidationError("Active appliance must belong to this appliance group.")


class Appliance(SyncTrackedModel):
    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="appliances",
    )
    appliance_group = models.ForeignKey(
        ApplianceGroup,
        on_delete=models.CASCADE,
        related_name="appliances",
        null=True,
        blank=True,
    )
    hostname = models.CharField(max_length=128, blank=True)
    serial_number = models.CharField(max_length=64)
    model = models.CharField(max_length=128, blank=True)
    software_version = models.CharField(max_length=64, blank=True)
    details_collected_at = models.DateTimeField(null=True, blank=True)
    topology_resolved_at = models.DateTimeField(null=True, blank=True)
    virtual_systems_collected_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["hostname", "serial_number"]
        constraints = [
            models.UniqueConstraint(
                fields=["management_station", "serial_number"],
                name="integrations_unique_appliance_serial_per_station",
            ),
        ]

    def __str__(self) -> str:
        return self.hostname or self.serial_number

    def clean(self) -> None:
        if self.appliance_group is None:
            return
        if self.appliance_group.management_station_id != self.management_station_id:
            raise ValidationError("Appliance group must belong to the same management station.")


class EnforcementPoint(SyncTrackedModel):
    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="enforcement_points",
    )
    appliance = models.ForeignKey(
        Appliance,
        on_delete=models.CASCADE,
        related_name="enforcement_points",
        null=True,
        blank=True,
    )
    appliance_group = models.ForeignKey(
        ApplianceGroup,
        on_delete=models.CASCADE,
        related_name="enforcement_points",
        null=True,
        blank=True,
    )
    vsys_name = models.CharField(max_length=64)
    vsys_display_name = models.CharField(max_length=128, blank=True)
    in_scope = models.BooleanField(default=False)
    discovery_key = models.CharField(max_length=256, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["vsys_name", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance_group", "vsys_name"],
                name="integrations_unique_enforcement_point_per_group_vsys",
                condition=models.Q(appliance_group__isnull=False),
            ),
            models.UniqueConstraint(
                fields=["appliance", "vsys_name"],
                name="integrations_unique_enforcement_point_per_appliance_vsys",
                condition=models.Q(appliance__isnull=False),
            ),
        ]

    def __str__(self) -> str:
        owner = self.appliance_group or self.appliance
        return f"{owner} / {self.vsys_name}"

    def clean(self) -> None:
        owner_count = int(self.appliance is not None) + int(self.appliance_group is not None)
        if owner_count != 1:
            raise ValidationError("Enforcement point must belong to exactly one appliance or appliance group.")
        if self.appliance is not None and self.appliance.management_station_id != self.management_station_id:
            raise ValidationError("Appliance must belong to the same management station.")
        if self.appliance_group is not None and self.appliance_group.management_station_id != self.management_station_id:
            raise ValidationError("Appliance group must belong to the same management station.")


class EnforcementNode(SyncTrackedModel):
    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="enforcement_nodes",
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="nodes",
    )
    appliance = models.ForeignKey(
        Appliance,
        on_delete=models.CASCADE,
        related_name="enforcement_nodes",
    )
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["id"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "enforcement_point"],
                name="integrations_unique_enforcement_node_per_appliance_point",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} @ {self.enforcement_point.vsys_name}"

    def clean(self) -> None:
        if self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError("Enforcement point must belong to the same management station.")
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError("Appliance must belong to the same management station.")
        if self.enforcement_point.appliance_id is not None:
            if self.appliance_id != self.enforcement_point.appliance_id:
                raise ValidationError("Appliance-scoped enforcement points must use the same appliance.")
            return
        if self.appliance.appliance_group_id != self.enforcement_point.appliance_group_id:
            raise ValidationError("Appliance must belong to the enforcement point appliance group.")


class Snapshot(TimestampedModel):
    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="snapshots",
        null=True,
        blank=True,
    )
    appliance_group = models.ForeignKey(
        ApplianceGroup,
        on_delete=models.CASCADE,
        related_name="snapshots",
        null=True,
        blank=True,
    )
    appliance = models.ForeignKey(
        Appliance,
        on_delete=models.CASCADE,
        related_name="snapshots",
        null=True,
        blank=True,
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="snapshots",
        null=True,
        blank=True,
    )
    enforcement_node = models.ForeignKey(
        EnforcementNode,
        on_delete=models.CASCADE,
        related_name="snapshots",
        null=True,
        blank=True,
    )
    source_type = models.CharField(max_length=64)
    scope_name = models.CharField(max_length=128, blank=True)
    payload = models.JSONField(default=dict, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    collected_at = models.DateTimeField()

    class Meta:
        ordering = ["-collected_at", "source_type"]

    def __str__(self) -> str:
        target = (
            self.enforcement_node
            or self.enforcement_point
            or self.appliance
            or self.appliance_group
            or self.management_station
        )
        return f"{self.source_type} @ {target}"

    def clean(self) -> None:
        scope_targets = {
            "management_station": self.management_station,
            "appliance_group": self.appliance_group,
            "appliance": self.appliance,
            "enforcement_point": self.enforcement_point,
            "enforcement_node": self.enforcement_node,
        }
        populated_targets = {name: value for name, value in scope_targets.items() if value is not None}

        if len(populated_targets) != 1:
            raise ValidationError("Snapshot must be attached to exactly one scope target.")

        target_name, target = next(iter(populated_targets.items()))
        if target_name == "management_station":
            return

        if target.management_station_id is None:
            raise ValidationError("Snapshot target must belong to a management station.")
