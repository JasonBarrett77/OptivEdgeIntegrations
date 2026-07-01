"""Policy object models shared across addresses, services, and similar families."""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from ..base import SyncTrackedModel
from ..collected import EnforcementPoint, ManagementStation
from .base import CONFIG_SOURCE_CHOICES, PolicyObjectBase


class ScopedPolicyObject(PolicyObjectBase, SyncTrackedModel):
    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
    )
    config_source = models.CharField(max_length=32, choices=CONFIG_SOURCE_CHOICES)

    class Meta:
        abstract = True

    def clean(self) -> None:
        if self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError("Policy object must belong to the same management station as the enforcement point.")

        if (
            self.source_snapshot.enforcement_point_id != self.enforcement_point_id
            and self.source_snapshot.appliance_id is None
            and self.source_snapshot.appliance_group_id is None
        ):
            raise ValidationError(
                "Policy object source snapshot must belong to the enforcement point or a related appliance/appliance group."
            )

        snapshot_station_id = (
            self.source_snapshot.management_station_id
            or getattr(self.source_snapshot.appliance, "management_station_id", None)
            or getattr(self.source_snapshot.appliance_group, "management_station_id", None)
            or getattr(self.source_snapshot.enforcement_point, "management_station_id", None)
        )
        if snapshot_station_id != self.management_station_id:
            raise ValidationError("Policy object source snapshot must belong to the same management station.")


class AddressObject(ScopedPolicyObject):
    TYPE_BUILTIN_ANY = "builtin_any"
    TYPE_EDL = "edl"
    TYPE_IP_NETMASK = "ip_netmask"
    TYPE_FQDN = "fqdn"
    TYPE_IP_RANGE = "ip_range"
    TYPE_IP_WILDCARD = "ip_wildcard"

    ADDRESS_TYPE_CHOICES = [
        (TYPE_BUILTIN_ANY, "Any"),
        (TYPE_EDL, "External Dynamic List"),
        (TYPE_IP_NETMASK, "IP Netmask"),
        (TYPE_FQDN, "FQDN"),
        (TYPE_IP_RANGE, "IP Range"),
        (TYPE_IP_WILDCARD, "IP Wildcard"),
    ]

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="address_objects",
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="address_objects",
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="address_objects",
    )
    address_type = models.CharField(max_length=32, choices=ADDRESS_TYPE_CHOICES)
    value = models.TextField(blank=True)
    normalized_value = models.TextField(blank=True)
    ipv4_start_int = models.BigIntegerField(null=True, blank=True)
    ipv4_end_int = models.BigIntegerField(null=True, blank=True)
    num_hosts = models.BigIntegerField(null=True, blank=True)
    is_any = models.BooleanField(default=False)
    is_edl = models.BooleanField(default=False)
    is_builtin = models.BooleanField(default=False)
    description = models.TextField(blank=True)
    raw_object = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "name", "precedence_rank"]),
            models.Index(fields=["enforcement_point", "normalized_value"]),
            models.Index(fields=["enforcement_point", "namespace_type", "namespace_value"]),
            models.Index(fields=["enforcement_point", "is_any"]),
            models.Index(fields=["enforcement_point", "ipv4_start_int"]),
            models.Index(fields=["enforcement_point", "ipv4_end_int"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_address_object_per_point_namespace",
            ),
            models.UniqueConstraint(
                fields=["enforcement_point"],
                condition=models.Q(is_any=True),
                name="integrations_single_any_address_object_per_point",
            ),
            models.CheckConstraint(
                condition=models.Q(is_any=False) | models.Q(is_builtin=True),
                name="integrations_any_address_object_must_be_builtin",
            ),
            models.CheckConstraint(
                condition=~models.Q(address_type="edl") | models.Q(is_edl=True),
                name="integrations_edl_address_object_flag",
            ),
            models.CheckConstraint(
                condition=~models.Q(address_type="builtin_any")
                | (models.Q(is_any=True) & models.Q(is_builtin=True)),
                name="integrations_builtin_any_address_object_flags",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} / {self.namespace_key} / {self.name}"

    def clean(self) -> None:
        super().clean()
        if self.is_any and not self.is_builtin:
            raise ValidationError("Address objects marked is_any must also be marked is_builtin.")

        if self.is_edl and self.address_type != self.TYPE_EDL:
            raise ValidationError("Address objects marked is_edl must use the edl address type.")

        if self.address_type == self.TYPE_BUILTIN_ANY and (not self.is_any or not self.is_builtin):
            raise ValidationError("Built-in any address objects must set both is_any and is_builtin.")

        if self.address_type == self.TYPE_EDL and not self.is_edl:
            raise ValidationError("EDL address objects must set is_edl.")


class AddressObjectTag(models.Model):
    address_object = models.ForeignKey(
        AddressObject,
        on_delete=models.CASCADE,
        related_name="tags",
    )
    value = models.CharField(max_length=255)
    prov = models.CharField(max_length=128, blank=True)
    position = models.PositiveIntegerField()

    class Meta:
        ordering = ["position", "id"]

    def __str__(self) -> str:
        return self.value


class AddressGroup(ScopedPolicyObject):
    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="address_groups",
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="address_groups",
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="address_groups",
    )
    dynamic_filter = models.TextField(blank=True)
    raw_group = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "name", "precedence_rank"]),
            models.Index(fields=["enforcement_point", "namespace_type", "namespace_value"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_address_group_per_point_namespace",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} / {self.namespace_key} / {self.name}"

    def clean(self) -> None:
        super().clean()


class AddressGroupTag(models.Model):
    address_group = models.ForeignKey(
        AddressGroup,
        on_delete=models.CASCADE,
        related_name="tags",
    )
    value = models.CharField(max_length=255)
    prov = models.CharField(max_length=128, blank=True)
    position = models.PositiveIntegerField()

    class Meta:
        ordering = ["position", "id"]

    def __str__(self) -> str:
        return self.value


class AddressGroupMember(models.Model):
    address_group = models.ForeignKey(
        AddressGroup,
        on_delete=models.CASCADE,
        related_name="members",
    )
    value = models.CharField(max_length=255)
    prov = models.CharField(max_length=128, blank=True)
    position = models.PositiveIntegerField()

    class Meta:
        ordering = ["position", "id"]

    def __str__(self) -> str:
        return self.value
