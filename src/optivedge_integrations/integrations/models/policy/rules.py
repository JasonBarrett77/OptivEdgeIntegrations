"""Security rule and rule-adjacent policy models."""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from ..base import SyncTrackedModel
from ..collected import EnforcementPoint, ManagementStation
from ..provenance import ProvenancedMixin
from .base import CONFIG_SOURCE_CHOICES


class SecurityRule(ProvenancedMixin, SyncTrackedModel):
    SOURCE_LOCAL = "local"
    SOURCE_PUSHED_PRE = "pushed_pre"
    SOURCE_PUSHED_POST = "pushed_post"
    SOURCE_DEFAULT = "default"

    CONFIG_SOURCE_CHOICES = CONFIG_SOURCE_CHOICES

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="security_rules",
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="security_rules",
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="security_rules",
    )
    config_source = models.CharField(max_length=32, choices=CONFIG_SOURCE_CHOICES)
    effective_order = models.PositiveIntegerField()
    rule_position = models.PositiveIntegerField()
    name = models.CharField(max_length=255)
    uuid = models.CharField(max_length=64, blank=True)
    action = models.CharField(max_length=32, blank=True)
    disabled = models.BooleanField(default=False)
    rule_type = models.CharField(max_length=64, blank=True)
    description = models.TextField(blank=True)
    log_start = models.BooleanField(null=True, blank=True)
    log_end = models.BooleanField(null=True, blank=True)
    log_setting = models.CharField(max_length=128, blank=True)
    raw_rule = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["effective_order", "name", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name"],
                name="integrations_unique_security_rule_name_per_point",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} / {self.name}"

    def clean(self) -> None:
        if self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError("Security rule must belong to the same management station as the enforcement point.")
        if self.source_snapshot.enforcement_point_id != self.enforcement_point_id and self.source_snapshot.appliance_id is None:
            raise ValidationError("Security rule source snapshot must belong to the enforcement point or a related appliance.")
        snapshot_station_id = (
            self.source_snapshot.management_station_id
            or getattr(self.source_snapshot.appliance, "management_station_id", None)
            or getattr(self.source_snapshot.enforcement_point, "management_station_id", None)
        )
        if snapshot_station_id != self.management_station_id:
            raise ValidationError("Security rule source snapshot must belong to the same management station.")


class SecurityRuleValue(models.Model):
    security_rule = models.ForeignKey(
        SecurityRule,
        on_delete=models.CASCADE,
        related_name="%(class)ss",
    )
    value = models.CharField(max_length=255)
    prov = models.CharField(max_length=128, blank=True)
    position = models.PositiveIntegerField()

    class Meta:
        abstract = True
        ordering = ["position", "id"]

    def __str__(self) -> str:
        return self.value


class SecurityRuleFromZone(SecurityRuleValue):
    pass


class SecurityRuleToZone(SecurityRuleValue):
    pass


class SecurityRuleAddressRef(models.Model):
    class RefType(models.TextChoices):
        ADDRESS_OBJECT = "address_object", "Address Object"
        STATIC_ADDRESS_GROUP = "static_address_group", "Static Address Group"
        DYNAMIC_ADDRESS_GROUP = "dynamic_address_group", "Dynamic Address Group"
        ANY = "any", "Any"
        REGION = "region", "Region"

    raw_value = models.CharField(max_length=255)
    position = models.PositiveIntegerField()
    ref_type = models.CharField(max_length=32, choices=RefType.choices)
    address_object = models.ForeignKey(
        "integrations.AddressObject",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    address_group = models.ForeignKey(
        "integrations.AddressGroup",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    region = models.ForeignKey(
        "integrations.Region",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )

    class Meta:
        abstract = True
        ordering = ["position", "id"]

    def clean(self) -> None:
        if self.ref_type == self.RefType.ADDRESS_OBJECT:
            if self.address_object is None or self.address_group is not None:
                raise ValidationError(
                    "Address-object refs require address_object and must not set address_group."
                )
            return

        if self.ref_type == self.RefType.STATIC_ADDRESS_GROUP:
            if self.address_object is None or self.address_group is None:
                raise ValidationError(
                    "Static-address-group refs require both address_object and address_group."
                )
            return

        if self.ref_type == self.RefType.DYNAMIC_ADDRESS_GROUP:
            if self.address_object is not None or self.address_group is None:
                raise ValidationError(
                    "Dynamic-address-group refs require address_group and must not set address_object."
                )
            return

        if self.ref_type == self.RefType.ANY:
            if self.address_object is None or self.address_group is not None:
                raise ValidationError(
                    "Any refs require address_object and must not set address_group."
                )
            if not self.address_object.is_any:
                raise ValidationError("Any refs must point to an address object marked is_any.")
            return

        if self.ref_type == self.RefType.REGION:
            if self.address_object is not None or self.address_group is not None:
                raise ValidationError(
                    "Region refs must not set address_object or address_group. "
                    "region may be null (builtin country/region code) or set (custom region object)."
                )
            return

        raise ValidationError("Unsupported address ref type.")

    def __str__(self) -> str:
        target = self.address_group or self.address_object or self.region or self.raw_value
        return f"{self.raw_value} -> {target}"


class SecurityRuleSourceAddressRef(SecurityRuleAddressRef):
    security_rule = models.ForeignKey(
        SecurityRule,
        on_delete=models.CASCADE,
        related_name="source_address_refs",
    )

    class Meta(SecurityRuleAddressRef.Meta):
        indexes = [
            models.Index(fields=["security_rule", "ref_type"]),
            models.Index(fields=["address_object"]),
            models.Index(fields=["address_group"]),
            models.Index(fields=["region"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                        address_object__isnull=False,
                        address_group__isnull=True,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.STATIC_ADDRESS_GROUP,
                        address_object__isnull=False,
                        address_group__isnull=False,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.DYNAMIC_ADDRESS_GROUP,
                        address_object__isnull=True,
                        address_group__isnull=False,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.ANY,
                        address_object__isnull=False,
                        address_group__isnull=True,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.REGION,
                        address_object__isnull=True,
                        address_group__isnull=True,
                    )
                ),
                name="integrations_valid_source_address_ref_shape",
            ),
        ]


class SecurityRuleDestinationAddressRef(SecurityRuleAddressRef):
    security_rule = models.ForeignKey(
        SecurityRule,
        on_delete=models.CASCADE,
        related_name="destination_address_refs",
    )

    class Meta(SecurityRuleAddressRef.Meta):
        indexes = [
            models.Index(fields=["security_rule", "ref_type"]),
            models.Index(fields=["address_object"]),
            models.Index(fields=["address_group"]),
            models.Index(fields=["region"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                        address_object__isnull=False,
                        address_group__isnull=True,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.STATIC_ADDRESS_GROUP,
                        address_object__isnull=False,
                        address_group__isnull=False,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.DYNAMIC_ADDRESS_GROUP,
                        address_object__isnull=True,
                        address_group__isnull=False,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.ANY,
                        address_object__isnull=False,
                        address_group__isnull=True,
                    )
                    | models.Q(
                        ref_type=SecurityRuleAddressRef.RefType.REGION,
                        address_object__isnull=True,
                        address_group__isnull=True,
                    )
                ),
                name="integrations_valid_destination_address_ref_shape",
            ),
        ]


class SecurityRuleSourceUser(SecurityRuleValue):
    pass


class SecurityRuleApplication(SecurityRuleValue):
    pass


class SecurityRuleService(SecurityRuleValue):
    pass


class SecurityRuleCategory(SecurityRuleValue):
    pass


class SecurityRuleSourceHip(SecurityRuleValue):
    pass


class SecurityRuleDestinationHip(SecurityRuleValue):
    pass


class SecurityRuleSaasUser(SecurityRuleValue):
    pass


class SecurityRuleSaasTenant(SecurityRuleValue):
    pass


class SecurityRuleProfileGroup(SecurityRuleValue):
    pass


class SecurityRuleProfile(SecurityRuleValue):
    profile_type = models.CharField(max_length=64)

    class Meta(SecurityRuleValue.Meta):
        ordering = ["profile_type", "position", "id"]

    def __str__(self) -> str:
        return f"{self.profile_type}: {self.value}"
