"""Normalization result types."""

from __future__ import annotations

from dataclasses import dataclass

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressObject,
    Appliance,
    ApplianceGroup,
    EnforcementNode,
    EnforcementPoint,
    DeviceConfigurationProfile,
    SecurityRule,
)


@dataclass(slots=True)
class PANOSNormalizedCollection:
    address_objects: list[AddressObject]
    address_groups: list[AddressGroup]
    appliances: list[Appliance]
    appliance_groups: list[ApplianceGroup]
    enforcement_points: list[EnforcementPoint]
    enforcement_nodes: list[EnforcementNode]
    device_configuration_profiles: list[DeviceConfigurationProfile]
    security_rules: list[SecurityRule]
