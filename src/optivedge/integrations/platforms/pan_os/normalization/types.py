"""Normalization result types."""

from __future__ import annotations

from dataclasses import dataclass

from optivedge.integrations.models import (
    AddressGroup,
    AddressObject,
    Appliance,
    ApplianceGroup,
    EnforcementNode,
    EnforcementPoint,
    ManagementPlaneProfile,
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
    management_plane_profiles: list[ManagementPlaneProfile]
    security_rules: list[SecurityRule]
