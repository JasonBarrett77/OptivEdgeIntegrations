"""PAN-OS normalization package.

This package owns translation from vendor-specific PAN-OS payloads into AegisGo
domain models. Raw response persistence should remain a separate concern.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import (
    Appliance,
    EnforcementPoint,
    ManagementStation,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.normalization.panorama import (
    normalize_show_managed_devices,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import (
    normalize_addresses,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    normalize_device_configuration_profile,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
    normalize_security_rules,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection


def normalize_collected_response(
    management_station: ManagementStation,
    collected: PANOSCollectedResponse,
) -> PANOSNormalizedCollection:
    if collected.source_type == "show_managed_devices":
        return normalize_show_managed_devices(management_station, collected)

    return PANOSNormalizedCollection(
        address_objects=[],
        address_groups=[],
        appliances=[],
        appliance_groups=[],
        enforcement_points=[],
        enforcement_nodes=[],
        device_configuration_profiles=[],
        security_rules=[],
    )


def normalize_appliance_device_configuration(appliance: Appliance) -> PANOSNormalizedCollection:
    return normalize_device_configuration_profile(appliance)


def normalize_enforcement_point_security_rules(enforcement_point: EnforcementPoint) -> PANOSNormalizedCollection:
    return normalize_security_rules(enforcement_point)


def normalize_enforcement_point_addresses(enforcement_point: EnforcementPoint) -> PANOSNormalizedCollection:
    return normalize_addresses(enforcement_point)


__all__ = [
    "PANOSNormalizedCollection",
    "normalize_addresses",
    "normalize_appliance_device_configuration",
    "normalize_enforcement_point_addresses",
    "normalize_enforcement_point_security_rules",
    "normalize_device_configuration_profile",
    "normalize_collected_response",
    "normalize_security_rules",
    "normalize_show_managed_devices",
]
