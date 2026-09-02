"""PAN-OS normalization package.

This package owns translation from vendor-specific PAN-OS payloads into OptivEdge
domain models. Raw response persistence should remain a separate concern.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import (
    Appliance,
    EnforcementPoint,
    ManagementStation,
    Zone,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.normalization.panorama import (
    normalize_show_managed_devices,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import (
    normalize_addresses,
    normalize_appliance_group_shared_objects,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    normalize_device_configuration_profile,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.dynamic_address_content import (
    NormalizedDynamicAddressContent,
    normalize_enforcement_point_dynamic_address_content,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
    normalize_security_rules,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
    normalize_certificate_objects,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.interface_management_profiles import (
    normalize_interface_management_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.interfaces import (
    NormalizedInterfaces,
    normalize_interfaces,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_interfaces import (
    normalize_management_interfaces,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.zones import (
    normalize_zones,
)


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


def normalize_appliance_group_shared_scope(appliance_group) -> PANOSNormalizedCollection:
    """Shared-scope objects for a group. MUST run before its enforcement points."""
    return normalize_appliance_group_shared_objects(appliance_group)


def normalize_enforcement_point_zones(enforcement_point: EnforcementPoint) -> list[Zone]:
    return normalize_zones(enforcement_point)


def normalize_appliance_certificate_objects(appliance: Appliance) -> dict:
    """Every SSL/TLS service profile and certificate profile on one appliance, in every scope."""
    return normalize_certificate_objects(appliance)


def normalize_appliance_interface_management_profiles(appliance: Appliance) -> list:
    """Every interface management profile on one appliance, bound or not."""
    return normalize_interface_management_profiles(appliance)


def normalize_appliance_interfaces(appliance: Appliance) -> NormalizedInterfaces:
    """Every interface on one appliance, with whatever could not be made sense of."""
    return normalize_interfaces(appliance)


def normalize_appliance_management_interfaces(appliance: Appliance) -> list:
    """Every administrative surface on one appliance - MGT, aux, and bound layer-3 interfaces."""
    return normalize_management_interfaces(appliance)


__all__ = [
    "NormalizedDynamicAddressContent",
    "NormalizedInterfaces",
    "PANOSNormalizedCollection",
    "normalize_addresses",
    "normalize_appliance_device_configuration",
    "normalize_appliance_group_shared_scope",
    "normalize_appliance_certificate_objects",
    "normalize_appliance_interface_management_profiles",
    "normalize_appliance_interfaces",
    "normalize_appliance_management_interfaces",
    "normalize_enforcement_point_addresses",
    "normalize_enforcement_point_dynamic_address_content",
    "normalize_enforcement_point_security_rules",
    "normalize_enforcement_point_zones",
    "normalize_device_configuration_profile",
    "normalize_collected_response",
    "normalize_security_rules",
    "normalize_show_managed_devices",
    "normalize_zones",
]
