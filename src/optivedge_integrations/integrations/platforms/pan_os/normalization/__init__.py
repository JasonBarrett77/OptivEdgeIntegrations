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
from optivedge_integrations.integrations.platforms.pan_os.normalization.dynamic_address_content import (
    NormalizedDynamicAddressContent,
    normalize_enforcement_point_dynamic_address_content,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
    normalize_security_rules,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_profiles import (
    normalize_appliance_group_security_profiles,
    normalize_security_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication_settings import (
    normalize_authentication_settings,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.login_banner import (
    normalize_login_banner,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_ssh import (
    normalize_management_ssh,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_tls import (
    normalize_management_tls,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.master_key import (
    normalize_master_key,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    normalize_services_settings,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_services import (
    normalize_device_services,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.password_complexity import (
    normalize_password_complexity,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.password_profiles import (
    normalize_password_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication import (
    normalize_authentication_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.admin_users import (
    normalize_admin_users,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication_sequences import (
    normalize_authentication_sequences,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.server_profiles import (
    normalize_server_profiles,
)
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
        security_rules=[],
    )


def normalize_enforcement_point_security_rules(enforcement_point: EnforcementPoint) -> PANOSNormalizedCollection:
    return normalize_security_rules(enforcement_point)


def normalize_enforcement_point_addresses(enforcement_point: EnforcementPoint) -> PANOSNormalizedCollection:
    return normalize_addresses(enforcement_point)


def normalize_appliance_group_shared_scope(appliance_group) -> PANOSNormalizedCollection:
    """Shared-scope objects for a group. MUST run before its enforcement points."""
    return normalize_appliance_group_shared_objects(appliance_group)


def normalize_enforcement_point_zones(enforcement_point: EnforcementPoint) -> list[Zone]:
    return normalize_zones(enforcement_point)


def normalize_appliance_management_tls(appliance: Appliance) -> dict:
    """The management interface's SSL/TLS binding. PAN-MGT-010 and PAN-CRT-006.

    Must run after `normalize_appliance_certificate_objects`: it resolves over the profile ROWS.
    """
    return normalize_management_tls(appliance)


def normalize_appliance_management_ssh(appliance: Appliance) -> dict:
    """The management SSH server's configured offer. PAN-MCR-001 and 003."""
    return normalize_management_ssh(appliance)


def normalize_appliance_master_key(appliance: Appliance) -> dict:
    """The master key state. PAN-CRT-007."""
    return normalize_master_key(appliance)


def normalize_appliance_services_settings(appliance: Appliance) -> dict:
    """Update server verification and the high-DP-load logging setting. PAN-MGT-009 and 011."""
    return normalize_services_settings(appliance)


def normalize_appliance_device_services(appliance: Appliance) -> dict:
    """NTP, SNMP and system identity. PAN-SVC-001, 002, 004, 005, 007 and 009.

    MUST run after `normalize_appliance_management_interfaces`: whether SNMP is reachable is a
    property of the surfaces that normalizer writes, not of the `snmp-setting` subtree.
    """
    return normalize_device_services(appliance)


def normalize_appliance_login_banner(appliance: Appliance) -> dict:
    """The management login banner and its acknowledgement. PAN-MGT-007 and 008."""
    return normalize_login_banner(appliance)


def normalize_appliance_authentication_settings(appliance: Appliance) -> dict:
    """Device-wide administrator authentication settings. PAN-AUTH-014 to 017."""
    return normalize_authentication_settings(appliance)


def normalize_appliance_password_complexity(appliance: Appliance) -> dict:
    """The global minimum password complexity. PAN-AUTH-001 to 013."""
    return normalize_password_complexity(appliance)


def normalize_appliance_password_profiles(appliance: Appliance) -> dict:
    """Password profiles, with the global policy each one would override."""
    return normalize_password_profiles(appliance)


def normalize_appliance_server_profiles(appliance: Appliance) -> dict:
    """Every AAA server profile on one appliance, in every scope, with its referrer count."""
    return normalize_server_profiles(appliance)


def normalize_appliance_admin_users(appliance: Appliance) -> dict:
    """Every administrator account under mgt-config/users, with the superuser total."""
    return normalize_admin_users(appliance)


def normalize_appliance_authentication_profiles(appliance: Appliance) -> dict:
    """Authentication profiles, in every scope they occupy."""
    return normalize_authentication_profiles(appliance)


def normalize_appliance_authentication_sequences(appliance: Appliance) -> dict:
    """Authentication sequences, in every scope - after profiles, before admin users."""
    return normalize_authentication_sequences(appliance)


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
    "normalize_appliance_group_security_profiles",
    "normalize_appliance_group_shared_scope",
    "normalize_appliance_admin_users",
    "normalize_appliance_server_profiles",
    "normalize_appliance_authentication_profiles",
    "normalize_appliance_authentication_sequences",
    "normalize_appliance_authentication_settings",
    "normalize_appliance_login_banner",
    "normalize_appliance_management_tls",
    "normalize_appliance_management_ssh",
    "normalize_appliance_master_key",
    "normalize_appliance_services_settings",
    "normalize_appliance_device_services",
    "normalize_appliance_password_complexity",
    "normalize_appliance_password_profiles",
    "normalize_appliance_certificate_objects",
    "normalize_appliance_interface_management_profiles",
    "normalize_appliance_interfaces",
    "normalize_appliance_management_interfaces",
    "normalize_enforcement_point_addresses",
    "normalize_enforcement_point_dynamic_address_content",
    "normalize_enforcement_point_security_rules",
    "normalize_enforcement_point_zones",
    "normalize_collected_response",
    "normalize_security_profiles",
    "normalize_security_rules",
    "normalize_show_managed_devices",
    "normalize_zones",
]
