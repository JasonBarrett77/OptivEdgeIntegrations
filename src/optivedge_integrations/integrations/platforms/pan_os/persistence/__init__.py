"""PAN-OS persistence package.

This package owns raw response persistence for collected PAN-OS data, such as
management-station snapshots. Normalization into AegisGo domain models should
remain a separate concern, even when endpoint-specific routing lives nearby.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import Appliance, ApplianceGroup, EnforcementPoint, ManagementStation
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.persistence.appliance import (
    persist_appliance_snapshot,
    persist_show_merged_config,
)
from optivedge_integrations.integrations.platforms.pan_os.persistence.appliance_group import (
    persist_appliance_group_snapshot,
    persist_show_pushed_shared_policy,
)
from optivedge_integrations.integrations.platforms.pan_os.persistence.common import (
    PANOSPersistedCollection,
    persist_management_station_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.persistence.enforcement_point import (
    persist_enforcement_point_snapshot,
    persist_show_pushed_shared_policy_vsys,
)
from optivedge_integrations.integrations.platforms.pan_os.persistence.panorama import (
    persist_show_managed_devices,
)


def persist_collected_response(
    management_station: ManagementStation,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    if collected.source_type == "show_managed_devices":
        return persist_show_managed_devices(management_station, collected)

    return persist_management_station_snapshot(management_station, collected)


def persist_appliance_collected_response(
    appliance: Appliance,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    if collected.source_type == "show_merged_config":
        return persist_show_merged_config(appliance, collected)

    return persist_appliance_snapshot(appliance, collected)


def persist_appliance_group_collected_response(
    appliance_group: ApplianceGroup,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    if collected.source_type == "show_pushed_shared_policy":
        return persist_show_pushed_shared_policy(appliance_group, collected)

    return persist_appliance_group_snapshot(appliance_group, collected)


def persist_enforcement_point_collected_response(
    enforcement_point: EnforcementPoint,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    if collected.source_type == "show_pushed_shared_policy_vsys":
        return persist_show_pushed_shared_policy_vsys(enforcement_point, collected)

    return persist_enforcement_point_snapshot(enforcement_point, collected)


__all__ = [
    "PANOSPersistedCollection",
    "persist_appliance_collected_response",
    "persist_appliance_snapshot",
    "persist_appliance_group_collected_response",
    "persist_appliance_group_snapshot",
    "persist_collected_response",
    "persist_enforcement_point_collected_response",
    "persist_enforcement_point_snapshot",
    "persist_management_station_snapshot",
    "persist_show_merged_config",
    "persist_show_pushed_shared_policy",
    "persist_show_pushed_shared_policy_vsys",
    "persist_show_managed_devices",
]
