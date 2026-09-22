"""Panorama-specific PAN-OS persistence helpers.

This module owns persistence entry points for Panorama-only commands such as
`show managed devices`. Normalization can expand here without mixing Panorama
rules into generic PAN-OS snapshot persistence helpers.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import ManagementStation
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.persistence.common import (
    PANOSPersistedCollection,
    persist_management_station_snapshot,
)


def persist_show_managed_devices(
    management_station: ManagementStation,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    return persist_management_station_snapshot(management_station, collected)


def persist_show_dg_hierarchy(
    management_station: ManagementStation,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    """The device-group hierarchy is station-scoped, like the managed-device inventory."""
    return persist_management_station_snapshot(management_station, collected)
