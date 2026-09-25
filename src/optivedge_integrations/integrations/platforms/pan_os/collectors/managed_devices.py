"""PAN-OS collector for managed-device inventory commands.

This module stays PAN-OS-specific and should only own command definitions and
collection behavior for the managed-devices endpoint family.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import ManagementStation
from optivedge_integrations.integrations.platforms.pan_os.collectors.base import collect_op_response
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession, PANSessionError


SHOW_MANAGED_DEVICES_COMMAND = "<show><devices><all></all></devices></show>"

#: The snapshot source_type this collector writes. Named here, beside the command it comes
#: from, so persistence and the station views cannot drift from the collector.
MANAGED_DEVICES_SOURCE_TYPE = "show_managed_devices"


def collect_show_managed_devices(session: PANSession) -> PANOSCollectedResponse:
    management_station = getattr(session, "management_station", None)
    if management_station is not None:
        station_type = getattr(management_station, "station_type", None)
        if station_type != ManagementStation.StationType.PAN_PANORAMA:
            raise PANSessionError(
                "show managed devices is only supported for Panorama management stations"
            )

    request = PANOSOperationRequest(
        command_xml=SHOW_MANAGED_DEVICES_COMMAND,
        metadata={"command_name": "show managed devices"},
    )
    return collect_op_response(
        session,
        source_type=MANAGED_DEVICES_SOURCE_TYPE,
        request=request,
    )
