"""PAN-OS collector for the Panorama device-group hierarchy.

One op call per station. `show dg-hierarchy` returns every device group Panorama holds,
including ones that have pushed nothing, and expresses nesting by containment - which is
the whole reason it is collected rather than derived from provenance markers.

Panorama-only, guarded the same way `show managed devices` is: the command does not exist
on a firewall.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import ManagementStation
from optivedge_integrations.integrations.platforms.pan_os.collectors.base import collect_op_response
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession, PANSessionError


SHOW_DG_HIERARCHY_COMMAND = "<show><dg-hierarchy/></show>"

#: The snapshot source_type this collector writes. Named here, beside the command it comes
#: from, so persistence and normalization cannot drift from the collector.
DG_HIERARCHY_SOURCE_TYPE = "show_dg_hierarchy"


def collect_show_dg_hierarchy(session: PANSession) -> PANOSCollectedResponse:
    management_station = getattr(session, "management_station", None)
    if management_station is not None:
        station_type = getattr(management_station, "station_type", None)
        if station_type != ManagementStation.StationType.PAN_PANORAMA:
            raise PANSessionError(
                "show dg-hierarchy is only supported for Panorama management stations"
            )

    request = PANOSOperationRequest(
        command_xml=SHOW_DG_HIERARCHY_COMMAND,
        metadata={"command_name": "show dg-hierarchy"},
    )
    return collect_op_response(
        session,
        source_type=DG_HIERARCHY_SOURCE_TYPE,
        request=request,
    )
