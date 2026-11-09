"""PAN-OS collector for the MANAGEMENT STATION's own content deployment schedules.

THE FIREWALL SIDE OF THIS DOMAIN NEEDS NO COLLECTOR. `deviceconfig/system/update-schedule` is
carried whole by `show config merged`, which `collectors/merged_config.py` already issues per
appliance with no xpath restriction - so every column of `ContentUpdateSchedule` is normalizable
from a snapshot the estate already holds, at no new per-appliance cost.

THIS MODULE EXISTS FOR THE ONE READ NOTHING ISSUED. `deployment-update-schedule` lives ONLY on the
management station: `config_complete` at its path answers `code=6 Invalid sequence` on both lab
firewalls, which is "not valid on the device you ASKED". Every config snapshot the estate holds
today is a firewall's, because `collect_show_merged_config` passes `session.target` - so a
collector that reaches every appliance and never addresses the station itself collects nothing
about this object no matter how many firewalls it reads.

THE ABSENCE OF `target=` IS THE WHOLE OF IT. `collect_and_persist` in `flows.py` already opens a
session at the station and already persists a station-anchored `Snapshot` through
`persist_management_station_snapshot`, so what was missing was a station-scoped CONFIG read and
nothing else.

WHY `action=get` AND NOT `show`. Stage 4 measured both at this path. `get` returns the candidate,
which is what an administrator typed - committed or not - and answers a bare absence for a node
that is not there. `show` returns the committed configuration but ONLY through the RELATIVE xpath
`devices/entry/deviceconfig/system/deployment-update-schedule`: stage 4 asked it without the
`devices/entry/` prefix first and got `No such node` for entries that had just committed
successfully, so a collector written with the absolute form would report every estate as having no
central schedule and nothing would error. Stage 5 declared the `get` form, and this follows it.

THE CANDIDATE HAZARD IS REAL AND IS NOT WORKED AROUND HERE. An entry staged and never committed
makes an estate look governed when nothing is scheduled. That is a declared property of the read
rather than a defect in this module, and the operational oracle that would settle it -
`show deployment-update-schedule status name <name>`, one call per entry name - is costed in stage
5 and deliberately not built: no column rests on it.
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import (
    collect_config_response,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSConfigRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


#: The station's own schedule collection. ABSOLUTE, because that is the form `action=get` takes -
#: the relative form is required by `show config running` and is a different read. The
#: `entry[@name='localhost.localdomain']` layer is the station's own device entry and is literal
#: here, exactly as it is on a firewall.
DEPLOYMENT_UPDATE_SCHEDULE_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']"
    "/deviceconfig/system/deployment-update-schedule"
)

#: The snapshot source_type this collector writes. Named beside the xpath it comes from, following
#: `MANAGED_DEVICES_SOURCE_TYPE`, so persistence and the normalizer cannot drift from the
#: collector. `config_` prefixed like `config_device_telemetry` and `config_log_alarm_settings`,
#: which are the other two config-xpath reads in this package.
DEPLOYMENT_UPDATE_SCHEDULE_SOURCE_TYPE = "config_deployment_update_schedule"


def collect_content_deployment_schedule(session: PANSession) -> PANOSCollectedResponse:
    """Every content deployment schedule entry on one management station.

    NO `target=` IS PASSED AND THAT IS THE POINT, so this takes the session's own address rather
    than `session.target` the way every appliance-scoped collector does. One call per management
    station per snapshot - one for the estate rather than one per appliance.

    AN EMPTY ANSWER IS A READING AND NOT A FAILED READ. `collect_config_response` already coerces
    an xpath that matches nothing into an empty result, and stage 4 measured that the CONTAINER
    read returns a bare absence here rather than the `total-count="0"` envelope an ENTRY read
    returns - so the normalizer has one thing to ask: is the collection's own key in the payload
    or not. A snapshot that does not exist at all is the third state and means nobody asked.
    """
    request = PANOSConfigRequest(
        xpath=DEPLOYMENT_UPDATE_SCHEDULE_XPATH,
        action="get",
        metadata={"command_name": "get config at deviceconfig/system/deployment-update-schedule"},
    )
    return collect_config_response(
        session,
        source_type=DEPLOYMENT_UPDATE_SCHEDULE_SOURCE_TYPE,
        request=request,
    )
