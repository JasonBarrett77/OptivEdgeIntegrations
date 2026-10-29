"""PAN-OS collector for a firewall's view of its management estate - `show panorama-status`.

THE ONLY FIREWALL-SIDE INSTRUMENT FOR WHETHER THE REGISTRATION WORKS. The configuration says
which addresses the firewall is told to reach; this says which of them answered. It matters
because THREE different nodes on one appliance can hold a Panorama address - `local-panorama`,
`deviceconfig/setting/management/initcfg/panorama-server`, and the pushed template's copy - and
only one is the live setting, so a predicate over the configured slot alone reports a firewall as
managed when its only address is a stale bootstrap value.

THE REPLY IS A PLAIN STRING, not a structure, which is unusual in this estate and is the reason
this collector carries the warning rather than the normalizer discovering it. Measured on all
four lab appliances, 2026-10-29:

    Panorama Server 1 : 20.185.152.225
        Connected     : yes
        HA state      : Unknown
    Panorama Server 2 : 192.0.2.1
        Connected     : no
        HA state      : disconnected

So a consumer splits lines and reads labels. `HA state` is the firewall's own view of whether the
station it reached is in a pair - and `Unknown` for the connected slot on every appliance here
means it cannot tell "not a pair" from "not established", so it is not an answer to that
question. It is recorded because nothing else on a firewall carries it at all.

An OPERATIONAL read: it reports what is live, and it cannot carry an uncommitted edit. One op
call per appliance. Measured absent from this repo's collector set before 2026-10-29.
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import (
    collect_op_response,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


SHOW_PANORAMA_STATUS_COMMAND = "<show><panorama-status/></show>"

#: The snapshot source_type this collector writes.
PANORAMA_STATUS_SOURCE_TYPE = "show_panorama_status"


def collect_show_panorama_status(session: PANSession) -> PANOSCollectedResponse:
    """One appliance's management-connection status, as the device's own pre-formatted text."""
    request = PANOSOperationRequest(
        command_xml=SHOW_PANORAMA_STATUS_COMMAND,
        target=session.target,
        metadata={"command_name": "show panorama-status"},
    )
    return collect_op_response(
        session,
        source_type=PANORAMA_STATUS_SOURCE_TYPE,
        request=request,
    )
