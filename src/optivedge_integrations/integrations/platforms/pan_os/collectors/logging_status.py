"""PAN-OS collector for log forwarding health - `show logging-status`.

THE ONLY FIREWALL-SIDE INSTRUMENT FOR WHETHER FORWARDING IS ACTUALLY WORKING, and it answers
for the Panorama / Log Collector path only. No configuration read can answer the question:
forwarding that has silently stopped looks identical to forwarding that works in any
configuration review, and a TLS failure, an unreachable collector or a full buffer stops
delivery with no change to the configuration at all.

WHAT IT DOES NOT COVER is as important as what it does. Syslog, email and HTTP delivery health
are not in it, and nothing on the firewall reports them: `show system state filter *syslog*`,
`*logfwd*` and `*log-settings*` all return NO_MATCHES, the CLI index offers only debug/set/clear,
and `show netstat` is refused to an XML API client. That half of the question belongs to the
receiving system and is asserted against it rather than against the firewall.

An OPERATIONAL read, which reads RUNNING - so unlike the merged config it cannot report an
uncommitted edit. It is also the only read in this domain that is not a view of configuration,
which is why it has a source type and a module of its own rather than a branch inside one.
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


#: `verbose` is what adds the per-log-type counters. Without it the reply carries the connection
#: state alone, and connection is not delivery: a connected collector whose counter has not moved
#: since last Tuesday is exactly the failure the control exists to find.
SHOW_LOGGING_STATUS_COMMAND = (
    "<show><logging-status><verbose>yes</verbose></logging-status></show>"
)


def collect_show_logging_status(session: PANSession) -> PANOSCollectedResponse:
    """Collect one appliance's log forwarding status.

    One op call per appliance. The reply is PRE-FORMATTED TEXT inside XML elements - each log
    type is one padded line of six columns, and the connection state arrives as
    "Connection Status       : lr - Active" - so the normalizer parses strings rather than
    reading keys. That is the device's shape and not a choice: there is no structured form of
    this command.
    """
    request = PANOSOperationRequest(
        command_xml=SHOW_LOGGING_STATUS_COMMAND,
        target=session.target,
        metadata={"command_name": "show logging-status verbose"},
    )
    return collect_op_response(
        session,
        source_type="show_logging_status",
        request=request,
    )
