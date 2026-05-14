"""PAN-OS collector for appliance-scoped merged configuration.

This module owns the `show config merged` command definition and collection
behavior for individual PAN-OS appliances reached through a management station.
"""

from __future__ import annotations

from optivedge.integrations.platforms.pan_os.collectors.base import collect_op_response
from optivedge.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge.integrations.platforms.pan_os.session import PANSession


SHOW_MERGED_CONFIG_COMMAND = "<show><config><merged></merged></config></show>"
SHOW_SYSTEM_INFO_COMMAND = "<show><system><info></info></show>"

def collect_show_merged_config(session: PANSession) -> PANOSCollectedResponse:
    request = PANOSOperationRequest(
        command_xml=SHOW_MERGED_CONFIG_COMMAND,
        target=session.target,
        metadata={"command_name": "show merged config"},
    )
    return collect_op_response(
        session,
        source_type="show_merged_config",
        request=request,
    )
