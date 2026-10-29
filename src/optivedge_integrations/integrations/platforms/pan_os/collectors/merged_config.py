"""PAN-OS collector for appliance-scoped merged configuration.

This module owns the `show config merged` command definition and collection
behavior for individual PAN-OS appliances reached through a management station.
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import collect_op_response
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


SHOW_MERGED_CONFIG_COMMAND = "<show><config><merged></merged></config></show>"

#: `<system>` WAS NEVER CLOSED HERE and the device refuses the command outright.
#:
#: Measured 2026-10-29 on all four lab appliances, through Panorama's `target=` proxy: the
#: previous value - `<show><system><info></info></show>`, missing `</system>` - answers HTTP
#: 400 "Request is not a valid XML" on every one of them, while the balanced form below and
#: the self-closing `<show><system><info/></system></show>` both answer in full (44 keys on a
#: PA-5220, 53 on a PA-VM). So `collect_show_system_info` has never once succeeded, and every
#: column resting on it has been holding its own default with nothing reporting a failure the
#: caller could act on - the wrapper in `flows.py` records the exception as one failed read
#: among three and carries on.
#:
#: This constant sat here unreferenced by anything but its own definition until
#: `collectors/device_identification.py::collect_show_system_info` was written on 2026-10-29,
#: so the malformation had no call site to be noticed at. Its HOME is still wrong - this module
#: is about `show config merged` - and that is a separate defect from this one.
SHOW_SYSTEM_INFO_COMMAND = "<show><system><info></info></system></show>"

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
