"""PAN-OS collectors for system-level state that no configuration read exposes.

The master key is the case that forced this module. Its value is not in the running config -
so config diff and audit cannot see it - and only the surrounding properties are readable, via
an op command that works on Panorama and managed firewalls alike.
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import collect_op_response
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession

SHOW_MASTERKEY_PROPERTIES_COMMAND = (
    "<show><system><masterkey-properties></masterkey-properties></system></show>"
)


def collect_show_masterkey_properties(session: PANSession) -> PANOSCollectedResponse:
    """Master key lifetime properties for one device.

    Returns ten fields, measured 2026-09-03 on a PA-5220, a PA-VM and a Panorama:
    expire-at, remind-at, hours/minutes/seconds-to-expiry, the same three for the reminder,
    on-hsm and auto-renew-mkey. The CLI additionally prints an Encryption Level that the API
    does not return.

    `expire-at` of 0 is what the CLI renders as "unspecified", and it means the master key has
    never been set - a lifetime is mandatory when setting one, in both the CLI and the GUI, so
    a set key always has a concrete expiry. That inference is vendor-documented rather than
    measured here; see the payload contract's master-key node, which says so explicitly.
    """
    request = PANOSOperationRequest(
        command_xml=SHOW_MASTERKEY_PROPERTIES_COMMAND,
        target=session.target,
        metadata={"command_name": "show system masterkey-properties"},
    )
    return collect_op_response(
        session,
        source_type="show_masterkey_properties",
        request=request,
    )
