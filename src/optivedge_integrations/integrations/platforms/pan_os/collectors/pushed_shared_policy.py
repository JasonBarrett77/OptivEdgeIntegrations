"""PAN-OS collectors for pushed shared policy commands.

This module owns command definitions and collection behavior for pushed shared
policy retrieval at appliance-group and VSYS scopes.
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import collect_op_response
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


SHOW_PUSHED_SHARED_POLICY_COMMAND = (
    "<show><config><pushed-shared-policy/></config></show>"
)


def build_show_pushed_shared_policy_vsys_command(vsys_name: str) -> str:
    return (
        "<show><config><pushed-shared-policy>"
        f"<vsys>{vsys_name}</vsys>"
        "</pushed-shared-policy></config></show>"
    )


def collect_show_pushed_shared_policy(session: PANSession) -> PANOSCollectedResponse:
    request = PANOSOperationRequest(
        command_xml=SHOW_PUSHED_SHARED_POLICY_COMMAND,
        target=session.target,
        metadata={"command_name": "show config pushed-shared-policy"},
    )
    return collect_op_response(
        session,
        source_type="show_pushed_shared_policy",
        request=request,
    )


def collect_show_pushed_shared_policy_vsys(
    session: PANSession,
    *,
    vsys_name: str,
) -> PANOSCollectedResponse:
    request = PANOSOperationRequest(
        command_xml=build_show_pushed_shared_policy_vsys_command(vsys_name),
        target=session.target,
        metadata={
            "command_name": "show config pushed-shared-policy",
            "vsys_name": vsys_name,
        },
    )
    return collect_op_response(
        session,
        source_type="show_pushed_shared_policy_vsys",
        request=request,
    )
