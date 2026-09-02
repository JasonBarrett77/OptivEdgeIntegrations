"""Shared PAN-OS collector helpers.

This module provides vendor-specific collection primitives that can be reused by
individual endpoint collectors without taking ownership of orchestration or storage.
"""

from __future__ import annotations

from typing import Any

from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSConfigRequest,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


def collect_op_response(
    session: PANSession,
    *,
    source_type: str,
    request: PANOSOperationRequest,
) -> PANOSCollectedResponse:
    response = session.op(
        request.command_xml,
        target=request.target,
    )
    return PANOSCollectedResponse(
        source_type=source_type,
        request=request,
        response=response,
    )


def collect_config_response(
    session: PANSession,
    *,
    source_type: str,
    request: PANOSConfigRequest,
) -> PANOSCollectedResponse:
    """Read a config xpath directly, for what `show config merged` does not carry.

    Reads only. `request.action` is asserted rather than trusted, because this helper sits in
    the collection path and a mutating action reaching it would turn a survey into a change.
    """
    if request.action != "get":
        raise ValueError(
            f"collectors perform reads only; refusing config action {request.action!r}"
        )
    response = session.request_xml_api(
        {"type": request.request_type, "action": request.action, "xpath": request.xpath},
        target=request.target,
    )
    return PANOSCollectedResponse(
        source_type=source_type,
        request=request,
        response=response,
    )
