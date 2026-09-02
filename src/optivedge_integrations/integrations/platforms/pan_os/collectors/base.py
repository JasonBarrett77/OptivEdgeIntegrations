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
    # An xpath that matches nothing returns `<result/>`, which parses to None. That is a
    # real answer - "this appliance defines none of these" - and differs from an op command,
    # where an empty result means the command told us nothing. Left as None it reaches
    # persistence as a null payload and trips the snapshot's NOT NULL constraint, turning a
    # legitimate reading into a crash. Measured 2026-09-02: the PA-VM has no predefined
    # ssl-tls-service-profile at all, while both PA-5220s do.
    response_root = response.get("response")
    if isinstance(response_root, dict) and response_root.get("result", "missing") is None:
        response_root["result"] = {}
    return PANOSCollectedResponse(
        source_type=source_type,
        request=request,
        response=response,
    )
