"""Shared PAN-OS collector helpers.

This module provides vendor-specific collection primitives that can be reused by
individual endpoint collectors without taking ownership of orchestration or storage.
"""

from __future__ import annotations

from typing import Any

from optivedge.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge.integrations.platforms.pan_os.session import PANSession


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
