from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class PANOSOperationRequest:
    command_xml: str
    request_type: str = "op"
    target: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PANOSCollectedResponse:
    source_type: str
    request: PANOSOperationRequest
    response: dict[str, Any]
