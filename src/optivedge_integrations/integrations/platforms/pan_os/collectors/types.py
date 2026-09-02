from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class PANOSOperationRequest:
    command_xml: str
    request_type: str = "op"
    target: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class PANOSConfigRequest:
    """A `type=config` read, for the parts of the tree no op command reaches.

    Nearly everything is collected with `show config merged`, which is one call for the whole
    device. `/config/predefined` is the exception: it is NOT included in the merged config
    (measured 2026-09-02 - the merged top level is devices, mgt-config, shared), and the
    `show predefined` op command addresses an entirely different namespace, the content/App-ID
    catalog, which has no ssl-tls-service-profile in it. So a predefined object is reachable
    only by asking for its config xpath directly.

    `action` stays a field rather than a constant because this is a COLLECTOR: only reads
    belong here. Anything that mutates config belongs nowhere in this package.
    """

    xpath: str
    action: str = "get"
    request_type: str = "config"
    target: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PANOSCollectedResponse:
    source_type: str
    request: PANOSOperationRequest | PANOSConfigRequest
    response: dict[str, Any]
