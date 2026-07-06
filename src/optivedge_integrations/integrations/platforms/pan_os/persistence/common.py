"""Shared PAN-OS persistence helpers.

This module owns generic snapshot persistence helpers that apply across PAN-OS
collection flows before endpoint-specific normalization is introduced.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.utils import timezone

from optivedge_integrations.integrations.models import ManagementStation, Snapshot
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse


@dataclass(slots=True)
class PANOSPersistedCollection:
    snapshot: Snapshot
    payload: Any


def extract_result_payload(collected: PANOSCollectedResponse) -> Any:
    response_root = collected.response.get("response")
    if not isinstance(response_root, dict):
        raise ValueError("collected response does not include a response root")
    if "result" not in response_root:
        raise ValueError("collected response does not include a response.result subtree")
    return response_root["result"]


def persist_management_station_snapshot(
    management_station: ManagementStation,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    payload = extract_result_payload(collected)
    collected_at = timezone.now()
    snapshot = Snapshot.objects.create(
        management_station=management_station,
        source_type=collected.source_type,
        payload=payload,
        metadata={},
        collected_at=collected_at,
    )
    return PANOSPersistedCollection(
        snapshot=snapshot,
        payload=payload,
    )
