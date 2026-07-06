"""Enforcement-point scoped PAN-OS persistence helpers."""

from __future__ import annotations

from django.utils import timezone

from optivedge_integrations.integrations.models import EnforcementPoint, Snapshot
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.persistence.common import (
    PANOSPersistedCollection,
    extract_result_payload,
)


def persist_enforcement_point_snapshot(
    enforcement_point: EnforcementPoint,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    payload = extract_result_payload(collected)
    collected_at = timezone.now()
    snapshot = Snapshot.objects.create(
        enforcement_point=enforcement_point,
        source_type=collected.source_type,
        scope_name=enforcement_point.vsys_name,
        payload=payload,
        metadata={
            "target": collected.request.target or "",
            "command_name": collected.request.metadata.get("command_name", ""),
            "vsys_name": collected.request.metadata.get("vsys_name", enforcement_point.vsys_name),
        },
        collected_at=collected_at,
    )
    enforcement_point.last_synced_at = collected_at
    enforcement_point.save(update_fields=["last_synced_at", "updated_at"])
    return PANOSPersistedCollection(
        snapshot=snapshot,
        payload=payload,
    )


def persist_show_pushed_shared_policy_vsys(
    enforcement_point: EnforcementPoint,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    return persist_enforcement_point_snapshot(enforcement_point, collected)
