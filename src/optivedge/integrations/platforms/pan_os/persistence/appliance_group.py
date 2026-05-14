"""Appliance-group scoped PAN-OS persistence helpers."""

from __future__ import annotations

from django.utils import timezone

from optivedge.integrations.models import ApplianceGroup, Snapshot
from optivedge.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge.integrations.platforms.pan_os.persistence.common import (
    PANOSPersistedCollection,
    extract_result_payload,
)


def persist_appliance_group_snapshot(
    appliance_group: ApplianceGroup,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    payload = extract_result_payload(collected)
    collected_at = timezone.now()
    snapshot = Snapshot.objects.create(
        appliance_group=appliance_group,
        source_type=collected.source_type,
        scope_name=appliance_group.name,
        payload=payload,
        metadata={
            "target": collected.request.target or "",
            "command_name": collected.request.metadata.get("command_name", ""),
        },
        collected_at=collected_at,
    )
    appliance_group.last_synced_at = collected_at
    appliance_group.save(update_fields=["last_synced_at", "updated_at"])
    return PANOSPersistedCollection(
        snapshot=snapshot,
        payload=payload,
    )


def persist_show_pushed_shared_policy(
    appliance_group: ApplianceGroup,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    return persist_appliance_group_snapshot(appliance_group, collected)
