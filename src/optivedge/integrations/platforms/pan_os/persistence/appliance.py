"""Appliance-scoped PAN-OS persistence helpers.

This module owns raw snapshot persistence for commands collected against a
specific appliance target.
"""

from __future__ import annotations

from optivedge.integrations.models import Appliance
from optivedge.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge.integrations.platforms.pan_os.persistence.common import (
    PANOSPersistedCollection,
    extract_result_payload,
)
from django.utils import timezone
from optivedge.integrations.models import Snapshot


def persist_appliance_snapshot(
    appliance: Appliance,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    payload = extract_result_payload(collected)
    collected_at = timezone.now()
    snapshot = Snapshot.objects.create(
        appliance=appliance,
        source_type=collected.source_type,
        scope_name=appliance.serial_number,
        payload=payload,
        metadata={
            "target": collected.request.target or appliance.serial_number,
            "command_name": collected.request.metadata.get("command_name", ""),
        },
        collected_at=collected_at,
    )
    appliance.last_synced_at = collected_at
    appliance.save(update_fields=["last_synced_at", "updated_at"])
    return PANOSPersistedCollection(
        snapshot=snapshot,
        payload=payload,
    )


def persist_show_merged_config(
    appliance: Appliance,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    return persist_appliance_snapshot(appliance, collected)
