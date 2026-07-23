"""Appliance-scoped PAN-OS persistence helpers.

This module owns raw snapshot persistence for commands collected against a
specific appliance target.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import Appliance
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.persistence.common import (
    PANOSPersistedCollection,
    extract_result_payload,
)
from django.utils import timezone
from optivedge_integrations.integrations.models import Snapshot


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


def persist_appliance_dynamic_content_snapshot(
    appliance: Appliance,
    collected: PANOSCollectedResponse,
    *,
    scope_name: str,
) -> PANOSPersistedCollection:
    """Persist a snapshot of appliance-scoped dynamic/runtime content (EDL cache, DNS proxy
    FQDN cache) collected via the "Refresh EDL/FQDN cache" action.

    Deliberately does NOT update appliance.last_synced_at - that field reflects config sync
    time (merged config/pushed policy), a different freshness signal from this operational
    cache data, which must stay independently visible via AddressObjectResolvedEntry.collected_at.
    """
    payload = extract_result_payload(collected)
    collected_at = timezone.now()
    snapshot = Snapshot.objects.create(
        appliance=appliance,
        source_type=collected.source_type,
        scope_name=scope_name,
        payload=payload,
        metadata={
            "target": collected.request.target or appliance.serial_number,
            "command_name": collected.request.metadata.get("command_name", ""),
        },
        collected_at=collected_at,
    )
    return PANOSPersistedCollection(
        snapshot=snapshot,
        payload=payload,
    )


def persist_show_dns_proxy_fqdn_all(
    appliance: Appliance,
    collected: PANOSCollectedResponse,
) -> PANOSPersistedCollection:
    return persist_appliance_dynamic_content_snapshot(
        appliance, collected, scope_name=appliance.serial_number,
    )


def persist_show_external_list(
    appliance: Appliance,
    collected: PANOSCollectedResponse,
    *,
    scope_name: str,
) -> PANOSPersistedCollection:
    return persist_appliance_dynamic_content_snapshot(appliance, collected, scope_name=scope_name)
