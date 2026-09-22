"""App-level PAN-OS orchestration that composes platform refresh with shared rebuilds."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from optivedge_integrations.integrations.device_group_bindings import (
    DeviceGroupBindingRebuildResult,
    rebuild_device_group_bindings,
)
from optivedge_integrations.integrations.models import ManagementStation
from optivedge_integrations.integrations.platforms.pan_os.flows import (
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    PANOSInScopeRefreshCollection,
    refresh_in_scope_configuration_snapshots,
)
from optivedge_integrations.integrations.search_vocabulary import (
    SecurityRuleSearchVocabularyRebuildResult,
    rebuild_security_rule_search_vocabulary,
)


@dataclass(slots=True)
class PANOSIntegrationRefreshResult:
    platform_refresh: PANOSInScopeRefreshCollection
    security_rule_search_vocabulary: SecurityRuleSearchVocabularyRebuildResult
    device_group_bindings: DeviceGroupBindingRebuildResult


def refresh_panorama_in_scope_data(
    management_station: ManagementStation,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> PANOSIntegrationRefreshResult:
    """Run the PAN-OS in-scope refresh, then rebuild integration-level derived data."""

    platform_refresh = refresh_in_scope_configuration_snapshots(
        management_station,
        credentials_provider=credentials_provider,
        timeout=timeout,
        user_agent=user_agent,
    )
    security_rule_search_vocabulary = rebuild_security_rule_search_vocabulary(management_station)
    # After the refresh, never before: bindings are read from the provenance rows the refresh
    # has just rewritten.
    device_group_bindings = rebuild_device_group_bindings(management_station)
    return PANOSIntegrationRefreshResult(
        platform_refresh=platform_refresh,
        security_rule_search_vocabulary=security_rule_search_vocabulary,
        device_group_bindings=device_group_bindings,
    )
