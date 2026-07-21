"""App-level PAN-OS orchestration that composes platform refresh with shared rebuilds."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from optivedge_integrations.integrations.models import ManagementStation
from optivedge_integrations.integrations.platforms.pan_os.flows import (
    DEFAULT_TIMEOUT,
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


def refresh_panorama_in_scope_data(
    management_station: ManagementStation,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANOSIntegrationRefreshResult:
    """Run the PAN-OS in-scope refresh, then rebuild integration-level derived data."""

    platform_refresh = refresh_in_scope_configuration_snapshots(
        management_station,
        credentials_provider=credentials_provider,
        timeout=timeout,
        user_agent=user_agent,
    )
    security_rule_search_vocabulary = rebuild_security_rule_search_vocabulary(management_station)
    return PANOSIntegrationRefreshResult(
        platform_refresh=platform_refresh,
        security_rule_search_vocabulary=security_rule_search_vocabulary,
    )
