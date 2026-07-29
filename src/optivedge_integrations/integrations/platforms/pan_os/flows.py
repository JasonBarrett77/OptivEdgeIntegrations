"""PAN-OS orchestration entry points that compose session, collection, and persistence.

Keep this layer focused on high-level workflow composition rather than low-level
session behavior or direct data-shaping rules.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from django.db import transaction
from django.db.models import Q

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressObject,
    Appliance,
    ApplianceGroup,
    EnforcementPoint,
    DeviceConfigurationProfile,
    ManagementStation,
    SecurityRule,
    SecurityRuleDestinationAddressRef,
    SecurityRuleSourceAddressRef,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors import (
    clear_target_vsys,
    collect_show_dns_proxy_fqdn_all,
    collect_show_external_list,
    collect_show_managed_devices,
    collect_show_merged_config,
    collect_show_predefined_ip_block_lists,
    collect_show_predefined_url_lists,
    collect_show_pushed_shared_policy,
    collect_show_pushed_shared_policy_vsys,
    set_target_vsys,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    PANOSNormalizedCollection,
    normalize_enforcement_point_addresses,
    normalize_enforcement_point_dynamic_address_content,
    normalize_enforcement_point_security_rules,
    normalize_appliance_device_configuration,
    normalize_collected_response,
)
from optivedge_integrations.integrations.platforms.pan_os.persistence import (
    PANOSPersistedCollection,
    persist_appliance_collected_response,
    persist_appliance_group_collected_response,
    persist_collected_response,
    persist_enforcement_point_collected_response,
)
from optivedge_integrations.integrations.platforms.pan_os.session import (
    DEFAULT_TIMEOUT,
    PANSession,
    open_session,
)


@dataclass(slots=True)
class PANOSProcessedCollection:
    persisted: PANOSPersistedCollection
    normalized: PANOSNormalizedCollection


@dataclass(slots=True)
class PANOSApplianceCollectedSnapshot:
    appliance: Appliance
    persisted: PANOSPersistedCollection


@dataclass(slots=True)
class PANOSApplianceCollectionFailure:
    appliance: Appliance
    error_text: str


@dataclass(slots=True)
class PANOSApplianceBatchCollection:
    appliances: list[Appliance]
    collections: list[PANOSApplianceCollectedSnapshot]


@dataclass(slots=True)
class PANOSApplianceGroupCollectedSnapshot:
    appliance_group: ApplianceGroup
    persisted: PANOSPersistedCollection


@dataclass(slots=True)
class PANOSApplianceGroupCollectionFailure:
    appliance_group: ApplianceGroup
    error_text: str


@dataclass(slots=True)
class PANOSEnforcementPointCollectedSnapshot:
    enforcement_point: EnforcementPoint
    persisted: PANOSPersistedCollection


@dataclass(slots=True)
class PANOSEnforcementPointCollectionFailure:
    enforcement_point: EnforcementPoint
    error_text: str


@dataclass(slots=True)
class PANOSSecurityRuleNormalizedPoint:
    enforcement_point: EnforcementPoint
    security_rules: list[SecurityRule]


@dataclass(slots=True)
class PANOSSecurityRuleNormalizationFailure:
    enforcement_point: EnforcementPoint
    error_text: str


@dataclass(slots=True)
class PANOSSecurityRuleFailure:
    """One rule within an otherwise-successfully-normalized enforcement point failed and was
    skipped - distinct from PANOSSecurityRuleNormalizationFailure, which means the enforcement
    point's rules couldn't be normalized at all (e.g. a missing snapshot)."""

    enforcement_point: EnforcementPoint
    name: str
    config_source: str
    rule_position: int
    error_text: str


@dataclass(slots=True)
class PANOSAddressNormalizedPoint:
    enforcement_point: EnforcementPoint
    address_objects: list[AddressObject]
    address_groups: list[AddressGroup]


@dataclass(slots=True)
class PANOSDeviceConfigurationNormalizedAppliance:
    appliance: Appliance
    device_configuration_profiles: list[DeviceConfigurationProfile]


@dataclass(slots=True)
class PANOSDeviceConfigurationNormalizationFailure:
    appliance: Appliance
    error_text: str


@dataclass(slots=True)
class PANOSAddressNormalizationFailure:
    enforcement_point: EnforcementPoint
    error_text: str


@dataclass(slots=True)
class PANOSDynamicAddressContentNormalizedPoint:
    enforcement_point: EnforcementPoint
    updated_address_objects: list[AddressObject]
    total_resolved_entries: int


@dataclass(slots=True)
class PANOSDynamicAddressContentNormalizationFailure:
    enforcement_point: EnforcementPoint
    error_text: str


@dataclass(slots=True)
class PANOSDynamicContentRefreshResult:
    appliances: list[Appliance]
    enforcement_points: list[EnforcementPoint]
    fqdn_cache_collections: list[PANOSApplianceCollectedSnapshot]
    fqdn_cache_failures: list[PANOSApplianceCollectionFailure]
    external_list_collections: list[PANOSEnforcementPointCollectedSnapshot]
    external_list_failures: list[PANOSEnforcementPointCollectionFailure]
    dynamic_content_normalizations: list[PANOSDynamicAddressContentNormalizedPoint]
    dynamic_content_failures: list[PANOSDynamicAddressContentNormalizationFailure]


@dataclass(slots=True)
class PANOSInScopeConfigCollection:
    appliances: list[Appliance]
    appliance_groups: list[ApplianceGroup]
    enforcement_points: list[EnforcementPoint]
    merged_config_collections: list[PANOSApplianceCollectedSnapshot]
    merged_config_failures: list[PANOSApplianceCollectionFailure]
    predefined_lists_collections: list[PANOSApplianceCollectedSnapshot]
    predefined_lists_failures: list[PANOSApplianceCollectionFailure]
    shared_policy_collections: list[PANOSApplianceGroupCollectedSnapshot]
    shared_policy_failures: list[PANOSApplianceGroupCollectionFailure]
    vsys_policy_collections: list[PANOSEnforcementPointCollectedSnapshot]
    vsys_policy_failures: list[PANOSEnforcementPointCollectionFailure]
    device_configuration_normalizations: list[PANOSDeviceConfigurationNormalizedAppliance]
    device_configuration_failures: list[PANOSDeviceConfigurationNormalizationFailure]
    address_normalizations: list[PANOSAddressNormalizedPoint]
    address_failures: list[PANOSAddressNormalizationFailure]
    security_rule_normalizations: list[PANOSSecurityRuleNormalizedPoint]
    security_rule_failures: list[PANOSSecurityRuleNormalizationFailure]
    security_rule_item_failures: list[PANOSSecurityRuleFailure]


@dataclass(slots=True)
class PANOSInScopeRefreshCollection:
    inventory: PANOSProcessedCollection
    configuration_snapshots: PANOSInScopeConfigCollection


@dataclass(slots=True)
class PANOSInScopeRenormalizationResult:
    appliances: list[Appliance]
    enforcement_points: list[EnforcementPoint]
    device_configuration_normalizations: list[PANOSDeviceConfigurationNormalizedAppliance]
    device_configuration_failures: list[PANOSDeviceConfigurationNormalizationFailure]
    address_normalizations: list[PANOSAddressNormalizedPoint]
    address_failures: list[PANOSAddressNormalizationFailure]
    security_rule_normalizations: list[PANOSSecurityRuleNormalizedPoint]
    security_rule_failures: list[PANOSSecurityRuleNormalizationFailure]
    security_rule_item_failures: list[PANOSSecurityRuleFailure]


def get_in_scope_appliances(management_station: ManagementStation) -> list[Appliance]:
    enforcement_points = management_station.enforcement_points.filter(in_scope=True).select_related(
        "appliance",
        "appliance_group",
    ).prefetch_related(
        "nodes__appliance",
        "appliance_group__appliances",
    )

    appliances_by_id: dict[int, Appliance] = {}
    for enforcement_point in enforcement_points:
        if enforcement_point.appliance_id is not None and enforcement_point.appliance is not None:
            appliances_by_id[enforcement_point.appliance.pk] = enforcement_point.appliance
            continue

        node_appliances = [node.appliance for node in enforcement_point.nodes.all()]
        if node_appliances:
            for appliance in node_appliances:
                appliances_by_id[appliance.pk] = appliance
            continue

        if enforcement_point.appliance_group is not None:
            for appliance in enforcement_point.appliance_group.appliances.all():
                appliances_by_id[appliance.pk] = appliance

    return sorted(
        appliances_by_id.values(),
        key=lambda appliance: (appliance.hostname or "", appliance.serial_number),
    )


def get_in_scope_appliance_groups(management_station: ManagementStation) -> list[ApplianceGroup]:
    appliance_groups = management_station.appliance_groups.filter(
        enforcement_points__in_scope=True,
    ).distinct()
    return list(appliance_groups.order_by("name", "pk"))


def get_in_scope_enforcement_points(management_station: ManagementStation) -> list[EnforcementPoint]:
    enforcement_points = management_station.enforcement_points.filter(in_scope=True).select_related(
        "appliance",
        "appliance_group",
    ).prefetch_related(
        "nodes__appliance",
        "appliance_group__appliances",
    )
    return list(enforcement_points.order_by("vsys_name", "pk"))


def collect_and_persist(
    management_station: ManagementStation,
    *,
    collector: Callable[[PANSession], PANOSCollectedResponse],
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    target: str | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANOSPersistedCollection:
    session = open_session(
        management_station,
        credentials_provider=credentials_provider,
        target=target,
        timeout=timeout,
        user_agent=user_agent,
    )
    collected = collector(session)
    return persist_collected_response(management_station, collected)


def collect_persist_and_normalize(
    management_station: ManagementStation,
    *,
    collector: Callable[[PANSession], PANOSCollectedResponse],
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    target: str | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANOSProcessedCollection:
    session = open_session(
        management_station,
        credentials_provider=credentials_provider,
        target=target,
        timeout=timeout,
        user_agent=user_agent,
    )
    collected = collector(session)
    persisted = persist_collected_response(management_station, collected)
    normalized = normalize_collected_response(management_station, collected)
    return PANOSProcessedCollection(
        persisted=persisted,
        normalized=normalized,
    )


def collect_appliance_and_persist(
    appliance: Appliance,
    *,
    collector: Callable[[PANSession], PANOSCollectedResponse],
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANOSPersistedCollection:
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    collected = collector(session)
    return persist_appliance_collected_response(appliance, collected)


def resolve_group_collection_appliance(appliance_group: ApplianceGroup) -> Appliance:
    if appliance_group.active_appliance is not None:
        return appliance_group.active_appliance

    appliance = appliance_group.appliances.order_by("hostname", "serial_number", "pk").first()
    if appliance is None:
        raise ValueError("appliance group does not have any appliances to target for collection")
    return appliance


def resolve_enforcement_point_collection_appliance(enforcement_point: EnforcementPoint) -> Appliance:
    if enforcement_point.appliance is not None:
        return enforcement_point.appliance

    appliance_group = enforcement_point.appliance_group
    if appliance_group is None:
        raise ValueError("enforcement point does not have an appliance or appliance group target")

    node_appliances = [node.appliance for node in enforcement_point.nodes.select_related("appliance").all()]
    if appliance_group.active_appliance is not None:
        for appliance in node_appliances:
            if appliance.pk == appliance_group.active_appliance.pk:
                return appliance

    if node_appliances:
        return sorted(
            node_appliances,
            key=lambda appliance: (appliance.hostname or "", appliance.serial_number, appliance.pk),
        )[0]

    if appliance_group.active_appliance is not None:
        return appliance_group.active_appliance

    appliance = appliance_group.appliances.order_by("hostname", "serial_number", "pk").first()
    if appliance is None:
        raise ValueError("enforcement point does not have any appliances to target for collection")
    return appliance


def collect_appliance_merged_config(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANOSPersistedCollection:
    return collect_appliance_and_persist(
        appliance,
        collector=collect_show_merged_config,
        credentials_provider=credentials_provider,
        timeout=timeout,
        user_agent=user_agent,
    )


def collect_appliance_predefined_address_lists(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> list[PANOSPersistedCollection]:
    """Collect PAN-OS's predefined (vendor-shipped) IP block list and URL list catalogs for
    one appliance. Appliance-wide, not vsys-scoped, so one session covers both calls."""
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    return [
        persist_appliance_collected_response(appliance, collect_show_predefined_ip_block_lists(session)),
        persist_appliance_collected_response(appliance, collect_show_predefined_url_lists(session)),
    ]


def collect_appliance_group_pushed_shared_policy(
    appliance_group: ApplianceGroup,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANOSPersistedCollection:
    appliance = resolve_group_collection_appliance(appliance_group)
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    collected = collect_show_pushed_shared_policy(session)
    return persist_appliance_group_collected_response(appliance_group, collected)


def collect_enforcement_point_pushed_shared_policy(
    enforcement_point: EnforcementPoint,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANOSPersistedCollection:
    appliance = resolve_enforcement_point_collection_appliance(enforcement_point)
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    collected = collect_show_pushed_shared_policy_vsys(
        session,
        vsys_name=enforcement_point.vsys_name,
    )
    return persist_enforcement_point_collected_response(enforcement_point, collected)


def renormalize_in_scope_configuration(
    management_station: ManagementStation,
) -> PANOSInScopeRenormalizationResult:
    """Re-run normalization for a station's in-scope appliances/enforcement points against
    already-collected snapshots, without contacting the device at all.

    Each normalize_* call independently re-queries the latest stored Snapshot rather than
    using anything collected in this same call, so this is safe to run any time normalized
    data needs reprocessing (e.g. after a normalization bug fix) without re-running the
    much slower network collection.
    """
    appliances = get_in_scope_appliances(management_station)
    enforcement_points = get_in_scope_enforcement_points(management_station)
    device_configuration_normalizations: list[PANOSDeviceConfigurationNormalizedAppliance] = []
    device_configuration_failures: list[PANOSDeviceConfigurationNormalizationFailure] = []
    address_normalizations: list[PANOSAddressNormalizedPoint] = []
    address_failures: list[PANOSAddressNormalizationFailure] = []
    security_rule_normalizations: list[PANOSSecurityRuleNormalizedPoint] = []
    security_rule_failures: list[PANOSSecurityRuleNormalizationFailure] = []
    security_rule_item_failures: list[PANOSSecurityRuleFailure] = []

    for appliance in appliances:
        try:
            normalized = normalize_appliance_device_configuration(appliance)
        except Exception as exc:
            device_configuration_failures.append(
                PANOSDeviceConfigurationNormalizationFailure(
                    appliance=appliance,
                    error_text=str(exc),
                )
            )
            continue
        device_configuration_normalizations.append(
            PANOSDeviceConfigurationNormalizedAppliance(
                appliance=appliance,
                device_configuration_profiles=normalized.device_configuration_profiles,
            )
        )

    for enforcement_point in enforcement_points:
        try:
            normalized = normalize_enforcement_point_addresses(enforcement_point)
        except Exception as exc:
            address_failures.append(
                PANOSAddressNormalizationFailure(
                    enforcement_point=enforcement_point,
                    error_text=str(exc),
                )
            )
            continue
        address_normalizations.append(
            PANOSAddressNormalizedPoint(
                enforcement_point=enforcement_point,
                address_objects=normalized.address_objects,
                address_groups=normalized.address_groups,
            )
        )

    for enforcement_point in enforcement_points:
        try:
            normalized = normalize_enforcement_point_security_rules(enforcement_point)
        except Exception as exc:
            security_rule_failures.append(
                PANOSSecurityRuleNormalizationFailure(
                    enforcement_point=enforcement_point,
                    error_text=str(exc),
                )
            )
            continue
        security_rule_normalizations.append(
            PANOSSecurityRuleNormalizedPoint(
                enforcement_point=enforcement_point,
                security_rules=normalized.security_rules,
            )
        )
        for rule_failure in normalized.security_rule_failures:
            security_rule_item_failures.append(
                PANOSSecurityRuleFailure(
                    enforcement_point=enforcement_point,
                    name=rule_failure.name,
                    config_source=rule_failure.config_source,
                    rule_position=rule_failure.rule_position,
                    error_text=rule_failure.error_text,
                )
            )

    return PANOSInScopeRenormalizationResult(
        appliances=appliances,
        enforcement_points=enforcement_points,
        device_configuration_normalizations=device_configuration_normalizations,
        device_configuration_failures=device_configuration_failures,
        address_normalizations=address_normalizations,
        address_failures=address_failures,
        security_rule_normalizations=security_rule_normalizations,
        security_rule_failures=security_rule_failures,
        security_rule_item_failures=security_rule_item_failures,
    )


def collect_in_scope_configuration_snapshots(
    management_station: ManagementStation,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANOSInScopeConfigCollection:
    appliances = get_in_scope_appliances(management_station)
    appliance_groups = get_in_scope_appliance_groups(management_station)
    enforcement_points = get_in_scope_enforcement_points(management_station)
    merged_config_collections: list[PANOSApplianceCollectedSnapshot] = []
    merged_config_failures: list[PANOSApplianceCollectionFailure] = []
    predefined_lists_collections: list[PANOSApplianceCollectedSnapshot] = []
    predefined_lists_failures: list[PANOSApplianceCollectionFailure] = []
    shared_policy_collections: list[PANOSApplianceGroupCollectedSnapshot] = []
    shared_policy_failures: list[PANOSApplianceGroupCollectionFailure] = []
    vsys_policy_collections: list[PANOSEnforcementPointCollectedSnapshot] = []
    vsys_policy_failures: list[PANOSEnforcementPointCollectionFailure] = []

    for appliance in appliances:
        try:
            persisted = collect_appliance_merged_config(
                appliance,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            merged_config_failures.append(
                PANOSApplianceCollectionFailure(
                    appliance=appliance,
                    error_text=str(exc),
                )
            )
            continue
        merged_config_collections.append(
            PANOSApplianceCollectedSnapshot(
                appliance=appliance,
                persisted=persisted,
            )
        )

    for appliance in appliances:
        try:
            persisted_list = collect_appliance_predefined_address_lists(
                appliance,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            predefined_lists_failures.append(
                PANOSApplianceCollectionFailure(
                    appliance=appliance,
                    error_text=str(exc),
                )
            )
            continue
        for persisted in persisted_list:
            predefined_lists_collections.append(
                PANOSApplianceCollectedSnapshot(
                    appliance=appliance,
                    persisted=persisted,
                )
            )

    for appliance_group in appliance_groups:
        try:
            persisted = collect_appliance_group_pushed_shared_policy(
                appliance_group,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            shared_policy_failures.append(
                PANOSApplianceGroupCollectionFailure(
                    appliance_group=appliance_group,
                    error_text=str(exc),
                )
            )
            continue
        shared_policy_collections.append(
            PANOSApplianceGroupCollectedSnapshot(
                appliance_group=appliance_group,
                persisted=persisted,
            )
        )

    for enforcement_point in enforcement_points:
        try:
            persisted = collect_enforcement_point_pushed_shared_policy(
                enforcement_point,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            vsys_policy_failures.append(
                PANOSEnforcementPointCollectionFailure(
                    enforcement_point=enforcement_point,
                    error_text=str(exc),
                )
            )
            continue
        vsys_policy_collections.append(
            PANOSEnforcementPointCollectedSnapshot(
                enforcement_point=enforcement_point,
                persisted=persisted,
            )
        )

    renormalized = renormalize_in_scope_configuration(management_station)

    return PANOSInScopeConfigCollection(
        appliances=appliances,
        appliance_groups=appliance_groups,
        enforcement_points=enforcement_points,
        merged_config_collections=merged_config_collections,
        merged_config_failures=merged_config_failures,
        predefined_lists_collections=predefined_lists_collections,
        predefined_lists_failures=predefined_lists_failures,
        shared_policy_collections=shared_policy_collections,
        shared_policy_failures=shared_policy_failures,
        vsys_policy_collections=vsys_policy_collections,
        vsys_policy_failures=vsys_policy_failures,
        device_configuration_normalizations=renormalized.device_configuration_normalizations,
        device_configuration_failures=renormalized.device_configuration_failures,
        address_normalizations=renormalized.address_normalizations,
        address_failures=renormalized.address_failures,
        security_rule_normalizations=renormalized.security_rule_normalizations,
        security_rule_failures=renormalized.security_rule_failures,
        security_rule_item_failures=renormalized.security_rule_item_failures,
    )


def refresh_in_scope_configuration_snapshots(
    management_station: ManagementStation,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANOSInScopeRefreshCollection:
    with transaction.atomic():
        inventory = collect_persist_and_normalize(
            management_station,
            collector=collect_show_managed_devices,
            credentials_provider=credentials_provider,
            timeout=timeout,
            user_agent=user_agent,
        )

    configuration_snapshots = collect_in_scope_configuration_snapshots(
        management_station,
        credentials_provider=credentials_provider,
        timeout=timeout,
        user_agent=user_agent,
    )
    return PANOSInScopeRefreshCollection(
        inventory=inventory,
        configuration_snapshots=configuration_snapshots,
    )


def collect_appliance_fqdn_cache(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANOSPersistedCollection:
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    collected = collect_show_dns_proxy_fqdn_all(session)
    return persist_appliance_collected_response(appliance, collected)


def _candidate_edl_names(enforcement_point: EnforcementPoint) -> list[str]:
    """Distinct ip-type EDL address object names actually referenced by this enforcement
    point's rules - directly or via any level of nested static group, already flattened onto
    ref rows by resolve_static_group_members. Excludes FQDN (handled by the bulk appliance-wide
    FQDN cache call, not a per-name EDL show command)."""
    candidate_filter = Q(
        address_object__address_type=AddressObject.TYPE_EDL,
        address_object__edl_list_type="ip",
    )
    source_names = (
        SecurityRuleSourceAddressRef.objects.filter(security_rule__enforcement_point=enforcement_point)
        .filter(candidate_filter)
        .values_list("address_object__name", flat=True)
    )
    destination_names = (
        SecurityRuleDestinationAddressRef.objects.filter(security_rule__enforcement_point=enforcement_point)
        .filter(candidate_filter)
        .values_list("address_object__name", flat=True)
    )
    return sorted(set(source_names) | set(destination_names))


def collect_enforcement_point_external_lists(
    enforcement_point: EnforcementPoint,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> list[PANOSPersistedCollection]:
    """Collect every candidate EDL for one enforcement point (vsys).

    EDL collection is vsys-scoped at the device level (confirmed against a real device -
    `request system external-list show` requires a prior `set system setting target-vsys`
    on the same connection, and that setting is connection-scoped, not account-scoped). This
    always opens its own fresh PANSession, sets target-vsys once, collects every candidate name
    on it, then clears target-vsys before returning - never reuse this session for anything
    else, and never call this same vsys context from more than one session concurrently.
    """
    candidate_names = _candidate_edl_names(enforcement_point)
    if not candidate_names:
        return []

    appliance = resolve_enforcement_point_collection_appliance(enforcement_point)
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    set_target_vsys(session, vsys_name=enforcement_point.vsys_name)
    try:
        persisted: list[PANOSPersistedCollection] = []
        for name in candidate_names:
            collected = collect_show_external_list(session, name=name)
            persisted.append(
                persist_appliance_collected_response(
                    appliance,
                    collected,
                    scope_name=f"{enforcement_point.vsys_name}:{name}",
                )
            )
        return persisted
    finally:
        clear_target_vsys(session)


def refresh_in_scope_dynamic_content(
    management_station: ManagementStation,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = "AegisGo/1.0",
) -> PANOSDynamicContentRefreshResult:
    """Collect and normalize runtime EDL/FQDN resolved content for a station's in-scope
    appliances/enforcement points.

    Deliberately separate from refresh_in_scope_configuration_snapshots(): FQDN cache is one
    cheap bulk call per appliance, but EDL collection is one API call per referenced EDL name
    (each potentially paginated) - a fundamentally different cost profile, so this stays an
    explicitly-triggered action rather than riding along on every regular sync. Requires
    security rules to already be normalized (candidate selection reads existing address-ref
    rows) - a precondition of running this after a regular sync, not enforced here since an
    empty candidate set degrades gracefully to "nothing to do" rather than an error.
    """
    appliances = get_in_scope_appliances(management_station)
    enforcement_points = get_in_scope_enforcement_points(management_station)

    fqdn_cache_collections: list[PANOSApplianceCollectedSnapshot] = []
    fqdn_cache_failures: list[PANOSApplianceCollectionFailure] = []
    for appliance in appliances:
        try:
            persisted = collect_appliance_fqdn_cache(
                appliance,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            fqdn_cache_failures.append(
                PANOSApplianceCollectionFailure(appliance=appliance, error_text=str(exc))
            )
            continue
        fqdn_cache_collections.append(
            PANOSApplianceCollectedSnapshot(appliance=appliance, persisted=persisted)
        )

    external_list_collections: list[PANOSEnforcementPointCollectedSnapshot] = []
    external_list_failures: list[PANOSEnforcementPointCollectionFailure] = []
    for enforcement_point in enforcement_points:
        try:
            persisted_list = collect_enforcement_point_external_lists(
                enforcement_point,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            external_list_failures.append(
                PANOSEnforcementPointCollectionFailure(enforcement_point=enforcement_point, error_text=str(exc))
            )
            continue
        for persisted in persisted_list:
            external_list_collections.append(
                PANOSEnforcementPointCollectedSnapshot(enforcement_point=enforcement_point, persisted=persisted)
            )

    dynamic_content_normalizations: list[PANOSDynamicAddressContentNormalizedPoint] = []
    dynamic_content_failures: list[PANOSDynamicAddressContentNormalizationFailure] = []
    for enforcement_point in enforcement_points:
        try:
            normalized = normalize_enforcement_point_dynamic_address_content(enforcement_point)
        except Exception as exc:
            dynamic_content_failures.append(
                PANOSDynamicAddressContentNormalizationFailure(
                    enforcement_point=enforcement_point, error_text=str(exc),
                )
            )
            continue
        dynamic_content_normalizations.append(
            PANOSDynamicAddressContentNormalizedPoint(
                enforcement_point=enforcement_point,
                updated_address_objects=normalized.updated_address_objects,
                total_resolved_entries=normalized.total_resolved_entries,
            )
        )

    return PANOSDynamicContentRefreshResult(
        appliances=appliances,
        enforcement_points=enforcement_points,
        fqdn_cache_collections=fqdn_cache_collections,
        fqdn_cache_failures=fqdn_cache_failures,
        external_list_collections=external_list_collections,
        external_list_failures=external_list_failures,
        dynamic_content_normalizations=dynamic_content_normalizations,
        dynamic_content_failures=dynamic_content_failures,
    )
