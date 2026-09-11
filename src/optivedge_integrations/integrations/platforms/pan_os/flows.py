"""PAN-OS orchestration entry points that compose session, collection, and persistence.

Keep this layer focused on high-level workflow composition rather than low-level
session behavior or direct data-shaping rules.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from django.db import transaction
from django.db.models import Q

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressObject,
    Appliance,
    ApplianceGroup,
    EnforcementPoint,
    ManagementStation,
    SecurityRule,
    SecurityRuleDestinationAddressRef,
    SecurityRuleSourceAddressRef,
    Zone,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors import (
    clear_target_vsys,
    collect_show_dns_proxy_fqdn_all,
    collect_show_external_list,
    collect_show_managed_devices,
    collect_show_merged_config,
    collect_predefined_certificates,
    collect_show_masterkey_properties,
    collect_predefined_ssl_tls_service_profiles,
    collect_show_predefined_ip_block_lists,
    collect_show_predefined_url_lists,
    collect_show_pushed_shared_policy,
    collect_show_pushed_shared_policy_vsys,
    set_target_vsys,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    PANOSNormalizedCollection,
    normalize_appliance_group_shared_scope,
    normalize_enforcement_point_addresses,
    normalize_enforcement_point_zones,
    normalize_enforcement_point_dynamic_address_content,
    normalize_enforcement_point_security_rules,
    normalize_appliance_admin_users,
    normalize_appliance_authentication_profiles,
    normalize_appliance_authentication_sequences,
    normalize_appliance_certificate_objects,
    normalize_appliance_interface_management_profiles,
    normalize_appliance_authentication_settings,
    normalize_appliance_login_banner,
    normalize_appliance_management_tls,
    normalize_appliance_management_ssh,
    normalize_appliance_master_key,
    normalize_appliance_services_settings,
    normalize_appliance_password_complexity,
    normalize_appliance_password_profiles,
    normalize_appliance_server_profiles,
    normalize_appliance_interfaces,
    normalize_appliance_management_interfaces,
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
    DEFAULT_USER_AGENT,
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
    """One normalization pass. Exactly one owner is set.

    `enforcement_point` for a vsys pass; `appliance_group` for the shared-scope pass that
    precedes them, since shared objects belong to the group rather than to any one vsys.
    """

    enforcement_point: EnforcementPoint | None = None
    appliance_group: ApplianceGroup | None = None
    address_objects: list[AddressObject] = field(default_factory=list)
    address_groups: list[AddressGroup] = field(default_factory=list)
    #: Per-object failures and inferences. A pass can succeed and still carry these -
    #: that is the point, and it is why a count of them is worth surfacing.
    policy_object_issues: list = field(default_factory=list)


@dataclass(slots=True)
class PANOSInterfaceManagementProfileNormalizedAppliance:
    appliance: Appliance
    profiles: list


@dataclass(slots=True)
class PANOSInterfaceManagementProfileNormalizationFailure:
    appliance: Appliance
    error_text: str


@dataclass(slots=True)
class PANOSApplianceObjectNormalizedAppliance:
    appliance: Appliance
    #: Which normalizer ran - "admin users", "certificate objects", and so on.
    kind: str
    #: Whatever the normalizer counted, as it named it.
    counts: dict


@dataclass(slots=True)
class PANOSApplianceObjectNormalizationFailure:
    appliance: Appliance
    kind: str
    error_text: str


@dataclass(slots=True)
class PANOSInterfaceNormalizedAppliance:
    appliance: Appliance
    interfaces: list
    #: Entries that could not be made sense of. Present even on success: a run that
    #: normalized forty interfaces and could not classify one is not a clean run, and the
    #: caller needs to be able to say so.
    issues: list


@dataclass(slots=True)
class PANOSInterfaceNormalizationFailure:
    appliance: Appliance
    error_text: str


@dataclass(slots=True)
class PANOSManagementInterfaceNormalizedAppliance:
    appliance: Appliance
    management_interfaces: list


@dataclass(slots=True)
class PANOSManagementInterfaceNormalizationFailure:
    appliance: Appliance
    error_text: str


@dataclass(slots=True)
class PANOSAddressNormalizationFailure:
    """enforcement_point is None when the shared-scope pass for an appliance group failed;
    error_text names the group in that case."""

    enforcement_point: EnforcementPoint | None
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
class PANOSZoneNormalizedPoint:
    enforcement_point: EnforcementPoint
    zones: list[Zone]


@dataclass(slots=True)
class PANOSZoneNormalizationFailure:
    enforcement_point: EnforcementPoint
    error_text: str


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
    address_normalizations: list[PANOSAddressNormalizedPoint]
    address_failures: list[PANOSAddressNormalizationFailure]
    security_rule_normalizations: list[PANOSSecurityRuleNormalizedPoint]
    security_rule_failures: list[PANOSSecurityRuleNormalizationFailure]
    security_rule_item_failures: list[PANOSSecurityRuleFailure]
    zone_normalizations: list[PANOSZoneNormalizedPoint]
    zone_failures: list[PANOSZoneNormalizationFailure]
    management_interface_normalizations: list[PANOSManagementInterfaceNormalizedAppliance] = field(
        default_factory=list)
    management_interface_failures: list[PANOSManagementInterfaceNormalizationFailure] = field(
        default_factory=list)
    interface_normalizations: list[PANOSInterfaceNormalizedAppliance] = field(
        default_factory=list)
    interface_failures: list[PANOSInterfaceNormalizationFailure] = field(
        default_factory=list)
    interface_management_profile_normalizations: list[
        PANOSInterfaceManagementProfileNormalizedAppliance] = field(default_factory=list)
    interface_management_profile_failures: list[
        PANOSInterfaceManagementProfileNormalizationFailure] = field(default_factory=list)
    appliance_object_normalizations: list[
        PANOSApplianceObjectNormalizedAppliance] = field(default_factory=list)
    appliance_object_failures: list[
        PANOSApplianceObjectNormalizationFailure] = field(default_factory=list)


@dataclass(slots=True)
class PANOSInScopeRefreshCollection:
    inventory: PANOSProcessedCollection
    configuration_snapshots: PANOSInScopeConfigCollection


@dataclass(slots=True)
class PANOSInScopeRenormalizationResult:
    appliances: list[Appliance]
    enforcement_points: list[EnforcementPoint]
    address_normalizations: list[PANOSAddressNormalizedPoint]
    address_failures: list[PANOSAddressNormalizationFailure]
    security_rule_normalizations: list[PANOSSecurityRuleNormalizedPoint]
    security_rule_failures: list[PANOSSecurityRuleNormalizationFailure]
    security_rule_item_failures: list[PANOSSecurityRuleFailure]
    zone_normalizations: list[PANOSZoneNormalizedPoint]
    zone_failures: list[PANOSZoneNormalizationFailure]
    management_interface_normalizations: list[PANOSManagementInterfaceNormalizedAppliance] = field(
        default_factory=list)
    management_interface_failures: list[PANOSManagementInterfaceNormalizationFailure] = field(
        default_factory=list)
    interface_normalizations: list[PANOSInterfaceNormalizedAppliance] = field(
        default_factory=list)
    interface_failures: list[PANOSInterfaceNormalizationFailure] = field(
        default_factory=list)
    interface_management_profile_normalizations: list[
        PANOSInterfaceManagementProfileNormalizedAppliance] = field(default_factory=list)
    interface_management_profile_failures: list[
        PANOSInterfaceManagementProfileNormalizationFailure] = field(default_factory=list)
    appliance_object_normalizations: list[
        PANOSApplianceObjectNormalizedAppliance] = field(default_factory=list)
    appliance_object_failures: list[
        PANOSApplianceObjectNormalizationFailure] = field(default_factory=list)


def get_in_scope_appliances(management_station: ManagementStation) -> list[Appliance]:
    enforcement_points = management_station.enforcement_points.filter(in_scope=True).select_related(
        "appliance",
        "appliance_group",
        "management_station",
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
        "management_station",
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
    user_agent: str = DEFAULT_USER_AGENT,
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
    user_agent: str = DEFAULT_USER_AGENT,
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
    user_agent: str = DEFAULT_USER_AGENT,
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
    user_agent: str = DEFAULT_USER_AGENT,
) -> PANOSPersistedCollection:
    return collect_appliance_and_persist(
        appliance,
        collector=collect_show_merged_config,
        credentials_provider=credentials_provider,
        timeout=timeout,
        user_agent=user_agent,
    )


def collect_appliance_masterkey_properties(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> PANOSPersistedCollection:
    """PAN-CRT-007's only source. The key is not in the config, so nothing else can see it."""
    return collect_appliance_and_persist(
        appliance,
        collector=collect_show_masterkey_properties,
        credentials_provider=credentials_provider,
        timeout=timeout,
        user_agent=user_agent,
    )


def collect_appliance_predefined_catalogs(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> tuple[list[PANOSPersistedCollection], list[str]]:
    """Collect PAN-OS's predefined (vendor-shipped) catalogs for one appliance.

    Appliance-wide, not vsys-scoped, so one session covers every call. Two of the three are
    `show predefined` op commands; the SSL/TLS service profiles are a direct config read,
    because they live in the config tree's predefined branch rather than the content catalog
    `show predefined` addresses, and `show config merged` does not carry that branch either.
    """
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    # Collected INDEPENDENTLY. These are three unrelated reads, and letting one exception
    # abandon the other two is not hypothetical: `show predefined ip-block-list-v2` raises
    # "No data found. Verify xpath and retry" on both PA-5220s (11.1.13-h3) while succeeding
    # on the PA-VM (11.2.3), so every predefined catalog was being discarded for those
    # appliances on the strength of one unrelated failure. Failures are returned rather than
    # swallowed - the caller records them per appliance - so a partial collection is visible
    # as partial instead of passing for complete.
    persisted: list[PANOSPersistedCollection] = []
    failures: list[str] = []
    for collect in (
        collect_show_predefined_ip_block_lists,
        collect_show_predefined_url_lists,
        collect_predefined_ssl_tls_service_profiles,
        collect_predefined_certificates,
    ):
        try:
            persisted.append(persist_appliance_collected_response(appliance, collect(session)))
        except Exception as exc:  # noqa: BLE001 - recorded and reported, not suppressed
            failures.append(f"{collect.__name__}: {exc}")
    return persisted, failures


def collect_appliance_group_pushed_shared_policy(
    appliance_group: ApplianceGroup,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
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
    user_agent: str = DEFAULT_USER_AGENT,
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


#: Appliance-anchored object normalizers that return a plain count dict. Each one reads the
#: same merged snapshot and owns a different subtree, so they share one loop and one failure
#: type instead of a dataclass pair each.
#:
#: They were built and NOT wired here - certificate objects, authentication profiles and
#: password profiles all landed with their own controls and tabs, and the only thing that ever
#: called them was a test. The renormalize button left four model families stale and said
#: nothing, because a normalizer nobody calls fails exactly like a device with nothing to
#: report. Anything appliance-anchored belongs in this tuple.
#: ORDER MATTERS for the first two. `normalize_admin_users` resolves each administrator's
#: authentication profile to decide whether MFA governs that account (PAN-AUTH-020), so the
#: profiles have to exist first - otherwise every administrator normalizes as unresolved, which
#: renders as "MFA not confirmed" on a device that is fine.
APPLIANCE_OBJECT_NORMALIZERS = (
    ("authentication profiles", normalize_appliance_authentication_profiles),
    # Between the two: members resolve over the profile rows, and an administrator bound to a
    # sequence resolves over the rows this writes.
    ("authentication sequences", normalize_appliance_authentication_sequences),
    ("admin users", normalize_appliance_admin_users),
    ("server profiles", normalize_appliance_server_profiles),
    ("password profiles", normalize_appliance_password_profiles),
    ("password complexity", normalize_appliance_password_complexity),
    ("authentication settings", normalize_appliance_authentication_settings),
    ("login banner", normalize_appliance_login_banner),
    ("master key", normalize_appliance_master_key),
    ("services settings", normalize_appliance_services_settings),
    ("certificate objects", normalize_appliance_certificate_objects),
    # AFTER certificate objects, and it must stay after: the binding resolves over the
    # SslTlsServiceProfile rows that normalizer writes. Run first, it would find last run's
    # rows - or none - and record a binding against a profile that no longer matches.
    ("management TLS", normalize_appliance_management_tls),
    ("management SSH", normalize_appliance_management_ssh),
)


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
    management_interface_normalizations: list[PANOSManagementInterfaceNormalizedAppliance] = []
    management_interface_failures: list[PANOSManagementInterfaceNormalizationFailure] = []
    interface_normalizations: list[PANOSInterfaceNormalizedAppliance] = []
    interface_failures: list[PANOSInterfaceNormalizationFailure] = []
    profile_normalizations: list[PANOSInterfaceManagementProfileNormalizedAppliance] = []
    profile_failures: list[PANOSInterfaceManagementProfileNormalizationFailure] = []
    address_normalizations: list[PANOSAddressNormalizedPoint] = []
    address_failures: list[PANOSAddressNormalizationFailure] = []
    security_rule_normalizations: list[PANOSSecurityRuleNormalizedPoint] = []
    security_rule_failures: list[PANOSSecurityRuleNormalizationFailure] = []
    security_rule_item_failures: list[PANOSSecurityRuleFailure] = []
    zone_normalizations: list[PANOSZoneNormalizedPoint] = []
    zone_failures: list[PANOSZoneNormalizationFailure] = []
    appliance_object_normalizations: list[PANOSApplianceObjectNormalizedAppliance] = []
    appliance_object_failures: list[PANOSApplianceObjectNormalizationFailure] = []

    for appliance in appliances:
        # Management surfaces read the same merged snapshot but are a separate model and a
        # separate failure. Deliberately NOT gated on the device-configuration result: they
        # answer a different question - which doors are open, and to whom - and one failing
        # must not silently take the other's rows away.
        try:
            surfaces = normalize_appliance_management_interfaces(appliance)
        except Exception as exc:
            management_interface_failures.append(
                PANOSManagementInterfaceNormalizationFailure(appliance=appliance, error_text=str(exc))
            )
        else:
            management_interface_normalizations.append(
                PANOSManagementInterfaceNormalizedAppliance(
                    appliance=appliance, management_interfaces=surfaces
                )
            )

        # Every appliance, both HA members included - the same convention as the two
        # normalizations above. Its own try/except for the same reason: one plane of the
        # answer failing must not silently remove another.
        try:
            normalized_interfaces = normalize_appliance_interfaces(appliance)
        except Exception as exc:
            interface_failures.append(
                PANOSInterfaceNormalizationFailure(appliance=appliance, error_text=str(exc))
            )
        else:
            interface_normalizations.append(
                PANOSInterfaceNormalizedAppliance(
                    appliance=appliance,
                    interfaces=normalized_interfaces.interfaces,
                    issues=normalized_interfaces.issues,
                )
            )

        # Profiles are separate from the surfaces they create: an unused profile produces
        # no surface, which is the whole reason it has a model. Its own try/except for the
        # same reason as its neighbours.
        try:
            profiles = normalize_appliance_interface_management_profiles(appliance)
        except Exception as exc:
            profile_failures.append(
                PANOSInterfaceManagementProfileNormalizationFailure(
                    appliance=appliance, error_text=str(exc))
            )
        else:
            profile_normalizations.append(
                PANOSInterfaceManagementProfileNormalizedAppliance(
                    appliance=appliance, profiles=profiles)
            )

        # Each object normalizer gets its OWN try/except, for the reason its neighbours
        # above do: one subtree failing must not silently remove another's rows.
        for kind, normalize in APPLIANCE_OBJECT_NORMALIZERS:
            try:
                counts = normalize(appliance)
            except Exception as exc:
                appliance_object_failures.append(
                    PANOSApplianceObjectNormalizationFailure(
                        appliance=appliance, kind=kind, error_text=str(exc))
                )
            else:
                appliance_object_normalizations.append(
                    PANOSApplianceObjectNormalizedAppliance(
                        appliance=appliance, kind=kind, counts=dict(counts or {}))
                )

    # Shared scope belongs to the appliance group and must be rebuilt BEFORE any of its
    # enforcement points: replace_addresses() is a delete-and-recreate, and security rule
    # address refs FK to those rows, so rewriting shared scope afterwards would cascade
    # a point's refs away.
    for appliance_group in get_in_scope_appliance_groups(management_station):
        try:
            shared = normalize_appliance_group_shared_scope(appliance_group)
        except Exception as exc:
            address_failures.append(
                PANOSAddressNormalizationFailure(
                    enforcement_point=None,
                    error_text=f"shared scope for appliance group {appliance_group}: {exc}",
                )
            )
            continue
        address_normalizations.append(
            PANOSAddressNormalizedPoint(
                appliance_group=appliance_group,
                address_objects=shared.address_objects,
                address_groups=shared.address_groups,
                policy_object_issues=shared.policy_object_issues,
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
                policy_object_issues=normalized.policy_object_issues,
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

    for enforcement_point in enforcement_points:
        try:
            zones = normalize_enforcement_point_zones(enforcement_point)
        except Exception as exc:
            zone_failures.append(
                PANOSZoneNormalizationFailure(
                    enforcement_point=enforcement_point,
                    error_text=str(exc),
                )
            )
            continue
        zone_normalizations.append(
            PANOSZoneNormalizedPoint(
                enforcement_point=enforcement_point,
                zones=zones,
            )
        )

    return PANOSInScopeRenormalizationResult(
        appliances=appliances,
        enforcement_points=enforcement_points,
        management_interface_normalizations=management_interface_normalizations,
        management_interface_failures=management_interface_failures,
        interface_normalizations=interface_normalizations,
        interface_failures=interface_failures,
        interface_management_profile_normalizations=profile_normalizations,
        interface_management_profile_failures=profile_failures,
        address_normalizations=address_normalizations,
        address_failures=address_failures,
        security_rule_normalizations=security_rule_normalizations,
        security_rule_failures=security_rule_failures,
        security_rule_item_failures=security_rule_item_failures,
        zone_normalizations=zone_normalizations,
        zone_failures=zone_failures,
        appliance_object_normalizations=appliance_object_normalizations,
        appliance_object_failures=appliance_object_failures,
    )


def collect_in_scope_configuration_snapshots(
    management_station: ManagementStation,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
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
            persisted_list, catalog_failures = collect_appliance_predefined_catalogs(
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
        # Per-catalog failures are reported individually, so one unavailable catalog reads as
        # one missing catalog rather than as a lost appliance.
        for error_text in catalog_failures:
            predefined_lists_failures.append(
                PANOSApplianceCollectionFailure(appliance=appliance, error_text=error_text)
            )
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
        management_interface_normalizations=renormalized.management_interface_normalizations,
        management_interface_failures=renormalized.management_interface_failures,
        address_normalizations=renormalized.address_normalizations,
        address_failures=renormalized.address_failures,
        security_rule_normalizations=renormalized.security_rule_normalizations,
        security_rule_failures=renormalized.security_rule_failures,
        security_rule_item_failures=renormalized.security_rule_item_failures,
        zone_normalizations=renormalized.zone_normalizations,
        zone_failures=renormalized.zone_failures,
        appliance_object_normalizations=renormalized.appliance_object_normalizations,
        appliance_object_failures=renormalized.appliance_object_failures,
    )


def refresh_in_scope_configuration_snapshots(
    management_station: ManagementStation,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
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
    user_agent: str = DEFAULT_USER_AGENT,
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
    user_agent: str = DEFAULT_USER_AGENT,
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
    user_agent: str = DEFAULT_USER_AGENT,
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
