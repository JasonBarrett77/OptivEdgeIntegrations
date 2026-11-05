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
    PolicyObjectNamespace,
    SecurityRule,
    SecurityRuleDestinationAddressRef,
    SecurityRuleSourceAddressRef,
    Zone,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors import (
    clear_target_vsys,
    collect_show_dns_proxy_fqdn_all,
    LIST_TYPE_CUSTOM,
    LIST_TYPE_PREDEFINED,
    collect_show_external_list,
    collect_content_deployment_schedule,
    collect_show_managed_devices,
    collect_show_merged_config,
    collect_predefined_certificates,
    collect_predefined_gp_app_config_dictionary,
    collect_predefined_security_profiles,
    collect_show_high_availability_all,
    collect_request_license_info,
    collect_show_iot_icd_version,
    collect_pushed_vsys_profiles,
    collect_predefined_applications,
    collect_show_cloud_appid_connection,
    collect_show_logging_status,
    collect_show_system_info,
    collect_show_ntp,
    collect_show_device_telemetry_settings,
    collect_show_dhcp_client_mgmt_interface_state,
    collect_show_running_resource_monitor,
    collect_show_masterkey_properties,
    collect_show_panorama_status,
    collect_predefined_log_forwarding_profiles,
    collect_predefined_ssl_tls_service_profiles,
    collect_show_predefined_ip_block_lists,
    collect_show_predefined_ssl_exclude_cert,
    collect_show_predefined_url_categories,
    collect_show_predefined_url_lists,
    collect_show_pushed_shared_policy,
    collect_show_pushed_shared_policy_vsys,
    collect_show_rule_hit_count,
    set_target_vsys,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.device_groups import (
    collect_show_dg_hierarchy,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_groups import (
    NormalizedDeviceGroups,
    normalize_show_dg_hierarchy,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    PANOSNormalizedCollection,
    normalize_appliance_group_shared_scope,
    normalize_enforcement_point_addresses,
    normalize_enforcement_point_rulebase_device_match,
    normalize_enforcement_point_zones,
    normalize_enforcement_point_dynamic_address_content,
    normalize_enforcement_point_security_rules,
    normalize_appliance_group_security_profiles,
    normalize_security_profiles,
    normalize_appliance_policy_rule_settings,
    normalize_enforcement_point_security_rule_posture,
    normalize_enforcement_point_vsys_rule_posture,
    normalize_security_rule_profile_coverage,
    normalize_appliance_admin_role_posture,
    normalize_appliance_admin_users,
    normalize_appliance_authentication_profiles,
    normalize_appliance_authentication_sequences,
    normalize_appliance_certificate_objects,
    normalize_appliance_globalprotect,
    normalize_appliance_globalprotect_gateways,
    normalize_appliance_certificate_settings,
    normalize_appliance_interface_management_profiles,
    normalize_appliance_authentication_settings,
    normalize_appliance_log_settings,
    normalize_appliance_login_banner,
    normalize_appliance_management_tls,
    normalize_appliance_high_availability,
    normalize_appliance_management_ssh,
    normalize_appliance_device_identification,
    normalize_appliance_configuration_backup_evidence,
    normalize_appliance_dataplane_utilisation,
    normalize_appliance_globalprotect_portal_presence,
    normalize_appliance_licence_inventory,
    normalize_appliance_log_alarm_settings,
    normalize_appliance_platform_content_streams,
    normalize_appliance_master_key,
    normalize_appliance_panorama_registration,
    normalize_appliance_management_plane,
    normalize_appliance_services_settings,
    normalize_appliance_content_update_schedule,
    normalize_station_content_deployment_schedule,
    normalize_appliance_wildfire_settings,
    normalize_appliance_device_services,
    normalize_appliance_password_complexity,
    normalize_appliance_password_profiles,
    normalize_appliance_server_profiles,
    normalize_appliance_interfaces,
    normalize_appliance_session_settings,
    normalize_appliance_ike_crypto_profiles,
    normalize_appliance_ike_gateways,
    normalize_appliance_ipsec_crypto_profiles,
    normalize_appliance_monitor_profiles,
    normalize_appliance_ipsec_tunnels,
    normalize_appliance_ipsec_tunnel_paths,
    normalize_appliance_zone_protection_counts,
    normalize_enforcement_point_dos_policy_rules,
    normalize_appliance_lldp_global_settings,
    normalize_appliance_dhcp_interface_configs,
    normalize_appliance_tunnel_inspection_coverage,
    normalize_appliance_routing_adjacencies,
    normalize_appliance_management_interfaces,
    normalize_appliance_decryption_settings,
    normalize_appliance_ssl_decryption_exclusions,
    normalize_appliance_ssl_decryption_vendor_exclusion_optout,
    normalize_appliance_cloud_app_engine,
    normalize_enforcement_point_decryption_policy,
    normalize_enforcement_point_saas_security,
    normalize_enforcement_point_user_id,
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
class PANOSPolicyObjectNormalized:
    """A vsys- or group-scoped object normalizer's result - security profiles today. Exactly one
    of the two owners is set: the group for its shared-scope pass, the point for its own."""

    kind: str
    counts: dict
    appliance_group: ApplianceGroup | None = None
    enforcement_point: EnforcementPoint | None = None


@dataclass(slots=True)
class PANOSPolicyObjectNormalizationFailure:
    kind: str
    error_text: str
    appliance_group: ApplianceGroup | None = None
    enforcement_point: EnforcementPoint | None = None


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
    #: `show logging-status`, the one read in this estate that is not a view of configuration.
    #: Appended rather than folded into predefined_lists_* because a failure here means one
    #: control goes silent, and a failure there means a different one over-reports - two
    #: outcomes a reader has to be able to tell apart.
    logging_status_collections: list[PANOSApplianceCollectedSnapshot] = field(
        default_factory=list)
    logging_status_failures: list[PANOSApplianceCollectionFailure] = field(
        default_factory=list)
    #: `show high-availability all` and `show panorama-status`, the two operational reads
    #: PAN-HAP-001 to 005 rest on. Their own lists for the same reason the logging one has its
    #: own: a failure here leaves a verdict holding its firing default - which a reader has to
    #: be able to tell from a verdict that was computed - and not a column wrong.
    high_availability_collections: list[PANOSApplianceCollectedSnapshot] = field(
        default_factory=list)
    high_availability_failures: list[PANOSApplianceCollectionFailure] = field(
        default_factory=list)
    #: `show cloud-appid connection-to-cloud`, the only firewall-side reading of whether the
    #: App-ID Cloud Engine is RUNNING. Its own pair for the same reason as the two above: a
    #: failure here leaves `CloudAppEngineSetting.ace_failure_reason` at `unread` and the verdict
    #: at its firing default, which is a different thing for a reader to act on from a column
    #: that came out wrong. PAN-SAS-005, and the premise PAN-SAS-003 and 004 rest on.
    cloud_appid_connection_collections: list[PANOSApplianceCollectedSnapshot] = field(
        default_factory=list)
    cloud_appid_connection_failures: list[PANOSApplianceCollectionFailure] = field(
        default_factory=list)
    panorama_status_collections: list[PANOSApplianceCollectedSnapshot] = field(
        default_factory=list)
    panorama_status_failures: list[PANOSApplianceCollectionFailure] = field(
        default_factory=list)
    #: The three device-identification op reads - `request license info`,
    #: `show system info` and `show iot icd version`. Their own pair for the same reason the
    #: logging-status pair is its own: a failure here leaves PAN-IOT-001's licence half and the
    #: whole of PAN-IOT-003 resting on companion flags that FIRE, which a reader acts on
    #: differently from a configuration read that came back wrong.
    device_identification_collections: list[PANOSApplianceCollectedSnapshot] = field(
        default_factory=list)
    device_identification_failures: list[PANOSApplianceCollectionFailure] = field(
        default_factory=list)
    #: The three device-services op reads - `show ntp`, `show device-telemetry settings` and
    #: `show dhcp client mgmt-interface-state`. Their own pair for the same reason the
    #: device-identification pair is its own: a failure here leaves PAN-SVC-001's second half,
    #: the whole of PAN-SVC-003's lease question and PAN-SVC-008's delivery state resting on
    #: columns that FIRE, which a reader acts on differently from a value that came back wrong.
    device_services_collections: list[PANOSApplianceCollectedSnapshot] = field(
        default_factory=list)
    device_services_failures: list[PANOSApplianceCollectionFailure] = field(
        default_factory=list)
    #: The MANAGEMENT STATION's own content deployment schedules - the one read in this estate
    #: addressed at the station's own configuration rather than at an appliance's, so ONE call for
    #: the estate rather than one per appliance. A single value rather than a list for that
    #: reason. PAN-UPD-006. A failure here leaves `deployment_schedule_read` false and both
    #: verdict columns EMPTY, which is "nobody asked" and is a different thing for a reader to act
    #: on from an estate that was read and holds no schedule.
    content_deployment_schedule_collection: PANOSPersistedCollection | None = None
    content_deployment_schedule_failure: str = ""
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
    policy_object_normalizations: list[PANOSPolicyObjectNormalized] = field(default_factory=list)
    policy_object_failures: list[PANOSPolicyObjectNormalizationFailure] = field(default_factory=list)


@dataclass(slots=True)
class PANOSInScopeRefreshCollection:
    inventory: PANOSProcessedCollection
    configuration_snapshots: PANOSInScopeConfigCollection
    #: None only for a station whose hierarchy could not be collected; every Panorama has
    #: at least the synthesized Shared root once it has been.
    device_groups: NormalizedDeviceGroups | None = None


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
    policy_object_normalizations: list[PANOSPolicyObjectNormalized] = field(default_factory=list)
    policy_object_failures: list[PANOSPolicyObjectNormalizationFailure] = field(default_factory=list)
    #: The station-anchored verdict over its own content deployment schedules. PAN-UPD-006. Its
    #: own pair because it is the only normalization here that is not per appliance and not per
    #: enforcement point: it runs once for the station, and a failure leaves the estate-level row
    #: untouched rather than removing an appliance's.
    content_deployment_schedule_counts: dict[str, int] = field(default_factory=dict)
    content_deployment_schedule_failure: str = ""


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


def collect_and_normalize_device_groups(
    management_station: ManagementStation,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> NormalizedDeviceGroups:
    """Collect the device-group hierarchy for one station and normalize it into the tree.

    Its own flow rather than a branch of `collect_persist_and_normalize`, because that one
    returns a `PANOSNormalizedCollection` of topology objects and this returns a tree - a
    shape it has no field for, and no reason to grow one.
    """
    session = open_session(
        management_station,
        credentials_provider=credentials_provider,
        timeout=timeout,
        user_agent=user_agent,
    )
    collected = collect_show_dg_hierarchy(session)
    persist_collected_response(management_station, collected)
    return normalize_show_dg_hierarchy(management_station, collected)


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


def collect_appliance_logging_status(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> PANOSPersistedCollection:
    """PAN-LOG-010's only source. No configuration read can say whether forwarding WORKS.

    One op call per appliance. Until this snapshot exists,
    `LoggingSettings.central_store_status_collected` is false on every row and the control is
    silent - which is the deliberate direction, because the alternative is a finding on every
    appliance in the estate.
    """
    return collect_appliance_and_persist(
        appliance,
        collector=collect_show_logging_status,
        credentials_provider=credentials_provider,
        timeout=timeout,
        user_agent=user_agent,
    )


def collect_appliance_high_availability(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> PANOSPersistedCollection:
    """PAN-HAP-001 to 004's runtime source. No configuration read can answer what it answers.

    One op call per appliance. Until this snapshot exists,
    `HighAvailabilityConfig.ha_runtime_state_collected` is false on every row and the four
    verdicts that rest on it hold their firing defaults - which is the deliberate direction, and
    is NOT the same as a finding: that column is what tells the two apart.
    """
    return collect_appliance_and_persist(
        appliance,
        collector=collect_show_high_availability_all,
        credentials_provider=credentials_provider,
        timeout=timeout,
        user_agent=user_agent,
    )


def collect_appliance_cloud_appid_connection(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> PANOSPersistedCollection:
    """PAN-SAS-005's only reading of whether the App-ID Cloud Engine WORKS.

    One op call per appliance. No configuration read can answer it: `deviceconfig/setting/cloudapp`
    says only whether somebody switched the engine off on purpose, and on every appliance in this
    lab that key reads reassuringly while the engine reports its licence check failing. Until this
    snapshot exists `CloudAppEngineSetting.ace_failure_reason` is `unread` on every row and
    `ace_not_operational` holds its firing default - which is the deliberate direction, and is NOT
    the same as a measured failure: the reason column is what tells the two apart.
    """
    return collect_appliance_and_persist(
        appliance,
        collector=collect_show_cloud_appid_connection,
        credentials_provider=credentials_provider,
        timeout=timeout,
        user_agent=user_agent,
    )


def collect_appliance_panorama_status(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> PANOSPersistedCollection:
    """PAN-HAP-005's only reading of whether the registration WORKS.

    One op call per appliance. Without it
    `PanoramaRegistration.panorama_address_in_force_unverified` stays true, which is accurate
    rather than merely safe: three different nodes can hold a Panorama address and nothing in
    the configuration says which one is live.
    """
    return collect_appliance_and_persist(
        appliance,
        collector=collect_show_panorama_status,
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

    Appliance-wide, not vsys-scoped, so one session covers every call. TWO of them are `show
    predefined` op commands; the rest - the SSL/TLS service profiles, the certificates, the
    security profiles and the Log Forwarding profiles - are direct config reads, because they
    live in the config tree's predefined branch rather than the content catalog `show predefined`
    addresses, and `show config merged` does not carry that branch either.
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
        # PAN-URL-001/002/003's DENOMINATOR, and the only route to it: nothing in any
        # configuration view carries the URL category catalogue. One op call per appliance.
        # Without it every per-category verdict on a url-filtering profile holds its firing
        # default and `category_catalogue_collected` is false on every row.
        collect_show_predefined_url_categories,
        collect_show_predefined_url_lists,
        collect_predefined_ssl_tls_service_profiles,
        collect_predefined_certificates,
        collect_predefined_security_profiles,
        # PAN-LOG-005's only route. Without it a vsys whose only coverage is the vendor's
        # predefined profile reports as having no log forwarding at all.
        collect_predefined_log_forwarding_profiles,
        # PAN-DEC-004's only route, and the THIRD `show predefined` op read here rather than a
        # fifth config read: measured on all four appliances, `action=get` at
        # /config/predefined/ssl-exclude-cert answers an empty count envelope for a populated
        # list and `action=show` denies the node exists. Without it
        # `stale_disabled_vendor_exclusion_count` is zero on every row and the control reports
        # nothing on an appliance carrying residue.
        collect_show_predefined_ssl_exclude_cert,
        # PAN-GPP-003's decoding input: the GlobalProtect app-setting dictionary. A portal
        # stores an app setting as an entry NAME and a member list and validates neither, so
        # without this nothing says what a stored setting MEANS or whether the name is real.
        # The entry count differs by appliance in this estate, which is why it is read here -
        # once per appliance - rather than once and reused.
        collect_predefined_gp_app_config_dictionary,
        # PAN-SAS-003's population: the App-ID catalogue, which is what makes "a rule names a
        # function child application rather than the base application" decidable at all.
        # BY FAR THE LARGEST READ IN THIS TUPLE - 3.6 to 7.3 MB per appliance, measured on three
        # lab appliances 2026-10-29, most of it the inline base64 icon on each of ~5,500
        # entries - and the normalizer needs four leaves of it. It shares this tuple's single
        # failure list, so losing it reads as "the predefined catalogs were partial for this
        # appliance"; `SaasApplicationPolicyPosture`'s two function columns then hold their
        # firing defaults and the normalizer's return value says the catalogue was absent.
        collect_predefined_applications,
    ):
        try:
            persisted.append(persist_appliance_collected_response(appliance, collect(session)))
        except Exception as exc:  # noqa: BLE001 - recorded and reported, not suppressed
            failures.append(f"{collect.__name__}: {exc}")
    return persisted, failures


def collect_appliance_device_identification(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> tuple[list[PANOSPersistedCollection], list[str]]:
    """PAN-IOT-001's and PAN-IOT-003's only sources. No configuration read carries any of them.

    Three op calls on one session, appliance-wide, COLLECTED INDEPENDENTLY. They answer three
    unrelated questions and letting one exception abandon the other two would be expensive here
    in particular: `request license info` is the only read in this estate that returns the SAME
    PAYLOAD for "nothing is licensed" and "nobody asked", and the column that separates them is
    computed from whether its snapshot exists. Losing it to a failure in the free-text ICD read
    would silently move an appliance from "entitlement absent" to "never measured".

    Failures are returned rather than swallowed, so a partial collection is visible as partial.
    """
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    persisted: list[PANOSPersistedCollection] = []
    failures: list[str] = []
    for collect in (
        collect_request_license_info,
        collect_show_system_info,
        collect_show_iot_icd_version,
    ):
        try:
            persisted.append(persist_appliance_collected_response(appliance, collect(session)))
        except Exception as exc:  # noqa: BLE001 - recorded and reported, not suppressed
            failures.append(f"{collect.__name__}: {exc}")
    return persisted, failures


def collect_appliance_platform_lifecycle(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> tuple[list[PANOSPersistedCollection], list[str]]:
    """PAN-PLT-006's own source. No configuration read carries it.

    ONE READ ON ONE SESSION, AND IT WAS THREE TWO DAYS AGO. `show running resource-monitor` is an
    operational command and the only thing that answers what it answers. The other two were
    `type=config&action=show` of one xpath each - `collect_device_telemetry` and
    `collect_log_alarm_settings` - and both are GONE, with the collectors themselves, by Jason's
    ruling `OptivEdgeProbe/reference/standing-rulings.md` section 5: A CONTROL USES THE
    CONFIGURATION THAT WAS COLLECTED. Both of those nodes are in the merged configuration this
    pass already collects, measured read-only on 2026-10-30, and both normalizers read it there.

    THE LOOP AND THE FAILURE LIST ARE KEPT FOR ONE READ ON PURPOSE. They cost nothing and the next
    operational read this domain needs inherits the shape: a failure leaves a verdict at its
    firing default rather than leaving a configuration column wrong, and those are different
    outcomes for a reader to act on.

    Failures are returned rather than swallowed, so a partial collection is visible as partial.
    """
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    persisted: list[PANOSPersistedCollection] = []
    failures: list[str] = []
    for collect in (
            collect_show_running_resource_monitor,
    ):
        try:
            persisted.append(persist_appliance_collected_response(appliance, collect(session)))
        except Exception as exc:  # noqa: BLE001 - recorded and reported, not suppressed
            failures.append(f"{collect.__name__}: {exc}")
    return persisted, failures


def collect_appliance_device_services(
    appliance: Appliance,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> tuple[list[PANOSPersistedCollection], list[str]]:
    """PAN-SVC-001's, 003's and 008's runtime halves. No configuration read carries any of them.

    A FOURTH READ WAS ADDED HERE ON 2026-10-30 AND REMOVED THE SAME DAY. It was
    `collect_device_telemetry`, a `type=config&action=show` of one node, added so the telemetry
    row would come from the running view rather than from the merged configuration this pass
    already collects. Jason's ruling the same day - USE THE CONFIGURATION THAT WAS COLLECTED -
    closed the question that read existed to answer, and closed it for every control rather than
    for this one. The op call `show device-telemetry settings` below stays, because it answers a
    question no configuration read answers: whether the device can DELIVER.

    THREE OP CALLS ON ONE SESSION, COLLECTED
    INDEPENDENTLY. The fourth arrived with ruling P374a, 2026-10-29: one model covers the
    telemetry node, this domain's normalizer writes it, so this is where its committed read is
    taken. The op call `show device-telemetry settings` beside it answers a DIFFERENT question -
    whether the device can deliver - and neither replaces the other. They are collected one per
    try for the reason
    `collect_appliance_device_identification` gives: they answer unrelated questions and letting
    one exception abandon the others is expensive here in particular, because each is the ONLY
    thing that can tell its own unknown from its own zero. Losing the lease read to a failure in
    the telemetry read would move an appliance from "resolving through an address nobody chose"
    to "nobody measured it", and those are different findings.

    THE FOURTH READ THIS DOMAIN NEEDS IS NOT HERE AND THE ABSENCE IS DELIBERATE. `show system
    info` is taken by `collect_appliance_device_identification` already, so
    `SystemIdentity.hostname_in_force` and its companion need no new call.

    ONE OF THE THREE TREATS A REFUSAL AS AN ANSWER. `show dhcp client mgmt-interface-state`
    RAISES on a statically addressed appliance, naming the effective mode, and its collector
    records that as an empty result - because "this interface is not a DHCP client" is a reading.
    Anything else propagates into `failures` below, which is what keeps an unreachable appliance
    from reading as a statically-addressed one.

    Failures are returned rather than swallowed, so a partial collection is visible as partial.
    """
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    persisted: list[PANOSPersistedCollection] = []
    failures: list[str] = []
    for collect in (
        collect_show_ntp,
        collect_show_device_telemetry_settings,
        collect_show_dhcp_client_mgmt_interface_state,
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


def collect_enforcement_point_rule_hit_count(
    enforcement_point: EnforcementPoint,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> PANOSPersistedCollection:
    """Per-rule usage telemetry for one vsys - the only read that says whether a rule is used.

    PER ENFORCEMENT POINT and not per appliance, because the command names the vsys inside the
    command body and there is no device-wide form of it. See
    `collectors/rule_hit_count.py` for what the reply reports when nothing is counting, which
    is the measurement the columns resting on it are safe because of.
    """
    appliance = resolve_enforcement_point_collection_appliance(enforcement_point)
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    collected = collect_show_rule_hit_count(
        session,
        vsys_name=enforcement_point.vsys_name,
    )
    return persist_enforcement_point_collected_response(enforcement_point, collected)


def collect_enforcement_point_pushed_profiles(
    enforcement_point: EnforcementPoint,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> PANOSPersistedCollection:
    """The pushed security profiles, read on the firewall's own pushed tree.

    A SECOND READ OF THE SAME QUESTION, and both are needed: the op read above omits the pushed
    security profiles entirely on the PA-5220 pair while this config get returns them on every
    lab appliance. See `collectors/pushed_profiles.py` for the measurement.
    """
    appliance = resolve_enforcement_point_collection_appliance(enforcement_point)
    session = open_session(
        appliance.management_station,
        credentials_provider=credentials_provider,
        target=appliance.serial_number,
        timeout=timeout,
        user_agent=user_agent,
    )
    collected = collect_pushed_vsys_profiles(
        session,
        vsys_name=enforcement_point.vsys_name,
    )
    return persist_enforcement_point_collected_response(enforcement_point, collected)


def collect_management_station_content_deployment_schedule(
    management_station: ManagementStation,
    *,
    credentials_provider: Callable[[], tuple[str, str]] | None = None,
    timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> PANOSPersistedCollection:
    """The station's own content deployment schedules. PAN-UPD-006.

    THE ONLY CONFIG READ IN THIS PACKAGE ADDRESSED AT THE MANAGEMENT STATION, which is why it goes
    through `collect_and_persist` with NO `target=` rather than through
    `collect_appliance_and_persist`. `deviceconfig/system/deployment-update-schedule` exists only
    on the station - `config_complete` at its path answers `code=6 Invalid sequence` on both lab
    firewalls - so a collector that reaches every appliance and never addresses the station
    collects nothing about it no matter how many firewalls it reads.

    One call per station per snapshot, so the cost is one call for the estate.
    """
    return collect_and_persist(
        management_station,
        collector=collect_content_deployment_schedule,
        credentials_provider=credentials_provider,
        timeout=timeout,
        user_agent=user_agent,
    )


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
    # AFTER admin users only for readability - it reads the same merged payload directly and
    # not the AdminUser rows, so it depends on nothing in this tuple and moving it is safe.
    ("admin role posture", normalize_appliance_admin_role_posture),
    ("server profiles", normalize_appliance_server_profiles),
    ("password profiles", normalize_appliance_password_profiles),
    ("password complexity", normalize_appliance_password_complexity),
    ("authentication settings", normalize_appliance_authentication_settings),
    ("login banner", normalize_appliance_login_banner),
    ("master key", normalize_appliance_master_key),
    # Device > IoT Security, the licence table and the installed content dictionary. Three op
    # snapshots and one merged leaf; depends on nothing else in this tuple.
    ("device identification", normalize_appliance_device_identification),
    ("services settings", normalize_appliance_services_settings),
    # SITE-TO-SITE VPN - PAN-IKE-001 to -009 and PAN-IPS-001 to -009. Eighteen controls that
    # reported nothing until 2026-11-04 because these five normalizers, written and tested,
    # were never called from this flow: the lab's merged snapshots carry 9 IKE gateways, 14 IKE
    # crypto profiles, 13 IPSec crypto profiles and 4 tunnels, and every one of those tables
    # was empty. Separate entries rather than one, so a failure in any costs only its own
    # model; the sixth joins the five.
    ("ike crypto profiles", normalize_appliance_ike_crypto_profiles),
    ("ike gateways", normalize_appliance_ike_gateways),
    ("ipsec crypto profiles", normalize_appliance_ipsec_crypto_profiles),
    ("monitor profiles", normalize_appliance_monitor_profiles),
    ("ipsec tunnels", normalize_appliance_ipsec_tunnels),
    # LAST, and it joins what the five above wrote rather than reading a payload of its own.
    ("ipsec tunnel paths", normalize_appliance_ipsec_tunnel_paths),
    # Device > Dynamic Updates, all five content types on one row. PAN-UPD-001 to PAN-UPD-005.
    # Reads the same merged device entry as its neighbours and depends on nothing else in this
    # tuple. A ROW PER HA PEER and not per pair: the update schedule does not sync across peers,
    # and the two lab PA-5220s hold different content types to prove it.
    ("content update schedule", normalize_appliance_content_update_schedule),
    # PLATFORM LIFECYCLE - PAN-PLT-001 to PAN-PLT-006. Seven members rather than one, so that a
    # failure in any of them costs only its own model: they read four different payloads between
    # them and none depends on another, so the order within this block carries no meaning.
    #
    # Each one anchors its row to the MERGED snapshot and reports in a companion column whether
    # its own read answered - "we never asked" must not look like "we asked and it was fine", and
    # on this domain that separation is what stops an unlicensed appliance, an opted-out one, an
    # idle dataplane and an unread one from all reading the same way.
    ("platform content streams", normalize_appliance_platform_content_streams),
    ("GlobalProtect portal presence", normalize_appliance_globalprotect_portal_presence),
    ("licence inventory", normalize_appliance_licence_inventory),
    ("log alarm settings", normalize_appliance_log_alarm_settings),
    ("configuration backup evidence", normalize_appliance_configuration_backup_evidence),
    ("dataplane utilisation", normalize_appliance_dataplane_utilisation),
    # Device > Setup > Management > Policy Rulebase Settings, two leaves of the same merged
    # device entry its neighbours read. Depends on nothing else in this tuple, and the point
    # loops that read the row it writes all run after this loop finishes.
    ("policy rule settings", normalize_appliance_policy_rule_settings),
    # Device > Setup > Management > Management Interface Settings, and the operational mode the
    # appliance reports when asked. Reads the same merged device entry as its neighbours plus
    # its own `show system info` snapshot, and depends on nothing else in this tuple.
    ("management plane", normalize_appliance_management_plane),
    # AFTER services settings, which owns the other column on the same LoggingSettings row.
    # The two write disjoint column sets and each deletes only its own provenance rows, so the
    # order is about PAN-MGT-011 keeping its behaviour if this one fails rather than about the
    # values. Device > Log Settings, the log-settings server profiles and per-vsys forwarding.
    ("log settings", normalize_appliance_log_settings),
    # Device > Setup > WildFire. Reads the same device entry as its neighbours and
    # depends on nothing else in this tuple.
    ("wildfire settings", normalize_appliance_wildfire_settings),
    # Reads the same device entry as its neighbour above, and additionally resolves whether SNMP
    # is REACHABLE - and whether the surfaces were walked at all - over the ManagementService
    # rows. Those are written before this loop starts, by
    # normalize_appliance_management_interfaces, so the dependency is on the surrounding
    # function's order rather than on this tuple's, and moving it within the tuple is safe.
    #
    # SIX MODELS AS OF 2026-10-29, not three: it also writes the management resolvers, the
    # telemetry decision and one service-paths row per enforcement point.
    ("device services", normalize_appliance_device_services),
    ("certificate objects", normalize_appliance_certificate_objects),
    # Network > GlobalProtect > Portals, plus the vsys's HIP objects and the licence reply
    # another domain's collector already takes. Reads the same merged payload as its neighbours
    # and depends on nothing else in this tuple - placed after the certificate objects because
    # a portal BINDS an SslTlsServiceProfile and a CertificateProfile and a reader will look
    # for them nearby, NOT because anything here resolves over those rows: this domain stores
    # the binding as a name, deliberately, and the resolution is another control's.
    ("globalprotect portals", normalize_appliance_globalprotect),
    # Network > GlobalProtect > Gateways, both halves of it - the vsys entry and the same-named
    # device-local entry under network/tunnel - plus the vsys's host-posture verdict.
    # MUST STAY AFTER "certificate objects" AND "authentication profiles" ABOVE, and that is a
    # real ordering obligation rather than tidiness: unlike the portal beside it, this domain
    # RESOLVES its bindings rather than storing the names alone. PAN-GPG-001 asserts the
    # protocol floor the bound SSL/TLS profile states, PAN-GPG-002 the device-binding refusal of
    # the bound certificate profile and the back end of the bound authentication profile, and
    # each is a property of the far row. Run before them it would resolve against the previous
    # collection's rows or against none, and report a correctly hardened gateway as unresolved -
    # the same obligation "management TLS" and "decryption settings" carry below.
    ("globalprotect gateways", normalize_appliance_globalprotect_gateways),
    # Device > Setup > Management > General Settings, one leaf. Reads the same merged device
    # entry as its neighbours and depends on nothing else in this tuple - placed beside the
    # certificate objects because they are one domain's controls and not because of an order.
    ("certificate settings", normalize_appliance_certificate_settings),
    # AFTER certificate objects, and it must stay after: the binding resolves over the
    # SslTlsServiceProfile rows that normalizer writes. Run first, it would find last run's
    # rows - or none - and record a binding against a profile that no longer matches.
    ("management TLS", normalize_appliance_management_tls),
    ("management SSH", normalize_appliance_management_ssh),    # Both read the same merged device entry as their neighbours and depend on nothing else in
    # this tuple. Each additionally reads its own operational snapshot where one exists; a
    # missing one is a reading in its own right rather than an ordering problem.
    ("high availability", normalize_appliance_high_availability),
    ("Panorama registration", normalize_appliance_panorama_registration),
    # Device > Certificate Management > SSL Decryption Exclusion, in both writable scopes, and
    # the shared opt-out list that says which of the VENDOR's exclusions somebody switched off.
    # Both read the same merged device entry as their neighbours and depend on nothing else in
    # this tuple; the opt-out additionally reads the `show predefined ssl-exclude-cert` snapshot
    # for its set difference, and a missing one is a reading in its own right.
    ("SSL decryption exclusions", normalize_appliance_ssl_decryption_exclusions),
    ("SSL decryption vendor exclusion opt-outs",
     normalize_appliance_ssl_decryption_vendor_exclusion_optout),
    # Device > Certificate Management > Certificates, the Forward Trust/Untrust designation -
    # stored at /config/shared/ssl-decrypt beside the two exclusion nodes above, and set on a
    # screen it is not on. MUST RUN AFTER "certificate objects" earlier in this tuple: its
    # local-authority verdict resolves the designated NAME against the certificate rows.
    ("decryption settings", normalize_appliance_decryption_settings),
    # Network hardening: Device > Setup > Session, Network > LLDP, Network > DHCP,
    # Policies > Tunnel Inspection and Network > Virtual Routers. All five read the same
    # merged device entry as their neighbours and depend on nothing else in this tuple -
    # including the per-interface LLDP and residue columns, which are written by
    # `normalize_appliance_interfaces` above this loop and not read back here. The tunnel
    # coverage one additionally reads the per-vsys pushed-shared-policy snapshot where one
    # was collected; a missing one is a reading in its own right rather than an ordering
    # problem.
    ("session settings", normalize_appliance_session_settings),
    ("LLDP global settings", normalize_appliance_lldp_global_settings),
    ("DHCP interface configurations", normalize_appliance_dhcp_interface_configs),
    ("tunnel inspection coverage", normalize_appliance_tunnel_inspection_coverage),
    ("routing adjacencies", normalize_appliance_routing_adjacencies),
    # Device > Setup > Content-ID > App-ID Cloud Engine, one leaf, plus the engine's own
    # operational reply. Reads the same merged device entry as its neighbours and depends on
    # nothing else in this tuple; a missing operational snapshot is a reading in its own right
    # rather than an ordering problem. PAN-SAS-005.
    ("App-ID Cloud Engine", normalize_appliance_cloud_app_engine),
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
    policy_object_normalizations: list[PANOSPolicyObjectNormalized] = []
    policy_object_failures: list[PANOSPolicyObjectNormalizationFailure] = []

    # THE ONE STATION-ANCHORED NORMALIZATION, run once rather than per appliance and OUTSIDE the
    # appliance loop for that reason. Its own try/except on the same grounds as its neighbours:
    # the estate-level row failing must not take an appliance's rows away, and an appliance's
    # failing must not leave the estate-level row stale.
    content_deployment_schedule_counts: dict[str, int] = {}
    content_deployment_schedule_failure = ""
    try:
        content_deployment_schedule_counts = dict(
            normalize_station_content_deployment_schedule(management_station) or {})
    except Exception as exc:
        content_deployment_schedule_failure = str(exc)

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

    # The decryption rulebase and its verdict. Reuses the policy-object failure pair rather than
    # adding a third: the shape is identical and two lists that can disagree are worse than one.
    # NO ORDERING OBLIGATION - the verdict is computed from the rules this same call parses, so
    # unlike the rulebase device match below it cannot read a previous run's rows.
    for enforcement_point in enforcement_points:
        try:
            counts = normalize_enforcement_point_decryption_policy(enforcement_point)
        except Exception as exc:
            policy_object_failures.append(PANOSPolicyObjectNormalizationFailure(
                kind="decryption policy", enforcement_point=enforcement_point,
                error_text=str(exc)))
        else:
            policy_object_normalizations.append(PANOSPolicyObjectNormalized(
                kind="decryption policy", enforcement_point=enforcement_point,
                counts={k: v for k, v in (counts or {}).items() if isinstance(v, int)}))

    # The three SaaS verdicts. Reuses the policy-object failure pair rather than adding a
    # fourth: the shape is identical and two lists that can disagree are worse than one. NO
    # ORDERING OBLIGATION - all three are computed from the payloads this same call parses, so
    # they cannot read a previous run's rows. PAN-SAS-001 to 004.
    for enforcement_point in enforcement_points:
        try:
            counts = normalize_enforcement_point_saas_security(enforcement_point)
        except Exception as exc:
            policy_object_failures.append(PANOSPolicyObjectNormalizationFailure(
                kind="SaaS security", enforcement_point=enforcement_point,
                error_text=str(exc)))
        else:
            policy_object_normalizations.append(PANOSPolicyObjectNormalized(
                kind="SaaS security", enforcement_point=enforcement_point,
                counts={k: v for k, v in (counts or {}).items() if isinstance(v, int)}))

    # The User-ID collector: its settings node, the discovery verdict over its include/exclude
    # list, and one row per monitored server. Reuses the policy-object failure pair rather than
    # adding another: the shape is identical and two lists that can disagree are worse than one.
    # NO ORDERING OBLIGATION - all three models are built from the one payload parse this call
    # takes, including the cross-subject `tls_service_profile_bound`, so it cannot read a previous
    # run's rows. PAN-UID-002 to 006.
    for enforcement_point in enforcement_points:
        try:
            counts = normalize_enforcement_point_user_id(enforcement_point)
        except Exception as exc:
            policy_object_failures.append(PANOSPolicyObjectNormalizationFailure(
                kind="User-ID collector", enforcement_point=enforcement_point,
                error_text=str(exc)))
        else:
            policy_object_normalizations.append(PANOSPolicyObjectNormalized(
                kind="User-ID collector", enforcement_point=enforcement_point,
                counts={k: v for k, v in (counts or {}).items() if isinstance(v, int)}))

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

    # ZONE PROTECTION PROFILES, AFTER EVERY VSYS'S ZONES - PAN-ZON-002 to -006, and the zone
    # side of PAN-ZON-001. Its wrapper states the order: this pass resolves
    # `Zone.zone_protection_unresolved` in place, and run before the zones it would leave every
    # zone row at the firing default it was written with. Never called from this flow until
    # 2026-11-04, so the lab's 13 profiles produced no rows and every traffic-bearing zone
    # reported its protection unresolved. Appliance-scoped, like the registry above, and
    # recorded through the same pair of lists.
    for appliance in appliances:
        try:
            counts = normalize_appliance_zone_protection_counts(appliance)
        except Exception as exc:
            appliance_object_failures.append(
                PANOSApplianceObjectNormalizationFailure(
                    appliance=appliance, kind="zone protection profiles",
                    error_text=str(exc))
            )
        else:
            appliance_object_normalizations.append(
                PANOSApplianceObjectNormalizedAppliance(
                    appliance=appliance, kind="zone protection profiles",
                    counts=dict(counts or {}))
            )

    # Security profiles and profile groups (Objects > Security Profiles). Shared scope is the
    # group's and is unioned across its points, as the address pass is; nothing FKs to these
    # rows, so the order against rules does not matter, but group-then-point keeps the two
    # passes reading alike. Each gets its own try/except, like every pass above.
    for appliance_group in get_in_scope_appliance_groups(management_station):
        try:
            counts = normalize_appliance_group_security_profiles(appliance_group)
        except Exception as exc:
            policy_object_failures.append(PANOSPolicyObjectNormalizationFailure(
                kind="security profiles", appliance_group=appliance_group, error_text=str(exc)))
        else:
            policy_object_normalizations.append(PANOSPolicyObjectNormalized(
                kind="security profiles", appliance_group=appliance_group, counts=dict(counts or {})))

    for enforcement_point in enforcement_points:
        try:
            counts = normalize_security_profiles(enforcement_point)
        except Exception as exc:
            policy_object_failures.append(PANOSPolicyObjectNormalizationFailure(
                kind="security profiles", enforcement_point=enforcement_point, error_text=str(exc)))
        else:
            policy_object_normalizations.append(PANOSPolicyObjectNormalized(
                kind="security profiles", enforcement_point=enforcement_point, counts=dict(counts or {})))

    # AFTER the profile groups above, never before: this reads a rule's group reference and
    # resolves it to the profile types that group actually names. Security rules normalize
    # earlier in this function, so computing it there would read the PREVIOUS run's groups, or
    # none at all on a first collection.
    for enforcement_point in enforcement_points:
        try:
            counts = normalize_security_rule_profile_coverage(enforcement_point)
        except Exception as exc:
            policy_object_failures.append(PANOSPolicyObjectNormalizationFailure(
                kind="rule profile coverage", enforcement_point=enforcement_point,
                error_text=str(exc)))
        else:
            policy_object_normalizations.append(PANOSPolicyObjectNormalized(
                kind="rule profile coverage", enforcement_point=enforcement_point,
                counts=dict(counts or {})))

    # AFTER the profile-coverage loop above, and the two of these must stay in this order. The
    # per-rule pass computes shadowing and duplicates over the whole rulebase's stored rows and
    # resolves the service and schedule collections the rules name; the vsys pass then takes
    # eight verdicts over what it wrote. Run either early and it reads the previous run's rows,
    # or none on a first collection - which for a verdict about an absent rule is the direction
    # that manufactures a finding.
    # THE DoS RULEBASE - PAN-ZON-007. Point-scoped, reads the merged and pushed rules
    # directly, and depends on nothing else here; the profile a rule names is resolved by the
    # security-profile pass's referrer walk. Never called from this flow until 2026-11-04, so
    # the lab's four DoS rules produced no rows and the control reported nothing.
    for enforcement_point in enforcement_points:
        try:
            counts = normalize_enforcement_point_dos_policy_rules(enforcement_point)
        except Exception as exc:
            policy_object_failures.append(PANOSPolicyObjectNormalizationFailure(
                kind="DoS policy rules", enforcement_point=enforcement_point,
                error_text=str(exc)))
        else:
            policy_object_normalizations.append(PANOSPolicyObjectNormalized(
                kind="DoS policy rules", enforcement_point=enforcement_point,
                counts={"dos policy rules": len(counts or [])}))

    for kind, normalize_point in (
            ("security rule posture", normalize_enforcement_point_security_rule_posture),
            ("vsys rule posture", normalize_enforcement_point_vsys_rule_posture)):
        for enforcement_point in enforcement_points:
            try:
                counts = normalize_point(enforcement_point)
            except Exception as exc:
                policy_object_failures.append(PANOSPolicyObjectNormalizationFailure(
                    kind=kind, enforcement_point=enforcement_point, error_text=str(exc)))
            else:
                policy_object_normalizations.append(PANOSPolicyObjectNormalized(
                    kind=kind, enforcement_point=enforcement_point,
                    counts={k: v for k, v in (counts or {}).items() if isinstance(v, int)}))

    # AFTER the security-rule pass above, and it must stay after: the verdict is taken over the
    # `SecurityRule` rows that pass writes, so run earlier it would read the PREVIOUS run's
    # rules - or none on a first collection, which reads as "this point has no device
    # dimension" and FIRES. Reuses the policy-object failure pair rather than adding a third:
    # the shape is identical and two lists that can disagree are worse than one.
    for enforcement_point in enforcement_points:
        try:
            counts = normalize_enforcement_point_rulebase_device_match(enforcement_point)
        except Exception as exc:
            policy_object_failures.append(PANOSPolicyObjectNormalizationFailure(
                kind="rulebase device match", enforcement_point=enforcement_point,
                error_text=str(exc)))
        else:
            policy_object_normalizations.append(PANOSPolicyObjectNormalized(
                kind="rulebase device match", enforcement_point=enforcement_point,
                counts=dict(counts or {})))

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
        policy_object_normalizations=policy_object_normalizations,
        policy_object_failures=policy_object_failures,
        content_deployment_schedule_counts=content_deployment_schedule_counts,
        content_deployment_schedule_failure=content_deployment_schedule_failure,
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
    logging_status_collections: list[PANOSApplianceCollectedSnapshot] = []
    logging_status_failures: list[PANOSApplianceCollectionFailure] = []
    cloud_appid_connection_collections: list[PANOSApplianceCollectedSnapshot] = []
    cloud_appid_connection_failures: list[PANOSApplianceCollectionFailure] = []
    high_availability_collections: list[PANOSApplianceCollectedSnapshot] = []
    high_availability_failures: list[PANOSApplianceCollectionFailure] = []
    panorama_status_collections: list[PANOSApplianceCollectedSnapshot] = []
    panorama_status_failures: list[PANOSApplianceCollectionFailure] = []
    device_identification_collections: list[PANOSApplianceCollectedSnapshot] = []
    device_identification_failures: list[PANOSApplianceCollectionFailure] = []
    device_services_collections: list[PANOSApplianceCollectedSnapshot] = []
    device_services_failures: list[PANOSApplianceCollectionFailure] = []
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

    # ITS OWN LOOP AND ITS OWN FAILURE LIST. One op call per appliance, and a failure here is
    # not a failure of the configuration collection: it leaves PAN-LOG-010 silent rather than
    # leaving any column wrong, which is a different thing for a reader to act on.
    for appliance in appliances:
        try:
            persisted = collect_appliance_logging_status(
                appliance,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            logging_status_failures.append(
                PANOSApplianceCollectionFailure(appliance=appliance, error_text=str(exc))
            )
            continue
        logging_status_collections.append(
            PANOSApplianceCollectedSnapshot(appliance=appliance, persisted=persisted)
        )

    # THE TWO HA/PANORAMA OPERATIONAL READS, each with its own loop and its own failure list,
    # on the same grounds as the logging one above: a failure leaves a verdict at its firing
    # default rather than leaving a configuration column wrong, and the two outcomes are
    # different things for a reader to act on.
    for appliance in appliances:
        try:
            persisted = collect_appliance_high_availability(
                appliance,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            high_availability_failures.append(
                PANOSApplianceCollectionFailure(appliance=appliance, error_text=str(exc))
            )
            continue
        high_availability_collections.append(
            PANOSApplianceCollectedSnapshot(appliance=appliance, persisted=persisted)
        )

    # ITS OWN LOOP AND ITS OWN FAILURE LIST, on the same grounds as the three above. PAN-SAS-005.
    for appliance in appliances:
        try:
            persisted = collect_appliance_cloud_appid_connection(
                appliance,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            cloud_appid_connection_failures.append(
                PANOSApplianceCollectionFailure(appliance=appliance, error_text=str(exc))
            )
        else:
            cloud_appid_connection_collections.append(
                PANOSApplianceCollectedSnapshot(appliance=appliance, persisted=persisted)
            )

    for appliance in appliances:
        try:
            persisted = collect_appliance_panorama_status(
                appliance,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            panorama_status_failures.append(
                PANOSApplianceCollectionFailure(appliance=appliance, error_text=str(exc))
            )
            continue
        panorama_status_collections.append(
            PANOSApplianceCollectedSnapshot(appliance=appliance, persisted=persisted)
        )

    # ITS OWN LOOP AND ITS OWN FAILURE LIST, for the reason above it. Three op calls per
    # appliance; per-read failures are reported individually so one unavailable read reads as
    # one missing read rather than as a lost appliance.
    for appliance in appliances:
        try:
            persisted_list, iot_failures = collect_appliance_device_identification(
                appliance,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            device_identification_failures.append(
                PANOSApplianceCollectionFailure(appliance=appliance, error_text=str(exc))
            )
            continue
        for error_text in iot_failures:
            device_identification_failures.append(
                PANOSApplianceCollectionFailure(appliance=appliance, error_text=error_text)
            )
        for persisted in persisted_list:
            device_identification_collections.append(
                PANOSApplianceCollectedSnapshot(appliance=appliance, persisted=persisted)
            )

    # ITS OWN LOOP AND ITS OWN FAILURE LIST, for the reason above it. Three op calls per
    # appliance; per-read failures are reported individually so one unavailable read reads as
    # one missing read rather than as a lost appliance.
    for appliance in appliances:
        try:
            persisted_list, svc_failures = collect_appliance_device_services(
                appliance,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        except Exception as exc:
            device_services_failures.append(
                PANOSApplianceCollectionFailure(appliance=appliance, error_text=str(exc))
            )
            continue
        for error_text in svc_failures:
            device_services_failures.append(
                PANOSApplianceCollectionFailure(appliance=appliance, error_text=error_text)
            )
        for persisted in persisted_list:
            device_services_collections.append(
                PANOSApplianceCollectedSnapshot(appliance=appliance, persisted=persisted)
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

    # TWO READS OF WHAT PANORAMA PUSHED, per point, collected INDEPENDENTLY - one failing must
    # not abandon the other, because the two disagree per platform and each is the only source
    # for what the other omits. They share the result lists because they answer one question at
    # one scope; a run can tell them apart by the snapshot's own source_type.
    for enforcement_point in enforcement_points:
        # The hit-count read joins these two because it shares their grain and their failure
        # shape: one op call per vsys, and a failure leaves three columns on every rule of that
        # point at their indeterminate values with `hit_count_reading_known` false - which is
        # the same "a verdict went unanswered" outcome, told apart by the snapshot's source_type.
        for collect_pushed in (collect_enforcement_point_pushed_shared_policy,
                               collect_enforcement_point_pushed_profiles,
                               collect_enforcement_point_rule_hit_count):
            try:
                persisted = collect_pushed(
                    enforcement_point,
                    credentials_provider=credentials_provider,
                    timeout=timeout,
                    user_agent=user_agent,
                )
            except Exception as exc:
                vsys_policy_failures.append(
                    PANOSEnforcementPointCollectionFailure(
                        enforcement_point=enforcement_point,
                        error_text=f"{collect_pushed.__name__}: {exc}",
                    )
                )
                continue
            vsys_policy_collections.append(
                PANOSEnforcementPointCollectedSnapshot(
                    enforcement_point=enforcement_point,
                    persisted=persisted,
                )
            )

    # THE STATION'S OWN CONFIGURATION, collected once for the estate and not per appliance. Placed
    # before the renormalization below because that is what normalizes it; its own try/except so
    # that a station that refuses this one read still yields every appliance's snapshots, and so
    # that the failure reads as "nobody asked" rather than as an estate with no central schedule.
    content_deployment_schedule_collection = None
    content_deployment_schedule_failure = ""
    try:
        content_deployment_schedule_collection = (
            collect_management_station_content_deployment_schedule(
                management_station,
                credentials_provider=credentials_provider,
                timeout=timeout,
                user_agent=user_agent,
            )
        )
    except Exception as exc:
        content_deployment_schedule_failure = str(exc)

    renormalized = renormalize_in_scope_configuration(management_station)

    return PANOSInScopeConfigCollection(
        appliances=appliances,
        appliance_groups=appliance_groups,
        enforcement_points=enforcement_points,
        merged_config_collections=merged_config_collections,
        merged_config_failures=merged_config_failures,
        predefined_lists_collections=predefined_lists_collections,
        predefined_lists_failures=predefined_lists_failures,
        logging_status_collections=logging_status_collections,
        logging_status_failures=logging_status_failures,
        cloud_appid_connection_collections=cloud_appid_connection_collections,
        cloud_appid_connection_failures=cloud_appid_connection_failures,
        high_availability_collections=high_availability_collections,
        high_availability_failures=high_availability_failures,
        panorama_status_collections=panorama_status_collections,
        panorama_status_failures=panorama_status_failures,
        device_identification_collections=device_identification_collections,
        device_identification_failures=device_identification_failures,
        device_services_collections=device_services_collections,
        device_services_failures=device_services_failures,
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
        policy_object_normalizations=renormalized.policy_object_normalizations,
        policy_object_failures=renormalized.policy_object_failures,
        content_deployment_schedule_collection=content_deployment_schedule_collection,
        content_deployment_schedule_failure=(
            content_deployment_schedule_failure
            or renormalized.content_deployment_schedule_failure),
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

    device_groups = collect_and_normalize_device_groups(
        management_station,
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
        device_groups=device_groups,
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


def _candidate_edl_names(enforcement_point: EnforcementPoint) -> list[tuple[str, str]]:
    """Distinct ip-type EDL address objects referenced by this enforcement point's rules, each
    paired with the command type that can actually read it.

    Referenced directly or via any level of nested static group, already flattened onto ref rows
    by resolve_static_group_members. Excludes FQDN (handled by the bulk appliance-wide FQDN
    cache call, not a per-name EDL show command).

    The type is not decoration. Measured 2026-09-22 on pan-fw-111: `type ip` and
    `type predefined-ip` accept disjoint sets of names and reject each other's outright, so a
    name alone is not enough to read one - see build_show_external_list_command. A predefined
    list is exactly the one this normalization marked PREDEFINED, which is how the pairing is
    decided here rather than by guessing from the name's prefix.
    """
    candidate_filter = Q(
        address_object__address_type=AddressObject.TYPE_EDL,
        address_object__edl_list_type="ip",
    )
    pairs: set[tuple[str, str]] = set()
    for ref_model in (SecurityRuleSourceAddressRef, SecurityRuleDestinationAddressRef):
        for name, namespace_type in (
            ref_model.objects.filter(security_rule__enforcement_point=enforcement_point)
            .filter(candidate_filter)
            .values_list("address_object__name", "address_object__namespace_type")
        ):
            list_type = (
                LIST_TYPE_PREDEFINED
                if namespace_type == PolicyObjectNamespace.PREDEFINED
                else LIST_TYPE_CUSTOM
            )
            pairs.add((name, list_type))
    return sorted(pairs)


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
    candidates = _candidate_edl_names(enforcement_point)
    if not candidates:
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
        for name, list_type in candidates:
            collected = collect_show_external_list(session, name=name, list_type=list_type)
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
