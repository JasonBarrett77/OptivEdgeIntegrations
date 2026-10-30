"""PAN-OS collection primitives and vendor-specific endpoint collectors."""

from optivedge_integrations.integrations.platforms.pan_os.collectors.merged_config import (
    SHOW_MERGED_CONFIG_COMMAND,
    SHOW_SYSTEM_INFO_COMMAND,
    collect_show_merged_config,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.device_identification import (
    REQUEST_LICENSE_INFO_COMMAND,
    SHOW_IOT_ICD_VERSION_COMMAND,
    collect_request_license_info,
    collect_show_iot_icd_version,
    collect_show_system_info,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.platform_lifecycle import (
    DEVICE_TELEMETRY_XPATH,
    LOG_ALARM_SETTINGS_XPATH,
    RESOURCE_MONITOR_WINDOW,
    RESOURCE_MONITOR_WINDOW_SAMPLES,
    SHOW_RESOURCE_MONITOR_COMMAND,
    collect_device_telemetry,
    collect_log_alarm_settings,
    collect_show_running_resource_monitor,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.device_services import (
    SHOW_DEVICE_TELEMETRY_SETTINGS_COMMAND,
    SHOW_DHCP_CLIENT_MGMT_INTERFACE_STATE_COMMAND,
    SHOW_NTP_COMMAND,
    collect_show_device_telemetry_settings,
    collect_show_dhcp_client_mgmt_interface_state,
    collect_show_ntp,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.managed_devices import (
    SHOW_MANAGED_DEVICES_COMMAND,
    collect_show_managed_devices,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.content_updates import (
    DEPLOYMENT_UPDATE_SCHEDULE_SOURCE_TYPE,
    DEPLOYMENT_UPDATE_SCHEDULE_XPATH,
    collect_content_deployment_schedule,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.pushed_shared_policy import (
    SHOW_PUSHED_SHARED_POLICY_COMMAND,
    build_show_pushed_shared_policy_vsys_command,
    collect_show_pushed_shared_policy,
    collect_show_pushed_shared_policy_vsys,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.pushed_profiles import (
    PUSHED_VSYS_PROFILES_XPATH_TEMPLATE,
    build_pushed_vsys_profiles_xpath,
    collect_pushed_vsys_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.dns_proxy_fqdn import (
    SHOW_DNS_PROXY_FQDN_ALL_COMMAND,
    collect_show_dns_proxy_fqdn_all,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.external_list import (
    LIST_TYPE_CUSTOM,
    LIST_TYPE_PREDEFINED,
    NUM_RECORDS_PER_PAGE,
    build_clear_target_vsys_command,
    build_set_target_vsys_command,
    build_show_external_list_command,
    clear_target_vsys,
    collect_show_external_list,
    set_target_vsys,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.system import (
    collect_show_masterkey_properties,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.logging_status import (
    SHOW_LOGGING_STATUS_COMMAND,
    collect_show_logging_status,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.high_availability import (
    HIGH_AVAILABILITY_SOURCE_TYPE,
    SHOW_HIGH_AVAILABILITY_ALL_COMMAND,
    collect_show_high_availability_all,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.panorama_status import (
    PANORAMA_STATUS_SOURCE_TYPE,
    SHOW_PANORAMA_STATUS_COMMAND,
    collect_show_panorama_status,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.cloud_appid import (
    CLOUD_APPID_CONNECTION_SOURCE_TYPE,
    SHOW_CLOUD_APPID_CONNECTION_COMMAND,
    collect_show_cloud_appid_connection,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.rule_hit_count import (
    RULE_HIT_COUNT_RULE_BASE,
    RULE_HIT_COUNT_SOURCE_TYPE,
    build_show_rule_hit_count_command,
    collect_show_rule_hit_count,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.predefined import (
    PREDEFINED_APPLICATION_SOURCE_TYPE,
    PREDEFINED_GP_APP_CONFIG_SOURCE_TYPE,
    PREDEFINED_SSL_EXCLUDE_CERT_SOURCE_TYPE,
    SHOW_PREDEFINED_IP_BLOCK_LISTS_COMMAND,
    SHOW_PREDEFINED_SSL_EXCLUDE_CERT_COMMAND,
    SHOW_PREDEFINED_URL_LISTS_COMMAND,
    collect_predefined_applications,
    collect_predefined_certificates,
    collect_predefined_gp_app_config_dictionary,
    collect_predefined_log_forwarding_profiles,
    collect_predefined_security_profiles,
    collect_predefined_ssl_tls_service_profiles,
    collect_show_predefined_ip_block_lists,
    collect_show_predefined_ssl_exclude_cert,
    collect_show_predefined_url_categories,
    collect_show_predefined_url_lists,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)

__all__ = [
    "CLOUD_APPID_CONNECTION_SOURCE_TYPE",
    "SHOW_CLOUD_APPID_CONNECTION_COMMAND",
    "collect_show_cloud_appid_connection",
    "PREDEFINED_APPLICATION_SOURCE_TYPE",
    "collect_predefined_applications",
    "HIGH_AVAILABILITY_SOURCE_TYPE",
    "LIST_TYPE_CUSTOM",
    "PUSHED_VSYS_PROFILES_XPATH_TEMPLATE",
    "build_pushed_vsys_profiles_xpath",
    "collect_pushed_vsys_profiles",
    "LIST_TYPE_PREDEFINED",
    "NUM_RECORDS_PER_PAGE",
    "PANORAMA_STATUS_SOURCE_TYPE",
    "RULE_HIT_COUNT_RULE_BASE",
    "RULE_HIT_COUNT_SOURCE_TYPE",
    "build_show_rule_hit_count_command",
    "collect_show_rule_hit_count",
    "PANOSCollectedResponse",
    "PANOSOperationRequest",
    "REQUEST_LICENSE_INFO_COMMAND",
    "SHOW_DNS_PROXY_FQDN_ALL_COMMAND",
    "SHOW_HIGH_AVAILABILITY_ALL_COMMAND",
    "SHOW_IOT_ICD_VERSION_COMMAND",
    "SHOW_LOGGING_STATUS_COMMAND",
    "SHOW_MERGED_CONFIG_COMMAND",
    "SHOW_MANAGED_DEVICES_COMMAND",
    "SHOW_PANORAMA_STATUS_COMMAND",
    "SHOW_PREDEFINED_IP_BLOCK_LISTS_COMMAND",
    "SHOW_PREDEFINED_URL_LISTS_COMMAND",
    "SHOW_PUSHED_SHARED_POLICY_COMMAND",
    "SHOW_SYSTEM_INFO_COMMAND",
    "DEVICE_TELEMETRY_XPATH",
    "LOG_ALARM_SETTINGS_XPATH",
    "RESOURCE_MONITOR_WINDOW",
    "RESOURCE_MONITOR_WINDOW_SAMPLES",
    "SHOW_RESOURCE_MONITOR_COMMAND",
    "collect_device_telemetry",
    "collect_log_alarm_settings",
    "collect_show_running_resource_monitor",
    "SHOW_NTP_COMMAND",
    "SHOW_DEVICE_TELEMETRY_SETTINGS_COMMAND",
    "SHOW_DHCP_CLIENT_MGMT_INTERFACE_STATE_COMMAND",
    "collect_show_ntp",
    "collect_show_device_telemetry_settings",
    "collect_show_dhcp_client_mgmt_interface_state",
    "build_clear_target_vsys_command",
    "build_set_target_vsys_command",
    "build_show_external_list_command",
    "build_show_pushed_shared_policy_vsys_command",
    "clear_target_vsys",
    "collect_show_dns_proxy_fqdn_all",
    "collect_show_external_list",
    "collect_request_license_info",
    "collect_show_iot_icd_version",
    "collect_show_merged_config",
    "collect_show_system_info",
    "collect_show_managed_devices",
    "DEPLOYMENT_UPDATE_SCHEDULE_SOURCE_TYPE",
    "DEPLOYMENT_UPDATE_SCHEDULE_XPATH",
    "collect_content_deployment_schedule",
    "collect_predefined_certificates",
    "collect_predefined_gp_app_config_dictionary",
    "collect_predefined_log_forwarding_profiles",
    "collect_predefined_security_profiles",
    "collect_show_high_availability_all",
    "collect_show_logging_status",
    "collect_show_masterkey_properties",
    "collect_predefined_ssl_tls_service_profiles",
    "collect_show_predefined_ip_block_lists",
    "collect_show_predefined_ssl_exclude_cert",
    "collect_show_predefined_url_categories",
    "collect_show_predefined_url_lists",
    "PREDEFINED_GP_APP_CONFIG_SOURCE_TYPE",
    "PREDEFINED_SSL_EXCLUDE_CERT_SOURCE_TYPE",
    "SHOW_PREDEFINED_SSL_EXCLUDE_CERT_COMMAND",
    "collect_show_panorama_status",
    "collect_show_pushed_shared_policy",
    "collect_show_pushed_shared_policy_vsys",
    "set_target_vsys",
]
