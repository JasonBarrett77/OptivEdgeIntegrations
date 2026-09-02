"""PAN-OS collection primitives and vendor-specific endpoint collectors."""

from optivedge_integrations.integrations.platforms.pan_os.collectors.merged_config import (
    SHOW_MERGED_CONFIG_COMMAND,
    collect_show_merged_config,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.managed_devices import (
    SHOW_MANAGED_DEVICES_COMMAND,
    collect_show_managed_devices,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.pushed_shared_policy import (
    SHOW_PUSHED_SHARED_POLICY_COMMAND,
    build_show_pushed_shared_policy_vsys_command,
    collect_show_pushed_shared_policy,
    collect_show_pushed_shared_policy_vsys,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.dns_proxy_fqdn import (
    SHOW_DNS_PROXY_FQDN_ALL_COMMAND,
    collect_show_dns_proxy_fqdn_all,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.external_list import (
    NUM_RECORDS_PER_PAGE,
    build_clear_target_vsys_command,
    build_set_target_vsys_command,
    build_show_external_list_command,
    clear_target_vsys,
    collect_show_external_list,
    set_target_vsys,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.predefined import (
    SHOW_PREDEFINED_IP_BLOCK_LISTS_COMMAND,
    SHOW_PREDEFINED_URL_LISTS_COMMAND,
    collect_predefined_ssl_tls_service_profiles,
    collect_show_predefined_ip_block_lists,
    collect_show_predefined_url_lists,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)

__all__ = [
    "NUM_RECORDS_PER_PAGE",
    "PANOSCollectedResponse",
    "PANOSOperationRequest",
    "SHOW_DNS_PROXY_FQDN_ALL_COMMAND",
    "SHOW_MERGED_CONFIG_COMMAND",
    "SHOW_MANAGED_DEVICES_COMMAND",
    "SHOW_PREDEFINED_IP_BLOCK_LISTS_COMMAND",
    "SHOW_PREDEFINED_URL_LISTS_COMMAND",
    "SHOW_PUSHED_SHARED_POLICY_COMMAND",
    "build_clear_target_vsys_command",
    "build_set_target_vsys_command",
    "build_show_external_list_command",
    "build_show_pushed_shared_policy_vsys_command",
    "clear_target_vsys",
    "collect_show_dns_proxy_fqdn_all",
    "collect_show_external_list",
    "collect_show_merged_config",
    "collect_show_managed_devices",
    "collect_predefined_ssl_tls_service_profiles",
    "collect_show_predefined_ip_block_lists",
    "collect_show_predefined_url_lists",
    "collect_show_pushed_shared_policy",
    "collect_show_pushed_shared_policy_vsys",
    "set_target_vsys",
]
