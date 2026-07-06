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
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)

__all__ = [
    "PANOSCollectedResponse",
    "PANOSOperationRequest",
    "SHOW_MERGED_CONFIG_COMMAND",
    "SHOW_MANAGED_DEVICES_COMMAND",
    "SHOW_PUSHED_SHARED_POLICY_COMMAND",
    "build_show_pushed_shared_policy_vsys_command",
    "collect_show_merged_config",
    "collect_show_managed_devices",
    "collect_show_pushed_shared_policy",
    "collect_show_pushed_shared_policy_vsys",
]
