"""PAN-OS collector for predefined (vendor-shipped) address/URL list catalogs.

`show predefined` is appliance-wide, not vsys-scoped: predefined IP block lists and URL lists
(e.g. panw-known-ip-list, panw-highrisk-ip-list) are baked into the PAN-OS software/content
version, not user-configured, so there is exactly one catalog per appliance regardless of how
many vsys/enforcement points it hosts. This only returns the catalog of list names/descriptions
- not each list's actual member IPs/URLs, which PAN-OS does not expose the same way as
user-defined EDLs (see external_list.py).
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import collect_op_response
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


SHOW_PREDEFINED_IP_BLOCK_LISTS_COMMAND = (
    "<show><predefined><xpath>/predefined/ip-block-list-v2</xpath></predefined></show>"
)
SHOW_PREDEFINED_URL_LISTS_COMMAND = (
    "<show><predefined><xpath>/predefined/url-predefined</xpath></predefined></show>"
)


def collect_show_predefined_ip_block_lists(session: PANSession) -> PANOSCollectedResponse:
    request = PANOSOperationRequest(
        command_xml=SHOW_PREDEFINED_IP_BLOCK_LISTS_COMMAND,
        target=session.target,
        metadata={"command_name": "show predefined ip-block-list-v2"},
    )
    return collect_op_response(
        session,
        source_type="show_predefined_ip_block_lists",
        request=request,
    )


def collect_show_predefined_url_lists(session: PANSession) -> PANOSCollectedResponse:
    request = PANOSOperationRequest(
        command_xml=SHOW_PREDEFINED_URL_LISTS_COMMAND,
        target=session.target,
        metadata={"command_name": "show predefined url-predefined"},
    )
    return collect_op_response(
        session,
        source_type="show_predefined_url_lists",
        request=request,
    )
