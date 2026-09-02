"""PAN-OS collector for predefined (vendor-shipped) address/URL list catalogs.

`show predefined` is appliance-wide, not vsys-scoped: predefined IP block lists and URL lists
(e.g. panw-known-ip-list, panw-highrisk-ip-list) are baked into the PAN-OS software/content
version, not user-configured, so there is exactly one catalog per appliance regardless of how
many vsys/enforcement points it hosts. This only returns the catalog of list names/descriptions
- not each list's actual member IPs/URLs, which PAN-OS does not expose the same way as
user-defined EDLs (see external_list.py).
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import (
    collect_config_response,
    collect_op_response,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSConfigRequest,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


SHOW_PREDEFINED_IP_BLOCK_LISTS_COMMAND = (
    "<show><predefined><xpath>/predefined/ip-block-list-v2</xpath></predefined></show>"
)
SHOW_PREDEFINED_URL_LISTS_COMMAND = (
    "<show><predefined><xpath>/predefined/url-predefined</xpath></predefined></show>"
)

#: NOT reachable by `show predefined`, despite the two lists above being. Measured 2026-09-02:
#: `show predefined` addresses the content/App-ID catalog - its children are application,
#: url-categories, service and so on - and asking it for /predefined/ssl-tls-service-profile
#: returns "No data found. Verify xpath and retry". The SSL/TLS profile lives in the config
#: tree's predefined branch, which is a different namespace with a similar name, and which
#: `show config merged` also omits. A direct config read is the only route.
PREDEFINED_SSL_TLS_SERVICE_PROFILE_XPATH = "/config/predefined/ssl-tls-service-profile"


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


def collect_predefined_ssl_tls_service_profiles(session: PANSession) -> PANOSCollectedResponse:
    """Collect the vendor-shipped SSL/TLS service profiles for one appliance.

    Needed because a predefined definition BEATS a same-named custom one - measured 2026-09-02
    by binding a custom `TLSv1.3_Default` with weaker settings and watching the device keep
    negotiating the predefined profile's TLS 1.3 and serve the predefined certificate. So a
    device bound to a predefined name cannot be assessed from the merged config at all, and
    `TLSv1.3_Default` is the shipped hardened profile an engineer is most likely to bind. The
    correctly configured device is precisely the one that would otherwise be unreadable.
    """
    request = PANOSConfigRequest(
        xpath=PREDEFINED_SSL_TLS_SERVICE_PROFILE_XPATH,
        target=session.target,
        metadata={"command_name": "config get predefined ssl-tls-service-profile"},
    )
    return collect_config_response(
        session,
        source_type="config_predefined_ssl_tls_service_profiles",
        request=request,
    )
