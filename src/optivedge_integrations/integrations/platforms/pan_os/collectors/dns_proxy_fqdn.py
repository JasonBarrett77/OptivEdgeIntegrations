"""PAN-OS collector for the DNS proxy FQDN resolution cache.

This module stays PAN-OS-specific and should only own command definitions and collection
behavior for the dns-proxy fqdn endpoint.

`show dns-proxy fqdn all` showed no vsys-scoping requirement during CLI exploration of a real
device (unlike EDL - see external_list.py's target-vsys handling), so this is treated as one
bulk, appliance-wide call. That's corroborating evidence, not certainty - if per-vsys DNS proxy
objects turn out to produce genuinely different results, the normalization step consuming this
snapshot should key off whatever per-entry tag the real response payload carries.
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import collect_op_response
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


SHOW_DNS_PROXY_FQDN_ALL_COMMAND = "<show><dns-proxy><fqdn><all/></fqdn></dns-proxy></show>"


def collect_show_dns_proxy_fqdn_all(session: PANSession) -> PANOSCollectedResponse:
    request = PANOSOperationRequest(
        command_xml=SHOW_DNS_PROXY_FQDN_ALL_COMMAND,
        target=session.target,
        metadata={"command_name": "show dns-proxy fqdn all"},
    )
    return collect_op_response(
        session,
        source_type="show_dns_proxy_fqdn_all",
        request=request,
    )
