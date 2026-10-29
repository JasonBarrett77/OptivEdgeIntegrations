"""PAN-OS collector for the App-ID Cloud Engine's own account of itself.

`show cloud-appid connection-to-cloud` is THE ONLY FIREWALL-SIDE INSTRUMENT for whether the engine
is actually running, and PAN-SAS-005's whole second half rests on it. No configuration read can
answer it: `deviceconfig/setting/cloudapp` says only whether somebody switched the engine off on
purpose, and on every appliance in this lab that key reads reassuringly while the engine reports
its licence check failing.

WHY NOT `request license info`, which is already collected. Measured 2026-10-29: it lists ten
features on a lab PA-VM and none of them is a SaaS or AI Access feature, so it can only answer by
what is ABSENT from its list - and it says nothing at all about the DEVICE CERTIFICATE, which this
reply reports as a second, independent precondition. A remediation reading only the licence would
buy a subscription and still have no engine.

AN OPERATIONAL read, so it reads RUNNING and cannot report an uncommitted edit - the opposite of
the merged config the configured half of this control comes from.

THE REPLY IS FREE TEXT AND ITS WORDING MOVES WITH THE BUILD. Measured the same day on two
appliances: 11.2.5 answers "Check if SaaS license or Ai Access license is installed and active"
where 11.1.13-h3 answers "Check if SaaS license is installed and active". So the normalizer matches
on the stable fragments ("License check failed", "Cloud connection:", "Device cert status:") and
classifies into the pipeline's own vocabulary rather than storing the vendor's sentence.

AND `Snapshot.payload` HOLDS A BARE STRING FOR THIS READ. `persistence/common.py::extract_result_payload`
returns `response.result` whatever its type, and this command's result is one multi-line string, so
a normalizer doing `payload.get(...)` raises rather than returning nothing - and `payload or {}`
does not save it, because a non-empty string is truthy. `normalization/saas_security.py` guards with
`isinstance(payload, str)` at the reading site.

Measured read-only against both PA-VMs and one PA-5220 on 2026-10-29 with NO device lease and no
write of any kind; the project's own `op_read_only` guard permits it unchanged, because it is a
`<show>`.
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import (
    collect_op_response,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


#: The command. There is no verbose form and no structured form: the reply is pre-formatted text
#: inside one XML element, which is the device's shape and not a choice.
SHOW_CLOUD_APPID_CONNECTION_COMMAND = (
    "<show><cloud-appid><connection-to-cloud/></cloud-appid></show>"
)

#: The snapshot source type the normalizer filters on. A constant beside the command because
#: nothing maps a source type to a reader - the normalizer that wants it writes its own
#: `latest_*_snapshot` helper and imports this.
CLOUD_APPID_CONNECTION_SOURCE_TYPE = "show_cloud_appid_connection"


def collect_show_cloud_appid_connection(session: PANSession) -> PANOSCollectedResponse:
    """Collect one appliance's App-ID Cloud Engine condition. PAN-SAS-005.

    One op call per appliance; the engine is device-wide and has no vsys, so a per-point call
    would be N requests for the same bytes. The reply is about 900 bytes on both lab platforms.
    """
    request = PANOSOperationRequest(
        command_xml=SHOW_CLOUD_APPID_CONNECTION_COMMAND,
        target=session.target,
        metadata={"command_name": "show cloud-appid connection-to-cloud"},
    )
    return collect_op_response(
        session,
        source_type=CLOUD_APPID_CONNECTION_SOURCE_TYPE,
        request=request,
    )
