"""PAN-OS collectors for device-identification state that no configuration read exposes.

Three op commands, all per appliance, all read-only, none of them narrowable:

`request license info` is the only statement of what an appliance is entitled to, and the
entitlement is granted off-box so no xpath carries it. It was sent with an argument on a
lab firewall and refused with code=17 ("request -> license -> info unexpected here"), so a
consumer cannot ask about one feature and has to read the whole table.

`show system info` carries the installed device-dictionary content version and release
date. ITS COMMAND STRING ALREADY EXISTED and was issued by nothing -
`merged_config.SHOW_SYSTEM_INFO_COMMAND`, defined beside the merged-config command and
referenced nowhere - so it is imported here rather than written again. Leaving the literal
where it is, in a module about `show config merged`, is a defect this module records rather
than fixes: moving it changes another module's surface.

`show iot icd version` answers a THREE-LINE FREE-TEXT BLOB rather than XML, on all four lab
appliances including the two holding no licence of any kind. Its numbering does not map
onto the content version and its TimeBuilt date ranks the estate the opposite way, so it is
collected to be SHOWN beside a staleness finding and never graded on.

The edge-service node, `deviceconfig/setting/iot/edge`, needs nothing here: it is in the
merged configuration a collector already issues.
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import collect_op_response
from optivedge_integrations.integrations.platforms.pan_os.collectors.merged_config import (
    SHOW_SYSTEM_INFO_COMMAND,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


REQUEST_LICENSE_INFO_COMMAND = "<request><license><info/></license></request>"
SHOW_IOT_ICD_VERSION_COMMAND = "<show><iot><icd><version/></icd></iot></show>"


def collect_request_license_info(session: PANSession) -> PANOSCollectedResponse:
    """One appliance's licence table.

    The reply has THREE shapes and two of them look like the third. Measured on all four lab
    appliances, 2026-10-29: a list of ten entries, a list of three, and `{'licenses': None}`.
    That last one is truthy at the outer dict and falsy one level in, and
    `result['licenses']['entry']` raises `TypeError` on it - and it means "this appliance
    holds nothing", which is NOT distinguishable from "this read never happened". The
    normalizer carries a companion flag for exactly that, because nothing in the payload can
    separate them.

    `request license info` REPORTS and installs nothing; `request license fetch` and
    `request license install` mutate and are not this module's business.
    """
    request = PANOSOperationRequest(
        command_xml=REQUEST_LICENSE_INFO_COMMAND,
        target=session.target,
        metadata={"command_name": "request license info"},
    )
    return collect_op_response(
        session,
        source_type="request_license_info",
        request=request,
    )


def collect_show_system_info(session: PANSession) -> PANOSCollectedResponse:
    """One appliance's system info - here for the installed content dictionary.

    Two keys matter to this domain and only one of them is always present. Measured
    2026-10-29: `device-dictionary-version` answers on all four lab appliances, while
    `device-dictionary-release-date` is ABSENT FROM THE REPLY ENTIRELY on both PA-5220s -
    the key is missing rather than empty, and the three sibling release-date keys vanish
    from the same two appliances.

    THE REPLY ALSO CARRIES `time`, the appliance's own clock, in the SAME LOCAL FRAME as the
    release date. That is what makes the content's age computable without parsing a timezone
    ABBREVIATION: both PA-VMs report the same content instant under different abbreviations
    (GMT and PDT) and subtracting one naive timestamp from the other gives the same five days
    on both. Nothing else in the estate supplies a comparable clock.
    """
    request = PANOSOperationRequest(
        command_xml=SHOW_SYSTEM_INFO_COMMAND,
        target=session.target,
        metadata={"command_name": "show system info"},
    )
    return collect_op_response(
        session,
        source_type="show_system_info",
        request=request,
    )


def collect_show_iot_icd_version(session: PANSession) -> PANOSCollectedResponse:
    """The IoT classification-data build, as free text.

    `result` is a plain string of three labelled lines and not a dict:

        Version: 13.pan_h1_r3
        TimeBuilt: 2026-02-06T13:34:53PST
        GitTag: 10c7d140

    So the parse belongs to the normalizer and a `.get()` on the result raises. Collected
    because it is the one instrument that DISAGREES with the graded one, and a reader of a
    staleness finding should be able to see that.
    """
    request = PANOSOperationRequest(
        command_xml=SHOW_IOT_ICD_VERSION_COMMAND,
        target=session.target,
        metadata={"command_name": "show iot icd version"},
    )
    return collect_op_response(
        session,
        source_type="show_iot_icd_version",
        request=request,
    )
