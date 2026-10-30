"""PAN-OS collectors for the device-services runtime state no configuration read carries.

THREE OP READS, AND EACH IS THE ONLY INSTRUMENT FOR A COLUMN A CONTROL IS GRADED ON. Stage 5
printed eight reads under `READ(S) NO COLLECTOR ISSUES TODAY`; five of them are not here and
every omission is a measurement rather than an oversight:

`show system info` ALREADY EXISTS, in `collectors/device_identification.py`, added for another
domain - so `SystemIdentity.hostname_in_force` and its companion need no new call at all.

`show system services` IS NOT HERE. It is the only oracle for whether a management service is
LISTENING, and stage 5 records that issuing it would turn five of the nine unmeasured
`disable-*` implicits into readings. But no column of THIS domain reads it: `ManagementService`
is `existing_unchanged` and `SnmpSettings.is_exposed` is already derived over the rows
`normalize_appliance_management_interfaces` writes. A collector whose output nothing normalises
is a snapshot nobody reads, so the read is named and declined. Measured 2026-10-29 for the
readback anyway, through Panorama: `[https, icmp, ssh]` on three appliances and
`[https, icmp, ssh, http]` on 6A9C0A9904E7D6E, whose template stack sets `disable-http: no` -
and `snmp` is absent from ALL FOUR, including 013201001475, which holds a complete SNMPv3 agent.

`show clock` IS NOT HERE and buys LESS than it looks: the abbreviation and the IANA key are
different vocabularies so the two cannot be compared, and stage 4 measured the command's answer
to be the DAEMON'S INERTIA rather than the device's assumption - the zone key was deleted and
committed and `show clock` still answered the old zone. Named so nobody commissions it expecting
the zone in force.

`show device-telemetry details` IS NOT HERE. It buys the DESTINATION rather than the decision,
and the only column that could use it - `telemetry_delivery_state` - is filled from the
`status` member of the settings read below, in the same call.
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import (
    collect_op_response,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import (
    PANSession,
    PANSessionAPIError,
)


#: BALANCED, NOT SELF-CLOSED-AND-UNCLOSED. `collectors/merged_config.py` carries the measured
#: note that `<show><system><info></info></show>` - missing `</system>` - answers HTTP 400
#: "Request is not a valid XML" on all four lab appliances, so a collector that had never once
#: succeeded looked exactly like a device with nothing to report. All three commands below were
#: issued against all four appliances on 2026-10-29 and all three answered.
SHOW_NTP_COMMAND = "<show><ntp></ntp></show>"
SHOW_DEVICE_TELEMETRY_SETTINGS_COMMAND = (
    "<show><device-telemetry><settings></settings></device-telemetry></show>")
SHOW_DHCP_CLIENT_MGMT_INTERFACE_STATE_COMMAND = (
    "<show><dhcp><client><mgmt-interface-state></mgmt-interface-state></client></dhcp></show>")

#: THE REFUSAL THAT IS AN ANSWER. `show dhcp client mgmt-interface-state` does not return an
#: empty lease on a statically addressed appliance - it RAISES, with a message naming the
#: effective addressing mode. Measured 2026-10-29 through Panorama's proxy: both PA-5220s answer
#: `Firewall management interface is not set to DHCP` and both PA-VMs return a lease.
#:
#: So this refusal is a second, independent oracle for `SystemIdentity.addressing_mode` - it is
#: the one that made the absent-`type`-means-static implicit a natural experiment rather than a
#: write - and recording it as a FAILED READ would turn "this appliance is statically addressed"
#: into "nobody asked", which is the distinction `DnsSettings.management_resolver_posture`
#: grades on. Matched on the MESSAGE and not on a code, the same way
#: `platform_lifecycle.py::_NO_SUCH_NODE` is, so that a code reused for something else is not
#: read as this.
_NOT_SET_TO_DHCP = "management interface is not set to dhcp"


def _is_not_set_to_dhcp(error: PANSessionAPIError) -> bool:
    """Is this refusal the one that reports a STATIC management interface, not a failure?"""
    return _NOT_SET_TO_DHCP in str(error).lower()


def collect_show_ntp(session: PANSession) -> PANOSCollectedResponse:
    """One appliance's time-service runtime state. PAN-SVC-001's second half.

    Carries a `<synched>` member naming the source actually keeping the clock - or the literal
    `LOCAL` - plus per-slot `name`, `reachable` and `status`. It is the ONLY instrument that
    answers whether anything is serving the clock, and the reply shape is three states:

        both slots configured   ntp-server-1 and ntp-server-2, plus synched
        one slot configured     ntp-server-1 only, plus synched
        no slot configured      synched ALONE - measured on 6A9C0A9904E7D6E, `{"synched": "LOCAL"}`

    ITS `authentication-type` MEMBER MUST NOT BE USED TO NAME THE MECHANISM, which is why no
    column reads it. Measured 2026-10-29: 013201001475 stores the config token `symmetric-key`
    and this command answers `symmetric key`, with a space; 691665AC334B458 stores `autokey` and
    answers `autokey`. Stage 4 recorded the same member reading `autokey` on 11.2.5 for a stored
    SYMMETRIC KEY. So it can discriminate authenticated from unauthenticated and nothing finer,
    and the mechanism is named from the configuration's own branch.
    """
    request = PANOSOperationRequest(
        command_xml=SHOW_NTP_COMMAND,
        target=session.target,
        metadata={"command_name": "show ntp"},
    )
    return collect_op_response(session, source_type="show_ntp", request=request)


def collect_show_device_telemetry_settings(session: PANSession) -> PANOSCollectedResponse:
    """One appliance's EFFECTIVE telemetry switches and its delivery status. PAN-SVC-008.

    The reply nests two levels - `deviceTelemetry/settings` - with the three category switches,
    `region`, and a `status` member that is not configuration at all.

    THIS READS RUNNING AND REPORTS THE IMPLICIT VALUES, which is what makes it the oracle behind
    the three materialised `yes` defaults: the configuration read returns only what somebody
    wrote.

    AND ITS `region` ANSWER DIFFERS FROM STAGE 4's FOR THE SAME ABSENCE. Stage 4 deleted the
    `region` KEY, committed, and this command answered `Americas`. Measured 2026-10-29 on
    691665AC334B458, whose WHOLE `device-telemetry` node is absent, it answers `region: null`
    while still answering `yes` for all three switches. So the materialisation covers the
    switches and not the region, and which of the two absences a reader is looking at decides
    what this member means. The normalizer stores stage 5's declared `americas` either way,
    because that is stage 5's decision and not this module's.
    """
    request = PANOSOperationRequest(
        command_xml=SHOW_DEVICE_TELEMETRY_SETTINGS_COMMAND,
        target=session.target,
        metadata={"command_name": "show device-telemetry settings"},
    )
    return collect_op_response(
        session, source_type="show_device_telemetry_settings", request=request)


def collect_show_dhcp_client_mgmt_interface_state(
    session: PANSession,
) -> PANOSCollectedResponse:
    """The management interface's DHCP lease, where there is one. PAN-SVC-003's own source.

    THE SINGLE MOST LOAD-BEARING UNISSUED READ IN THIS DOMAIN, in stage 5's words. Without it a
    collector reports "no resolver configured" for an appliance that is resolving through an
    address nobody chose - which is PAN-SVC-003's exact subject and the state TWO OF FOUR lab
    appliances are in: 6A9C0A9904E7D6E and 691665AC334B458 hold no `dns-setting` node at all and
    both leases carry `dns-server: 168.63.129.16`, from the same DHCP server.

    A STATIC APPLIANCE'S REFUSAL IS RECORDED AS AN ANSWER - an empty result, the same shape a
    config read gives for an xpath that matches nothing - because "this interface is not a DHCP
    client" is a reading and not a failed read. See `_NOT_SET_TO_DHCP`. Anything else propagates
    and no snapshot is written at all, which is how "the interface is static" stays
    distinguishable from "nobody asked".

    IT MIXES LEASE FACTS WITH EFFECTIVE DEVICE FACTS and a reader must not take its `hostname`
    or `ntp1` members for lease-supplied values. Stage 4 measured `hostname` moving with the
    CONFIGURATION key, and `ntp1` is present only on the appliance with a CONFIGURED time server
    - re-measured 2026-10-29, where 691665AC334B458 shows `ntp1: us.pool.ntp.org` (which it has
    configured) and 6A9C0A9904E7D6E shows no `ntp1` at all, from the same DHCP server. So NO
    instrument on this estate attributes a time server to a lease, and nothing here builds a
    column that claims one. `dns-server` is the member this domain reads.
    """
    request = PANOSOperationRequest(
        command_xml=SHOW_DHCP_CLIENT_MGMT_INTERFACE_STATE_COMMAND,
        target=session.target,
        metadata={"command_name": "show dhcp client mgmt-interface-state"},
    )
    try:
        return collect_op_response(
            session,
            source_type="show_dhcp_client_mgmt_interface_state",
            request=request,
        )
    except PANSessionAPIError as error:
        if not _is_not_set_to_dhcp(error):
            raise
        return PANOSCollectedResponse(
            source_type="show_dhcp_client_mgmt_interface_state",
            request=request,
            response={"response": {"@status": "success", "result": {}}},
        )
