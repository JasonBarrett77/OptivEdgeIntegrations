"""PAN-OS collectors for platform-lifecycle state no existing read carries.

THREE NEW READS, AND TWO OF THEM ARE THE FIRST COMMITTED-LOCAL READS IN THIS PACKAGE. Every
other configuration collector asks for the merged view or a pushed limb, both of which follow
the CANDIDATE - so they report what an administrator typed. Two of this domain's subjects rest
on what the firewall is ENFORCING, and for an absence the difference is the whole reading:

    action=get   absent node -> a bare `null`, and a staged edit looks identical to a committed one
    action=show  absent node -> status=error, "No such node", about the COMMITTED configuration

So `_collect_committed_node` catches exactly that refusal and records it as an ANSWER - an
empty result - because the absence is what the column stores. Anything else propagates and no
snapshot is written at all, which is how "the node is absent" stays distinguishable from "the
read never happened". Those two are different columns downstream and conflating them would make
an unreachable appliance read as a configured-nothing one.

WHAT IS NOT HERE, and each omission is a measurement rather than an oversight:

`show system info` and `request license info` ALREADY EXIST, in `collectors/device_identification.py`,
added for another domain. Four of this domain's nine subjects are filled from those two reads and
not one of them needed a new collector - the stage 5 artifact was written on 2026-10-27 and
measured them absent, which was true then and is not now.

`show config saved` IS NOT COLLECTED AND CANNOT BE. Its argument is MANDATORY - the bare form
answers code=17 on all four lab appliances - and nothing in the 70,462-command CLI index lists
the snapshot names, so a collector holding this command has no way to find an argument to pass
it. Missing and malformed are also ONE message, so even with a name it could not tell a snapshot
that was never taken from a corrupt one. The work owed is an ENUMERATION INSTRUMENT, and until
one exists `ConfigurationBackupEvidence.on_box_snapshot_list_collected` is false everywhere,
which is both its until-renormalized value and its true one.

THE GLOBALPROTECT PORTAL SWEEP IS NOT HERE EITHER, and that is a deliberate substitution. Stage
5 declared a per-vsys `action=get` at each vsys's `global-protect/global-protect-portal`,
naming the enumeration as the work owed - because a vsys1-only read answers "not a portal" on
an appliance that IS one. The merged configuration a collector already issues on every appliance
carries EVERY vsys entry with its own `global-protect` subtree, measured on all four lab
appliances, so it has the property the declared read lacks and costs no extra call. The
normalizer reads it from there and reports how many vsys it saw.
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
from optivedge_integrations.integrations.platforms.pan_os.session import (
    PANSession,
    PANSessionAPIError,
)


DEVICE_TELEMETRY_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/device-telemetry"
)
LOG_ALARM_SETTINGS_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/management"
    "/common-criteria-alarm-generation"
)

#: THE WINDOW IS PART OF THE COMMAND AND THE BARE FORM MUST NOT BE USED. `show running
#: resource-monitor` with no window returns all five at once - 43,184 bytes on a PA-5220
#: against 13,587 for its largest single window - and a column derived from "every window" has
#: no defined meaning. Stage 3 records that WHICH window is chosen decides whether the word
#: `sustained` can be expressed at all: a one-second window cannot express it and a
#: thirteen-week one cannot resolve a monthly review.
#:
#: THE MINUTE WINDOW, 60 SAMPLES, IS THIS MODULE'S CHOICE and nothing upstream made it. It is
#: the shortest window that averages over more than one instant, so "sustained" means something,
#: and it is the one whose `task` node is null on every appliance - only the `second` window
#: carries that, which is why nothing here reads it. Changing the window changes what the
#: maximum means, so the window is STORED on the row beside the number.
RESOURCE_MONITOR_WINDOW = "minute"
RESOURCE_MONITOR_WINDOW_SAMPLES = 60
SHOW_RESOURCE_MONITOR_COMMAND = (
    "<show><running><resource-monitor><minute><last>"
    f"{RESOURCE_MONITOR_WINDOW_SAMPLES}"
    "</last></minute></resource-monitor></running></show>"
)

#: The refusal that means "this node is not in the committed configuration". Matched on the
#: MESSAGE and not on a code: the reply carries `@code` 7 for this shape, and matching the text
#: is what keeps a code reused for something else from being read as an absence. Measured on all
#: four lab appliances at both xpaths above.
_NO_SUCH_NODE = "no such node"


def _is_no_such_node(error: PANSessionAPIError) -> bool:
    """Is this refusal the one that reports an absence rather than a failure?"""
    return _NO_SUCH_NODE in str(error).lower()


def _collect_committed_node(
    session: PANSession,
    *,
    source_type: str,
    xpath: str,
    command_name: str,
) -> PANOSCollectedResponse:
    """One committed-local node, where ABSENCE IS THE ANSWER AND NOT A FAILED READ.

    The empty result this returns for a `No such node` refusal is the same shape
    `collect_config_response` already produces for an xpath that matches nothing, so the
    normalizer has one thing to read: the node's own key is in the payload or it is not. A
    snapshot that does not exist at all is the third state and means nobody asked.
    """
    request = PANOSConfigRequest(
        xpath=xpath,
        action="show",
        target=session.target,
        metadata={"command_name": command_name},
    )
    try:
        return collect_config_response(session, source_type=source_type, request=request)
    except PANSessionAPIError as error:
        if not _is_no_such_node(error):
            raise
        return PANOSCollectedResponse(
            source_type=source_type,
            request=request,
            response={"response": {"@status": "success", "result": {}}},
        )


def collect_device_telemetry(session: PANSession) -> PANOSCollectedResponse:
    """One appliance's device-telemetry sharing switches, as COMMITTED.

    Four keys when the node is there - `device-health-performance`, `product-usage`,
    `threat-prevention` and `region` - and nothing when it is not. Both states are in this lab:
    the node is absent on 691665AC334B458, present with all three switches `yes` on
    6A9C0A9904E7D6E, and present with all three `no` on both PA-5220s.

    AN ABSENT KEY HERE IS NOT `no`. Nothing on the device says what it does with the node
    missing, so the normalizer stores NULL for a switch it did not read and the companion
    column carries the uncertainty. KEY ORDER DIFFERS BETWEEN APPLIANCES - one returns `region`
    first where the others return it last - so every reader must key on names.

    The committed view is chosen over the merged one deliberately: merged follows the candidate,
    so a staged opt-in would read as enforced.
    """
    return _collect_committed_node(
        session,
        source_type="config_device_telemetry",
        xpath=DEVICE_TELEMETRY_XPATH,
        command_name="show config at deviceconfig/system/device-telemetry",
    )


def collect_log_alarm_settings(session: PANSession) -> PANOSCollectedResponse:
    """One appliance's log-database alarm node, as COMMITTED.

    THIS IS THE ONLY READ IN THIS DOMAIN THAT SAYS ABSENT OUT LOUD, and the absence is the
    reading: the node was absent on all four lab appliances before any fixture was built, at the
    container and at all twenty-one leaves, and the 1.2 MB merged body contains no
    `common-criteria-alarm-generation` string at all - so the claim that the merged view carries
    this node is UNTESTED and could not be tested on this estate.

    THE PARENT IS SHARED FURNITURE. `deviceconfig/setting/management` carries
    `hostname-type-in-syslog`, `quota-settings`, `rule-require-audit-comment` and another
    domain's `enable-certificate-expiration-check`, so this read is addressed at the alarm
    container and never at its parent.

    THE CONTAINER FORM IS TRUSTED rather than read leaf by leaf. One get against twenty-one is
    the whole difference in per-appliance cost, and the container carries every child that is
    set - verified against a built fixture on two appliances, where six written leaves came back
    from one read.
    """
    return _collect_committed_node(
        session,
        source_type="config_log_alarm_settings",
        xpath=LOG_ALARM_SETTINGS_XPATH,
        command_name="show config at common-criteria-alarm-generation",
    )


def collect_show_running_resource_monitor(session: PANSession) -> PANOSCollectedResponse:
    """One appliance's dataplane load for ONE named window.

    The reply is data-processors keyed by name, each carrying `cpu-load-average` entries keyed by
    `coreid` whose `value` is a COMMA-SEPARATED STRING of samples - one per window unit, 60 for
    the minute window - which must be split and never parsed as a number.

    THE PROCESSOR KEY IS PLATFORM-SHAPED: `dp0` on a PA-VM, `s1dp0` on a PA-5220. A reader
    hard-coding either returns nothing on half the estate.

    AND THE SAMPLES COME BACK `0,0,0,...` ON ALL FOUR LAB APPLIANCES - populated, truthy and all
    zero - so this read cannot by itself tell an idle appliance from one whose counters never
    populated. The normalizer records that the read answered, which is the only thing that can.
    """
    request = PANOSOperationRequest(
        command_xml=SHOW_RESOURCE_MONITOR_COMMAND,
        target=session.target,
        metadata={
            "command_name": "show running resource-monitor minute last 60",
            "window": RESOURCE_MONITOR_WINDOW,
        },
    )
    return collect_op_response(
        session,
        source_type="show_running_resource_monitor",
        request=request,
    )
