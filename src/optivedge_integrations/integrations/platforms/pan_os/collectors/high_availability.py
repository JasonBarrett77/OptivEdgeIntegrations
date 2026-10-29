"""PAN-OS collector for the RUNTIME half of an HA relationship - `show high-availability all`.

NO CONFIGURATION READ CAN ANSWER WHAT THIS DOES. `deviceconfig/high-availability` says what the
appliance is configured for; whether a peer is actually answering, whether configuration and
session state are really being exchanged, and whether the HA1 control link is encrypted are
runtime facts with no key behind them. This estate measures the gap directly: both PA-5220s hold
`enabled: yes` and `configuration-synchronization/enabled: yes` while the same read answers
`state-sync: User-disabled`, so stored configuration and the formed relationship disagree on a
pair that looks healthy in any configuration review.

`ha1-encrypt-imported` HAS NO CONFIGURATION NODE ANYWHERE and is the reason this is `<all/>`
rather than `<state/>`: stage 4 measured the two commands as answering identically except that
`<all/>` additionally carries that leaf. Without it, PAN-HAP-002 rests on a switch that cannot
take effect - `validate full` refuses an HA1 encryption commit with "requires an import of the
high-availability-key" - and a firewall with the switch on and no key reads as protected.

An OPERATIONAL read, so it reports RUNNING and cannot carry an uncommitted edit. One op call per
appliance. ON AN APPLIANCE WITH NO HA NODE IT STILL ANSWERS: `{'enabled': 'no', 'group':
{'local-info': {'ha1-encrypt-imported': 'no'}}}`, measured on both PA-VMs 2026-10-29 - which is
the only instrument in this estate that can tell "HA is off" apart from "nobody collected it",
because `type=config&action=get` at the absent node returns None and `action=show` raises.
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


SHOW_HIGH_AVAILABILITY_ALL_COMMAND = "<show><high-availability><all/></high-availability></show>"

#: The snapshot source_type this collector writes. Named beside the command it comes from, the
#: way `device_groups.py` does, so normalization cannot drift from the collector.
HIGH_AVAILABILITY_SOURCE_TYPE = "show_high_availability_all"


def collect_show_high_availability_all(session: PANSession) -> PANOSCollectedResponse:
    """One appliance's HA runtime state.

    Unlike `show dg-hierarchy` this needs no station-type guard: the command exists on a
    firewall, which is the only thing it is ever asked of here, and an appliance with HA off
    answers a short reply rather than refusing.
    """
    request = PANOSOperationRequest(
        command_xml=SHOW_HIGH_AVAILABILITY_ALL_COMMAND,
        target=session.target,
        metadata={"command_name": "show high-availability all"},
    )
    return collect_op_response(
        session,
        source_type=HIGH_AVAILABILITY_SOURCE_TYPE,
        request=request,
    )
