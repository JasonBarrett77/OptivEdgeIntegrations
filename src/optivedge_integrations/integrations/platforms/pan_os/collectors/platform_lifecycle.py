"""PAN-OS collector for the one platform-lifecycle read no existing read carries.

ONE READ NOW, AND IT WAS THREE. `show running resource-monitor` is an operational command and
nothing else answers what it answers. The other two were `type=config&action=show` of one xpath
each - the telemetry node and the log-database alarm node - and both are GONE, with
`_collect_committed_node` and its `No such node` handling, on 2026-10-30.

WHY, AND IT IS THE RULE AND NOT A TIDY-UP. Jason's ruling,
`OptivEdgeProbe/reference/standing-rulings.md` section 5: A CONTROL USES THE CONFIGURATION THAT
WAS COLLECTED. Which config files are collected was decided once; a control reads them and does
not re-open whether a value is enforced now or staged to be enforced. The reasoning those two
reads rested on was that the merged view follows the CANDIDATE, so a staged edit reads as
enforced - which is true, measured, and true of **every control in the assessment**, not of two
nodes. A per-node second read is one domain paying for a condition that belongs to the pipeline.

AND THE MEASUREMENT THAT RETIRED THEM, which is the part to reuse: a config-mode `show` that
SUCCEEDS is reading the running configuration, so whatever it returns is in the merged
configuration too. Read-only on 2026-10-30, both nodes were compared key by key between
`action=show` and `show config merged` on every appliance holding them - identical. **A successful
`action=show` can therefore never justify its own collection.** The only thing a dedicated read
establishes that the merged view cannot is the candidate-versus-running difference, and section 5
is the ruling that closes that question.

ONE OF THOSE TWO JUSTIFICATIONS WAS ALSO STALE, and that is recorded rather than buried: the
alarm read existed because the merged view's carriage of its node was untestable - the node was
absent on all four lab appliances when that was written. Fixtures were built afterwards and
nothing re-read it. `reference/field-notes.md` carries it under the heading about a justification
that said "could not be tested on this estate".

WHAT IS NOT HERE, and each omission is a measurement rather than an oversight:

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
    collect_op_response,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import (
    PANSession,
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



# THE TWO DEDICATED CONFIG-MODE READS LIVED HERE AND WERE REMOVED ON 2026-10-30, with
# `_collect_committed_node` and its `No such node` handling, by Jason's ruling
# `OptivEdgeProbe/reference/standing-rulings.md` section 5 - A CONTROL USES THE CONFIGURATION THAT
# WAS COLLECTED.
#
# `collect_device_telemetry` and `collect_log_alarm_settings` each issued `type=config&action=show`
# at one xpath, so a control could read the RUNNING view of that node rather than the merged
# configuration the pass already collects. The rule that retired them: a config-mode `show` which
# SUCCEEDS is reading the running configuration, so whatever it returns is in the merged
# configuration too - measured on both nodes, read-only, on 2026-10-30. A successful `action=show`
# can therefore never justify its own collection. Both normalizers read the merged configuration.
#
# WHAT THEY WERE FOR, SO NOBODY REBUILDS THEM FOR THE SAME REASON: the only thing a dedicated read
# establishes that the merged view cannot is the candidate-versus-running difference, and section 5
# is the ruling that closes that question for controls. If you want one for something that is not
# a control, that is outside the ruling and outside this module's history.


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
