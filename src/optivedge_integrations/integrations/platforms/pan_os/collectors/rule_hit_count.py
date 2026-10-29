"""PAN-OS collector for per-rule usage telemetry - `show rule-hit-count`.

THE ONLY READ THAT SAYS WHETHER A RULE IS USED. No configuration view carries it: a rule that
has never matched a packet is byte-identical in `show config merged` to the rule beside it that
carries every session on the device, so PAN-POL-013 and PAN-POL-015 have no configuration answer
at all. It is the third read of this domain and the only operational one.

ONE OP CALL PER VSYS PER APPLIANCE, which is why it is per enforcement point rather than per
appliance: the command names the vsys inside the command body rather than taking a target
parameter, and there is no device-wide form of it.

WHAT IT REPORTS WHEN NOTHING IS COUNTING IS THE TRAP, and it is measured rather than inferred.
On 691665AC334B458, whose `deviceconfig/setting/management/rule-hit-count` reads `no`, this
command SUCCEEDS and answers, for every rule:

    hit-count 0 · last-hit-timestamp 0 · last-reset-timestamp 0 · latest yes

which is byte-identical to what 013201001475 answers for a rule that is being counted and has
never matched. So the reply cannot distinguish "no traffic has matched this rule" from "this
appliance is not counting", and a threshold over the age alone would report every rule on a
non-counting appliance as idle. `PolicyRuleSettings.rule_hit_count_enabled` is the other half of
the reading and `SecurityRule.hit_count_reading_known` is where the two are combined.
(Measured 2026-10-29 on both serials, read-only, through Panorama with `target=`.)

TWO MORE THINGS THE REPLY CARRIES THAT THE CONFIGURATION DOES NOT:

- `last-reset-timestamp`, which is the vendor acknowledging that the counter resets on a reboot
  or a dataplane restart. A rule whose counter was reset inside the window being judged has no
  usable age, which is a STATE of the reading and not a small number.
- the two rules PAN-OS ships. Measured on 013201001475 vsys10, a vsys with no
  `rulebase/security/rules` node at all: the reply still lists `intrazone-default` and
  `interzone-default`. They are the entire enforced policy of such a vsys and no config read
  returns them, so this is the one read that sees them.

An OPERATIONAL read, so it reads RUNNING and cannot report an uncommitted edit - unlike the
merged config the rest of this domain normalizes from.
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


#: Nothing maps a source type to a reader - see `predefined.py`'s note on the same point.
RULE_HIT_COUNT_SOURCE_TYPE = "show_rule_hit_count_vsys"

#: The rulebase is named in the command and `security` is the only one this domain asks for.
#: The other rulebases - nat, qos, decryption and the rest - take the same command with a
#: different entry name and belong to whichever domain asserts over them.
RULE_HIT_COUNT_RULE_BASE = "security"


def build_show_rule_hit_count_command(vsys_name: str, *, rule_base: str = RULE_HIT_COUNT_RULE_BASE) -> str:
    """The command for one vsys's security rulebase.

    THE NESTING IS THE DEVICE'S AND IS NOT OBVIOUS: `vsys` wraps `vsys-name`, which wraps an
    `entry` NAMED for the vsys, which wraps `rule-base`, which wraps an `entry` NAMED for the
    rulebase, which wraps `rules` and finally the `all` selector. Written flat it is refused.
    """
    return (
        "<show><rule-hit-count><vsys><vsys-name>"
        f"<entry name='{vsys_name}'>"
        f"<rule-base><entry name='{rule_base}'><rules><all/></rules></entry></rule-base>"
        "</entry>"
        "</vsys-name></vsys></rule-hit-count></show>"
    )


def collect_show_rule_hit_count(
    session: PANSession,
    *,
    vsys_name: str,
    rule_base: str = RULE_HIT_COUNT_RULE_BASE,
) -> PANOSCollectedResponse:
    """Collect one enforcement point's per-rule usage telemetry.

    The reply is STRUCTURED - one `entry` per rule with seven sibling leaves, all of them epoch
    seconds as strings - so unlike `show logging-status` the normalizer reads keys rather than
    parsing padded text.
    """
    request = PANOSOperationRequest(
        command_xml=build_show_rule_hit_count_command(vsys_name, rule_base=rule_base),
        target=session.target,
        metadata={
            "command_name": "show rule-hit-count",
            "vsys_name": vsys_name,
            "rule_base": rule_base,
        },
    )
    return collect_op_response(
        session,
        source_type=RULE_HIT_COUNT_SOURCE_TYPE,
        request=request,
    )
