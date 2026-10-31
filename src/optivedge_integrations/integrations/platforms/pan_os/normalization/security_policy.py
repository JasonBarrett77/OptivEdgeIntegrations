"""The security-policy domain's three passes - PAN-POL.

THREE PASSES AND THREE GRAINS, which is why they are one module and not one function:

- `normalize_policy_rule_settings(appliance)` reads the two device-wide switches at
  `deviceconfig/setting/management` into `PolicyRuleSettings`. Appliance-anchored.
- `normalize_security_rule_policy_posture(enforcement_point)` sets fifteen columns on the
  point's `SecurityRule` rows. It runs AFTER `replace_security_rules` and after the profile
  coverage pass, because eight of its columns are computed from stored rows and two read a
  column another pass writes.
- `normalize_vsys_rule_posture(enforcement_point)` takes eight verdicts over those same rows
  into one `VsysRulePosture`. It runs LAST.

WHAT IS COMPUTED HERE AND WHAT IS NOT, stated once rather than per column, because the shape of
the gap is the same in both halves and a reader needs the boundary:

Computed from stored rows and the merged payload: the open-zone count, the port count over
resolved service objects and groups, the schedule kind and lapse, shadowing, duplicates, and
every verdict on `VsysRulePosture`.

NOT computed, and the columns stay at their indeterminate value with the companion firing:
`permits_high_risk_application` and `high_risk_application_characteristic`, which need
`/config/predefined/application` - a read no collector issues - and which are not a property of
the rule at all but the result of evaluating an application FILTER against today's content
release. See the stage 7 artifact for what closing that costs.

THE HIT-COUNT HALF IS COMPUTED AND IS THE ONE THING IN THIS MODULE THAT NEEDED A NEW READ.
`collectors/rule_hit_count.py` is it, and its module docstring carries the measurement that
makes the result safe: on an appliance whose `rule-hit-count` key reads `no` the read SUCCEEDS
and answers zero for every rule, byte-identical to a counting appliance whose rules have never
matched. So a reading is only believed where `PolicyRuleSettings.rule_hit_count_enabled` is
TRUE, and `hit_count_reading_known` is where the two readings meet.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from django.db import transaction
from django.db.models import Q

from optivedge_integrations.integrations.models import (
    Appliance,
    EnforcementPoint,
    PolicyRuleSettings,
    SecurityRule,
    Snapshot,
    VsysRulePosture,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.rule_hit_count import (
    RULE_HIT_COUNT_SOURCE_TYPE,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ensure_list,
    merged_shared,
    merged_vsys_entry,
    parse_yes_no_field,
    pushed_vsys_panorama,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    write_node_row,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    MERGED_CONFIG_SOURCE_TYPE,
    choose_local_appliance,
    latest_merged_snapshot,
    latest_pushed_vsys_snapshot,
)

#: What the action field's six members do. Measured: four of the six BLOCK and differ only in
#: what the sender is told, so a rulebase that refuses with a silent `drop` satisfies every
#: intent written as "deny" even though it matches no `deny` literal. Stage 3's settlement.
ALLOW_ACTION = "allow"
BLOCKING_ACTIONS = frozenset({"deny", "drop", "reset-client", "reset-server", "reset-both"})

#: The keyword that means "every value of this element". It is a MEMBER like any other on the
#: wire, which is the whole reason a breadth question needs a resolver: `any` is one member and
#: so is a /8.
ANY_KEYWORD = "any"

#: The one service member that is NOT a reference. Its ports are the ports of whatever
#: applications the rule names, which is vendor content rather than configuration - so a rule
#: naming it has NO establishable port count and must read as indeterminate, not as narrow.
APPLICATION_DEFAULT = "application-default"

#: The port leaf is FREE TEXT with three forms, measured on 013201001475: a single value
#: (`443`), a range (`8001-8006`) and a comma list (`139,445,6667`). A comparison against a
#: threshold would be comparing against a string, which is why the count is a column.
_PORT_MAX = 65535


# --------------------------------------------------------------------------- device-wide

def _management_node(snapshot: Snapshot) -> dict[str, Any]:
    entry = device_entry_from_snapshot(snapshot)
    deviceconfig = entry.get("deviceconfig") if isinstance(entry, dict) else None
    deviceconfig = deviceconfig if isinstance(deviceconfig, dict) else {}
    setting = deviceconfig.get("setting")
    setting = setting if isinstance(setting, dict) else {}
    management = setting.get("management")
    return management if isinstance(management, dict) else {}


#: ONE OF THESE TWO KEYS IS NOW MEASURED AND THE OTHER IS NOT, and the difference is worth
#: reading before changing either. `Implicit.not_assumed` stores NULL and records a
#: `not_configured` provenance row, which is the difference between "the device does this and
#: nobody wrote it down" and "we have no idea"; the control resting on such a column is written
#: so that NULL MATCHES and the finding is raised.
#:
#: For `disable-shadow-rule-check` the guess would be worse than absent: the leaf is a NEGATIVE,
#: so assuming `no` from the name would put the reassuring answer on a control whose evidence
#: this key suppresses. What would settle it is named rather than done: two rules where one
#: shadows the other, staged in one vsys, and one `validate full` - a COMMIT GATE, which no
#: collector may issue.
#: `rule-hit-count`. MEASURED 2026-10-31 AND IT IS ON, after reading `unmeasured` until then.
#: BOTH ARMS ARE READ ON THE ORACLE THAT IS THE SETTING - the Policy Rule Hit Count checkbox -
#: on two appliances in opposite key states, on committed configuration, with no write taken:
#: pan-fw-111 has NO `rule-hit-count` key and its box renders ENABLED, pan-fw-201 has
#: `rule-hit-count: no` and its box renders UNCHECKED. The rendering moves with the key.
#:
#: WHY ONE APPLIANCE'S CHECKBOX COULD NOT SETTLE IT, recorded because it nearly settled it the
#: wrong way: pan-fw-201's unchecked box is its CONFIGURED value. Check the key's presence on
#: the appliance you are looking at before reading its UI. pan-fw-111's management node carries
#: seven other keys and not this one, which is what makes its box a reading of the ABSENT state.
RULE_HIT_COUNT_ABSENT = Implicit.measured(
    True,
    "stage4-security-policy.json objects['mgmt-rule-settings'].fields['rule-hit-count'].implicit: "
    "an absent key asserts that hit counting is ON. Measured 2026-10-31 on the Policy Rule Hit "
    "Count checkbox in both directions, on committed configuration, without a write - pan-fw-111 "
    "carries seven other keys under deviceconfig/setting/management and NOT this one, and its box "
    "renders ENABLED; pan-fw-201 carries `rule-hit-count: no` and its box renders UNCHECKED. "
    "Corroborated by the counters as an independent consequence (fw-core-tpa-a, no key, allow_icmp "
    "at hit-count 16758) and by the vendor Help - 'Policy Rule Hit Count (enabled by default)', "
    "ngfw/help/11-2 defining-policies-on-panorama")
SHADOW_CHECK_UNMEASURED = Implicit.not_assumed(
    "stage 4 left `disable-shadow-rule-check`'s implicit UNMEASURED and named exactly what "
    "would settle it - two rules where one shadows the other, staged in one vsys, and one "
    "`validate full`, which is a commit gate no collector can issue. The key is a NEGATIVE, so "
    "inferring `no` from its name would hand the reassuring answer to a control whose whole "
    "evidence this key suppresses")


def normalize_policy_rule_settings(appliance: Appliance) -> dict[str, int]:
    """One appliance's device-wide policy-rule switches.

    ONE ROW PER APPLIANCE, so an HA pair yields two rows for one real configuration and nothing
    deduplicates them - see the model docstring. That is not cosmetic: the two peers' management
    containers have been measured differing while config sync reported synchronized.

    MEASURED 2026-10-29 on both serials this domain's lab stands on. On 013201001475 the
    `management` CONTAINER carries `@ptpl=ptpl_fw-core-tpa` and `@src=tpl` while the two leaves
    inside it carry no marker of their own. The provenance recorded here is therefore the LEAF's,
    read through `parse_yes_no_field`, which is `local` for an unmarked leaf - not the
    container's `template`. That is CLAUDE.md's rule and not a shortcut: a container's `@ptpl`
    names the LOSING layer, moves when an unrelated template is edited, and never inherits
    downward, so attributing it to the leaf would record a provenance that can change without
    the value changing.
    """
    snapshot = appliance_merged_snapshot(appliance)
    if snapshot is None:
        return {"policy_rule_settings": 0}
    management = _management_node(snapshot)

    hit_count, hit_rk, hit_rv = parse_yes_no_field(
        management.get("rule-hit-count"), implicit=RULE_HIT_COUNT_ABSENT)
    shadow, shadow_rk, shadow_rv = parse_yes_no_field(
        management.get("disable-shadow-rule-check"), implicit=SHADOW_CHECK_UNMEASURED)

    with transaction.atomic():
        write_node_row(
            PolicyRuleSettings, appliance, snapshot,
            {"rule_hit_count_enabled": hit_count,
             "disable_shadow_rule_check": shadow},
            [("rule_hit_count_enabled", hit_rk, hit_rv),
             ("disable_shadow_rule_check", shadow_rk, shadow_rv)])
    return {"policy_rule_settings": 1}


def appliance_merged_snapshot(appliance: Appliance) -> Snapshot | None:
    """The appliance's own merged snapshot.

    `snapshots.latest_merged_snapshot` takes an ENFORCEMENT POINT and resolves which appliance
    speaks for it; this node is device-wide and has no vsys axis, so the appliance is the key.
    One query rather than a branch inside the shared helper, which would have to switch on the
    type of its argument.
    """
    return (Snapshot.objects.filter(appliance=appliance, source_type=MERGED_CONFIG_SOURCE_TYPE)
            .order_by("-collected_at", "-pk").first())


# --------------------------------------------------------------------------- ports

def expand_port_leaf(text: str) -> set[int] | None:
    """Every port one `protocol/<tcp|udp>/port` leaf opens, or None where it cannot be read.

    THE LEAF IS FREE TEXT AND HAS THREE FORMS, all measured on 013201001475: a single value, a
    hyphen range and a comma list, and a comma list of ranges is the fourth combination the
    grammar allows. None rather than an empty set for anything else: an unreadable leaf means
    the count is INDETERMINATE, and an empty set would make the rule that names it the tightest
    on the device.
    """
    ports: set[int] = set()
    raw = str(text or "").strip()
    if not raw:
        return None
    for piece in raw.split(","):
        piece = piece.strip()
        if not piece:
            return None
        if "-" in piece:
            low, _, high = piece.partition("-")
            if not low.strip().isdigit() or not high.strip().isdigit():
                return None
            start, end = int(low), int(high)
        elif piece.isdigit():
            start = end = int(piece)
        else:
            return None
        if start > end or end > _PORT_MAX:
            return None
        ports.update(range(start, end + 1))
    return ports


def _service_collections(point_snapshot: Snapshot | None,
                         pushed_snapshot: Snapshot | None,
                         vsys_name: str) -> tuple[dict[str, dict], dict[str, dict]]:
    """`({name: service entry}, {name: service-group entry})` for one enforcement point.

    THREE SCOPES UNIONED, in the order a name resolves: the vsys's own collection, the
    firewall-local `shared` collection, and whatever Panorama pushed. A reader written for one
    finds nothing in the others SILENTLY, which for a count whose null means "indeterminate" is
    the direction that quietly passes a rule.

    THE PUSHED REPLY IS NOT SPELLED LIKE THE MERGED ONE and that is the trap this walk exists to
    avoid: `rulebase` is not a key in it at all - its root is `policy`, the subtree is
    `panorama`, and the children are `pre-rulebase` and `post-rulebase`. Service objects pushed
    from Panorama sit directly under `panorama`, beside those two.

    LAST SCOPE WINS IS NOT THE PRECEDENCE RULE and this does not claim it is: a name defined at
    two scopes resolves by `PolicyObjectScope.ORDER`, which these collections carry no marker
    for. The union is built vsys-first so the narrowest definition is the one kept, which is the
    right answer for the lab and is recorded in the artifact as a limit rather than a result.
    """
    services: dict[str, dict] = {}
    groups: dict[str, dict] = {}

    def absorb(container: Any) -> None:
        if not isinstance(container, dict):
            return
        for key, target in (("service", services), ("service-group", groups)):
            node = container.get(key)
            if not isinstance(node, dict):
                continue
            for entry in ensure_list(node.get("entry")):
                if isinstance(entry, dict) and entry.get("@name"):
                    target.setdefault(str(entry["@name"]), entry)

    if point_snapshot is not None:
        payload = point_snapshot.payload
        if isinstance(payload, dict):
            absorb(merged_vsys_entry(payload, vsys_name))
            absorb(merged_shared(payload))
    if pushed_snapshot is not None:
        absorb(pushed_vsys_panorama(pushed_snapshot.payload))
    return services, groups


def resolve_service_ports(members: list[str],
                          services: dict[str, dict],
                          groups: dict[str, dict]) -> set[int] | None:
    """The union of ports a rule's service list opens, or None where it cannot be established.

    RECURSIVE, because a service group may contain service groups - which is one of the four
    reasons a predicate cannot answer this. Cycles are broken by a seen-set rather than trusted
    not to exist: the device refuses one at commit, and a collector reads the CANDIDATE.

    None for `application-default`, for `any`, for a name that resolves to nothing, and for a
    port leaf in a form this reader does not know. Every one of those is INDETERMINATE and not
    zero, and the companion `permitted_port_count_known` fires on exactly those rows.
    """
    ports: set[int] = set()
    seen: set[str] = set()

    def walk(name: str) -> bool:
        if name in seen:
            return True
        seen.add(name)
        entry = services.get(name)
        if entry is not None:
            protocol = entry.get("protocol")
            if not isinstance(protocol, dict):
                return False
            found = False
            for branch in ("tcp", "udp"):
                node = protocol.get(branch)
                if not isinstance(node, dict):
                    continue
                expanded = expand_port_leaf(node.get("port"))
                if expanded is None:
                    return False
                ports.update(expanded)
                found = True
            # BOTH BRANCHES ARE THE SUBJECT, and a single-branch reader would miss two of the
            # four services the control names. A service object with neither branch opens
            # nothing anybody can name, which is indeterminate rather than zero.
            return found
        group = groups.get(name)
        if group is None:
            return False
        member_node = group.get("members")
        member_names = [str(v).strip() for v in ensure_list(
            member_node.get("member") if isinstance(member_node, dict) else None)]
        if not member_names:
            return False
        return all(walk(member) for member in member_names if member)

    if not members:
        return None
    for member in members:
        lowered = member.strip().lower()
        if lowered in (ANY_KEYWORD, APPLICATION_DEFAULT):
            return None
        if not walk(member.strip()):
            return None
    return ports


# --------------------------------------------------------------------------- schedules

def _schedule_collections(point_snapshot: Snapshot | None,
                          pushed_snapshot: Snapshot | None,
                          vsys_name: str) -> dict[str, dict]:
    """`{name: schedule entry}` across the same three scopes the services walk covers."""
    schedules: dict[str, dict] = {}

    def absorb(container: Any) -> None:
        if not isinstance(container, dict):
            return
        node = container.get("schedule")
        if not isinstance(node, dict):
            return
        for entry in ensure_list(node.get("entry")):
            if isinstance(entry, dict) and entry.get("@name"):
                schedules.setdefault(str(entry["@name"]), entry)

    if point_snapshot is not None and isinstance(point_snapshot.payload, dict):
        absorb(merged_vsys_entry(point_snapshot.payload, vsys_name))
        absorb(merged_shared(point_snapshot.payload))
    if pushed_snapshot is not None:
        absorb(pushed_vsys_panorama(pushed_snapshot.payload))
    return schedules


def schedule_verdict(name: str, schedules: dict[str, dict],
                     *, now: datetime) -> tuple[str, bool | None]:
    """`(schedule_kind, schedule_window_expired)` for one rule's schedule reference.

    FOUR ANSWERS AND THE EMPTY ONE IS NOT HERE: this function having run is what distinguishes
    `none` from the empty string, so a rule with no schedule gets `none` and a rule nobody
    resolved keeps the empty default the column was migrated with.

    ONLY THE NON-RECURRING BRANCH HAS AN END, so a recurring schedule's lapse is NULL rather
    than False - and that is the false pass to watch for rather than a gap: a temporary rule
    carrying a repeating daily window looks time-bounded and never expires.

    EXPIRED MEANS EVERY WINDOW HAS CLOSED. A member list may hold several ranges and the rule is
    still in force while any one of them is open, so the test is over the LATEST end. A range
    this reader cannot parse leaves the lapse NULL for the whole rule: one unreadable window
    cannot be read as closed, and the alternative - ignoring it - would report a rule as expired
    on the strength of the windows that happened to parse.

    The vendor's own narrowing is worth knowing beside this and is NOT expressible as a column:
    Help p.358 says a closing window affects only NEW sessions, so a lapsed rule does not stop
    what it has already started.
    """
    if not name:
        return SecurityRule.SCHEDULE_KIND_NONE, None
    entry = schedules.get(name)
    if entry is None:
        # A rule's references are VALIDATED at commit, so this cannot happen on a committed
        # rule - and the merged view follows the CANDIDATE, so it can happen on a staged one.
        # Unresolved is not `none`: the rule names a window nobody could read.
        return "", None
    schedule_type = entry.get("schedule-type")
    if not isinstance(schedule_type, dict):
        return "", None
    if isinstance(schedule_type.get("recurring"), dict):
        return SecurityRule.SCHEDULE_KIND_RECURRING, None
    non_recurring = schedule_type.get("non-recurring")
    if not isinstance(non_recurring, dict):
        return "", None
    windows = [str(v).strip() for v in ensure_list(non_recurring.get("member"))]
    latest_end: datetime | None = None
    for window in windows:
        _, _, end = window.partition("-")
        parsed = _parse_schedule_moment(end)
        if parsed is None:
            return SecurityRule.SCHEDULE_KIND_NON_RECURRING, None
        if latest_end is None or parsed > latest_end:
            latest_end = parsed
    if latest_end is None:
        return SecurityRule.SCHEDULE_KIND_NON_RECURRING, None
    return SecurityRule.SCHEDULE_KIND_NON_RECURRING, latest_end < now


def _parse_schedule_moment(text: str) -> datetime | None:
    """`YYYY/MM/DD@HH:MM` to an aware datetime, or None.

    MEASURED on 013201001475: `2020/01/01@00:00-2020/01/02@00:00` is the wire form, so the
    separator between the two ends is the same hyphen that appears in neither end.

    READ AS UTC, which is a KNOWN APPROXIMATION and is recorded rather than hidden: the string
    carries no zone and the window is the device's local time. A rule whose window closed within
    the appliance's offset of now can therefore be judged a few hours early or late. Nothing in
    this domain grades on hours.
    """
    raw = str(text or "").strip()
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y/%m/%d@%H:%M").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# --------------------------------------------------------------------------- match tuples

def _members(rule: SecurityRule, accessor: str) -> list[str]:
    return [str(row.value or "").strip()
            for row in getattr(rule, accessor).all() if str(row.value or "").strip()]


def _side_is_open(members: list[str]) -> bool:
    """Whether a member list is exactly the keyword `any`.

    An EMPTY list is open too: PAN-OS treats a rule with no `from`/`to` element as matching any
    zone, which is why rule normalization materialises an explicit `any` member for the address
    sides. A zone side with no rows is the same state.
    """
    if not members:
        return True
    return len(members) == 1 and members[0].lower() == ANY_KEYWORD


def _match_tuple(rule: SecurityRule) -> tuple:
    """The comparable shape of one rule's match set, for the duplicate test.

    EQUALITY OVER SORTED MEMBER NAMES AND THE TWO BREADTH TOTALS. It is not the dataplane's
    notion of a match set and does not claim to be: two rules naming different address objects
    that happen to cover the same space are NOT equal here, and two naming the same objects in a
    different order ARE. That is the narrow, defensible reading - `has_exact_duplicate` is about
    a rule somebody copied, not about overlap, which is what shadowing is for.

    `action` IS PART OF IT, so a permit and a deny over the same tuple are not duplicates - they
    are a shadowing relation and the other column's subject.
    """
    return (
        tuple(sorted(m.lower() for m in _members(rule, "securityrulefromzones"))),
        tuple(sorted(m.lower() for m in _members(rule, "securityruletozones"))),
        tuple(sorted(m.lower() for m in _members(rule, "securityruleapplications"))),
        tuple(sorted(m.lower() for m in _members(rule, "securityruleservices"))),
        tuple(sorted(r.raw_value.lower() for r in rule.source_address_refs.all())),
        tuple(sorted(r.raw_value.lower() for r in rule.destination_address_refs.all())),
        str(rule.action or "").lower(),
        bool(rule.negate_source),
        bool(rule.negate_destination),
    )


def _covers(earlier: SecurityRule, later: SecurityRule) -> bool:
    """Whether `earlier` matches everything `later` matches, with the same decision.

    THIS IS NOT THE DEVICE'S DEFINITION OF SHADOWING AND CANNOT BE. The firewall's own answer
    comes only from pre-commit validation - a COMMIT GATE, not a view - so no collector can ask
    it. What is implemented is a CONSERVATIVE containment over the stored match tuple: every
    element of `later` must be a subset of `earlier`'s, with `any` on `earlier` covering
    anything, and the two must share an action.

    CONSERVATIVE IN ONE DIRECTION ONLY, deliberately: an address side is compared by NAME and by
    the interval total behind it, so a /8 covers a /24 inside it. Where either side's breadth is
    unknown - a dynamic group, an EDL the device could not fetch - it is NOT treated as covering
    anything, so an unresolvable rule is never reported as shadowed. False negatives are the
    acceptable error here; a rule wrongly reported as dead is a rule somebody deletes.
    """
    if str(earlier.action or "").lower() != str(later.action or "").lower():
        return False
    if earlier.disabled or later.disabled:
        return False
    for accessor in ("securityrulefromzones", "securityruletozones",
                     "securityruleapplications", "securityruleservices"):
        broad = {m.lower() for m in _members(earlier, accessor)}
        narrow = {m.lower() for m in _members(later, accessor)}
        if ANY_KEYWORD in broad or not broad:
            continue
        if ANY_KEYWORD in narrow or not narrow:
            return False
        if not narrow.issubset(broad):
            return False
    for side in ("source", "destination"):
        if not _address_side_covers(earlier, later, side):
            return False
    return True


def _address_side_covers(earlier: SecurityRule, later: SecurityRule, side: str) -> bool:
    """One address side of the containment test.

    Negation on either rule makes the comparison unsafe and returns False: the complement of a
    set is not comparable to the set by name, and the stored interval total for a negated side
    is the complement's - so a name-wise subset can be a space-wise superset.
    """
    if side == "source":
        if earlier.negate_source or later.negate_source:
            return False
        broad_refs = earlier.source_address_refs.all()
        narrow_refs = later.source_address_refs.all()
        broad_total, narrow_total = earlier.source_num_hosts, later.source_num_hosts
    else:
        if earlier.negate_destination or later.negate_destination:
            return False
        broad_refs = earlier.destination_address_refs.all()
        narrow_refs = later.destination_address_refs.all()
        broad_total, narrow_total = earlier.destination_num_hosts, later.destination_num_hosts
    broad_names = {str(r.raw_value or "").strip().lower() for r in broad_refs}
    narrow_names = {str(r.raw_value or "").strip().lower() for r in narrow_refs}
    if ANY_KEYWORD in broad_names:
        return True
    if ANY_KEYWORD in narrow_names:
        return False
    if narrow_names and narrow_names.issubset(broad_names):
        return True
    # An interval comparison only where BOTH totals were established. A null on either side is
    # indeterminate, and indeterminate must not read as covered.
    if broad_total is None or narrow_total is None:
        return False
    if len(broad_names) != 1 or len(narrow_names) != 1:
        return False
    broad_ref = next(iter(broad_refs), None)
    narrow_ref = next(iter(narrow_refs), None)
    if broad_ref is None or narrow_ref is None:
        return False
    broad_object = broad_ref.address_object
    narrow_object = narrow_ref.address_object
    if broad_object is None or narrow_object is None:
        return False
    if None in (broad_object.ipv4_start_int, broad_object.ipv4_end_int,
                narrow_object.ipv4_start_int, narrow_object.ipv4_end_int):
        return False
    return (broad_object.ipv4_start_int <= narrow_object.ipv4_start_int
            and broad_object.ipv4_end_int >= narrow_object.ipv4_end_int)


# --------------------------------------------------------------------------- hit counts

def _hit_count_snapshot(enforcement_point: EnforcementPoint) -> Snapshot | None:
    return (Snapshot.objects.filter(enforcement_point=enforcement_point,
                                    source_type=RULE_HIT_COUNT_SOURCE_TYPE)
            .order_by("-collected_at", "-pk").first())


def hit_count_rows(payload: Any) -> dict[str, dict[str, str]]:
    """`{rule name: leaves}` from one `show rule-hit-count` reply.

    THE NESTING IS FIVE DEEP AND EVERY LEVEL IS A NAMED ENTRY - vsys, then rulebase, then rules
    - so a walk written for a flatter shape finds nothing and finds it silently. Written against
    a reply measured on 013201001475 vsys6/vsys8/vsys10 and 691665AC334B458 vsys1.
    """
    rows: dict[str, dict[str, str]] = {}
    if not isinstance(payload, dict):
        return rows
    root = payload.get("rule-hit-count")
    if not isinstance(root, dict):
        return rows
    vsys = root.get("vsys")
    if not isinstance(vsys, dict):
        return rows
    for vsys_entry in ensure_list(vsys.get("entry")):
        if not isinstance(vsys_entry, dict):
            continue
        rule_base = vsys_entry.get("rule-base")
        if not isinstance(rule_base, dict):
            continue
        for base_entry in ensure_list(rule_base.get("entry")):
            if not isinstance(base_entry, dict):
                continue
            rules = base_entry.get("rules")
            if not isinstance(rules, dict):
                continue
            for rule_entry in ensure_list(rules.get("entry")):
                if isinstance(rule_entry, dict) and rule_entry.get("@name"):
                    rows[str(rule_entry["@name"])] = rule_entry
    return rows


def _epoch(text: Any) -> int | None:
    """An epoch-seconds leaf, or None for the device's own `0`.

    ZERO IS NOT A TIMESTAMP HERE AND MUST NOT BE READ AS ONE. MEASURED 2026-10-29 on every vsys
    of both serials: `last-hit-timestamp` is `0` for a rule that has never matched. Parsing it
    as 1970 would make an untouched rule the oldest thing on the device by fifty-six years,
    which is a fabricated age rather than a missing one.
    """
    raw = str(text or "").strip()
    if not raw.isdigit():
        return None
    value = int(raw)
    return value or None


def hit_count_verdict(row: dict[str, str] | None, *, counting: bool | None,
                      now: datetime) -> tuple[int | None, bool]:
    """`(days_since_last_hit, hit_count_reading_known)` for one rule.

    THE SECOND VALUE IS THE ONE THAT MATTERS and it is false in three different situations that
    the first value cannot tell apart:

    - no reading was taken for this rule at all;
    - a reading was taken on an appliance that is NOT COUNTING, where the reply is zeros that
      look exactly like a counted rule nothing has matched (measured on 691665AC334B458, whose
      `rule-hit-count` key reads `no` and whose reply is indistinguishable from the counting
      appliance's);
    - the device reports `latest: no` for the rule, which stage 4 found on one appliance of
      three with its meaning unestablished - so it is treated as "do not believe this row"
      rather than guessed at.

    A COUNTER RESET IS THE FOURTH CASE and it is handled by the same false: the vendor ships
    `last-reset-timestamp` precisely because the counter resets on a reboot or a dataplane
    restart, so an age measured from before a reset is an age of the reset and not of the rule.
    Where a reset is recorded and no hit is, the reading is not known.
    """
    if row is None or counting is not True:
        return None, False
    if str(row.get("latest", "")).strip().lower() == "no":
        return None, False
    last_hit = _epoch(row.get("last-hit-timestamp"))
    last_reset = _epoch(row.get("last-reset-timestamp"))
    if last_hit is None:
        # Counted, believed, and never matched. The AGE is unknown - there is no timestamp to
        # take it from - but the READING is known, which is what lets a control say "this rule
        # has never been used" instead of "nobody looked".
        return None, last_reset is None
    if last_reset is not None and last_reset > last_hit:
        return None, False
    age = int((now - datetime.fromtimestamp(last_hit, tz=timezone.utc)).total_seconds() // 86400)
    return max(age, 0), True


# --------------------------------------------------------------------------- the rule pass

#: Enough of a decile to be worth computing, and the reason this is a constant rather than a
#: literal: a ranking over a handful of rules says nothing, and a ranking over all-zero hit
#: counts says less. Below this many BELIEVED readings in a rulebase, `busy_rule_placed_late`
#: stays NULL - no answer rather than a weak one.
MIN_RULES_FOR_PLACEMENT_RANKING = 10


def normalize_security_rule_policy_posture(enforcement_point: EnforcementPoint) -> dict[str, int]:
    """Set the security-policy domain's per-rule columns for one enforcement point.

    RUNS AFTER the rules themselves and after the profile-coverage pass. Eight of these columns
    are computed from the STORED rows of the whole rulebase, so computing them inside rule
    normalization would read a partial set - and two more read a column the coverage pass writes.
    Run early it would answer from the previous run's rows, or from none on a first collection,
    which for a verdict about an absence is the direction that manufactures a finding.
    """
    now = datetime.now(tz=timezone.utc)
    point_snapshot = latest_merged_snapshot(enforcement_point)
    pushed_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    services, groups = _service_collections(
        point_snapshot, pushed_snapshot, enforcement_point.vsys_name)
    schedules = _schedule_collections(
        point_snapshot, pushed_snapshot, enforcement_point.vsys_name)
    hit_rows = hit_count_rows(
        getattr(_hit_count_snapshot(enforcement_point), "payload", None))
    settings = PolicyRuleSettings.objects.filter(
        appliance=choose_local_appliance(enforcement_point)).first()
    counting = settings.rule_hit_count_enabled if settings is not None else None

    rules = list(
        SecurityRule.objects.filter(enforcement_point=enforcement_point)
        .order_by("effective_order", "rule_position", "pk")
        .prefetch_related("securityrulefromzones", "securityruletozones",
                          "securityruleapplications", "securityruleservices",
                          "source_address_refs__address_object",
                          "destination_address_refs__address_object"))

    tuples = [_match_tuple(rule) for rule in rules]
    tuple_counts: dict[tuple, int] = {}
    for shape in tuples:
        tuple_counts[shape] = tuple_counts.get(shape, 0) + 1

    believed: list[tuple[SecurityRule, int]] = []
    pending: list[tuple[SecurityRule, dict[str, Any]]] = []
    updated = 0
    counts = {"rules": len(rules), "port_counts_established": 0,
              "shadowed": 0, "duplicates": 0, "hit_readings_believed": 0}

    for index, rule in enumerate(rules):
        values: dict[str, Any] = {}

        from_open = _side_is_open(_members(rule, "securityrulefromzones"))
        to_open = _side_is_open(_members(rule, "securityruletozones"))
        values["open_zone_side_count"] = int(from_open) + int(to_open)

        ports = resolve_service_ports(
            _members(rule, "securityruleservices"), services, groups)
        values["permitted_port_count"] = None if ports is None else len(ports)
        if ports is not None:
            counts["port_counts_established"] += 1

        kind, expired = schedule_verdict(rule.schedule, schedules, now=now)
        values["schedule_kind"] = kind
        values["schedule_window_expired"] = expired

        # SHADOWING, over the rules evaluated BEFORE this one. `effective_order` is the order
        # the list is sorted by, and it is a RECONSTRUCTION from config_source and document
        # order rather than a reading - the device's own `index: N` is reported only by
        # `show running security-policy`, which nothing collects. So this is a verdict about a
        # MODEL of the evaluation order, and disabling a rule renumbers the device's indexes
        # below it while leaving this reconstruction unchanged.
        shadowed = any(_covers(rules[earlier], rule) for earlier in range(index))
        values["is_shadowed_by_earlier_rule"] = shadowed
        values["shadow_relation_computed"] = True
        if shadowed:
            counts["shadowed"] += 1

        duplicate = tuple_counts[tuples[index]] > 1
        values["has_exact_duplicate"] = duplicate
        values["duplicate_comparison_computed"] = True
        if duplicate:
            counts["duplicates"] += 1

        age, known = hit_count_verdict(
            hit_rows.get(rule.name), counting=counting, now=now)
        values["days_since_last_hit"] = age
        values["hit_count_reading_known"] = known
        if known:
            counts["hit_readings_believed"] += 1
            believed.append((rule, int(str(hit_rows[rule.name].get("hit-count") or 0) or 0)))

        # NOT COMPUTED, and left at the value the migration gave them rather than defaulted to
        # something cheaper: `/config/predefined/application` is a read no collector issues, and
        # an application FILTER is a predicate evaluated against a content release rather than a
        # property of the rule. NULL on the boolean means `not checked`, which is different from
        # the `false` that would mean `checked and clean`.
        values["permits_high_risk_application"] = None
        values["high_risk_application_characteristic"] = ""

        pending.append((rule, values))

    placement = _placement_ranking(believed, rules) \
        if len(believed) >= MIN_RULES_FOR_PLACEMENT_RANKING else {}
    for rule, values in pending:
        values["busy_rule_placed_late"] = placement.get(rule.pk)
        changed = [name for name, value in values.items() if getattr(rule, name) != value]
        if changed:
            for name in changed:
                setattr(rule, name, values[name])
            rule.save(update_fields=changed)
            updated += 1
    counts["updated"] = updated
    return counts


def _placement_ranking(believed: list[tuple[SecurityRule, int]],
                       rules: list[SecurityRule]) -> dict[int, bool]:
    """`{rule pk: busy_rule_placed_late}` over the rules whose hit reading is believed.

    THE RANKING IS ONLY OVER BELIEVED READINGS, so a rulebase with fewer than
    MIN_RULES_FOR_PLACEMENT_RANKING of them gets no answer at all rather than a decile over
    noise. Rules outside the believed set are absent from the result, which the caller stores as
    NULL - `not established`, which is what it is.

    TOP DECILE BY HIT VOLUME AND BOTTOM QUARTILE BY POSITION, with `is_shadowed_by_earlier_rule`
    as the safety constraint stage 3 attached: a rule that is already shadowed must not be
    reported as merely misplaced, because moving it up would change what the policy DOES.
    """
    # ALL-ZERO VOLUMES ARE NO ANSWER AND NOT A WEAK ONE, which is the whole reason this returns
    # an empty map rather than False for every rule. MEASURED on 013201001475 vsys6: every one
    # of 22 believed readings reports `hit-count 0`, because nothing has driven traffic through
    # that vsys. A decile over that names an arbitrary tenth of the rulebase, and reporting
    # `False` instead would claim the ranking ran and found nothing out of place - a claim about
    # relative volume where no volume exists.
    if not any(volume > 0 for _rule, volume in believed):
        return {}
    ordered = sorted(believed, key=lambda pair: pair[1], reverse=True)
    decile = max(1, len(ordered) // 10)
    busy = {rule.pk for rule, volume in ordered[:decile] if volume > 0}
    positions = {rule.pk: index for index, rule in enumerate(rules)}
    late_from = len(rules) - max(1, len(rules) // 4)
    result: dict[int, bool] = {}
    for rule, _volume in believed:
        if rule.is_shadowed_by_earlier_rule:
            result[rule.pk] = False
            continue
        result[rule.pk] = rule.pk in busy and positions[rule.pk] >= late_from
    return result


# --------------------------------------------------------------------------- the vsys pass

def normalize_vsys_rule_posture(enforcement_point: EnforcementPoint) -> dict[str, int]:
    """One enforcement point's eight policy-posture verdicts.

    RUNS LAST of this domain's three passes: every verdict is taken over the `SecurityRule` rows
    and over columns the pass above writes.

    A ROW IS ALWAYS WRITTEN, which is where this diverges from `RulebaseDeviceMatchVerdict`. A
    vsys with no rulebase node at all still ENFORCES the two rules PAN-OS ships, and "this vsys
    has no policy of its own" is the answer these controls exist to give - so a missing row would
    silence exactly the subject. `rules_collected` is what says whether anything was read.
    """
    point_snapshot = latest_merged_snapshot(enforcement_point)
    pushed_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    rules = list(
        SecurityRule.objects.filter(enforcement_point=enforcement_point)
        .order_by("effective_order", "rule_position", "pk")
        .prefetch_related("securityrulefromzones", "securityruletozones",
                          "securityruleapplications", "securityruleservices",
                          "source_address_refs__address_object",
                          "source_address_refs__address_group",
                          "destination_address_refs__address_object",
                          "destination_address_refs__address_group"))

    # `rules_collected` asks whether a READ ANSWERED, not whether it found rules. An empty
    # rulebase with a snapshot behind it is a measured emptiness; no snapshot is not.
    rules_collected = point_snapshot is not None

    permitting = [r for r in rules if str(r.action or "").lower() == ALLOW_ACTION
                  and not r.disabled]
    blocking = [r for r in rules if str(r.action or "").lower() in BLOCKING_ACTIONS
                and not r.disabled]
    last_permit = max((r.effective_order for r in permitting), default=None)

    values = {
        "rules_collected": rules_collected,
        "has_logged_catch_all_deny": _has_logged_catch_all(blocking, last_permit),
        "default_rules_log_session_end": _default_rules_log_end(rules),
        "has_application_block_rule_above_permits": _app_block_above_permits(
            blocking, permitting),
        "vendor_hostile_list_block_directions_missing": _hostile_directions_missing(
            blocking, last_permit),
        "expresses_geographic_boundary": _names_a_region(rules),
        "has_prestaged_blocklist_rule": _prestaged_blocklist(blocking, last_permit),
        "has_port_matched_block_rule": _port_matched_block(blocking),
    }
    with transaction.atomic():
        VsysRulePosture.objects.update_or_create(
            enforcement_point=enforcement_point,
            defaults={
                "management_station": enforcement_point.management_station,
                "source_snapshot": point_snapshot,
                **values,
            },
        )
    return {"vsys_rule_postures": 1, "rules": len(rules),
            "permitting_rules": len(permitting), "blocking_rules": len(blocking),
            "pushed_snapshot": int(pushed_snapshot is not None)}


def _open_on_every_side(rule: SecurityRule) -> bool:
    """Whether this rule matches everything - the shape a catch-all has to have.

    Both zone sides open, both address sides naming `any`, and the application and service
    lists open. A rule narrower than that on ANY axis leaves traffic unrefused, so counting it
    as a catch-all would report a vsys as covered by a rule that is not.
    """
    if not _side_is_open(_members(rule, "securityrulefromzones")):
        return False
    if not _side_is_open(_members(rule, "securityruletozones")):
        return False
    if not _side_is_open(_members(rule, "securityruleapplications")):
        return False
    if not _side_is_open(_members(rule, "securityruleservices")):
        return False
    for refs in (rule.source_address_refs.all(), rule.destination_address_refs.all()):
        names = {str(r.raw_value or "").strip().lower() for r in refs}
        if names != {ANY_KEYWORD}:
            return False
    return not (rule.negate_source or rule.negate_destination)


def _has_logged_catch_all(blocking: list[SecurityRule], last_permit: int | None) -> bool:
    """PAN-POL-010: a refusal of everything left over, with the refusal RECORDED.

    `log_end` true is half the assertion and is the half a check on the rule's existence alone
    would drop - an unlogged catch-all refuses the traffic and leaves no evidence it did.
    """
    for rule in blocking:
        if not _open_on_every_side(rule):
            continue
        if last_permit is not None and rule.effective_order <= last_permit:
            continue
        if rule.log_end:
            return True
    return False


def _default_rules_log_end(rules: list[SecurityRule]) -> bool:
    """PAN-POL-009's half about the two rules PAN-OS ships.

    TRUE ONLY WHERE AN OVERRIDE ROW SAYS SO. Where no override node exists there are no
    `config_source = default` rows at all, and the measured shipped value is session-end logging
    OFF - measured on 013201001475 vsys6, where both default rules' Actions tabs render Log at
    Session End UNTICKED while an ordinary rule storing no log key renders it TICKED. So the
    absence of rows is false rather than unknown, and false fires.
    """
    defaults = [r for r in rules if r.config_source == SecurityRule.SOURCE_DEFAULT]
    if not defaults:
        return False
    return all(bool(r.log_end) for r in defaults)


def _app_block_above_permits(blocking: list[SecurityRule],
                             permitting: list[SecurityRule]) -> bool:
    """PAN-POL-007: a refusal matched on APPLICATIONS, evaluated before the permits it covers.

    "Above every permitting rule whose application set it intersects" is the assertion, and the
    intersection is what makes it narrower than "above everything": a refusal of `bittorrent`
    sitting below a permit of `web-browsing` still refuses bittorrent, because the permit cannot
    match it. So a blocking rule qualifies when no permitting rule it INTERSECTS is evaluated
    before it. A permitting rule whose application list is `any` intersects everything.
    """
    for rule in blocking:
        apps = {m.lower() for m in _members(rule, "securityruleapplications")}
        if not apps or ANY_KEYWORD in apps:
            continue
        intersected_above = False
        for permit in permitting:
            if permit.effective_order >= rule.effective_order:
                continue
            permit_apps = {m.lower() for m in _members(permit, "securityruleapplications")}
            if not permit_apps or ANY_KEYWORD in permit_apps or (permit_apps & apps):
                intersected_above = True
                break
        if not intersected_above:
            return True
    return False


def _ref_rows(rule: SecurityRule, side: str):
    return (rule.source_address_refs.all() if side == "source"
            else rule.destination_address_refs.all())


def _hostile_directions_missing(blocking: list[SecurityRule],
                                last_permit: int | None) -> int:
    """PAN-POL-017, as the COUNT of directions with no standing block - 0, 1 or 2.

    WHAT IS NOT DONE HERE AND WHY: this does NOT test the referenced name against the vendor's
    own hostile-list names. Stage 3 forbade carrying those ten names downstream and the reason
    is sound - they came from ONE appliance of three, the Help prints no slug for any of them,
    and the configurable list object has five type branches of which none is the predefined
    kind, so there is no path to create one. What IS tested is whether some blocking rule above
    the permits names an EXTERNAL LIST on that side.

    THE CONSEQUENCE IS A WIDER PASS THAN THE CONTROL ASKS FOR, and it is recorded rather than
    hidden: a rule naming a customer's own EDL satisfies this where a rule naming the vendor's
    predefined list is what the control means. The narrowing needs the predefined names as data,
    which is a read this domain does not have.
    """
    missing = 2
    for side in ("source", "destination"):
        for rule in blocking:
            if last_permit is not None and rule.effective_order > last_permit:
                continue
            for ref in _ref_rows(rule, side):
                obj = ref.address_object
                if obj is not None and obj.is_edl:
                    missing -= 1
                    break
            else:
                continue
            break
    return missing


def _names_a_region(rules: list[SecurityRule]) -> bool:
    """PAN-POL-018: does this vsys's policy say anything about geography at all.

    EITHER POLARITY OF ACTION COUNTS - a rule permitting only named regions expresses a boundary
    just as a rule refusing them does - and so does a DISABLED rule, because what is asserted is
    whether the policy expresses the decision rather than whether it is in force today.
    """
    for rule in rules:
        for side in ("source", "destination"):
            for ref in _ref_rows(rule, side):
                if ref.ref_type == ref.RefType.REGION:
                    return True
    return False


def _prestaged_blocklist(blocking: list[SecurityRule], last_permit: int | None) -> bool:
    """PAN-POL-019's standing blocklist rule: a responder's edit point, already in place.

    An ADDRESS GROUP or an EXTERNAL LIST on a side, because both are editable without touching
    the rule - which is the whole point of pre-staging one. A rule naming a literal address is
    not one: changing it is a rule edit and needs the same approval a new rule does.
    """
    for rule in blocking:
        if last_permit is not None and rule.effective_order > last_permit:
            continue
        for side in ("source", "destination"):
            for ref in _ref_rows(rule, side):
                if ref.address_group_id is not None:
                    return True
                obj = ref.address_object
                if obj is not None and obj.is_edl:
                    return True
    return False


def _port_matched_block(blocking: list[SecurityRule]) -> bool:
    """PAN-POL-003's mechanism half: a refusal matched on the PORT rather than the application.

    A service list naming something that is neither `any` nor `application-default`. Which
    services must be blocked is the estate's decision and is not asked here; the device ships
    service objects for HTTP and HTTPS and for nothing else, so every other port needs an object
    the customer builds and this answers only whether any such rule exists.
    """
    for rule in blocking:
        members = {m.lower() for m in _members(rule, "securityruleservices")}
        if not members:
            continue
        if members - {ANY_KEYWORD, APPLICATION_DEFAULT}:
            return True
    return False


__all__ = [
    "ALLOW_ACTION",
    "BLOCKING_ACTIONS",
    "MIN_RULES_FOR_PLACEMENT_RANKING",
    "RULE_HIT_COUNT_ABSENT",
    "SHADOW_CHECK_UNMEASURED",
    "appliance_merged_snapshot",
    "expand_port_leaf",
    "hit_count_rows",
    "hit_count_verdict",
    "normalize_policy_rule_settings",
    "normalize_security_rule_policy_posture",
    "normalize_vsys_rule_posture",
    "resolve_service_ports",
    "schedule_verdict",
]
