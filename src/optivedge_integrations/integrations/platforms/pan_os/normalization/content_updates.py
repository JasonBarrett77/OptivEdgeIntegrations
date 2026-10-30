"""Dynamic content update scheduling - PAN-UPD-001 to PAN-UPD-006.

TWO NORMALIZERS AT TWO GRAINS, in one module because they are one domain and one screen family,
and separated into two models because one is per APPLIANCE and the other per MANAGEMENT STATION.

`normalize_content_update_schedule` reads the merged device entry its neighbours read and owns the
`deviceconfig/system/update-schedule` subtree. `normalize_content_deployment_schedule` reads the
station's own `config_deployment_update_schedule` snapshot, which `collectors/content_updates.py`
takes, and is the only normalizer in this package anchored to a management station rather than to
an appliance or an enforcement point.

THE RECURRENCE IS A PRESENCE AND NOT A VALUE, which is the whole shape of the firewall half. Each
content type's `recurring` container holds AT MOST ONE branch element - the device enforces that
by silent replacement at the write - and the cadence is that element's own NAME. So the reader
asks which of a measured set of sibling names is present, and stores the name. A `threshold`,
`new-app-threshold` or `sync-to-peer` key sitting in the same container is NOT a cadence, which is
why the branch is resolved by intersecting against the measured set rather than by taking whatever
key is there.

THE ACTION'S KEY PATH CONTAINS THE IN-FORCE BRANCH'S NAME, so which key to read is itself a value:
the action leaf exists once per timed branch - `daily/action`, `hourly/action` - and the one that
matters is the one under whichever branch exists. That is why neither column can be a plain key
read and why both are computed here rather than claused on downstream.

AND THE TWO SIDES SPELL `action` DIFFERENTLY, which is the trap in this module. On the FIREWALL it
is a LEAF carrying `download-only` or `download-and-install`. On PANORAMA it is a CONTAINER whose
single child's presence is the value, and the device list hangs under that child -
`<branch>/action/download-and-install/devices/member`. Code written against either shape reads
nothing out of the other.
"""

from __future__ import annotations

from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    ContentDeploymentSchedule,
    ContentUpdateSchedule,
    ManagementStation,
    Snapshot,
)
from optivedge_integrations.integrations.models.content_updates import (
    ACTION_DOWNLOAD_AND_INSTALL,
    AV_RECURRENCES,
    GP_CLIENTLESS_VPN_RECURRENCES,
    GP_DATAFILE_RECURRENCES,
    NOT_SCHEDULED,
    ROLLOUT_MULTIPLE_DISJOINT,
    ROLLOUT_MULTIPLE_OVERLAPPING,
    ROLLOUT_NONE,
    ROLLOUT_SINGLE,
    SCOPE_DEVICE_LOCAL,
    SCOPE_PANORAMA_OWN,
    THREATS_RECURRENCES,
    WILDFIRE_RECURRENCES,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.content_updates import (
    DEPLOYMENT_UPDATE_SCHEDULE_SOURCE_TYPE,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ensure_list,
    parse_integer_field,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    write_node_row,
)


#: The five content types of the FIREWALL node, each with the column prefix its two columns carry
#: and the recurrence branch set measured for it. The config name and the column prefix differ for
#: the two GlobalProtect types, which is why this is a table rather than a derivation.
_FIREWALL_CONTENT_TYPES = (
    ("anti-virus", "av", AV_RECURRENCES),
    ("threats", "threats", THREATS_RECURRENCES),
    ("wildfire", "wildfire", WILDFIRE_RECURRENCES),
    ("global-protect-datafile", "gp_datafile", GP_DATAFILE_RECURRENCES),
    ("global-protect-clientless-vpn", "gp_clientless_vpn", GP_CLIENTLESS_VPN_RECURRENCES),
)

#: What an absent `threshold` or `new-app-threshold` means. NOTHING IS STORED, and the declaration
#: is deliberate rather than a gap: stage 4 records both keys as `implicit.status: unmeasured` with
#: `consumer_disposition: not_assumed`, because with the key deleted the dialog's Threshold field
#: renders ` [1 - 336]` as an emptyText HINT rather than a value - the UI says "nothing is set" and
#: cannot say what the device does with nothing set. Four vendor wordings disagree about what the
#: threshold even gates: help p.950 sentence 1 says INSTALLATION, sentence 2 on the same page says
#: DOWNLOAD, the config help-string names no action at all, and the dialog's on-screen help says a
#: content update must be at least this many hours old for "the action" to be taken.
#:
#: `Implicit.not_assumed` is what makes the column hold a real NULL: `parse_integer_field` returns
#: `implicit.value` on an absent key and this one's value is None. A materialised number here
#: would assert that a review window exists.
_THRESHOLD_ABSENT = Implicit.not_assumed(
    "what an absent Applications-and-Threats threshold does is UNMEASURED. stage4-updates.json "
    "records implicit.status=unmeasured / consumer_disposition=not_assumed / "
    "may_materialise=false for both `threshold` and `new-app-threshold`, because the only "
    "control goes blank: with the key deleted the schedule dialog renders ` [1 - 336]` as an "
    "emptyText hint rather than a value, and four vendor wordings disagree about what the "
    "threshold gates. Storing any number would assert a wait nobody measured")

#: The seven content-type children one PANORAMA entry chooses between. Measured by
#: `config_complete` at the entry on the lab's one management station: all seven are the same
#: shape, one child named `recurring`, at the same depth.
#:
#: ONE ENTRY HOLDS EXACTLY ONE OF THEM, ENFORCED BY SILENT REPLACEMENT. Writing a second
#: content-type element into an entry holding `app-and-threat` returned the entry holding ONLY the
#: new one, the whole first subtree gone, with no message - measured three times through one entry
#: on committed configuration. So a reader takes the FIRST that is present and a second would be a
#: state the device cannot hold.
_STATION_CONTENT_TYPES = (
    "anti-virus",
    "app",
    "app-and-threat",
    "cellular-firmware",
    "url-database",
    "wf-content",
    "wildfire",
)

#: Keys that sit in a `recurring` container and are NOT cadences. The firewall node's branch set
#: is measured, so the branch there is resolved by intersection and this list is belt and braces;
#: on the STATION the branch set was never enumerated, so this is what keeps a future sibling from
#: being reported as a cadence. Nothing downstream clauses on the station's cadence - it lands in
#: the `schedules` display column only - so a name this misses cannot move a verdict.
_NOT_A_CADENCE = frozenset({"threshold", "new-app-threshold", "sync-to-peer"})


def _as_dict(node) -> dict:
    """A container, or an empty one. An absent or scalar node is an empty container.

    Every walk in this module goes through here rather than through `node.get(...)` directly,
    because the merged view hands back a STRING for a node that happens to hold only text and
    `None` for one that is absent, and `.get` on either raises where the honest answer is "no
    children".
    """
    return node if isinstance(node, dict) else {}


def _schedule_node(snapshot: Snapshot) -> tuple[dict, dict]:
    """(`deviceconfig/system`, `deviceconfig/system/update-schedule`) of a merged snapshot.

    Both are returned because the COMPANION column is computed from the parent and the cadences
    from the child, and they answer different questions. `deviceconfig/system` carries hostname,
    timezone, the update server and much else on every firewall, so its emptiness is a sound proxy
    for "this appliance was not usefully read"; the child's absence is a real configuration state
    and means the appliance runs NO automatic retrieval for any content type.
    """
    entry = _as_dict(device_entry_from_snapshot(snapshot))
    system = _as_dict(_as_dict(entry.get("deviceconfig")).get("system"))
    return system, _as_dict(system.get("update-schedule"))


def _recurrence_and_action(content_node, branches: tuple[str, ...]) -> tuple[str, str]:
    """(cadence, action) for one content type of the FIREWALL node.

    The cadence is the name of whichever of `branches` is present under `recurring`, and the
    action is the `action` leaf under THAT branch. Both fall back to `none`, which is the measured
    reading of the absence in each case and is the firing side of every clause that names them:

    - no branch element at all means the appliance runs NO automatic retrieval for this content -
      nothing is checked for, nothing is downloaded and nothing is installed, and what it holds
      ages until a person installs by hand. Measured with a natural experiment that cost no
      writes: 013201001475 carried no `update-schedule` node whatsoever before stage 6's
      fixtures, and all three config views agreed.
    - an explicit `<none/>` branch means the same thing and parses to the key `none` with no
      value, which is why it needs no separate arm.
    - a branch present with NO `action` key means the scheduled run takes neither action.
      Measured on a COMMITTED timed branch carrying `at` and no `action`: `show config running`
      showed `daily: {at: "23:50"}` and nothing else, the screen rendered `(None, ...)`, and the
      dialog's OK button wrote nothing - which is what rules out "the rendered None is a value the
      form holds". WHAT IT DOES NOT ESTABLISH is what such a run actually DOES when it fires; no
      schedule was allowed to fire in the lab, and treating it as "retrieves nothing" is the safe
      direction.

    A BRANCH NAME THIS SET DOES NOT CARRY READS AS `none`, which fires. That is deliberate: the
    sets are the device's own, measured identically on two platforms and two major versions, and a
    cadence a later build adds should report rather than be reported as the one it resembles.
    """
    recurring = _as_dict(_as_dict(content_node).get("recurring"))
    present = [name for name in branches
               if name in recurring and name not in _NOT_A_CADENCE]
    if not present or present == [NOT_SCHEDULED]:
        return NOT_SCHEDULED, NOT_SCHEDULED
    # At most one can exist - silent replacement - so a second would be a state the device cannot
    # hold. Taking the first in the MEASURED order rather than in the payload's keeps the answer
    # stable if one ever does.
    branch = present[0]
    action, _, _ = scalar_value(_as_dict(recurring.get(branch)).get("action"))
    return branch, (action or NOT_SCHEDULED)


def normalize_content_update_schedule(appliance: Appliance) -> dict[str, int]:
    """One appliance's dynamic content update schedule, all five content types. PAN-UPD-001 to 005.

    Reads the MERGED snapshot, which is what stage 5 declared for every column and what a
    collector already issues. The view follows the CANDIDATE, so what lands here is what an
    administrator has typed rather than what the firewall enforces - stage 4 measured the
    divergence on this very object, with the candidate holding `at: 23:55` while
    `show config running` held `23:50`. The committed read that would settle it is costed in stage
    5 with `issued_today: false` and no column rests on it, so it is not issued here.

    NO ROW WITHOUT A SNAPSHOT, following the shipped node-row writer. An appliance with no merged
    snapshot is absent from every query rather than present and false, which is the one residual
    case `update_schedule_collected` cannot plug; it is recorded in stage 5's `not_stored` and is
    not this module's to fix.
    """
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"content_update_schedules": 0}
    system, schedule = _schedule_node(snapshot)

    collected = bool(system)
    values: dict[str, object] = {
        "scope": SCOPE_DEVICE_LOCAL,
        "update_schedule_collected": collected,
    }
    for config_name, prefix, branches in _FIREWALL_CONTENT_TYPES:
        if collected:
            recurrence, action = _recurrence_and_action(schedule.get(config_name), branches)
        else:
            # THE EMPTY STRING, WHICH FIRES. An appliance whose `deviceconfig/system` node arrived
            # empty was not usefully read, and `""` is not `daily` - so every negated equality in
            # this domain catches it with no companion column and no second firing group. `none`
            # here would say "we read it and nothing is scheduled" about a reply nobody received.
            recurrence, action = "", ""
        values[f"{prefix}_recurrence"] = recurrence
        values[f"{prefix}_action"] = action

    # THE TWO MEASURED COLUMNS, AND THE ONLY TWO KEYS THIS MODEL READS. Siblings of the branches
    # rather than children of one, confirmed on the device: one threshold governs whichever branch
    # is in force and survives a change of branch. They are read whether or not the parent node
    # answered, because `parse_integer_field` on an absent key returns the declared implicit -
    # NULL - which is the same thing an unread appliance holds.
    threats_recurring = _as_dict(_as_dict(schedule.get("threats")).get("recurring"))
    threshold, threshold_rk, threshold_rv = parse_integer_field(
        threats_recurring.get("threshold"), implicit=_THRESHOLD_ABSENT)
    new_app, new_app_rk, new_app_rv = parse_integer_field(
        threats_recurring.get("new-app-threshold"), implicit=_THRESHOLD_ABSENT)
    values["threats_threshold_hours"] = threshold
    values["threats_new_app_threshold_hours"] = new_app

    with transaction.atomic():
        write_node_row(
            ContentUpdateSchedule, appliance, snapshot, values,
            [("threats_threshold_hours", threshold_rk, threshold_rv),
             ("threats_new_app_threshold_hours", new_app_rk, new_app_rv)])
    return {"content_update_schedules": 1}


def latest_deployment_schedule_snapshot(
        management_station: ManagementStation) -> Snapshot | None:
    """The station's own content deployment schedules, as last collected.

    A MISSING SNAPSHOT IS "NOBODY ASKED" AND NOT "NO SCHEDULE", which is the distinction the whole
    station subject turns on. There is no station-scoped snapshot an estate is guaranteed to have
    - unlike the merged config, which every appliance has - so this returns None routinely and the
    caller writes the firing row rather than skipping it.
    """
    return (
        Snapshot.objects.filter(
            management_station=management_station,
            appliance__isnull=True,
            source_type=DEPLOYMENT_UPDATE_SCHEDULE_SOURCE_TYPE,
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def _station_entry(entry: dict) -> dict:
    """One deployment schedule entry, flattened to what the verdicts and the display both need.

    Returns `{name, enabled, content_type, recurrence, action, devices}`. The two parse hazards
    stage 4 measured are both handled here and neither is optional: WITHIN ONE RESPONSE some
    leaves arrive as bare strings and some as `{"#text": ...}` dicts, because the dict form is
    what a leaf still carrying `@dirtyId` looks like and after a commit that is per ELEMENT rather
    than per entry - so `scalar_value` is used for every leaf including the device members.

    `disabled` IS THE ONLY WAY TO SWITCH A DEPLOYMENT SCHEDULE OFF. There is no `none` branch on
    this object's recurrence - `<none/>` is refused `recurring -> none unexpected here` - so the
    firewall's way of saying "no schedule" does not exist here. An ABSENT `disabled` behaves as
    `no`: with the key committed as `yes` the operational oracle answers `Schedule "<n>" is
    disabled`, and with the key deleted and committed it answers the cadence and `is in waiting`.
    Stage 4 did not write an explicit `no`, so absent and explicit-`no` were not distinguished and
    it declines to promote the implicit; both read as ENABLED here, which is the reading the oracle
    supports and the one that counts a schedule towards governance rather than away from it.
    """
    disabled_text, _, _ = scalar_value(entry.get("disabled"))
    content_type = next((name for name in _STATION_CONTENT_TYPES if name in entry), "")
    recurring = _as_dict(_as_dict(entry.get(content_type)).get("recurring"))
    cadences = [name for name in recurring if name not in _NOT_A_CADENCE]
    recurrence = cadences[0] if cadences else ""
    action_node = _as_dict(_as_dict(recurring.get(recurrence)).get("action"))
    # A CONTAINER WHOSE SINGLE CHILD'S PRESENCE IS THE VALUE, not a text leaf - the opposite of
    # the firewall node's shape. `download-and-scp` is a third child the grammar offers and is
    # neither installing nor the plain download, so it is reported by its own name rather than
    # folded into either.
    action = next(iter(action_node), "")
    installing = _as_dict(action_node.get(ACTION_DOWNLOAD_AND_INSTALL))
    members = ensure_list(_as_dict(installing.get("devices")).get("member"))
    devices = sorted({text for text, _, _ in (scalar_value(m) for m in members) if text})
    name, _, _ = scalar_value(entry.get("@name"))
    return {
        "name": name,
        "enabled": disabled_text.strip().lower() != "yes",
        "content_type": content_type,
        "recurrence": recurrence,
        "action": action,
        "devices": devices,
    }


def _rollout_shape(installing: list[dict]) -> str:
    """The computable shape of the estate's content rollout, from the installing entries' lists.

    STAGING PHYSICALLY IS TWO SCHEDULES OVER TWO DISJOINT DEVICE LISTS, because the product has no
    ring, canary or test-group construct at all. So the only thing a computation can say is how
    many schedules install and whether their device lists overlap; whether a staging plan was
    INTENDED is what PAN-UPD-006's second record discharges onto an engineer.

    AN INSTALLING SCHEDULE WITH NO DEVICE LIST IS NOT A RING OF NOBODY AND IS NOT DISJOINT EITHER.
    An absent `devices` list asserts that the schedule installs to no firewall - measured - so two
    schedules where one names nobody cannot be shown to stage anything, and they read
    `multiple_overlapping`. That is the less-staged side of the two, which is the direction a
    reader should be wrong in: `multiple_disjoint` is the shape that looks deliberate.
    """
    if not installing:
        return ROLLOUT_NONE
    if len(installing) == 1:
        return ROLLOUT_SINGLE
    sets = [set(record["devices"]) for record in installing]
    if any(not covered for covered in sets):
        return ROLLOUT_MULTIPLE_OVERLAPPING
    for index, covered in enumerate(sets):
        for other in sets[index + 1:]:
            if covered & other:
                return ROLLOUT_MULTIPLE_OVERLAPPING
    return ROLLOUT_MULTIPLE_DISJOINT


def normalize_content_deployment_schedule(
        management_station: ManagementStation) -> dict[str, int]:
    """A verdict over one management station's content deployment schedules. PAN-UPD-006.

    ONE ROW PER STATION AND IT IS WRITTEN WHETHER OR NOT THE READ ANSWERED, which is the opposite
    of its appliance-side sibling and is deliberate. The commonest failing state is that NO
    schedule entry exists at all, and an entry-grained row cannot report that it does not exist;
    equally, a station nobody collected must not be absent from every query, because then an
    uncollected estate and a standalone one with no station at all read identically.

    THE THREE STATES THIS KEEPS APART, which every obvious reader collapses:

    - no snapshot: `deployment_schedule_read` false, both token columns EMPTY, both counts zero.
      Nobody asked.
    - a snapshot carrying no collection: `deployment_schedule_read` true,
      `central_schedule_state` `none`. Measured twice in this lab - the station held no schedule
      before stage 4's fixtures and holds none after them - and absence IS the finding for
      PAN-UPD-006's first half.
    - a snapshot carrying entries that are all disabled: `all_disabled`. An estate whose single
      schedule is disabled has no central governance whatsoever, and a count of entries reports
      one.

    `deployment_schedule_read` IS THE EXISTENCE OF THE SNAPSHOT AND NOT THE CONTENT OF A PARENT
    NODE, which differs from what stage 5 wrote for it. Stage 5's second `derived_from` clause
    names "the station's `deviceconfig/system` node within it carrying at least one key" - but the
    read stage 5 itself declared is addressed at `deployment-update-schedule` and carries no
    parent node to inspect, so that clause cannot be evaluated against this payload. The existence
    of the snapshot is the honest equivalent and sits on the SAME side of the assertion: no read,
    no snapshot, column false, and the control fires.
    """
    snapshot = latest_deployment_schedule_snapshot(management_station)
    entries: list[dict] = []
    if snapshot is not None:
        collection = _as_dict((snapshot.payload or {}).get("deployment-update-schedule"))
        entries = [_station_entry(_as_dict(raw))
                   for raw in ensure_list(collection.get("entry")) if isinstance(raw, dict)]

    if snapshot is None:
        values: dict[str, object] = {
            "scope": SCOPE_PANORAMA_OWN,
            "deployment_schedule_read": False,
            "central_schedule_state": "",
            "enabled_schedule_count": 0,
            "installing_schedule_count": 0,
            "rollout_staging_shape": "",
            "schedules": [],
        }
    else:
        enabled = [record for record in entries if record["enabled"]]
        installing = [record for record in entries
                      if record["action"] == ACTION_DOWNLOAD_AND_INSTALL]
        if not entries:
            state = NOT_SCHEDULED
        elif not enabled:
            state = "all_disabled"
        else:
            state = "enabled"
        values = {
            "scope": SCOPE_PANORAMA_OWN,
            "deployment_schedule_read": True,
            "central_schedule_state": state,
            "enabled_schedule_count": len(enabled),
            # EVERY INSTALLING ENTRY, ENABLED OR NOT, which is stage 5's wording - "the number of
            # schedule entries carrying a `download-and-install` action under their content
            # type's `recurring` branch" - and not a count of what is in force. A disabled
            # installing schedule installs nothing, so this count is wider than the behaviour;
            # `enabled` is carried per entry in `schedules` so the engineer PAN-UPD-006's second
            # record discharges onto can see which. Reported in the stage 7 artifact.
            "installing_schedule_count": len(installing),
            "rollout_staging_shape": _rollout_shape(installing),
            "schedules": entries,
        }

    with transaction.atomic():
        ContentDeploymentSchedule.objects.update_or_create(
            management_station=management_station,
            defaults={"source_snapshot": snapshot, **values},
        )
    return {"content_deployment_schedules": 1}
