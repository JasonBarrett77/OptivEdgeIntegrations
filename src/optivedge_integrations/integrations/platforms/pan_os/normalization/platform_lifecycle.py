"""Platform lifecycle normalization - PAN-PLT-001 to PAN-PLT-006.

SIX ENTRY POINTS, ONE PER CONCERN, and they are separate so that one failure does not cost
the other five: `flows.APPLIANCE_OBJECT_NORMALIZERS` catches per member, and these six read
four different payloads between them. None depends on another and they may be reordered.

    normalize_platform_content_streams          FirewallContentStreams + Appliance's one column
    normalize_globalprotect_portal_presence     GlobalProtectPortalPresence
    normalize_licence_inventory                 LicenceInventory + LicenceEntitlement
    normalize_log_alarm_settings                LogAlarmSettings
    normalize_configuration_backup_evidence     ConfigurationBackupEvidence
    normalize_dataplane_utilisation             DataplaneUtilisation

THERE WAS A SEVENTH, `normalize_device_telemetry_settings`, and ruling P374a deleted it on
2026-10-29: `device_services.py` covers that node with one model for both domains. Two of this
module's helpers survived that for a day and were removed on 2026-10-30 with the dedicated read
they served: `OptivEdgeProbe/reference/standing-rulings.md` section 5.

EVERY ROW IS ANCHORED TO THE MERGED SNAPSHOT, not to the read that fills it. An appliance that
was collected and never asked for its license table or its dataplane load still gets a row, with the companion column saying so - and the companion is the only thing in
any of these models that can separate "we never asked" from "we asked and it was fine". That
follows `MasterKey` and `DeviceIdentificationState`; no merged snapshot means no row, because
there is nothing to anchor to.

FOUR READS FILL THESE SEVEN, AND TWO OF THEM WERE ALREADY BEING ISSUED:

    show system info                  EXISTS - collectors/device_identification.py
    request license info              EXISTS - collectors/device_identification.py
    show config merged                EXISTS - every appliance, every collection
    config show at two deviceconfig nodes, and show running resource-monitor - NEW, this domain

WHAT THIS MODULE DOES NOT ASSUME, each because an oracle was looked for and not found:

  - a telemetry switch that is not in the committed configuration is NULL and not `no`;
  - `enable-alarm-generation` absent is NULL and not `no` - stage 4 took its ladder end to end
    on that node and still found no oracle, and the vendor's documented default is a LEAD this
    code may not promote: the Help documents one and its own field table on the same page
    states none;
  - a license table that answers `{"licenses": null}` is UNKNOWN, not "nothing licensed";
  - a dataplane whose cores all read 0 is not an idle dataplane and not an absent one.

THE CONTENT WINDOWS ARE THIS MODULE'S OWN NUMBERS and nothing upstream carries one - see
`APPLICATIONS_THREATS_MINIMUM_DAYS` below, where the choice and its cost are stated.

Measured on 013201001475 and 013201001085 (PA-5220, 11.1.13-h3), 6A9C0A9904E7D6E (PA-VM,
11.2.3-h3) and 691665AC334B458 (PA-VM, 11.2.5) on 2026-10-29. Appliances are named by SERIAL:
691665AC334B458 answers to the factory-default hostname `PA-VM` and has never had one set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    ConfigurationBackupEvidence,
    DataplaneUtilisation,
    FirewallContentStreams,
    GlobalProtectPortalPresence,
    LicenceEntitlement,
    LicenceInventory,
    LogAlarmSettings,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.platform_lifecycle import (
    RESOURCE_MONITOR_WINDOW,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ensure_list,
    entry_container,
    parse_text_field,
    parse_yes_no_field,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)
# IMPORTED RATHER THAN COPIED, and both are private to their module on purpose. `_content_age_days`
# carries a measurement this domain cannot re-derive: the appliance's OWN clock and its content
# release date are rendered in the same local frame, so subtracting one naive timestamp from the
# other is correct whatever that frame is - verified on the two PA-VMs, which report the same
# content instant as "02:35:51 GMT" and "19:35:51 PDT" and give an identical age. A private copy
# here would be a second place for that reasoning to rot. `_vsys_entries` is the fourth copy of a
# four-line walk whose own docstring explains why it was not promoted while four runs are changing
# this repository at once; importing it means there is no fifth.
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_identification import (
    _content_age_days as content_age_days,
    _licence_entries as licence_entries,
    latest_license_info_snapshot,
    latest_system_info_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.globalprotect import (
    _vsys_entries as vsys_entries,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    write_node_row,
)


# ---------------------------------------------------------------------------
# What a reply means when it does not say
# ---------------------------------------------------------------------------

#: A content stream's release date. An ABSENT key asserts that this reply carries no release
#: date for the stream and NOT that the stream is uninstalled - measured off a natural
#: experiment with the positive control inside one reply: both PA-5220s report a real
#: `app-version` of 8939-9248 with no `app-release-date` key at all, while on one PA-VM
#: `av-version` is 0 and `av-release-date` is absent beside an `app-release-date` that is
#: present. Set and unset in one answer, twice, in two directions.
RELEASE_DATE_IMPLICIT = Implicit.measured(
    "",
    "stage4-platform-lifecycle.json objects['system-info'].fields['app-release-date'].implicit "
    "is status=measured / consumer_disposition=measured / may_materialise=true: an absent "
    "release-date key asserts the reply carries no date for that stream and not that the stream "
    "is uninstalled. Measured on all four lab appliances 2026-10-28")

#: A telemetry sharing switch. NOT ASSUMED: nothing on the device says what it does with the
#: node missing, and the two directions are a firewall reported as opted out when nobody knows
#: against one reported as sharing when nobody knows. The lab now holds both states - the node
#: absent on one PA-VM, present with every switch `yes` on the other, present with every switch
#: `no` on both PA-5220s - and none of the three settles what ABSENCE asserts.
#: Every leaf of the alarm node. THE STRONGEST NEGATIVE STATEMENT IN THIS DOMAIN: the node is
#: absent in running on the appliances that have no fixture, so the keys genuinely lack a value
#: by construction - and the five-point bar still fails, because THERE IS NO ORACLE TO MOVE. A
#: config read-back of a key you just wrote watches nothing; `show system state filter` answers
#: NO_MATCHES for *alarm*; `show log alarm` answers `invalid client cli` through the API on all
#: four appliances; and Device > Log Settings has no route in the UI map. The vendor's
#: documented default is a LEAD and not a measurement - the Help documents one and its own field
#: table on the same page states none, and the Help has measured wrong before.
ALARM_LEAF_IMPLICIT = Implicit.not_assumed(
    "stage4-platform-lifecycle.json objects['common-criteria-alarm-generation'] records every "
    "leaf at implicit.status=unmeasured / consumer_disposition=not_assumed: absent on all four "
    "appliances in running, and the bar fails at points 3 and 4 because no instrument on the "
    "device reports what it does with the key absent")

#: `base-license-name`. THE ONE IMPLICIT IN THIS DOMAIN WHERE THE ABSENCE IS THE DISCRIMINATOR
#: AND A CONSUMER MAY ACT ON IT: absent on the platform-licence row and present on every
#: subscription row, across thirteen rows on two appliances, so an absent key asserts that this
#: row IS the base licence rather than a subscription on one. A second field agreed on the
#: partition independently - the rows lacking it describe themselves as capacity tiers.
BASE_LICENCE_IMPLICIT = Implicit.measured(
    "",
    "stage4-platform-lifecycle.json objects['license-info'].fields['base-license-name'].implicit "
    "is status=measured / may_materialise=true: eleven rows carry the key and the two that lack "
    "it are exactly the two whose `feature` is the platform name. Measured on 6A9C0A9904E7D6E "
    "and 691665AC334B458, 2026-10-28")

#: `expires`, `expired` and `description`. Present on every one of the thirteen rows measured, so
#: there is no absent state - and NO WRITE CAN CREATE A LICENCE ROW, which makes this a field
#: with no absent state available to anyone short of a differently-licensed appliance.
LICENCE_ROW_IMPLICIT = Implicit.not_assumed(
    "stage4-platform-lifecycle.json objects['license-info'] records these keys at "
    "implicit.status=unmeasured / consumer_disposition=not_assumed / may_materialise=false: "
    "present on every row read, and no write can create a license row to make one absent")


# ---------------------------------------------------------------------------
# The content currency windows
# ---------------------------------------------------------------------------

#: THESE FOUR NUMBERS ARE THIS MODULE'S AND NOTHING UPSTREAM CARRIES ONE. Stage 5 declares that
#: `content_currency_state` is "the difference between today and a reported date compared against
#: a per-stream window" and names no window; stage 3's severity ranks are stated in terms of
#: "past the window that stream is published on" and the number did not travel. So the choice is
#: made here, in one place, where it can be corrected without touching the classification:
#:
#:   applications and threats   published WEEKLY. Preferred 7 days - one publication cycle.
#:                              Minimum 14 - a release was skipped rather than merely missed.
#:   the malware streams        published DAILY. Preferred 1 day, minimum 7 - "a malware stream
#:                              frozen for days", which is stage 3's own phrase for its rank 2.
#:
#: WHAT A WRONG NUMBER COSTS, in the two directions: too tight reports a healthy estate, which
#: is checkable in a minute and arrives with the age attached; too loose passes a stale stream,
#: which is a customer told they are safe. They are set on the tight side for that reason, and
#: the decision is recorded in the stage 7 artifact's `spec_gaps` so stage 5 gets the signal.
APPLICATIONS_THREATS_MINIMUM_DAYS = 14
APPLICATIONS_THREATS_PREFERRED_DAYS = 7
MALWARE_MINIMUM_DAYS = 7
MALWARE_PREFERRED_DAYS = 1

#: The horizons on an entitlement. Thirty days is the VENDOR's own - a warning appears in the
#: system log daily once a licence is within thirty days of expiry - and ninety is stage 3's,
#: the point at which a renewal still fits in a normal purchasing cycle.
EXPIRY_WARNING_DAYS = LicenceInventory.EXPIRY_WARNING_DAYS
RENEWAL_HORIZON_DAYS = LicenceInventory.RENEWAL_HORIZON_DAYS

#: `expires` holds the literal `Never` on every licence in this estate, which no date parser
#: accepts. It is a SENTINEL and not a date: a control comparing this column against a horizon
#: meets a string that either errors or is silently dropped from the comparison.
NEVER_EXPIRES = "never"

#: The formats `request license info` has been seen to render a real expiry in. NOT MEASURED ON
#: THIS ESTATE - every licence here says `Never` - so this list is a candidate set and an expiry
#: it cannot read lands on the FIRING side, never the reassuring one. See `_days_until`.
_EXPIRY_FORMATS = ("%B %d, %Y", "%b %d, %Y", "%Y/%m/%d", "%Y-%m-%d", "%m/%d/%Y")

#: How a SUPPORT entitlement is recognised among the feature names. A word-boundary occurrence
#: of `support`, which is the same test stage 6's independent second reading made
#: (`entry[feature~'Support']`) and found nothing on either licensed appliance.
#:
#: THE DIRECTION OF ERROR IS NAMED BECAUSE IT IS THE UNSAFE ONE. A name containing `support`
#: that is not a support entitlement would be read as one, which moves this appliance off
#: `absent_from_inventory` - a finding - and onto a pass. The alternative, an exact list of names
#: nobody in this project has read, can never match and so always fires; that is the shipped
#: precedent one domain over (`IOT_SECURITY_FEATURE_NAMES`) and it was rejected here because
#: stage 6's second oracle used the substring and a reader comparing the two needs the same test.
#: No appliance in this estate holds a support row, so neither choice is exercised today.
SUPPORT_FEATURE_TOKEN = "support"


# ---------------------------------------------------------------------------
# Reading the replies
# ---------------------------------------------------------------------------

def _system_info_node(snapshot: Snapshot | None) -> dict[str, Any] | None:
    """`show system info`'s keys, or None where the read never happened.

    The reply is `{"system": {...}}` and a few captures carry the keys at the top level, so both
    are accepted. NONE AND {} ARE DIFFERENT ANSWERS HERE: None means no snapshot exists and the
    companion column must say so, while an empty dict is a reply that carried nothing.
    """
    if snapshot is None:
        return None
    payload = snapshot.payload
    if not isinstance(payload, dict):
        return {}
    system = payload.get("system")
    return system if isinstance(system, dict) else payload


def _latest(appliance: Appliance, source_type: str) -> Snapshot | None:
    """The newest snapshot of one source type for one appliance.

    The eleventh copy of this four-line query in `normalization/`, and it stays local for the
    reason `device_identification.py::_latest_appliance_snapshot` records: a shared
    `latest_appliance_snapshot(appliance, source_type)` is the right consolidation and it belongs
    to a change that owns every copy, not to one of four runs editing this repository at once.
    """
    return (
        Snapshot.objects.filter(appliance=appliance, source_type=source_type)
        .order_by("-collected_at", "-pk")
        .first()
    )


def latest_resource_monitor_snapshot(appliance: Appliance) -> Snapshot | None:
    return _latest(appliance, "show_running_resource_monitor")


# ---------------------------------------------------------------------------
# FirewallContentStreams, and the one new column on Appliance
# ---------------------------------------------------------------------------

#: The three streams PAN-PLT-002 asserts, as (column stem, payload key stem). Stage 3 scopes the
#: control to applications, antivirus and threats; the device dictionary and URL filtering
#: streams are stored and not graded.
ASSERTED_STREAMS = ("app", "av", "threat")

#: Which of the asserted streams is a malware stream, for the rank-2 verdict. WildFire is one
#: too and has no release-date key in the reply at all, so it can contribute "never installed"
#: and never "behind".
MALWARE_STREAMS = ("av",)


@dataclass(slots=True)
class NormalizedContentStreams:
    """One appliance's content streams, before persistence."""

    versions: dict[str, str] = field(default_factory=dict)
    release_dates: dict[str, str] = field(default_factory=dict)
    ages: dict[str, int | None] = field(default_factory=dict)
    device_certificate_status: str = ""
    collected: bool = False
    release_date_reported: bool = False
    currency_state: str = ""


def _is_never_installed(version: str) -> bool:
    """Is this version string the appliance's own spelling of "never installed"?

    TWO LITERALS FOR ONE STATE and both are TRUTHY: the four content streams answer `0` and the
    URL filtering stream answers `0000.00.00.000`. A truthiness test reports an uninstalled
    stream as installed and a numeric comparison treats `0` as the lowest version rather than as
    no version, so only a comparison against the literals is right.
    """
    return version.strip() in FirewallContentStreams.NEVER_INSTALLED_VERSIONS


def content_currency_state(normalized: NormalizedContentStreams) -> str:
    """Which content-currency state one appliance is in.

    THE EMPTY STRING IS A STATE THIS FUNCTION CAN RETURN and it is not in the column's choice
    list: it is what an uncollected appliance holds, it is not `current`, and the control's
    clause is a negated equality against `current` - so it FIRES. Returning a token for an
    appliance whose read never answered would be a verdict over a reply nobody received.

    THE ORDER IS THE SEVERITY ORDER AND EVERY BRANCH ABOVE `current` IS A FINDING. Stage 5 places
    four of the six at the control's baseline severity and `inside_minimum_outside_preferred`
    one below, so the only thing the order decides is WHICH reason a reader is given - and the
    never-installed and no-date-reported states are put first deliberately, because both say the
    arithmetic could not be performed rather than that it came out badly.
    """
    if not normalized.collected:
        return ""
    for stream in ("app", "av", "threat", "wildfire"):
        if _is_never_installed(normalized.versions.get(stream, "")):
            return "stream_never_installed"
    for stream in ASSERTED_STREAMS:
        version = normalized.versions.get(stream, "")
        if not version:
            # The read answered and this stream's version key was not in it. Treated as the
            # unreadable case rather than as uninstalled: an absent VERSION key has never been
            # measured on any appliance, so nothing says which it means.
            return "release_date_not_reported"
        if normalized.ages.get(stream) is None:
            return "release_date_not_reported"
    behind = [s for s in ("app", "threat")
              if (normalized.ages.get(s) or 0) > APPLICATIONS_THREATS_MINIMUM_DAYS]
    if behind:
        return "applications_and_threats_behind"
    if any((normalized.ages.get(s) or 0) > MALWARE_MINIMUM_DAYS for s in MALWARE_STREAMS):
        return "malware_stream_behind"
    outside_preferred = (
        any((normalized.ages.get(s) or 0) > APPLICATIONS_THREATS_PREFERRED_DAYS
            for s in ("app", "threat"))
        or any((normalized.ages.get(s) or 0) > MALWARE_PREFERRED_DAYS for s in MALWARE_STREAMS)
    )
    if outside_preferred:
        return "inside_minimum_outside_preferred"
    return "current"


def build_content_streams(system_node: dict[str, Any] | None,
                          collected_at: datetime | None) -> NormalizedContentStreams:
    """Every column of the content-streams row, from one `show system info` reply.

    Separated from persistence so it can be exercised against a captured payload without a
    database, which is how this domain's readback was taken.
    """
    normalized = NormalizedContentStreams(collected=system_node is not None)
    system = system_node or {}

    for stream, key in (("app", "app-version"), ("av", "av-version"),
                        ("threat", "threat-version"), ("wildfire", "wildfire-version"),
                        ("url_filtering", "url-filtering-version"),
                        ("device_dictionary", "device-dictionary-version")):
        normalized.versions[stream] = str(system.get(key) or "").strip()

    for stream, key in (("app", "app-release-date"), ("av", "av-release-date"),
                        ("threat", "threat-release-date"),
                        ("device_dictionary", "device-dictionary-release-date")):
        # THE MATERIALISED DEFAULT AND THE NEVER-COLLECTED STATE ARE THE SAME EMPTY STRING, which
        # is deliberate and is why the companion column exists: a clause asserting a date is
        # present fires on both, which is the safe direction. What the column must never be read
        # as is a proxy for installation - on both PA-5220s "no date reported" is true while
        # "content installed" is also true.
        value, _raw_key, _raw_prov = parse_text_field(
            system.get(key), implicit=RELEASE_DATE_IMPLICIT)
        normalized.release_dates[stream] = value.strip()

    for stream in ASSERTED_STREAMS:
        normalized.ages[stream] = content_age_days(
            system, normalized.release_dates.get(stream, ""), collected_at)

    normalized.device_certificate_status = str(system.get("device-certificate-status") or "").strip()

    # EVERY ASSERTED STREAM THAT IS INSTALLED REPORTED A DATE. The version is consulted beside
    # the date so an uninstalled stream is not reported as a missing date - which is the
    # comparison between two columns that no predicate can make.
    if normalized.collected:
        installed = [s for s in ASSERTED_STREAMS
                     if normalized.versions.get(s)
                     and not _is_never_installed(normalized.versions[s])]
        normalized.release_date_reported = bool(installed) and all(
            normalized.release_dates.get(s) for s in installed)

    normalized.currency_state = content_currency_state(normalized)
    return normalized


def normalize_platform_content_streams(appliance: Appliance) -> dict[str, int]:
    """One appliance's content streams, and the one `show system info` key `Appliance` lacks.

    `Appliance.device_certificate_status` IS WRITTEN HERE AND NOT BY THE TOPOLOGY NORMALIZER
    that fills the rest of that row, because the read which fills the rest - `show managed
    devices` - does not carry the key at all. It is written blank where this collection did not
    take `show system info`, which is the honest reading: blank means nobody looked, and the
    word `None` means the appliance looked and has no certificate.
    """
    merged = latest_merged_snapshot(appliance)
    if merged is None:
        return {"firewall_content_streams": 0}

    system_snapshot = latest_system_info_snapshot(appliance)
    normalized = build_content_streams(
        _system_info_node(system_snapshot),
        system_snapshot.collected_at if system_snapshot is not None else None,
    )

    with transaction.atomic():
        write_node_row(
            FirewallContentStreams, appliance, merged,
            {
                "app_version": normalized.versions["app"],
                "app_release_date": normalized.release_dates["app"],
                "av_version": normalized.versions["av"],
                "av_release_date": normalized.release_dates["av"],
                "threat_version": normalized.versions["threat"],
                "threat_release_date": normalized.release_dates["threat"],
                "wildfire_version": normalized.versions["wildfire"],
                "url_filtering_version": normalized.versions["url_filtering"],
                "device_dictionary_version": normalized.versions["device_dictionary"],
                "device_dictionary_release_date":
                    normalized.release_dates["device_dictionary"],
                "release_date_reported": normalized.release_date_reported,
                "content_streams_collected": normalized.collected,
                "content_currency_state": normalized.currency_state,
            })
        Appliance.objects.filter(pk=appliance.pk).update(
            device_certificate_status=normalized.device_certificate_status)
    return {"firewall_content_streams": 1, "appliance_certificate_status": 1}


# DEVICE TELEMETRY IS NORMALIZED IN `device_services.py` AND NOT HERE, by ruling P374a,
# 2026-10-29. `normalize_device_telemetry_settings`, `build_device_telemetry` and
# `TELEMETRY_SWITCH_IMPLICIT` were deleted with the model they filled. Two snapshot helpers stayed
# for a day so that normalizer could read a dedicated committed snapshot of the node, and went on
# 2026-10-30 when the read did: `OptivEdgeProbe/reference/standing-rulings.md` section 5, A CONTROL
# USES THE CONFIGURATION THAT WAS COLLECTED.


# ---------------------------------------------------------------------------
# GlobalProtectPortalPresence
# ---------------------------------------------------------------------------

#: Strongest first. An appliance spans several vsys and the row is one verdict over all of them,
#: so the state reported is the strongest shape found anywhere - a portal in vsys3 makes the
#: appliance a portal whatever vsys1 holds.
_PORTAL_STATE_ORDER = (
    "entries_present",
    "container_staged_uncommitted",
    "container_empty",
    "container_absent",
)


def portal_container_state(vsys_entry: dict[str, Any]) -> tuple[str, int]:
    """(state, entry count) for one vsys's portal container, telling FOUR shapes apart.

    `entry_container` already separates three of them and its docstring records why that matters
    - a reader testing truthiness reports absent and empty identically. The fourth is this
    domain's: a container carrying ONLY candidate decorations and no entry at all, measured as
    `{"@admin": "admin", "@dirtyId": "50", ...}`, which is a portal somebody STAGED and never
    committed. `entry_container` classes it `empty`, correctly for its own purpose, and an
    appliance reported as a portal on the strength of it would have an advisory triaged onto a
    firewall with no portal configured.
    """
    state, entries = entry_container(vsys_entry, "global-protect", "global-protect-portal")
    if state == "populated":
        return "entries_present", len(entries)
    if state == "empty":
        parent = vsys_entry.get("global-protect")
        holder = parent.get("global-protect-portal") if isinstance(parent, dict) else None
        if isinstance(holder, dict) and holder and all(
                str(key).startswith("@") for key in holder):
            return "container_staged_uncommitted", 0
        return "container_empty", 0
    return "container_absent", 0


def build_portal_presence(snapshot: Snapshot) -> dict[str, Any]:
    """The verdict over every vsys of one appliance.

    THE VSYS SWEEP IS THE WHOLE POINT. Stage 4 measured a vsys1-only read answering `No such
    node` on an appliance whose own sweep lists a portal under a different vsys, and both
    PA-5220s are in that state - so a reader of vsys1 reports "not a portal" on half this
    estate. The merged payload names every vsys the device's own `/vsys` carries, which is why
    it is read here instead of the per-vsys get stage 5 declared.
    """
    device_entry = device_entry_from_snapshot(snapshot)
    vsys_node = device_entry.get("vsys") if isinstance(device_entry, dict) else None
    raw = ensure_list((vsys_node or {}).get("entry")) if isinstance(vsys_node, dict) else []
    parsed = vsys_entries(snapshot)

    count = 0
    states: set[str] = set()
    for _name, entry in parsed:
        state, entries = portal_container_state(entry)
        count += entries
        states.add(state)

    if not parsed:
        # Nothing was read for a portal at all. `not_collected` rather than `container_absent`:
        # the second would claim the appliance has no portal, which nobody established.
        container_state = "not_collected"
    else:
        container_state = next(s for s in _PORTAL_STATE_ORDER if s in states)

    total, read = len(raw), len(parsed)
    if read == 0:
        coverage = "no_vsys_read"
    elif read < total:
        coverage = "some_vsys_unread"
    else:
        coverage = "every_vsys_read"

    return {
        "portal_entry_count": count,
        "portal_container_state": container_state,
        "portal_vsys_coverage": coverage,
        "vsys_read_count": read,
        "vsys_total_count": total,
    }


def normalize_globalprotect_portal_presence(appliance: Appliance) -> dict[str, int]:
    """Whether one appliance is a GlobalProtect portal, across every vsys. PAN-PLT-003's input.

    NOT THE SAME ROW AS `GlobalProtectEnforcementPoint`, which another domain writes one of per
    VSYS with its own `portal_count`. This is one per APPLIANCE and spans every vsys, which is
    what PAN-PLT-003 asks and what a per-vsys row cannot answer without a quantifier no
    predicate has. The overlap is real; reconciling the two is a product decision.
    """
    merged = latest_merged_snapshot(appliance)
    if merged is None:
        return {"globalprotect_portal_presences": 0}
    with transaction.atomic():
        write_node_row(
            GlobalProtectPortalPresence, appliance, merged, build_portal_presence(merged))
    return {"globalprotect_portal_presences": 1}


# ---------------------------------------------------------------------------
# LicenceInventory and LicenceEntitlement
# ---------------------------------------------------------------------------

def _days_until(expires: str, now: datetime | None) -> int | None:
    """Whole days until a reported expiry, or None where there is no readable date.

    `Never` returns None and so does a string no candidate format reads, and the CALLER keeps
    those two apart from a date it could read - because a null here must never be allowed to
    pass a horizon test. Every license in this estate says `Never`.
    """
    text = (expires or "").strip()
    if not text or text.lower() == NEVER_EXPIRES:
        return None
    for fmt in _EXPIRY_FORMATS:
        try:
            when = datetime.strptime(text, fmt)
        except ValueError:
            continue
        reference = (now or datetime.utcnow()).replace(tzinfo=None)
        return (when - reference).days
    return None


def _is_support_feature(feature: str) -> bool:
    """Does this feature name a SUPPORT entitlement? See SUPPORT_FEATURE_TOKEN for the direction."""
    words = "".join(c if c.isalnum() else " " for c in (feature or "").lower()).split()
    return SUPPORT_FEATURE_TOKEN in words


@dataclass(slots=True)
class NormalizedLicenceInventory:
    """One appliance's entitlement verdict, before persistence."""

    inventory_read: str = ""
    row_count: int = 0
    expired_count: int = 0
    expiring_count: int = 0
    entitlement_state: str = ""
    support_state: str = ""
    features_held: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)


def _entitlement_state(read: str, expired: int, expiring: int,
                       soonest: int | None, unreadable: bool) -> str:
    """Which state the whole entitlement set is in, worst first.

    AN UNREADABLE EXPIRY LANDS ON `active_inside_90_days`, WHICH IS A FINDING, and the choice is
    named because stage 5's vocabulary has no token for it. The vendor's own `expired` flag is
    read first and covers the failure that matters, so what is left unresolved by an unreadable
    date is only HOW SOON a live entitlement lapses - and the lowest placed finding band says
    that without asserting a thirty-day claim the device did not support.
    `active_beyond_90_days` is the only token this function may not reach on an unknown: it is
    the one the control's clause passes.
    """
    if read == "not_collected":
        return "inventory_not_collected"
    if read == "null_licenses_element":
        return "no_licence_rows_returned"
    if expired:
        return "expired_entitlement_present"
    if expiring:
        return "expiring_within_30_days"
    if unreadable:
        return "active_inside_90_days"
    if soonest is not None and soonest <= RENEWAL_HORIZON_DAYS:
        return "active_inside_90_days"
    return "active_beyond_90_days"


def _support_state(read: str, rows: list[dict[str, Any]], now: datetime | None) -> str:
    """Whether a support entitlement is present and how much of its term remains.

    NO APPLIANCE IN THIS ESTATE CARRIES ONE, so `absent_from_inventory` is the value every row
    holds today - and it is a FINDING at the baseline severity rather than a pass, because an
    absent row is the same shape as a subscription nobody bought and stage 3's rank 1
    consequence, software updates gone until renewal, is what it cannot be distinguished from.
    """
    if read == "not_collected":
        return "inventory_not_collected"
    support = [row for row in rows if _is_support_feature(str(row.get("feature") or ""))]
    if not support:
        return "absent_from_inventory"
    if any(row.get("expired") is True for row in support):
        return "expired"
    remaining = [d for d in (_days_until(str(row.get("expires") or ""), now) for row in support)
                 if d is not None]
    if remaining and min(remaining) <= RENEWAL_HORIZON_DAYS:
        return "expires_within_90_days"
    # A support row that is present, not flagged expired and whose expiry reads `Never` or
    # unreadably: `Never` is a real answer and beyond any horizon. An unreadable one takes the
    # same branch, which is the one place this function can reach the passing token on an
    # unknown - and it is reachable only with a support row present, which nothing here has.
    return "active_beyond_90_days"


def build_licence_inventory(licence_snapshot: Snapshot | None) -> NormalizedLicenceInventory:
    """The verdict and the per-row readings, from one `request license info` reply.

    THREE SHAPES AND THE THIRD IS THE TRAP, which is why `licence_entries` is imported rather
    than rewritten: `{"licenses": null}` is TRUTHY at the outer dict and falsy one level in, and
    `result["licenses"]["entry"]` raises TypeError on it. Three readings of one reply and only
    the middle one is right. It is also the shape BOTH PA-5220s answer with.
    """
    normalized = NormalizedLicenceInventory()
    if licence_snapshot is None:
        normalized.inventory_read = "not_collected"
        normalized.entitlement_state = _entitlement_state("not_collected", 0, 0, None, False)
        normalized.support_state = _support_state("not_collected", [], None)
        return normalized

    entries = licence_entries(licence_snapshot.payload)
    if entries is None:
        # NO `licenses` KEY AT ALL - a shape nobody has seen. Read as not collected rather than
        # as an empty inventory: a reply that does not carry the element is not a statement about
        # what is licensed, and `not_collected` is the token that fires.
        normalized.inventory_read = "not_collected"
        normalized.entitlement_state = _entitlement_state("not_collected", 0, 0, None, False)
        normalized.support_state = _support_state("not_collected", [], None)
        return normalized

    now = licence_snapshot.collected_at
    for entry in entries:
        feature = str(entry.get("feature") or "").strip()
        if not feature:
            # A row with no feature name cannot be keyed and is not written. Measured present on
            # every one of the thirteen rows read across two appliances, so this is a guard
            # rather than a case anybody has seen.
            continue
        expires, expires_rk, expires_rv = parse_text_field(
            entry.get("expires"), implicit=LICENCE_ROW_IMPLICIT)
        expired, expired_rk, expired_rv = parse_yes_no_field(
            entry.get("expired"), implicit=LICENCE_ROW_IMPLICIT)
        base, base_rk, base_rv = parse_text_field(
            entry.get("base-license-name"), implicit=BASE_LICENCE_IMPLICIT)
        description, desc_rk, desc_rv = parse_text_field(
            entry.get("description"), implicit=LICENCE_ROW_IMPLICIT)
        normalized.rows.append({
            "feature": feature,
            "values": {
                "expires": expires.strip(),
                # UN-INVERTED: the vendor's key names the FAILURE, so True means EXPIRED. Stage 4
                # measured this as the only negated polarity in the domain and warned that a
                # normalizer storing it without knowing stores the opposite of "licensed".
                "expired": expired,
                "base_license_name": base.strip(),
                "description": description.strip(),
            },
            "provenance": [
                ("expires", expires_rk, expires_rv),
                ("expired", expired_rk, expired_rv),
                ("base_license_name", base_rk, base_rv),
                ("description", desc_rk, desc_rv),
            ],
            "expires_text": expires.strip(),
        })

    normalized.inventory_read = "rows_returned" if normalized.rows else "null_licenses_element"
    normalized.row_count = len(normalized.rows)
    normalized.features_held = sorted(row["feature"] for row in normalized.rows)

    live = [row for row in normalized.rows if row["values"]["expired"] is not True]
    normalized.expired_count = sum(
        1 for row in normalized.rows if row["values"]["expired"] is True)
    unreadable = False
    horizons: list[int] = []
    for row in live:
        text = row["expires_text"]
        days = _days_until(text, now)
        if days is not None:
            horizons.append(days)
        elif text and text.lower() != NEVER_EXPIRES:
            unreadable = True
    normalized.expiring_count = sum(1 for d in horizons if d <= EXPIRY_WARNING_DAYS)
    normalized.entitlement_state = _entitlement_state(
        normalized.inventory_read, normalized.expired_count, normalized.expiring_count,
        min(horizons) if horizons else None, unreadable)
    normalized.support_state = _support_state(
        normalized.inventory_read,
        [{"feature": r["feature"], **r["values"]} for r in normalized.rows], now)
    return normalized


def normalize_licence_inventory(appliance: Appliance) -> dict[str, int]:
    """One appliance's entitlement verdict AND its per-entitlement rows. PAN-PLT-004.

    BOTH GRAINS IN ONE PASS, because they come from one reply and splitting them would read it
    twice and let the count disagree with the rows it counted.

    STALE ROWS ARE DELETED. An entitlement that lapses off an appliance's table would otherwise
    leave a row behind, and a stale entitlement row is a false statement about what the appliance
    holds rather than merely an old one.
    """
    merged = latest_merged_snapshot(appliance)
    if merged is None:
        return {"licence_inventories": 0, "licence_entitlements": 0}

    normalized = build_licence_inventory(latest_license_info_snapshot(appliance))

    with transaction.atomic():
        write_node_row(
            LicenceInventory, appliance, merged,
            {
                "licence_inventory_read": normalized.inventory_read,
                "licence_row_count": normalized.row_count,
                "expired_entitlement_count": normalized.expired_count,
                "expiring_within_30_days_count": normalized.expiring_count,
                "entitlement_state": normalized.entitlement_state,
                "support_entitlement_state": normalized.support_state,
                "entitlement_features_held": normalized.features_held,
            })
        for row in normalized.rows:
            write_node_row(
                LicenceEntitlement, appliance, merged, row["values"], row["provenance"],
                lookup={"appliance": appliance, "feature": row["feature"]})
        # `write_node_row` WITH A WIDER `lookup` PLUS AN EXPLICIT SWEEP, which is a deliberate
        # departure from the delete-and-recreate shape the project's own notes record for a
        # collection-grained model. `update_or_create` cannot remove a row, so the sweep is what
        # stops a lapsed entitlement reporting configuration the appliance no longer holds - and
        # the provenance rows go with it, because `ProvenancedMixin` declares a `GenericRelation`
        # and a delete cascades through it. Recreating every row instead would churn primary keys
        # on a table whose rows are stable for years and whose identity is a vendor-issued name.
        LicenceEntitlement.objects.filter(appliance=appliance).exclude(
            feature__in=[row["feature"] for row in normalized.rows]).delete()
    return {"licence_inventories": 1, "licence_entitlements": len(normalized.rows)}


# ---------------------------------------------------------------------------
# LogAlarmSettings
# ---------------------------------------------------------------------------

#: The thirteen children of `log-databases-alarm-threshold`, which is the node's own ceiling and
#: NOT the number of log databases: `show system logdb-quota` reports about twenty-five log
#: types, so twelve or more quota'd databases have no alarm threshold available at ANY value and
#: "every log database is thresholded" is false by construction. Read from the payload rather
#: than against this list, so a fourteenth child the vendor adds is counted; the list is here
#: because the ceiling is what a reader of the count needs.
LOG_DB_ALARM_THRESHOLD_CEILING = LogAlarmSettings.LOG_DB_ALARM_THRESHOLD_CEILING


def alarm_mechanism_state(*, answered: bool, node_present: bool, generation: bool | None,
                          threshold_count: int, route_present: bool) -> str:
    """Which alarm-mechanism state one appliance is in, worst first.

    THE EMPTY STRING IS A STATE THIS FUNCTION RETURNS and it is not in the column's choice list:
    it is what an appliance whose committed read never answered holds, it is not
    `on_with_thresholds_and_route`, and the control's clause is a negated equality against that
    token - so it FIRES. `node_absent` is NOT used for it, because that token is a claim about
    the device and only a read that answered can make it.

    THE ORDERING IS STAGE 3's AND A SET OF CLAUSES CANNOT EXPRESS IT: "on but with no threshold"
    is worse than "on with thresholds and no route", which no conjunction says.
    """
    if not answered:
        return ""
    if not node_present:
        return "node_absent"
    if generation is not True:
        # NULL TAKES THIS BRANCH TOO and the token says `generation_off`, which is the one place
        # this classification cannot keep "off" and "unknown" apart: the node is present, the
        # master switch is not in it, and what the device does then is unmeasured. The companion
        # column is what a reader consults, and the direction is the firing one either way.
        return "generation_off"
    if threshold_count == 0:
        return "on_without_thresholds"
    if not route_present:
        return "on_with_thresholds_no_route"
    return "on_with_thresholds_and_route"


def build_log_alarm_settings(
        answered: bool, node: dict[str, Any] | None) -> tuple[dict[str, Any], list]:
    """(values, provenance rows) for one appliance's alarm node.

    PROVENANCE IS WRITTEN AND ON THIS SUBJECT IT CAN ONLY EVER SAY `not_configured` -
    "normalization declined to guess" - which is the point: an absent key here is the only state
    this estate holds, and a missing row would say "nothing tracks this field" instead.

    THE MARKER IS THE VALUE'S OWN AND NEVER AN ANCESTOR'S. Stage 4 measured the PARENT carrying
    `@src: tpl` and `@ptpl: ptpl_fw-core-tpa` on one PA-5220 while holding no children at all,
    so inheriting it would label a non-existent local value as template-supplied and name a
    template that supplies nothing.
    """
    # PRESENT MEANS THE CONTAINER EXISTS, EVEN HOLDING NOTHING. An emptied container is a
    # different verdict from an absent node, and stage 6's own teardown note says so: deleting
    # the leaves alone leaves something that reads as present.
    present = node is not None
    generation, gen_rk, gen_rv = parse_yes_no_field(
        (node or {}).get("enable-alarm-generation"), implicit=ALARM_LEAF_IMPLICIT)
    cli, cli_rk, cli_rv = parse_yes_no_field(
        (node or {}).get("enable-cli-alarm-notification"), implicit=ALARM_LEAF_IMPLICIT)
    web, web_rk, web_rv = parse_yes_no_field(
        (node or {}).get("enable-web-alarm-notification"), implicit=ALARM_LEAF_IMPLICIT)

    thresholds: dict[str, int] = {}
    container = (node or {}).get("log-databases-alarm-threshold")
    if isinstance(container, dict):
        for key, raw in container.items():
            if str(key).startswith("@"):
                continue
            # THE PARENT IS A CONTAINER ONLY, measured against stage 2's claim that it is a
            # leaf-plus-container: a write of 90 at the parent was REFUSED, and the CLI grammar
            # agrees - `set ... log-databases-alarm-threshold` carries no <value> placeholder
            # where every one of its children carries <0-100>.
            text = str(raw if not isinstance(raw, dict) else raw.get("#text") or "").strip()
            try:
                thresholds[str(key)] = int(text)
            except ValueError:
                continue
    # THE CONTAINER'S OWN PROVENANCE, READ OFF THE CONTAINER AND NOT OFF A CHILD. It holds no
    # value of its own, so `parse_text_field` returns the empty string either way - what is
    # wanted from it is the raw key: the Implicit where the node was never read (a
    # `not_configured` row, which is the only thing this subject can ever say) against the
    # container's own marker where it was.
    _container_value, thr_rk, thr_rv = parse_text_field(
        container, implicit=ALARM_LEAF_IMPLICIT)

    route_present = cli is True or web is True
    # KNOWN MEANS THE READ ANSWERED AND THE NODE CARRIED THE MASTER SWITCH, which is stage 5's
    # own wording and is NOT the same as the read answering. THE READBACK CAUGHT THIS: the first
    # version of this line read `known = answered`, and on both PA-5220s - where the committed
    # read answers `No such node` - it stored TRUE beside an `alarm_generation_enabled` of NULL.
    # That is the exact circularity the companion exists to prevent: the column that says "is
    # this unknown" was claiming the unknown was known, so a control trusting it would have
    # reported two appliances as measured when nothing on them had been read. The node answering
    # is recorded separately, in `alarm_settings_node_present`.
    #
    # ONE COMPANION FOR EVERY BOOLEAN ON THIS MODEL, not one each: all three measured booleans
    # come from the same node by the same read, so three separate companions would be three
    # copies of one fact.
    known = answered and isinstance(node, dict) and "enable-alarm-generation" in node

    values = {
        "alarm_settings_node_present": present,
        "alarm_generation_enabled": generation,
        "alarm_generation_enabled_known": known,
        "log_db_alarm_thresholds": thresholds,
        "log_db_alarm_threshold_count": len(thresholds),
        # NULL WHERE NO LOG TYPE CARRIES A THRESHOLD, not zero: zero is a WRITABLE value whose
        # meaning is unmeasured - the device accepted it where -1 and 101 were refused - so
        # storing it for "none recorded" would put a value a query ranks as the gentlest setting
        # where the absence belongs.
        "log_db_alarm_threshold_lowest": min(thresholds.values()) if thresholds else None,
        "cli_alarm_notification_enabled": cli,
        "web_alarm_notification_enabled": web,
        "alarm_notification_route_present": route_present,
        # THE VERDICT IS COMPUTED FROM `answered` AND NOT FROM `known`, deliberately: an
        # appliance whose node is genuinely absent is a state the device reported, and
        # `node_absent` is the token for it. Passing `known` here would blank the verdict on
        # exactly the three appliances whose absence this domain was built to report.
        "alarm_mechanism_state": alarm_mechanism_state(
            answered=answered, node_present=present, generation=generation,
            threshold_count=len(thresholds), route_present=route_present),
    }
    provenance = [
        ("alarm_generation_enabled", gen_rk, gen_rv),
        ("cli_alarm_notification_enabled", cli_rk, cli_rv),
        ("web_alarm_notification_enabled", web_rk, web_rv),
        ("log_db_alarm_thresholds", thr_rk, thr_rv),
    ]
    return values, provenance


def normalize_log_alarm_settings(appliance: Appliance) -> dict[str, int]:
    """One appliance's log-database alarm mechanism. PAN-PLT-006's first half.

    FROM THE MERGED CONFIGURATION THIS PASS ALREADY COLLECTED, per `standing-rulings.md` section
    5 - a control uses the configuration that was collected. It read a dedicated
    `type=config&action=show` of this one node until 2026-10-30.

    THE JUSTIFICATION FOR THAT READ WAS TRUE WHEN WRITTEN AND STALE WHEN APPLIED, and that is the
    part worth keeping. `collect_log_alarm_settings` says the node "was absent on all four lab
    appliances, at the container and at all twenty-one leaves, and the 1.2 MB merged body
    contains no `common-criteria-alarm-generation` string at all - so the claim that the merged
    view carries this node is UNTESTED and could not be tested on this estate." Both halves are
    now false. Measured read-only on 2026-10-30: the node is PRESENT in running on two appliances,
    with different values on each, and `show config merged` carries it byte-for-byte identically
    on both - `action=show` and the merged node compared field by field, equal. Somebody built
    those fixtures after that sentence was written and nothing re-read it.

    AND THE GENERAL RULE THAT FOLLOWS, which is why no other domain should repeat this: a
    config-mode `show` that SUCCEEDS is reading the running configuration, so whatever it returned
    is in the merged configuration too. A successful `action=show` can therefore never justify its
    own collection. The only thing a dedicated read tells you that the merged view cannot is the
    candidate-versus-running difference, and section 5 is the ruling that closes that question.
    """
    merged = latest_merged_snapshot(appliance)
    if merged is None:
        return {"log_alarm_settings": 0}
    node = device_entry_from_snapshot(merged)
    # THE PARENT IS SHARED FURNITURE and a walk must not raise on a missing step:
    # `deviceconfig/setting/management` also carries `hostname-type-in-syslog`, `quota-settings`
    # and another domain's `enable-certificate-expiration-check`, so any of these may be absent
    # on an appliance that holds the others.
    for step in ("deviceconfig", "setting", "management", "common-criteria-alarm-generation"):
        node = node.get(step) if isinstance(node, dict) else None
    # `answered` IS NOW ALWAYS TRUE where a row is written at all: the merged snapshot exists -
    # the early return above is what handles its absence - so the read did happen. What varies is
    # whether the NODE is in it, which is `node is None`, and `build_log_alarm_settings` already
    # separates those two for the reason its own docstring gives.
    answered, node = True, (node if isinstance(node, dict) else None)
    values, provenance = build_log_alarm_settings(answered, node)
    with transaction.atomic():
        write_node_row(LogAlarmSettings, appliance, merged, values, provenance)
    return {"log_alarm_settings": 1}


# ---------------------------------------------------------------------------
# ConfigurationBackupEvidence
# ---------------------------------------------------------------------------

def normalize_configuration_backup_evidence(appliance: Appliance) -> dict[str, int]:
    """What the firewall records about its own backups, which is nothing this control can use.

    BOTH COLUMNS ARE WRITTEN AT THEIR FIRING VALUES AND THAT IS NOT A STUB. `show config saved`
    takes a MANDATORY argument - the bare form answers code=17 on all four lab appliances,
    re-measured by this run - and nothing in the 70,462-command CLI index lists the snapshot
    names, so there is no enumeration instrument to collect from. `on_box_snapshot_list_collected`
    is therefore false on every appliance in every estate until one is built, which is BOTH its
    until-renormalized value and its true one, and the count beside it is zero because a count
    with no enumeration behind it reads as evidence and is not.

    THE ROW EXISTS ANYWAY, for two reasons. A control discharged onto an engineer still needs a
    row to hang its question on, and the false flag is the record that the firewall was asked and
    could not answer - which is a different statement from this domain never having been
    collected.
    """
    merged = latest_merged_snapshot(appliance)
    if merged is None:
        return {"configuration_backup_evidence": 0}
    with transaction.atomic():
        write_node_row(
            ConfigurationBackupEvidence, appliance, merged,
            {
                "on_box_saved_configuration_count": 0,
                "on_box_snapshot_list_collected": False,
            })
    return {"configuration_backup_evidence": 1}


# ---------------------------------------------------------------------------
# DataplaneUtilisation
# ---------------------------------------------------------------------------

def _cpu_samples(window_node: Any) -> dict[str, list[int]]:
    """Per-core sample series for one processor's window, keyed by core id.

    THE VALUE IS A COMMA-SEPARATED STRING AND MUST BE SPLIT, not parsed as a number: `int()` on
    it raises and `float()` would too, so a reader treating it as numeric gets an exception
    rather than a wrong answer - which is the better of the two failure directions and is why
    this is stated rather than guarded.
    """
    out: dict[str, list[int]] = {}
    if not isinstance(window_node, dict):
        return out
    series = window_node.get("cpu-load-average")
    # THE CORES ARE AN `entry` LIST UNDER THE SERIES NODE, and a SINGLE core arrives as a bare
    # dict rather than a list of one - which `ensure_list` is the project's answer to. The
    # un-wrapped form is accepted too because a capture replayed through this reader may carry
    # the list at either level, and a reader that handles one and not the other loses every core
    # but the first on an appliance with one data processor.
    if isinstance(series, dict) and "entry" in series:
        series = series.get("entry")
    for entry in ensure_list(series):
        if not isinstance(entry, dict):
            continue
        core = str(entry.get("coreid") or "").strip()
        if not core:
            continue
        samples = []
        for token in str(entry.get("value") or "").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                samples.append(int(token))
            except ValueError:
                continue
        out[core] = samples
    return out


def build_dataplane_utilisation(payload: Any) -> dict[str, Any]:
    """Every column of the dataplane row, from one window of `show running resource-monitor`.

    THE PROCESSOR KEY IS PLATFORM-SHAPED - `dp0` on a PA-VM, `s1dp0` on a PA-5220 - so the names
    are stored verbatim and nothing here hard-codes either: a reader that did would return
    nothing on half the estate, and one that normalized them away would lose which processor a
    reading came from.

    A WALL OF ZEROES IS NOT AN ABSENCE. The samples come back `0,0,0,...` on all four lab
    appliances, populated and truthy and all zero, so the maximum this computes cannot tell an
    idle appliance from one whose counters never populated - and `resource_monitor_collected` is
    the only thing that can.
    """
    processors: dict[str, dict[str, list[int]]] = {}
    node = payload.get("resource-monitor") if isinstance(payload, dict) else None
    node = node if isinstance(node, dict) else payload
    holder = node.get("data-processors") if isinstance(node, dict) else None
    if isinstance(holder, dict):
        for name, processor in holder.items():
            if str(name).startswith("@") or not isinstance(processor, dict):
                continue
            window = processor.get(RESOURCE_MONITOR_WINDOW)
            processors[str(name)] = _cpu_samples(window)

    every = [value for cores in processors.values() for values in cores.values()
             for value in values]
    return {
        "dataplane_cpu_load_samples": processors,
        "dataplane_cpu_load_max_percent": max(every) if every else None,
        "dataplane_count": len(processors),
        "collected_window": RESOURCE_MONITOR_WINDOW if processors else "",
        # ANSWERED AND CARRIED A SERIES, not merely answered: a reply with data-processors and no
        # `cpu-load-average` under the window asked for is a read that told us nothing, and a
        # true flag beside a null maximum would read as an idle appliance.
        "resource_monitor_collected": bool(every),
    }


def normalize_dataplane_utilisation(appliance: Appliance) -> dict[str, int]:
    """One appliance's dataplane load for the collected window. PAN-PLT-006's second half.

    THE ASSERTION STILL CANNOT REST ON THIS and the row says so rather than pretending: there is
    no configuration node anywhere on the firewall holding a dataplane CPU or session-utilization
    threshold, so "sustained" has no stored definition, and the vendor's own monitoring procedure
    instructs the reader to configure the SNMP MANAGER to watch these identifiers. The comparison
    is off-box by the vendor's design, which is a fact for stage 8 and not a column.
    """
    merged = latest_merged_snapshot(appliance)
    if merged is None:
        return {"dataplane_utilisations": 0}
    snapshot = latest_resource_monitor_snapshot(appliance)
    values = build_dataplane_utilisation(snapshot.payload if snapshot is not None else None)
    with transaction.atomic():
        write_node_row(DataplaneUtilisation, appliance, merged, values)
    return {"dataplane_utilisations": 1}


__all__ = [
    "APPLICATIONS_THREATS_MINIMUM_DAYS",
    "APPLICATIONS_THREATS_PREFERRED_DAYS",
    "MALWARE_MINIMUM_DAYS",
    "MALWARE_PREFERRED_DAYS",
    "NormalizedContentStreams",
    "NormalizedLicenceInventory",
    "alarm_mechanism_state",
    "build_content_streams",
    "build_dataplane_utilisation",
    "build_licence_inventory",
    "build_log_alarm_settings",
    "build_portal_presence",
    "content_currency_state",
    "latest_resource_monitor_snapshot",
    "normalize_configuration_backup_evidence",
    "normalize_dataplane_utilisation",
    "normalize_globalprotect_portal_presence",
    "normalize_licence_inventory",
    "normalize_log_alarm_settings",
    "normalize_platform_content_streams",
    "portal_container_state",
]
