"""Device-ID / IoT device identification normalization - PAN-IOT-001 to PAN-IOT-004.

TWO ENTRY POINTS, TWO GRAINS:

`normalize_device_identification_state(appliance)` reads three operational snapshots plus the
merged configuration and writes ONE ROW PER APPLIANCE. Like `master_key`, the row is anchored
to the MERGED snapshot so an appliance that was collected but never asked for its license
still gets a row - with `licence_read_taken` false, which FIRES. "We never asked" must not
look like "we asked and it was fine".

`normalize_rulebase_device_match(enforcement_point)` writes ONE ROW PER ENFORCEMENT POINT, as
a verdict over the `SecurityRule` rows another normalizer already wrote. It deliberately does
NOT re-read the rulebases: `replace_security_rules` already merges firewall-local rules, the
Panorama pre- and post-rulebases and the vendor's two predefined default rules into one
ordered set with `config_source` telling them apart, and a second reader would be a second
chance to read the set SHORT - which for a verdict about an absence is the dangerous
direction, because fewer rules read means fewer chances to find the dimension and a verdict
that fires more readily.

WHAT NEITHER FUNCTION WRITES is a `FieldProvenance` row. Two of the three appliance readings
are operational replies, which carry no marker of any kind and never will; the edge node was
read with neither `@ptpl` nor `@src` on any of the four lab appliances; and every column of
the verdict is computed. Both models DECLARE their computed columns in `DERIVED_FIELDS`
instead, which is what `provenance_for()` answers from.

Measured on 013201001475 (PA-5220, 11.1.13-h3), 013201001085 (PA-5220, 11.1.13-h3),
6A9C0A9904E7D6E (PA-VM, 11.2.3-h3) and 691665AC334B458 (PA-VM, 11.2.5) on 2026-10-29.
Appliances are named by SERIAL throughout: 691665AC334B458 answers to the factory-default
hostname `PA-VM` and has never had one set.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    DeviceIdentificationState,
    EnforcementPoint,
    RulebaseDeviceMatchVerdict,
    SecurityRule,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ensure_list,
    merged_shared,
    merged_vsys_entry,
    parse_text_field,
    pushed_shared,
    pushed_vsys_panorama,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot as latest_appliance_merged_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    choose_local_appliance,
    is_panorama_managed,
    latest_merged_snapshot,
    latest_pushed_shared_snapshot,
    latest_pushed_vsys_snapshot,
)


#: The `feature` strings in `request license info` that would mean the device-identification
#: entitlement is held. **NOT MEASURED, AND THE ONE INPUT THIS MODULE CANNOT SUPPLY ITSELF.**
#:
#: No appliance in the lab holds the entitlement, so no run has read the literal: the 13
#: feature strings across the two licensed appliances are PA-VM, Threat Prevention, Adv Threat
#: Prevention, Advanced URL Filtering, Advanced WildFire License, DNS Security, GlobalProtect
#: Gateway, GlobalProtect Portal, PAN-DB URL Filtering and WildFire License, and none of them
#: is it. The two candidates below are the vendor's own name for the product in prose - "an
#: active IoT Security subscription", PAN-OS Web Interface Help 11.2 p.845, Device > IoT
#: Security > DHCP Server Log Ingestion - plus the short form the lab's own rows follow, where
#: `feature` is "Adv Threat Prevention" beside a `description` of "Adv Threat Prevention Sub".
#:
#: THE MATCH IS EXACT AND NOT A SUBSTRING, deliberately. A substring test on "iot" would be
#: wider than the fact and would read an appliance as LICENSED on a feature that is not this
#: one, which makes the control pass - the unsafe direction. Exact and wrong leaves the column
#: false, which FIRES, and a finding on every appliance in an estate is checkable in a minute.
#: Filed as `archive/requests/open/stage7-iot-security-licence-feature-string.md`.
IOT_SECURITY_FEATURE_NAMES = frozenset({
    "iot security",
    "iot security subscription",
})

#: What `deviceconfig/setting/iot/edge/address` holding nothing means. NOT ASSUMED: stage 4
#: could not reach an oracle for this node - Device > IoT Security has no route in the UI map,
#: the compiled state tree answers NO_MATCHES for every concept tried, and no refusal message
#: named an effective value - so a guess here would decide whether an unconfigured firewall
#: reads as pointed at a vendor default or at nothing, and the wrong direction reports a blind
#: firewall as wired up. Nothing is stored and the blank FIRES.
EDGE_ADDRESS_IMPLICIT = Implicit.not_assumed(
    "stage4-device-id-iot.json iot-edge-service.fields.address.implicit is `unmeasured` with "
    "`merge_as: hold`: the Device > IoT Security screen is the only oracle and it has no route, "
    "so nothing establishes whether an absent address means a vendor default endpoint or none. "
    "Measured absent on all four lab appliances 2026-10-29")

#: `show iot icd version` answers three labelled lines of free text, so these are parsed out of
#: a string rather than read as keys. Measured on all four lab appliances 2026-10-29.
ICD_VERSION_LABEL = "version"
ICD_TIME_BUILT_LABEL = "timebuilt"

#: `show system info`'s `time`, e.g. "Thu Oct 29 05:42:55 2026". The appliance's own clock.
_DEVICE_CLOCK_FORMAT = "%a %b %d %H:%M:%S %Y"

#: `device-dictionary-release-date`, e.g. "2026/10/24 02:35:51 GMT" - the timestamp part only.
#: The trailing token is a timezone ABBREVIATION and not an offset, and it is deliberately
#: discarded rather than parsed: see `_content_age_days`.
_RELEASE_DATE_FORMAT = "%Y/%m/%d %H:%M:%S"


@dataclass(slots=True)
class NormalizedDeviceIdentificationState:
    """One appliance's device-identification state, before persistence."""

    device_id_licensed: bool
    licence_read_taken: bool
    edge_service_address: str
    device_dictionary_version: str
    device_dictionary_release_date: str
    device_dictionary_release_date_known: bool
    device_dictionary_age_days: int | None
    icd_build_version: str
    icd_built_at: str


def _licence_entries(payload: Any) -> list[dict[str, Any]] | None:
    """The license table's entries, or None when no table was reported at all.

    THREE SHAPES FROM ONE COMMAND and the third is the trap. Measured on all four lab
    appliances, 2026-10-29:

        {'licenses': {'entry': [... 10 entries ...]}}   691665AC334B458
        {'licenses': {'entry': [... 3 entries ...]}}    6A9C0A9904E7D6E
        {'licenses': None}                              both PA-5220s

    That third one is truthy at the outer dict and falsy one level in, and
    `payload['licenses']['entry']` raises `TypeError` on it - and it is a READ THAT HAPPENED
    and reported nothing, which is NOT the same fact as a read nobody took. The first draft of
    this function returned None for it, which made both PA-5220s report `licence_read_taken`
    false - an appliance that answered, recorded as never asked. Caught by this module's own
    test before the readback.

    So an EMPTY ENVELOPE RETURNS AN EMPTY LIST and None is reserved for a payload carrying no
    `licenses` key at all, which is a shape nobody has seen: for that the caller reads "not
    asked", because an unrecognized shape is not evidence of an empty one.
    """
    if not isinstance(payload, dict) or "licenses" not in payload:
        return None
    licenses = payload.get("licenses")
    if licenses is None:
        return []
    if not isinstance(licenses, dict):
        return None
    return [entry for entry in ensure_list(licenses.get("entry")) if isinstance(entry, dict)]


def _holds_device_identification_licence(entries: list[dict[str, Any]]) -> bool:
    """Does any entry name the device-identification feature and report itself in force?

    `expired` is read for `no` rather than tested for truth: the key is a yes/no string and
    every lab row carries `expired: no` beside `expires: Never`. An entry whose `expired` key
    is missing or says anything else is NOT counted - a row we cannot read as in force is not
    evidence that it is.
    """
    for entry in entries:
        feature = str(entry.get("feature") or "").strip().lower()
        if feature not in IOT_SECURITY_FEATURE_NAMES:
            continue
        if str(entry.get("expired") or "").strip().lower() == "no":
            return True
    return False


def _icd_lines(payload: Any) -> tuple[str, str]:
    """(version, time_built) out of `show iot icd version`'s three-line free-text reply.

    `Snapshot.payload` here is a plain STRING and not a dict - the one source type in this
    domain that is - so anything calling `.get()` on it raises. Measured 2026-10-29:

        'Version: 13.pan_h1_r3\\nTimeBuilt: 2026-02-06T13:34:53PST\\nGitTag: 10c7d140'

    GitTag is read and discarded: nothing asserts it and it duplicates the version's tail.
    """
    if not isinstance(payload, str):
        return "", ""
    version = ""
    time_built = ""
    for line in payload.splitlines():
        label, _, value = line.partition(":")
        key = label.strip().lower()
        if key == ICD_VERSION_LABEL:
            version = value.strip()
        elif key == ICD_TIME_BUILT_LABEL:
            time_built = value.strip()
    return version, time_built


def _device_clock(system_payload: Any) -> datetime | None:
    """The appliance's own clock, from `show system info`'s `time` key.

    This is what makes the content's age computable without parsing a timezone name. The key
    and `device-dictionary-release-date` are rendered in the SAME local frame, so subtracting
    one naive timestamp from the other is correct whatever that frame is - measured on the two
    PA-VMs, which report the same content instant as "02:35:51 GMT" and "19:35:51 PDT" and
    whose clocks differ by the same seven hours, giving an identical age on both.
    """
    if not isinstance(system_payload, dict):
        return None
    raw = str(system_payload.get("time") or "").strip()
    if not raw:
        return None
    try:
        return datetime.strptime(raw, _DEVICE_CLOCK_FORMAT)
    except ValueError:
        return None


def _release_instant(release_date: str) -> datetime | None:
    """The release timestamp, with its trailing timezone ABBREVIATION discarded.

    'GMT', 'PDT' and 'EDT' have all been read for the same appliance family and one of them
    moved on one appliance between 2026-10-26 and 2026-10-29 without the content changing, so
    the abbreviation describes the appliance's display setting rather than the content. It is
    dropped rather than mapped to an offset, because the comparison it feeds is against the
    same appliance's own clock in the same frame.
    """
    timestamp = " ".join(release_date.split()[:2]) if release_date else ""
    if not timestamp:
        return None
    try:
        return datetime.strptime(timestamp, _RELEASE_DATE_FORMAT)
    except ValueError:
        return None


def _content_age_days(system_payload: Any, release_date: str,
                      collected_at: datetime | None) -> int | None:
    """Whole days from the installed content's release to the moment of collection.

    Returns None only where the release date cannot be read at all, and the caller then sets
    `device_dictionary_release_date_known` to false so the control's second query fires on it.
    NEVER None beside a readable date: a null passes every threshold, so leaving one there
    would report the appliances nobody could measure as the cleanest in the estate.

    THE DEVICE'S OWN CLOCK IS PREFERRED and `collected_at` is the fallback. Mixing frames costs
    at most the appliance's UTC offset, which on a seven-day floor can move the answer by one
    day; the fallback is still taken, because the alternative is the null this docstring exists
    to avoid.
    """
    released = _release_instant(release_date)
    if released is None:
        return None
    now = _device_clock(system_payload)
    if now is None:
        if collected_at is None:
            return None
        now = collected_at.replace(tzinfo=None)
    return max((now - released).days, 0)


def build_device_identification_state(
    *,
    merged_payload: Any,
    licence_snapshot: Snapshot | None,
    system_info_snapshot: Snapshot | None,
    icd_snapshot: Snapshot | None,
) -> NormalizedDeviceIdentificationState:
    """Every column of the appliance row, from the four payloads that carry them.

    Separated from persistence so it can be exercised against a captured payload without a
    database, which is how the readback for this domain was taken.
    """
    config = merged_payload.get("config", {}) if isinstance(merged_payload, dict) else {}
    devices = config.get("devices", {}) if isinstance(config, dict) else {}
    device_entries = ensure_list(devices.get("entry")) if isinstance(devices, dict) else []
    device_entry = device_entries[0] if device_entries and isinstance(device_entries[0], dict) else {}
    deviceconfig = device_entry.get("deviceconfig") or {}
    setting = deviceconfig.get("setting") if isinstance(deviceconfig, dict) else None
    iot = setting.get("iot") if isinstance(setting, dict) else None
    edge = iot.get("edge") if isinstance(iot, dict) else None
    edge_address, _raw_key, _raw_prov = parse_text_field(
        (edge or {}).get("address") if isinstance(edge, dict) else None,
        implicit=EDGE_ADDRESS_IMPLICIT,
    )

    entries = _licence_entries(licence_snapshot.payload) if licence_snapshot is not None else None
    licence_read_taken = entries is not None
    device_id_licensed = _holds_device_identification_licence(entries or [])

    system_payload = system_info_snapshot.payload if system_info_snapshot is not None else None
    if isinstance(system_payload, dict):
        system = system_payload.get("system")
        system = system if isinstance(system, dict) else system_payload
    else:
        system = None
    dictionary_version = str((system or {}).get("device-dictionary-version") or "").strip()
    # ABSENT ON BOTH PA-5220s - the key is missing from the reply, not empty - along with its
    # three sibling release-date keys. Nothing in the reply says whether that is a platform
    # distinction or a content state, so the companion flag below carries the uncertainty.
    release_date = str((system or {}).get("device-dictionary-release-date") or "").strip()
    age_days = _content_age_days(
        system,
        release_date,
        system_info_snapshot.collected_at if system_info_snapshot is not None else None,
    )
    # KNOWN MEANS READABLE, not merely present. A date the parser cannot read would otherwise
    # leave a true flag beside a null age, and PAN-IOT-003's graded group would then admit the
    # row to a threshold that a null passes - the one hole the companion exists to close.
    release_date_known = bool(release_date) and age_days is not None

    icd_version, icd_built = _icd_lines(icd_snapshot.payload if icd_snapshot is not None else None)

    return NormalizedDeviceIdentificationState(
        device_id_licensed=device_id_licensed,
        licence_read_taken=licence_read_taken,
        edge_service_address=edge_address,
        device_dictionary_version=dictionary_version,
        device_dictionary_release_date=release_date,
        device_dictionary_release_date_known=release_date_known,
        device_dictionary_age_days=age_days,
        icd_build_version=icd_version,
        icd_built_at=icd_built,
    )


def _latest_appliance_snapshot(appliance: Appliance, source_type: str) -> Snapshot | None:
    """The newest snapshot of one source type for one appliance.

    The tenth copy of this four-line query in `normalization/`. Left local rather than
    generalised here: a shared `latest_appliance_snapshot(appliance, source_type)` would be the
    right consolidation and it belongs to whoever owns the module it would live in.
    """
    return (
        Snapshot.objects.filter(appliance=appliance, source_type=source_type)
        .order_by("-collected_at", "-pk")
        .first()
    )


def latest_license_info_snapshot(appliance: Appliance) -> Snapshot | None:
    return _latest_appliance_snapshot(appliance, "request_license_info")


def latest_system_info_snapshot(appliance: Appliance) -> Snapshot | None:
    return _latest_appliance_snapshot(appliance, "show_system_info")


def latest_iot_icd_version_snapshot(appliance: Appliance) -> Snapshot | None:
    return _latest_appliance_snapshot(appliance, "show_iot_icd_version")


def normalize_device_identification_state(appliance: Appliance) -> dict[str, int]:
    """Rebuild one appliance's device-identification row.

    Anchored to the MERGED snapshot, so an appliance that has been collected and never asked
    for its license still gets a row. No merged snapshot means no row at all - there is nothing
    to anchor to and nothing the edge column could say.
    """
    snapshot = latest_appliance_merged_snapshot(appliance)
    if snapshot is None:
        return {"device_identification_states": 0}

    normalized = build_device_identification_state(
        merged_payload=snapshot.payload or {},
        licence_snapshot=latest_license_info_snapshot(appliance),
        system_info_snapshot=latest_system_info_snapshot(appliance),
        icd_snapshot=latest_iot_icd_version_snapshot(appliance),
    )

    with transaction.atomic():
        DeviceIdentificationState.objects.update_or_create(
            appliance=appliance,
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": snapshot,
                "device_id_licensed": normalized.device_id_licensed,
                "licence_read_taken": normalized.licence_read_taken,
                "edge_service_address": normalized.edge_service_address,
                "device_dictionary_version": normalized.device_dictionary_version,
                "device_dictionary_release_date": normalized.device_dictionary_release_date,
                "device_dictionary_release_date_known": (
                    normalized.device_dictionary_release_date_known),
                "device_dictionary_age_days": normalized.device_dictionary_age_days,
                "icd_build_version": normalized.icd_build_version,
                "icd_built_at": normalized.icd_built_at,
            },
        )
    return {"device_identification_states": 1}


# ---------------------------------------------------------------------------
# The rulebase verdict
# ---------------------------------------------------------------------------

#: Members of `source-hip`/`destination-hip` that are keywords rather than references, so a
#: name resolution must never be attempted on them. Measured at the write path: `any`,
#: `no-hip` and `quarantine` are accepted where a name in neither namespace is refused as both
#: "not an allowed keyword" and "not a valid reference". `any` is the commonest member in the
#: estate and constrains nothing, which is why a populated member list is not a device match.
HIP_KEYWORDS = frozenset({"any", "no-hip", "quarantine"})

#: The action that makes a rule one that PERMITS traffic. PAN-OS carries six distinct action
#: values across the lab's rules; only this one is an allow, and the control asserts over rules
#: that permit rather than over rules that exist.
ALLOW_ACTION = "allow"


def _device_object_names(node: Any) -> set[str]:
    """The `@name`s of the device objects in one container, which may be absent or null.

    `device-object` is a KEY WITH A NULL VALUE in the device-wide pushed-shared payload on all
    four lab appliances - present, so a key test says yes, and empty, so an entry walk says no.
    Both PA-VMs answer the same way at both configuration containers. Measured 2026-10-29.
    """
    if not isinstance(node, dict):
        return set()
    container = node.get("device-object")
    if not isinstance(container, dict):
        return set()
    return {
        str(entry.get("@name") or "").strip()
        for entry in ensure_list(container.get("entry"))
        if isinstance(entry, dict) and str(entry.get("@name") or "").strip()
    }


def visible_device_object_names(enforcement_point: EnforcementPoint) -> set[str]:
    """Every device object this enforcement point could resolve a rule member against.

    FOUR CONTAINERS, because a rule member resolves across namespaces and a count taken from
    one of them is a count of the wrong thing:

      - the vsys's own `device-object`, in the merged configuration
      - firewall-local SHARED `device-object`, in the same payload, visible to every vsys
      - Panorama-pushed device-group scope, in the per-vsys pushed payload
      - Panorama SHARED, in the device-wide pushed payload

    A vsys with no device-group assignment still resolves shared objects, so the device-wide
    pushed read is taken even where the per-vsys one is empty - skipping it because the narrow
    one answered nothing is how 182 objects were dropped on one lab device once already.

    WHAT IS NOT HERE is `/config/predefined/iot-definitions/attribute`, the dictionary a device
    object's own `category` and `profile` members resolve into. Nothing stores it, the sizes
    differ per appliance (35,566 members on a PA-VM against 20,000-odd on a PA-5220), and
    `show config merged` omits the predefined namespace entirely - so this count says a rule
    COULD name a device and never that the device object itself resolves to anything.
    """
    names: set[str] = set()

    merged_snapshot = latest_merged_snapshot(enforcement_point)
    if merged_snapshot is not None:
        payload = merged_snapshot.payload or {}
        names |= _device_object_names(
            merged_vsys_entry(payload, enforcement_point.vsys_name))
        names |= _device_object_names(merged_shared(payload))

    pushed_vsys_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    if pushed_vsys_snapshot is not None:
        names |= _device_object_names(
            pushed_vsys_panorama(pushed_vsys_snapshot.payload))

    pushed_shared_snapshot = latest_pushed_shared_snapshot(enforcement_point)
    if pushed_shared_snapshot is not None:
        names |= _device_object_names(pushed_shared(pushed_shared_snapshot.payload))

    return names


def rule_device_match_counts(
    enforcement_point: EnforcementPoint,
    device_object_names: set[str],
) -> tuple[int, int]:
    """(rules naming a device object, rules that ALLOW and name one).

    Taken over the stored `SecurityRule` rows of this point, which already carry the
    firewall-local rulebase, the Panorama pre- and post-rulebases and the two predefined
    default rules, with `config_source` separating them. The device members are the
    `SecurityRuleSourceHip` and `SecurityRuleDestinationHip` child rows.

    A MEMBER IS A DEVICE MATCH ONLY IF IT RESOLVES. One member list holds a device object, a
    GlobalProtect HIP profile and the three bare keywords, all as plain strings, so resolution
    against the device-object namespace is the only discriminator there is - and the keyword
    `any`, which is what every populated list in this estate actually holds, constrains
    nothing. Counting a populated list as a device match would report the whole lab as having
    the dimension.

    THE GAP THAT REMAINS is a HIP profile sharing a name with a device object, which would be
    counted here as a device match. No HIP profile exists anywhere in the lab, so it could not
    be measured; PAN-GPG-005 lands in this same element for host posture and the two controls
    cannot be separated until a per-member kind is resolved at collection time.
    """
    if not device_object_names:
        return 0, 0
    naming = 0
    allowing = 0
    rules = (
        SecurityRule.objects.filter(enforcement_point=enforcement_point)
        .prefetch_related("securityrulesourcehips", "securityruledestinationhips")
    )
    for rule in rules:
        members = {
            str(member.value or "").strip()
            for member in list(rule.securityrulesourcehips.all())
            + list(rule.securityruledestinationhips.all())
        }
        resolved = {
            member for member in members
            if member and member.lower() not in HIP_KEYWORDS
            and member in device_object_names
        }
        if not resolved:
            continue
        naming += 1
        if str(rule.action or "").strip().lower() == ALLOW_ACTION:
            allowing += 1
    return naming, allowing


def normalize_rulebase_device_match(enforcement_point: EnforcementPoint) -> dict[str, int]:
    """Rebuild one enforcement point's device-match verdict.

    Anchored to the merged snapshot the rules themselves came from, so a point with no merged
    snapshot gets no row: there is no rule set to take a verdict over, and a verdict with
    nothing behind it would fire on the strength of nothing.
    """
    snapshot = latest_merged_snapshot(enforcement_point)
    if snapshot is None:
        return {"rulebase_device_match_verdicts": 0}

    device_object_names = visible_device_object_names(enforcement_point)
    naming, allowing = rule_device_match_counts(enforcement_point, device_object_names)

    with transaction.atomic():
        RulebaseDeviceMatchVerdict.objects.update_or_create(
            enforcement_point=enforcement_point,
            defaults={
                "management_station": enforcement_point.management_station,
                "source_snapshot": snapshot,
                # NEGATED so the column fires. True is both the measured state of every
                # appliance in this estate and the state of a point nobody has recomputed,
                # which is the direction a migration window has to announce.
                "has_no_rule_matching_on_device": allowing == 0,
                "rules_matching_on_device_count": naming,
                "device_object_count": len(device_object_names),
            },
        )
    return {"rulebase_device_match_verdicts": 1}


def speaking_appliance(enforcement_point: EnforcementPoint) -> Appliance | None:
    """Exposed so a caller can report WHY a point produced no verdict.

    `choose_local_appliance` and `is_panorama_managed` are re-exported through this module for
    the same reason: a consumer asking "should this point have had a pushed read?" must ask the
    one definition rather than infer it from the group being set.
    """
    return choose_local_appliance(enforcement_point)


__all__ = [
    "ALLOW_ACTION",
    "EDGE_ADDRESS_IMPLICIT",
    "HIP_KEYWORDS",
    "IOT_SECURITY_FEATURE_NAMES",
    "NormalizedDeviceIdentificationState",
    "build_device_identification_state",
    "is_panorama_managed",
    "latest_iot_icd_version_snapshot",
    "latest_license_info_snapshot",
    "latest_system_info_snapshot",
    "normalize_device_identification_state",
    "normalize_rulebase_device_match",
    "rule_device_match_counts",
    "speaking_appliance",
    "visible_device_object_names",
]
