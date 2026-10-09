"""Device > Setup > WildFire - the device-wide settings. PAN-AVW-004 and PAN-AVW-005.

One walk of `deviceconfig/setting/wildfire`, feeding one model that two controls read.

THE TWO THINGS MOST EASILY GOT WRONG, both measured 2026-10-09:

**Session information is stored as EXCLUSIONS.** The twelve enum members are all `exclude-*`,
so an empty list means nothing is withheld, which is FULL sharing and the state PAN-AVW-005
wants. Reading a ticked checkbox as a stored value would invert the control.

**The size limits look configured and are not.** Every entry on pan-fw-111 carries
`@src: tpl`, but the thing named there is a template STACK and no template holds a wildfire
node. So a value equal to its default was not pushed by anybody - which is exactly what
PAN-AVW-004, as a tuning check, needs to be able to say.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, FieldProvenance, WildfireSettings)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    Implicit,
    classify_prov_type,
    ensure_list,
    parse_yes_no_field,
    provenance_raw_key,
    provenance_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)


def _text(value):
    if isinstance(value, dict):
        return str(value.get("#text", "")).strip()
    return str(value).strip() if value is not None else ""


def wildfire_node(snapshot) -> dict:
    entry = device_entry_from_snapshot(snapshot)
    deviceconfig = entry.get("deviceconfig") if isinstance(entry, dict) else None
    deviceconfig = deviceconfig if isinstance(deviceconfig, dict) else {}
    setting = deviceconfig.get("setting")
    setting = setting if isinstance(setting, dict) else {}
    node = setting.get("wildfire")
    return node if isinstance(node, dict) else {}


def size_limits(node: dict) -> dict[str, int]:
    """{file type: configured limit}. Only what the config names.

    A type absent here is at its default and is NOT filled in: "nobody set this" and "somebody
    set it to the default value" are different facts about who did what, even though the
    tuning check treats them alike. Keeping them apart means the stored row still says which
    happened.
    """
    container = node.get("file-size-limit")
    limits = {}
    for entry in ensure_list(container.get("entry") if isinstance(container, dict) else None):
        if not isinstance(entry, dict) or not entry.get("@name"):
            continue
        raw = _text(entry.get("size-limit"))
        if raw.isdigit():
            limits[str(entry["@name"])] = int(raw)
    return limits


def untuned(limits: dict[str, int]) -> list[str]:
    """Which file types nobody has sized for this estate.

    Every type PAN-OS has a default for is checked, not only the ones the config names - an
    absent entry is the clearest case of untouched there is, and walking only what is present
    would report a device that configures nothing as fully tuned.
    """
    return sorted(
        file_type for file_type, default in WildfireSettings.DEFAULT_SIZE_LIMITS.items()
        if limits.get(file_type, default) == default)


def exclusions(node: dict, key: str) -> list[str]:
    """The `exclude-*` members in force. Empty means nothing is withheld."""
    container = node.get(key)
    if not isinstance(container, dict):
        return []
    return sorted(
        _text(member) for member in ensure_list(container.get("member"))
        if _text(member))


def normalize_wildfire_settings(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"wildfire_settings": 0}
    node = wildfire_node(snapshot)

    benign, benign_rk, benign_rv = parse_yes_no_field(
        node.get("report-benign-file"),
        implicit=Implicit.measured(
            False,
            "payload contract, wildfire-device-settings.report-benign-file: implicit 'no' - "
            "absent on pan-fw-111 and the box renders unticked, measured 2026-10-09"))
    grayware, gray_rk, gray_rv = parse_yes_no_field(
        node.get("report-grayware-file"),
        implicit=Implicit.measured(
            False,
            "payload contract, wildfire-device-settings.report-grayware-file: implicit 'no' - "
            "absent on pan-fw-111 and the box renders unticked, measured 2026-10-09"))

    limits = size_limits(node)
    still_default = untuned(limits)
    withheld = exclusions(node, "session-info-select")

    content_type = ContentType.objects.get_for_model(WildfireSettings)
    with transaction.atomic():
        obj, _ = WildfireSettings.objects.update_or_create(
            appliance=appliance,
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": snapshot,
                "size_limits": limits,
                "untuned_file_types": still_default,
                "size_limits_untuned": bool(still_default),
                "session_info_excluded": withheld,
                # The searchable form of the line above: a control may not rest on a JSON
                # column, so the boolean is stored beside the list it summarises.
                "shares_full_session_info": not withheld,
                "inline_session_info_excluded": exclusions(
                    node, "cloud-inline-wf-session-info-select"),
                "report_benign_file": benign,
                "report_grayware_file": grayware,
            },
        )
        FieldProvenance.objects.filter(
            content_type=content_type, object_id=obj.pk).delete()
        for field, raw_key, raw_value in (
                ("report_benign_file", benign_rk, benign_rv),
                ("report_grayware_file", gray_rk, gray_rv)):
            if raw_key is not ABSENT:
                FieldProvenance.objects.create(
                    content_type=content_type, object_id=obj.pk, field_name=field,
                    provenance_type=classify_prov_type(raw_key),
                    raw_key=provenance_raw_key(raw_key),
                    raw_value=provenance_value(raw_key, raw_value))
    return {"wildfire_settings": 1}
