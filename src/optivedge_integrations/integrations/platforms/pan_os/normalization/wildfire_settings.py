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
from optivedge_integrations.integrations.models.wildfire_settings import (
    defaults_for_version,
)
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


def untuned(limits: dict[str, int], defaults: dict[str, int]) -> list[str]:
    """Which file types nobody has sized for this estate.

    Every type the release has a default for, not only the ones the config names - an absent
    entry is the clearest case of untouched there is, and walking only what is present would
    report a device that configures nothing as fully tuned.

    `defaults` comes from PAN-OS's own declared values, read off Panorama's tooltip, rather
    than inferred from a device - which is what two earlier readings got wrong.
    """
    return sorted(
        file_type for file_type, default in defaults.items()
        if limits.get(file_type, default) == default)


def exclusions(node: dict, key: str) -> list[str]:
    """The `exclude-*` items in force. Empty means nothing is withheld.

    TWO WIRE SHAPES, AND THE DEVICE ONLY WRITES ONE OF THEM. Read on fw-core-tpa-a,
    serial 013201001475, 2026-10-29:

        <session-info-select>
          <exclude-username>yes</exclude-username>
          <exclude-src-ip>yes</exclude-src-ip>
        </session-info-select>

    They are TWELVE CHILD NODES EACH TAKING ITS OWN yes/no, not members of a list. Stage 4
    settled it by writing both forms at the same container: `<member>exclude-username</member>`
    is REFUSED and `<exclude-username>yes</exclude-username>` is ACCEPTED and reads back under
    both `get` and `show`.

    THE MEMBER-LIST BRANCH WAS THE ONLY BRANCH UNTIL 2026-10-29, and on the one appliance in
    this lab that withholds anything it returned the empty list - so `shares_full_session_info`
    read True, which is PAN-AVW-005's COMPLIANT side, on a firewall that withholds a username
    and a source address. The payload contract calls the twelve enum members and is wrong about
    the shape; the member branch is kept because nothing has measured that no PAN-OS release or
    sibling container uses it, and because reading it costs nothing when it is absent.

    A child set to `no` is NOT withheld and is not listed: the key is present and explicitly
    says the item is shared.
    """
    container = node.get(key)
    if not isinstance(container, dict):
        return []
    names = {_text(member) for member in ensure_list(container.get("member")) if _text(member)}
    names |= {child for child, value in container.items()
              if child.startswith("exclude-") and _text(value) == "yes"}
    return sorted(names)


def wholly_untuned(limits: dict[str, int], defaults: dict[str, int]) -> bool:
    """Whether NO asserted file type has been moved off the size the release ships.

    THE ALL QUANTIFIER, and the one PAN-AVW-004 asserts, as against `size_limits_untuned`'s ANY.
    An appliance that moved one of ten types has answered the control's question; an appliance
    that moved none has never sized this platform at all.

    An ABSENT entry counts as untouched, which is why this quantifies over `defaults` rather
    than over `limits`: walking only what the config names would report a device that configures
    nothing as fully sized.

    `defaults` EMPTY RETURNS TRUE, which fires, and that is deliberate - a release with no
    established table is indistinguishable here from an estate nobody sized, and
    `defaults_established` on the model is the column that says which.
    """
    return all(limits.get(file_type, default) == default
               for file_type, default in defaults.items())


def verdict_reporting_gap(benign: bool, grayware: bool) -> str:
    """WHICH of the two verdict-reporting settings is left off, as one token.

    The assertion is a DISJUNCTION over two booleans with a different severity on each half, and
    a clause list is one conjunction with no OR - so the only shape that is both one clause and
    one graded column is a single token naming which half is missing.
    """
    if benign and grayware:
        return WildfireSettings.GAP_NONE
    if benign:
        return WildfireSettings.GAP_GRAYWARE
    if grayware:
        return WildfireSettings.GAP_BENIGN
    return WildfireSettings.GAP_BOTH


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
    # PAN-OS's own declared defaults. Release-invariant for what this asserts: the only
    # per-release difference is `eml`, which 11.2 adds and which is excluded anyway.
    defaults = defaults_for_version(appliance.software_version)
    still_default = untuned(limits, defaults)
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
                # THE ALL QUANTIFIER beside the ANY one above. The two disagree on purpose and
                # the model's comments say which is which; PAN-AVW-004 asserts this one.
                "size_limits_wholly_untuned": wholly_untuned(limits, defaults),
                "session_info_excluded": withheld,
                # The searchable form of the line above: a control may not rest on a JSON
                # column, so the boolean is stored beside the list it summarises.
                "shares_full_session_info": not withheld,
                # WHETHER ANYBODY LOOKED. True unconditionally here, and that is the whole of
                # the claim: control only reaches this line when `latest_merged_snapshot`
                # returned a snapshot AND `device_entry_from_snapshot` found a device entry in
                # it - it raises otherwise - so a row written by this normalizer IS a row whose
                # node was read. An absent `wildfire` node beneath a device entry that was read
                # is a READING, not a failure, and means nothing is withheld.
                #
                # So False is reachable only on a row this normalizer has not written: one from
                # before the column existed, or an appliance nothing has collected. Those are
                # exactly the rows `shares_full_session_info` reports as compliant in silence,
                # and telling them apart is the column's only job.
                "session_info_read": True,

                "inline_session_info_excluded": exclusions(
                    node, "cloud-inline-wf-session-info-select"),
                "report_benign_file": benign,
                "report_grayware_file": grayware,
                # The disjunction the clause contract cannot write, as one graded token. It
                # follows mechanically from the two booleans above, so it can never disagree
                # with them.
                "verdict_reporting_gap": verdict_reporting_gap(benign, grayware),
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
