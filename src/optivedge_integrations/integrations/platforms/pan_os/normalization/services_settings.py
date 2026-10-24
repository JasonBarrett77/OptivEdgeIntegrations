"""Update server verification and the logging setting - PAN-MGT-009 and 011.

Two single-field clusters normalized in one pass because they come from one walk of the device
entry, and separated into two MODELS because they are two different PAN-OS screens.

Both values are read here rather than through a shared helper, unlike the other splits: they are
single scalars with no structure to get wrong, and the aggregate reads them the same way from
the same nodes. The defaults are the risk, and they are OPPOSITE - see the model docstrings.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, FieldProvenance, LoggingSettings, UpdateServerSettings)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ABSENT, classify_prov_type, provenance_raw_key, provenance_value, parse_yes_no_field)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot, latest_merged_snapshot)


def _nodes(snapshot):
    entry = device_entry_from_snapshot(snapshot)
    deviceconfig = entry.get("deviceconfig") if isinstance(entry, dict) else None
    deviceconfig = deviceconfig if isinstance(deviceconfig, dict) else {}
    system = deviceconfig.get("system")
    setting = deviceconfig.get("setting")
    setting = setting if isinstance(setting, dict) else {}
    management = setting.get("management")
    return (system if isinstance(system, dict) else {},
            management if isinstance(management, dict) else {})


def write_node_row(model, appliance, snapshot, values, provenance=(), *, lookup=None):
    """One row of a node-shaped model, with a provenance row per field that has one.

    Node-shaped meaning there is no named entry: the row IS the appliance, or the appliance and
    one more positional key. `lookup` defaults to `{"appliance": appliance}` and the caller
    passes a wider one where the grain is finer - `VsysLogForwarding` is one row per vsys.

    IT DELETES ONLY THE ROWS FOR THE FIELDS IT WRITES, and that is the whole reason this is
    shared rather than private. Two normalizers write `LoggingSettings`: this module writes the
    one Setup > Management checkbox PAN-MGT-011 reads, and `log_settings.py` writes the logging
    domain's columns from a different subtree. Wiping every provenance row for the object would
    make whichever ran last erase the other's, silently, and a missing row means "not tracked" -
    so the erasure would read as a deliberate statement.

    The cost of the narrower delete is that a field this model once wrote and no longer does
    keeps its stale row. Every caller writes its own complete set every pass, so that can only
    happen when a column is removed, which is a migration and is visible.

    `provenance` is [(field_name, raw_key, raw_value), ...]. A field whose raw_key is ABSENT is
    skipped entirely - the caller declared no implicit value for it, so nothing is tracked.
    """
    content_type = ContentType.objects.get_for_model(model)
    obj, _ = model.objects.update_or_create(
        **(lookup if lookup is not None else {"appliance": appliance}),
        defaults={
            "management_station": appliance.management_station,
            "appliance_group": appliance.appliance_group,
            "source_snapshot": snapshot,
            **values,
        },
    )
    written = [name for name, _, _ in provenance]
    if written:
        FieldProvenance.objects.filter(
            content_type=content_type, object_id=obj.pk, field_name__in=written).delete()
    FieldProvenance.objects.bulk_create([
        FieldProvenance(
            content_type=content_type, object_id=obj.pk, field_name=name,
            provenance_type=classify_prov_type(raw_key),
            raw_key=provenance_raw_key(raw_key),
            raw_value=provenance_value(raw_key, raw_value)[:128])
        for name, raw_key, raw_value in provenance if raw_key is not ABSENT])
    return obj


def normalize_services_settings(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"update_server_settings": 0, "logging_settings": 0}
    system, management = _nodes(snapshot)

    verify, verify_rk, verify_rv = parse_yes_no_field(
        system.get("server-verification"),
        implicit=Implicit.measured(
            True,
            "payload contract, mgmt-settings.server-verification: implicit 'yes' - the "
            "checkbox reads ticked with the key absent, measured 2026-09-01"))
    log_on_load, log_rk, log_rv = parse_yes_no_field(
        management.get("enable-log-high-dp-load"),
        implicit=Implicit.measured(
            False,
            "payload contract, mgmt-settings.enable-log-high-dp-load: implicit 'no' - the "
            "opposite polarity to server-verification in the same node"))

    with transaction.atomic():
        write_node_row(
            UpdateServerSettings, appliance, snapshot,
            {"verify_identity": verify},
            [("verify_identity", verify_rk, verify_rv)])
        write_node_row(
            LoggingSettings, appliance, snapshot,
            {"log_on_high_dp_load": log_on_load},
            [("log_on_high_dp_load", log_rk, log_rv)])
    return {"update_server_settings": 1, "logging_settings": 1}
