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


def _write(model, appliance, snapshot, field, value, raw_key, raw_value):
    content_type = ContentType.objects.get_for_model(model)
    obj, _ = model.objects.update_or_create(
        appliance=appliance,
        defaults={
            "management_station": appliance.management_station,
            "appliance_group": appliance.appliance_group,
            "source_snapshot": snapshot,
            field: value,
        },
    )
    FieldProvenance.objects.filter(content_type=content_type, object_id=obj.pk).delete()
    if raw_key is not ABSENT:
        FieldProvenance.objects.create(
            content_type=content_type, object_id=obj.pk, field_name=field,
            provenance_type=classify_prov_type(raw_key),
            raw_key=provenance_raw_key(raw_key), raw_value=provenance_value(raw_key, raw_value))
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
        _write(UpdateServerSettings, appliance, snapshot, "verify_identity",
               verify, verify_rk, verify_rv)
        _write(LoggingSettings, appliance, snapshot, "log_on_high_dp_load",
               log_on_load, log_rk, log_rv)
    return {"update_server_settings": 1, "logging_settings": 1}
