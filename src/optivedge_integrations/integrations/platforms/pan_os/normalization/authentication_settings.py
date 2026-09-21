"""Device-wide administrator authentication settings - PAN-AUTH-014 to 017.

Reads `deviceconfig/setting/management` through `authentication_settings_from_node`, which the
aggregate calls too. One parse for both models, deliberately: while `DeviceConfigurationProfile`
still carries these four numbers, the only thing stopping the two from disagreeing is that
neither reads the payload for itself.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, AuthenticationSettings, FieldProvenance)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT, classify_prov_type, provenance_raw_key,
    provenance_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    authentication_settings_from_node, device_entry_from_snapshot, latest_merged_snapshot)


def _management_node(snapshot):
    entry = device_entry_from_snapshot(snapshot)
    deviceconfig = entry.get("deviceconfig") if isinstance(entry, dict) else None
    setting = deviceconfig.get("setting") if isinstance(deviceconfig, dict) else None
    management = setting.get("management") if isinstance(setting, dict) else None
    # The whole node is absent on a device that has never had one of its keys set - measured on
    # both PA-5220s - so an empty dict is the normal case, not a collection failure.
    return management if isinstance(management, dict) else {}


def normalize_authentication_settings(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"authentication_settings": 0}

    values, provenance = authentication_settings_from_node(_management_node(snapshot))
    content_type = ContentType.objects.get_for_model(AuthenticationSettings)
    with transaction.atomic():
        obj, _ = AuthenticationSettings.objects.update_or_create(
            appliance=appliance,
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": snapshot,
                **values,
            },
        )
        FieldProvenance.objects.filter(content_type=content_type, object_id=obj.pk).delete()
        for field, raw_key, raw_value in provenance:
            # An absent key produces NO row: "pushed", "written locally" and "defaulted" stay
            # three different facts rather than one blank.
            if raw_key is not ABSENT:
                FieldProvenance.objects.create(
                    content_type=content_type, object_id=obj.pk, field_name=field,
                    provenance_type=classify_prov_type(raw_key),
                    raw_key=provenance_raw_key(raw_key), raw_value=provenance_value(raw_key, raw_value))
    return {"authentication_settings": 1}
