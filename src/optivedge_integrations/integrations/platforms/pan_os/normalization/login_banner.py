"""The management login banner - PAN-MGT-007 and 008.

Reads `deviceconfig/system` through `login_banner_from_node`, which the aggregate calls too.
One parse for both models while both exist.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, LoginBanner, FieldProvenance)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT, classify_prov_type, provenance_raw_key,
    provenance_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    login_banner_from_node, device_entry_from_snapshot, latest_merged_snapshot)


def _system_node(snapshot):
    entry = device_entry_from_snapshot(snapshot)
    deviceconfig = entry.get("deviceconfig") if isinstance(entry, dict) else None
    system = deviceconfig.get("system") if isinstance(deviceconfig, dict) else None
    return system if isinstance(system, dict) else {}


def normalize_login_banner(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"login_banners": 0}

    values, provenance = login_banner_from_node(_system_node(snapshot))
    content_type = ContentType.objects.get_for_model(LoginBanner)
    with transaction.atomic():
        obj, _ = LoginBanner.objects.update_or_create(
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
    return {"login_banners": 1}
