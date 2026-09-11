"""The master key - PAN-CRT-007.

Reads `read_master_key`, which the aggregate calls too, from the `show_masterkey_properties`
snapshot rather than the merged configuration. The row is anchored to the MERGED snapshot all
the same, so an appliance that has been collected but never asked for its master key still gets
a row - with state UNDETERMINED, which fires the control. "We never asked" must not look like
"we asked and it was fine".
"""

from __future__ import annotations

from django.db import transaction

from optivedge_integrations.integrations.models import Appliance, MasterKey
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_masterkey_snapshot, latest_merged_snapshot, read_master_key)

#: The aggregate's constants are the same three strings. Mapped explicitly rather than reused,
#: so `MasterKey` does not import a model it is replacing.
STATE = {"default": MasterKey.STATE_DEFAULT, "set": MasterKey.STATE_SET,
         "undetermined": MasterKey.STATE_UNDETERMINED}


def normalize_master_key(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"master_keys": 0}
    state, expires_at, auto_renew, on_hsm = read_master_key(
        latest_masterkey_snapshot(appliance))
    with transaction.atomic():
        MasterKey.objects.update_or_create(
            appliance=appliance,
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": snapshot,
                "state": STATE.get(state, MasterKey.STATE_UNDETERMINED),
                "expires_at": expires_at,
                "auto_renew_hours": auto_renew,
                "on_hsm": on_hsm,
            },
        )
    # No FieldProvenance: an operational reply carries no @ptpl and never will. The master key
    # tab records the same thing - it is the one device tab with no provenance column.
    return {"master_keys": 1}
