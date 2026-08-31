"""Normalize every interface management profile on an appliance, bound or not.

The "or not" is the reason this exists. `ManagementInterface` has a row only where a
profile is bound to something, so a profile bound to nothing leaves no trace anywhere - and
"is this profile unused" cannot be asked of a model that only records the used ones.

Bindings are counted from the same payload in the same pass rather than read back from
ManagementInterface, so the two cannot disagree and neither depends on the other having run
first.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    FieldProvenance,
    InterfaceManagementProfile,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import ensure_list
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.interfaces import (
    bound_management_profiles,
)

#: The entry-level provenance record, as FieldProvenance documents it: the `@ptpl` on a
#: named PAN-OS entry rather than on one of its fields.
ENTRY_FIELD = "__entry__"

#: Attributes that state where an entry came from. Measured 2026-08-31: a template-pushed
#: profile carries `@ptpl` on the entry AND on each service leaf; a locally-created one
#: carries none, so LOCAL is the absence of a row rather than a row saying "local".
PROVENANCE_ATTRIBUTES = {
    "@ptpl": FieldProvenance.ProvenanceType.TEMPLATE,
    "@src": FieldProvenance.ProvenanceType.PANORAMA,
}


def _entry_provenance(entry: dict) -> tuple[str, str, str] | None:
    for attribute, provenance_type in PROVENANCE_ATTRIBUTES.items():
        value = entry.get(attribute)
        if value:
            return provenance_type, attribute, str(value)
    return None


def _profile_entries(device_entry: dict) -> list[dict]:
    node = (((device_entry.get("network") or {}).get("profiles") or {})
            .get("interface-management-profile") or {})
    if not isinstance(node, dict):
        return []
    return [entry for entry in ensure_list(node.get("entry")) if isinstance(entry, dict)]


def normalize_interface_management_profiles(
    appliance: Appliance,
) -> list[InterfaceManagementProfile]:
    """Replace every profile for one appliance. Returns what was written."""
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")
    device_entry = device_entry_from_snapshot(snapshot)

    bindings: dict[str, list[str]] = {}
    for interface_name, profile_name in bound_management_profiles(device_entry):
        bindings.setdefault(profile_name, []).append(interface_name)

    written: list[InterfaceManagementProfile] = []
    with transaction.atomic():
        content_type = ContentType.objects.get_for_model(InterfaceManagementProfile)
        FieldProvenance.objects.filter(
            content_type=content_type,
            object_id__in=list(
                InterfaceManagementProfile.objects.filter(appliance=appliance)
                .values_list("pk", flat=True)),
        ).delete()
        InterfaceManagementProfile.objects.filter(appliance=appliance).delete()

        seen: set[str] = set()
        for entry in _profile_entries(device_entry):
            name = str(entry.get("@name") or "").strip()
            if not name or name in seen:
                # A profile with no name cannot be bound by anything, and a duplicate name
                # is not expressible in PAN-OS. Neither is silently dropped: they surface
                # as the interface normalizer's issues against the same payload.
                continue
            seen.add(name)
            bound = sorted(set(bindings.get(name, [])))
            profile = InterfaceManagementProfile.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                source_snapshot=snapshot,
                name=name,
                bound_interface_names=bound,
                bound_interface_count=len(bound),
            )
            provenance = _entry_provenance(entry)
            if provenance is not None:
                provenance_type, raw_key, raw_value = provenance
                FieldProvenance.objects.create(
                    content_type=content_type, object_id=profile.pk,
                    field_name=ENTRY_FIELD, provenance_type=provenance_type,
                    raw_key=raw_key, raw_value=raw_value[:128],
                )
            written.append(profile)
    return written
