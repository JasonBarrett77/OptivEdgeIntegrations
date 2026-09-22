"""Which vsys each device group has pushed to, derived from provenance.

`show dg-hierarchy` returns the groups and their nesting, and nothing about membership. The
membership that matters for attribution is not Panorama's assignment anyway - it is which
enforcement points are actually carrying a group's configuration, and that is exactly what a
`FieldProvenance` row of type `device_group` records: this object's value came from that
group. So the bindings are derived rather than collected, and they mean "has pushed here",
not "is assigned here".

A group with no bindings is a real state, not a gap: it has pushed nothing this collection
reached, and it has no findings to attribute either.

THREE THINGS THIS HAS TO GET RIGHT.

* **`shared` is a provenance value and Shared is a container.** 1,140 of the lab's 4,919
  device-group rows say `shared`, which is the shared scope rather than a device group -
  but an operator reads Shared as a container in the tree, so it binds to the Shared row
  rather than being dropped.
* **A content type whose model is gone must be skipped, not resolved.** `FieldProvenance`
  is a generic relation, so dropping a model leaves its rows behind - `DeviceConfigurationProfile`
  left 28 of them. Migration 0065 removes those; this skips any that appear later rather
  than raising in the middle of a sync.
* **One query per model, not one per row.** Resolving 4,919 rows object by object is 4,919
  queries. Each content type is resolved in one `values()` call over the foreign keys that
  model actually has.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    DeviceGroup,
    DeviceGroupBinding,
    EnforcementPoint,
    FieldProvenance,
    ManagementStation,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_groups import (
    SHARED_NAME,
)

#: The PAN-OS `@loc` value for the shared scope, which maps to the Shared container.
SHARED_PROVENANCE_VALUE = "shared"

#: The owner foreign keys a provenanced model may carry, in resolution order. A scoped policy
#: object names its enforcement point; a shared-scope object hangs off the appliance group and
#: therefore reaches every point in it; an appliance-scoped object reaches the points its
#: appliance participates in.
_OWNER_FIELDS = ("enforcement_point", "appliance_group", "appliance")


@dataclass(slots=True)
class DeviceGroupBindingRebuildResult:
    management_station: ManagementStation
    device_group_count: int
    binding_count: int
    created_binding_count: int
    deleted_binding_count: int
    #: Names that appear in provenance but not in the collected hierarchy. Each gets a row so
    #: attribution still works, flagged `discovered_from=provenance` so it is visible as the
    #: anomaly it is.
    provenance_only_names: list[str] = field(default_factory=list)
    #: Rows whose object could not be traced to an enforcement point - counted rather than
    #: silently dropped.
    unresolved_row_count: int = 0
    skipped_content_type_count: int = 0


def _enforcement_points_by_owner(management_station: ManagementStation):
    """(points by appliance_group_id, points by appliance_id) for one station, in two queries."""
    by_group: dict[int, list[int]] = defaultdict(list)
    for point_pk, group_pk in EnforcementPoint.objects.filter(
        management_station=management_station, appliance_group__isnull=False
    ).values_list("pk", "appliance_group_id"):
        by_group[group_pk].append(point_pk)

    by_appliance: dict[int, list[int]] = defaultdict(list)
    for point_pk, appliance_pk in EnforcementPoint.objects.filter(
        management_station=management_station, nodes__appliance__isnull=False
    ).values_list("pk", "nodes__appliance_id"):
        by_appliance[appliance_pk].append(point_pk)

    return by_group, by_appliance


def _resolve_points(model, pks, management_station, by_group, by_appliance):
    """{object pk: [enforcement point pk]} for one model, in one query.

    Objects belonging to another station are dropped here: `FieldProvenance` has no station
    of its own, so the model's own foreign key is what scopes the rebuild.
    """
    owner_fields = [name for name in _OWNER_FIELDS
                    if name in {f.name for f in model._meta.get_fields() if f.many_to_one}]
    if not owner_fields:
        return {}

    columns = [f"{name}_id" for name in owner_fields]
    has_station = "management_station" in {
        f.name for f in model._meta.get_fields() if f.many_to_one
    }
    if has_station:
        columns.append("management_station_id")

    resolved: dict[int, list[int]] = {}
    for row in model.objects.filter(pk__in=pks).values("pk", *columns):
        if has_station and row["management_station_id"] != management_station.pk:
            continue
        points: list[int] = []
        if "enforcement_point_id" in row and row["enforcement_point_id"]:
            points = [row["enforcement_point_id"]]
        elif "appliance_group_id" in row and row["appliance_group_id"]:
            points = by_group.get(row["appliance_group_id"], [])
        elif "appliance_id" in row and row["appliance_id"]:
            points = by_appliance.get(row["appliance_id"], [])
        if points:
            resolved[row["pk"]] = points
    return resolved


@transaction.atomic
def rebuild_device_group_bindings(
    management_station: ManagementStation,
) -> DeviceGroupBindingRebuildResult:
    """Rebuild every binding for one station from the provenance rows as they stand now."""

    rows = FieldProvenance.objects.filter(
        provenance_type=FieldProvenance.ProvenanceType.DEVICE_GROUP
    ).exclude(raw_value="")

    by_content_type: dict[int, set[int]] = defaultdict(set)
    names_by_object: dict[tuple[int, int], set[str]] = defaultdict(set)
    for content_type_id, object_id, raw_value in rows.values_list(
        "content_type_id", "object_id", "raw_value"
    ):
        by_content_type[content_type_id].add(object_id)
        names_by_object[(content_type_id, object_id)].add(raw_value)

    by_group, by_appliance = _enforcement_points_by_owner(management_station)

    wanted: set[tuple[str, int]] = set()
    unresolved = 0
    skipped_content_types = 0
    for content_type_id, pks in by_content_type.items():
        content_type = ContentType.objects.get_for_id(content_type_id)
        try:
            model = apps.get_model(content_type.app_label, content_type.model)
        except LookupError:
            skipped_content_types += 1
            continue
        if model is None:
            skipped_content_types += 1
            continue

        resolved = _resolve_points(model, pks, management_station, by_group, by_appliance)
        for object_id in pks:
            points = resolved.get(object_id)
            if not points:
                unresolved += 1
                continue
            for name in names_by_object[(content_type_id, object_id)]:
                for point_pk in points:
                    wanted.add((name, point_pk))

    groups = _ensure_groups(management_station, {name for name, _point in wanted})
    provenance_only = sorted(
        group.name for group in groups.values()
        if group.discovered_from == DeviceGroup.DISCOVERED_PROVENANCE
    )

    wanted_pairs = {(groups[name].pk, point_pk) for name, point_pk in wanted}
    existing = {
        (group_pk, point_pk): binding_pk
        for binding_pk, group_pk, point_pk in DeviceGroupBinding.objects.filter(
            device_group__management_station=management_station
        ).values_list("pk", "device_group_id", "enforcement_point_id")
    }

    stale = [binding_pk for pair, binding_pk in existing.items() if pair not in wanted_pairs]
    deleted = 0
    if stale:
        deleted = DeviceGroupBinding.objects.filter(pk__in=stale).delete()[0]

    created = DeviceGroupBinding.objects.bulk_create(
        [
            DeviceGroupBinding(device_group_id=group_pk, enforcement_point_id=point_pk)
            for group_pk, point_pk in sorted(wanted_pairs - set(existing))
        ]
    )

    return DeviceGroupBindingRebuildResult(
        management_station=management_station,
        device_group_count=len(groups),
        binding_count=len(wanted_pairs),
        created_binding_count=len(created),
        deleted_binding_count=deleted,
        provenance_only_names=provenance_only,
        unresolved_row_count=unresolved,
        skipped_content_type_count=skipped_content_types,
    )


def _ensure_groups(management_station: ManagementStation, names: set[str]):
    """{provenance name: DeviceGroup}, creating rows for names the hierarchy did not carry.

    `shared` resolves to the Shared container rather than becoming a device group of its own.
    """
    groups: dict[str, DeviceGroup] = {}
    for name in sorted(names):
        if name.casefold() == SHARED_PROVENANCE_VALUE:
            group, _created = DeviceGroup.objects.get_or_create(
                management_station=management_station,
                name=SHARED_NAME,
                defaults={
                    "is_shared": True,
                    "discovered_from": DeviceGroup.DISCOVERED_SYNTHESIZED,
                },
            )
        else:
            group, _created = DeviceGroup.objects.get_or_create(
                management_station=management_station,
                name=name,
                defaults={"discovered_from": DeviceGroup.DISCOVERED_PROVENANCE},
            )
        groups[name] = group
    return groups
