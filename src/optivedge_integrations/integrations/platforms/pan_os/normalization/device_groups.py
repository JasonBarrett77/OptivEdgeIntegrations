"""Normalize `show dg-hierarchy` into the device-group tree.

The payload carries `@name` and `@dg_id` and nothing else, with nesting by containment, so
this module is short by nature: walk it, upsert a row per group, hang the top level off the
synthesized Shared root, and mark anything that stopped appearing.

`ensure_list` on every child list is not defensive tidiness - a group with exactly one child
arrives as a dict rather than a list, and reading it as a list would silently drop a subtree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from django.db import transaction
from django.utils import timezone

from optivedge_integrations.integrations.models import DeviceGroup, ManagementStation, Snapshot
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import ensure_list
from optivedge_integrations.integrations.platforms.pan_os.collectors.device_groups import (
    DG_HIERARCHY_SOURCE_TYPE,
)

#: What Panorama calls the shared scope, and what an operator looks for in the tree.
SHARED_NAME = "Shared"


@dataclass(slots=True)
class DeviceGroupNode:
    name: str
    dg_id: str
    parent_name: str = ""


@dataclass(slots=True)
class NormalizedDeviceGroups:
    management_station: ManagementStation
    shared: DeviceGroup
    device_groups: list[DeviceGroup] = field(default_factory=list)
    missing_names: list[str] = field(default_factory=list)


def iter_dg_hierarchy_nodes(payload: Any) -> list[DeviceGroupNode]:
    """Every group in the payload, parents before children.

    An empty or missing `dg-hierarchy` is a real answer - a Panorama with no device groups -
    and returns nothing rather than raising.
    """
    if not isinstance(payload, dict):
        return []
    hierarchy = payload.get("dg-hierarchy")
    if not isinstance(hierarchy, dict):
        return []

    nodes: list[DeviceGroupNode] = []

    def walk(container: dict, parent_name: str) -> None:
        for entry in ensure_list(container.get("dg")):
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("@name") or "").strip()
            if not name:
                continue
            nodes.append(
                DeviceGroupNode(
                    name=name,
                    dg_id=str(entry.get("@dg_id") or "").strip(),
                    parent_name=parent_name,
                )
            )
            walk(entry, name)

    walk(hierarchy, "")
    return nodes


def latest_dg_hierarchy_snapshot(management_station: ManagementStation) -> Snapshot | None:
    return (
        Snapshot.objects.filter(
            management_station=management_station,
            source_type=DG_HIERARCHY_SOURCE_TYPE,
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def ensure_shared_device_group(
    management_station: ManagementStation,
    *,
    normalized_at,
    source_snapshot: Snapshot | None = None,
) -> DeviceGroup:
    """The Shared container, which `show dg-hierarchy` does not return.

    Panorama shows it, operators name it, and the tree needs a root - so it is created here
    and flagged `discovered_from=synthesized`, which is the honest label: no device said it.
    """
    shared, _created = DeviceGroup.objects.get_or_create(
        management_station=management_station,
        name=SHARED_NAME,
        defaults={
            "is_shared": True,
            "discovered_from": DeviceGroup.DISCOVERED_SYNTHESIZED,
        },
    )
    shared.is_shared = True
    shared.discovered_from = DeviceGroup.DISCOVERED_SYNTHESIZED
    shared.parent = None
    shared.source_snapshot = source_snapshot
    shared.last_synced_at = normalized_at
    shared.is_missing = False
    shared.missing_since = None
    shared.save()
    return shared


@transaction.atomic
def normalize_device_group_nodes(
    management_station: ManagementStation,
    nodes: list[DeviceGroupNode],
    *,
    source_snapshot: Snapshot | None = None,
    normalized_at=None,
) -> NormalizedDeviceGroups:
    normalized_at = normalized_at or timezone.now()
    shared = ensure_shared_device_group(
        management_station,
        normalized_at=normalized_at,
        source_snapshot=source_snapshot,
    )

    groups_by_name: dict[str, DeviceGroup] = {}
    for node in nodes:
        if node.name == SHARED_NAME:
            # Panorama does not emit Shared, but a group named "Shared" would collide with
            # the synthesized root. Keep the root and skip the entry rather than turning one
            # into the other.
            continue
        group, _created = DeviceGroup.objects.get_or_create(
            management_station=management_station,
            name=node.name,
            defaults={"discovered_from": DeviceGroup.DISCOVERED_COLLECTED},
        )
        group.dg_id = node.dg_id
        group.discovered_from = DeviceGroup.DISCOVERED_COLLECTED
        group.source_snapshot = source_snapshot
        group.last_synced_at = normalized_at
        group.is_missing = False
        group.missing_since = None
        group.save()
        groups_by_name[node.name] = group

    # Parents in a second pass: a child can appear before its parent has a row.
    for node in nodes:
        group = groups_by_name.get(node.name)
        if group is None:
            continue
        parent = groups_by_name.get(node.parent_name) if node.parent_name else shared
        group.parent = parent or shared
        group.save(update_fields=["parent", "updated_at"])

    # Only collected rows are swept. A group known solely from provenance was never in the
    # hierarchy to begin with, so marking it missing on every sync would say nothing.
    missing = (
        DeviceGroup.objects.filter(
            management_station=management_station,
            discovered_from=DeviceGroup.DISCOVERED_COLLECTED,
        )
        .exclude(name__in=list(groups_by_name))
        .exclude(pk=shared.pk)
    )
    missing_names = list(missing.values_list("name", flat=True))
    missing.filter(is_missing=False).update(is_missing=True, missing_since=normalized_at)

    return NormalizedDeviceGroups(
        management_station=management_station,
        shared=shared,
        device_groups=list(groups_by_name.values()),
        missing_names=missing_names,
    )


def normalize_show_dg_hierarchy(
    management_station: ManagementStation,
    collected: PANOSCollectedResponse,
) -> NormalizedDeviceGroups:
    from optivedge_integrations.integrations.platforms.pan_os.persistence.common import (
        extract_result_payload,
    )

    return normalize_device_group_nodes(
        management_station,
        iter_dg_hierarchy_nodes(extract_result_payload(collected)),
        source_snapshot=latest_dg_hierarchy_snapshot(management_station),
    )


def renormalize_device_groups(management_station: ManagementStation) -> NormalizedDeviceGroups | None:
    """Rebuild the tree from the stored snapshot, with no device contact.

    Returns None when the station has never had the hierarchy collected, which is the state
    of every station until the first sync after this landed.
    """
    snapshot = latest_dg_hierarchy_snapshot(management_station)
    if snapshot is None:
        return None
    return normalize_device_group_nodes(
        management_station,
        iter_dg_hierarchy_nodes(snapshot.payload),
        source_snapshot=snapshot,
    )
