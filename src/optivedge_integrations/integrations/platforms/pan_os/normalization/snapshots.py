"""Snapshot retrieval helpers for PAN-OS normalization.

Provides enforcement-point scoped lookups for the three snapshot types used during
normalization. Kept separate from common.py (payload parsing) since these are ORM
queries rather than pure data transformations.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import (
    Appliance,
    EnforcementPoint,
    ManagementStation,
    Snapshot,
)


def is_panorama_managed(enforcement_point: EnforcementPoint) -> bool:
    """Whether Panorama manages this enforcement point's device.

    Read from `ManagementStation.station_type`, which states it explicitly. Do NOT infer
    it from `EnforcementPoint.appliance_group` being set: `ApplianceGroup` models HA and
    multi-appliance topology, and a locally-managed HA pair is exactly what it is for.
    That inference was previously made here and would have raised "missing pushed shared
    policy snapshot" for a device that never had one, the first time a non-Panorama
    device was collected into a group.

    Anything asking "should pushed Panorama data exist for this?" belongs here, so there
    is one definition to change rather than three call sites to keep in step.
    """
    return (
        enforcement_point.management_station.station_type
        == ManagementStation.StationType.PAN_PANORAMA
    )


def choose_local_appliance(enforcement_point: EnforcementPoint) -> Appliance | None:
    if enforcement_point.appliance is not None:
        return enforcement_point.appliance

    appliance_group = enforcement_point.appliance_group
    if appliance_group is None:
        return None

    if appliance_group.active_appliance is not None:
        return appliance_group.active_appliance

    node = enforcement_point.nodes.select_related("appliance").order_by("id").first()
    if node is not None:
        return node.appliance

    return appliance_group.appliances.order_by("hostname", "serial_number", "pk").first()


def latest_merged_snapshot(enforcement_point: EnforcementPoint) -> Snapshot | None:
    appliance = choose_local_appliance(enforcement_point)
    if appliance is None:
        return None
    return (
        Snapshot.objects.filter(
            appliance=appliance,
            source_type="show_merged_config",
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def latest_pushed_vsys_snapshot(enforcement_point: EnforcementPoint) -> Snapshot | None:
    return (
        Snapshot.objects.filter(
            enforcement_point=enforcement_point,
            source_type="show_pushed_shared_policy_vsys",
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def latest_predefined_ip_block_lists_snapshot(enforcement_point: EnforcementPoint) -> Snapshot | None:
    appliance = choose_local_appliance(enforcement_point)
    if appliance is None:
        return None
    return (
        Snapshot.objects.filter(
            appliance=appliance,
            source_type="show_predefined_ip_block_lists",
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def latest_predefined_url_lists_snapshot(enforcement_point: EnforcementPoint) -> Snapshot | None:
    appliance = choose_local_appliance(enforcement_point)
    if appliance is None:
        return None
    return (
        Snapshot.objects.filter(
            appliance=appliance,
            source_type="show_predefined_url_lists",
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def latest_pushed_shared_snapshot(enforcement_point: EnforcementPoint) -> Snapshot | None:
    # Pushed shared policy only exists when Panorama manages the device; ask that
    # question directly rather than inferring it from topology. See is_panorama_managed().
    if not is_panorama_managed(enforcement_point):
        return None

    # Panorama collects this per appliance_group, so without one there is nothing to look
    # up. Callers treat the absent snapshot as an error for a Panorama-managed point.
    appliance_group = enforcement_point.appliance_group
    if appliance_group is None:
        return None
    return (
        Snapshot.objects.filter(
            appliance_group=appliance_group,
            source_type="show_pushed_shared_policy",
        )
        .order_by("-collected_at", "-pk")
        .first()
    )
