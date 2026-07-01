"""Snapshot retrieval helpers for PAN-OS normalization.

Provides enforcement-point scoped lookups for the three snapshot types used during
normalization. Kept separate from common.py (payload parsing) since these are ORM
queries rather than pure data transformations.
"""

from __future__ import annotations

from optivedge.integrations.models import Appliance, EnforcementPoint, Snapshot


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


def latest_pushed_shared_snapshot(enforcement_point: EnforcementPoint) -> Snapshot | None:
    # EP.appliance_group is the Panorama-management discriminant: all Panorama-managed
    # devices are modeled with appliance_group (TYPE_STANDALONE, TYPE_HA_PAIR, etc.).
    # EP.appliance (direct) means locally-managed with no Panorama. Pushed shared policy
    # is collected per appliance_group and has no meaning for locally-managed devices.
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
