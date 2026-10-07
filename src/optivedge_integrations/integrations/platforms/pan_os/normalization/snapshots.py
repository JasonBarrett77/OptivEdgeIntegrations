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


MERGED_CONFIG_SOURCE_TYPE = "show_merged_config"


def _has_merged_config(appliance: Appliance | None) -> bool:
    return appliance is not None and Snapshot.objects.filter(
        appliance=appliance, source_type=MERGED_CONFIG_SOURCE_TYPE).exists()


def choose_local_appliance(enforcement_point: EnforcementPoint) -> Appliance | None:
    """Which appliance's merged config speaks for this enforcement point.

    PREFERS THE ACTIVE MEMBER THAT HAS ONE, not simply the active member. The two differ after
    a failover, and the difference used to fail the whole enforcement point:

      1. A is active, a collection runs, A gets the merged-config snapshots.
      2. The pair fails over. B is active now.
      3. An inventory sync - step 1, which contacts Panorama and no firewall - reads
         `ha/state` and moves `active_appliance` to B.
      4. A renormalize, which contacts no device at all, resolves to B. B has never been
         collected, so `latest_merged_snapshot` returns None and `security_rules` raises
         "missing merged config snapshot" for every vsys on the pair.

    Nothing was misconfigured and nothing was lost - the configuration was in the database the
    whole time, under the other serial - and the recovery was a full re-collection.

    READING THE PEER IS CORRECT, not a fudge. An HA pair's configuration is synchronised, which
    is the premise behind the device-wide models holding one row per appliance that are
    "mostly identical across the pair". The one case where it is not is genuine HA drift, which
    nothing detects today in either direction, and reading the peer beats failing outright.

    The active member still wins whenever it has a snapshot, so a collected estate resolves
    exactly as before.
    """
    if enforcement_point.appliance is not None:
        return enforcement_point.appliance

    appliance_group = enforcement_point.appliance_group
    if appliance_group is None:
        return None

    if _has_merged_config(appliance_group.active_appliance):
        return appliance_group.active_appliance

    # Whichever node has been collected. Ordered so the choice is stable across runs rather
    # than following row order.
    nodes = (enforcement_point.nodes
             .select_related("appliance")
             .order_by("appliance__hostname", "appliance__serial_number", "appliance_id"))
    for node in nodes:
        if _has_merged_config(node.appliance):
            return node.appliance
    for appliance in appliance_group.appliances.order_by("hostname", "serial_number", "pk"):
        if _has_merged_config(appliance):
            return appliance

    # Nothing collected anywhere. Unchanged from before: return the same appliance this used
    # to, so the caller raises the same "missing merged config snapshot" it always did. A pair
    # that has never been collected is a different problem and says so.
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
            source_type=MERGED_CONFIG_SOURCE_TYPE,
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
