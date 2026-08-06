"""Snapshot retrieval helpers for PAN-OS normalization.

Provides enforcement-point scoped lookups for the three snapshot types used during
normalization. Kept separate from common.py (payload parsing) since these are ORM
queries rather than pure data transformations.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import Appliance, EnforcementPoint, Snapshot


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
    # Pushed shared policy is collected per appliance_group and has no meaning for a
    # locally-managed device, so this has to know whether Panorama manages the device.
    #
    # EP.appliance_group is used as that discriminant - Panorama-managed devices are all
    # modeled with a group (TYPE_STANDALONE, TYPE_HA_PAIR, ...), while EP.appliance
    # (direct) means locally managed. BUT THAT IS A PROXY, NOT THE FACT. It holds only
    # because the non-Panorama collection path was never completed, so every
    # EnforcementPoint in existence comes from normalization/panorama.py with
    # appliance_group set; EP.appliance is set only in tests.
    #
    # ApplianceGroup models HA/multi-appliance topology, not Panorama. A locally-managed
    # HA pair is exactly what it is for, and would set appliance_group on a device with no
    # Panorama - at which point this returns a group, addresses.py raises "Panorama-managed
    # but pushed-shared snapshot missing", and the error is nonsense.
    #
    # The explicit discriminant already exists: management_station.station_type
    # (PAN_PANORAMA / PAN_FIREWALL). Switch to it here, in addresses.py and in regions.py
    # before anyone removes either FK. See CLAUDE.md, "Topology model hierarchy".
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
