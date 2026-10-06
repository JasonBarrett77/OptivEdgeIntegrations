"""Panorama-specific normalization helpers.

Topology here is built from `show devices all`. **`show devicegroups` is a second,
unconsumed Panorama source** and worth knowing about: it returns device-group membership
*and* a per-device `shared-policy-md5sum`, which is the only observed signal for whether a
device's pushed policy is current. Two cautions, both measured: it does not exist on a
firewall, and `shared-policy-md5sum` was seen twice under a single device entry with the
same value, so it needs `force_list` treatment rather than being read as a scalar. See
`docs/palo-alto/pan-os/read-config-sources.md`.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    EnforcementNode,
    EnforcementPoint,
    ManagementStation,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ensure_list,
    first_text,
    iter_nested_entries,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection
from optivedge_integrations.integrations.platforms.pan_os.persistence.common import extract_result_payload


def build_ha_pair_group_name(serial_numbers: tuple[str, str]) -> str:
    return f"ha-pair-{serial_numbers[0]}-{serial_numbers[1]}"


def build_standalone_group_name(serial_number: str) -> str:
    return f"standalone-{serial_number}"


@dataclass(slots=True)
class ManagedDeviceNormalizationContext:
    appliance: Appliance
    appliance_group: ApplianceGroup
    observed_vsys_entries: list[dict[str, str]]


def iter_show_managed_devices_entries(collected: PANOSCollectedResponse) -> list[dict[str, object]]:
    payload = extract_result_payload(collected)
    entries: list[dict[str, object]] = []
    for entry in iter_nested_entries(payload):
        serial_number = first_text(
            entry,
            "serial",
            "serial-no",
            "serial_number",
        )
        if not serial_number:
            continue
        entries.append(entry)
    return entries


def get_or_create_observed_appliance(
    management_station: ManagementStation,
    entry: dict[str, object],
    *,
    normalized_at,
) -> Appliance:
    serial_number = first_text(entry, "serial", "serial-no", "serial_number")
    hostname = first_text(
        entry,
        "hostname",
        "host-name",
        "hostname-s",
        "dns-hostname",
        "name",
    )
    model = first_text(entry, "model")
    software_version = first_text(
        entry,
        "sw-version",
        "software-version",
        "version",
    )

    appliance, _created = Appliance.objects.get_or_create(
        management_station=management_station,
        serial_number=serial_number,
        defaults={
            "hostname": hostname,
            "model": model,
            "software_version": software_version,
            "last_synced_at": normalized_at,
        },
    )

    appliance.hostname = hostname or appliance.hostname
    appliance.model = model or appliance.model
    appliance.software_version = software_version or appliance.software_version
    appliance.last_synced_at = normalized_at
    return appliance


def attach_ha_pair_group(
    management_station: ManagementStation,
    appliance: Appliance,
    peer_serial_number: str,
    *,
    ha_state: str,
    normalized_at,
) -> ApplianceGroup:
    pair_serials = tuple(sorted([appliance.serial_number, peer_serial_number]))
    group_name = build_ha_pair_group_name(pair_serials)
    group, _created = ApplianceGroup.objects.get_or_create(
        management_station=management_station,
        name=group_name,
        defaults={
            "group_type": ApplianceGroup.TYPE_HA_PAIR,
            "discovery_key": ":".join(pair_serials),
        },
    )
    group.group_type = ApplianceGroup.TYPE_HA_PAIR
    group.discovery_key = ":".join(pair_serials)

    peer_appliance, _created = Appliance.objects.get_or_create(
        management_station=management_station,
        serial_number=peer_serial_number,
        defaults={
            "appliance_group": group,
        },
    )

    appliance.appliance_group = group
    appliance.topology_resolved_at = normalized_at
    peer_appliance.appliance_group = group
    peer_appliance.topology_resolved_at = normalized_at

    if ha_state == "active":
        group.active_appliance = appliance

    appliance.save()
    peer_appliance.save()
    group.save()
    return group


def attach_standalone_group(
    management_station: ManagementStation,
    appliance: Appliance,
    *,
    normalized_at,
) -> ApplianceGroup:
    group_name = build_standalone_group_name(appliance.serial_number)
    group, _created = ApplianceGroup.objects.get_or_create(
        management_station=management_station,
        name=group_name,
        defaults={
            "group_type": ApplianceGroup.TYPE_STANDALONE,
            "discovery_key": appliance.serial_number,
        },
    )
    group.group_type = ApplianceGroup.TYPE_STANDALONE
    group.discovery_key = appliance.serial_number
    group.active_appliance = appliance

    appliance.appliance_group = group
    appliance.topology_resolved_at = normalized_at
    appliance.save()
    group.save()
    return group


def normalize_vsys_entries(entry: dict[str, object]) -> list[dict[str, str]]:
    vsys = entry.get("vsys")
    if not isinstance(vsys, dict):
        return []
    vsys_entries = ensure_list(vsys.get("entry"))
    normalized_entries: list[dict[str, str]] = []
    for vsys_entry in vsys_entries:
        if not isinstance(vsys_entry, dict):
            continue
        vsys_name = first_text(vsys_entry, "@name", "name")
        if vsys_name:
            normalized_entries.append(
                {
                    "vsys_name": vsys_name,
                    "vsys_display_name": first_text(vsys_entry, "display-name"),
                }
            )
    return normalized_entries


def normalize_managed_device_entry(
    management_station: ManagementStation,
    entry: dict[str, object],
    *,
    normalized_at,
) -> ManagedDeviceNormalizationContext:
    appliance = get_or_create_observed_appliance(
        management_station,
        entry,
        normalized_at=normalized_at,
    )

    ha = entry.get("ha")
    ha_state = ""
    peer_serial_number = ""
    if isinstance(ha, dict):
        ha_state = first_text(ha, "state")
        peer = ha.get("peer")
        if isinstance(peer, dict):
            peer_serial_number = first_text(peer, "serial")

    if peer_serial_number:
        appliance_group = attach_ha_pair_group(
            management_station,
            appliance,
            peer_serial_number,
            ha_state=ha_state,
            normalized_at=normalized_at,
        )
    else:
        appliance_group = attach_standalone_group(
            management_station,
            appliance,
            normalized_at=normalized_at,
        )

    observed_vsys_entries = normalize_vsys_entries(entry)
    if observed_vsys_entries:
        appliance.virtual_systems_collected_at = normalized_at
        appliance.save()

    return ManagedDeviceNormalizationContext(
        appliance=appliance,
        appliance_group=appliance_group,
        observed_vsys_entries=observed_vsys_entries,
    )


def retire_superseded_enforcement_points(management_station, seen_point_ids, normalized_at):
    """Retire the enforcement points an appliance has moved away from, carrying scope with it.

    THE BUG THIS FIXES. An appliance's group is chosen afresh on every sync from
    `ha/peer/serial`: no peer serial means `standalone-<serial>`, a peer serial means
    `ha-pair-<a>-<b>`. A pair that is still negotiating - firewalls recently powered on, auto-
    commit not finished - reports no peer, so the first sync builds standalone groups and the
    next builds the HA pair. Enforcement points are keyed on (station, GROUP, vsys), so the
    second sync creates a NEW row per vsys and the first set was left behind: still present,
    still `in_scope`, pointing at a group the appliance no longer belongs to.

    Two consequences, and the second is the one that hurts. The station shows two rows per
    vsys. And scope was recorded on the OLD row while collection reads
    `enforcement_points.filter(in_scope=True)` - so an operator who chose scope before the pair
    came up has their choice silently applied to a row nothing collects through, and the
    estate looks collected when it is not.

    THE RULE. An enforcement point is superseded when every appliance that reaches it - through
    `EnforcementNode`, not by name - now belongs to a DIFFERENT group, and a point for the same
    vsys exists under one of those groups. Matching on `vsys_name` alone would pair two
    appliances that both have a `vsys1`, which is most of them.

    MARKED MISSING, NOT DELETED. `SyncTrackedModel.is_missing` is what this model has for
    "was here, is not now", deletion would cascade through the collected configuration to the
    findings recorded against it, and a row that turns out to have been retired wrongly is
    recoverable this way and not the other. `in_scope` is cleared as well, because that - not
    `is_missing`, which nothing reads for this model - is what collection follows.
    """
    retired = []
    stale = (EnforcementPoint.objects
             .filter(management_station=management_station, appliance_group__isnull=False)
             .exclude(pk__in=seen_point_ids)
             .prefetch_related("nodes__appliance"))
    for point in stale:
        appliances = [node.appliance for node in point.nodes.all() if node.appliance_id]
        if not appliances:
            # Nothing reaches it, so nothing says where it moved TO. Left alone: an
            # enforcement point for a device Panorama no longer manages is a different
            # question, and guessing at it here would retire rows for the wrong reason.
            continue
        if any(a.appliance_group_id == point.appliance_group_id for a in appliances):
            continue  # still served where it says it is
        replacement = (EnforcementPoint.objects
                       .filter(management_station=management_station,
                               appliance_group_id__in={a.appliance_group_id for a in appliances},
                               vsys_name=point.vsys_name)
                       .exclude(pk=point.pk)
                       .order_by("pk")
                       .first())
        if replacement is None:
            continue
        if point.in_scope and not replacement.in_scope:
            replacement.in_scope = True
            replacement.save(update_fields=["in_scope"])
        point.in_scope = False
        point.is_missing = True
        point.missing_since = normalized_at
        point.save(update_fields=["in_scope", "is_missing", "missing_since"])
        retired.append(point)
    return retired


def normalize_show_managed_devices(
    management_station: ManagementStation,
    collected: PANOSCollectedResponse,
) -> PANOSNormalizedCollection:
    appliances_by_id: dict[int, Appliance] = {}
    groups_by_id: dict[int, ApplianceGroup] = {}
    enforcement_points_by_id: dict[int, EnforcementPoint] = {}
    enforcement_nodes_by_id: dict[int, EnforcementNode] = {}
    normalized_at = timezone.now()

    with transaction.atomic():
        for entry in iter_show_managed_devices_entries(collected):
            context = normalize_managed_device_entry(
                management_station,
                entry,
                normalized_at=normalized_at,
            )
            appliances_by_id[context.appliance.id] = context.appliance
            groups_by_id[context.appliance_group.id] = context.appliance_group

            for vsys_entry in context.observed_vsys_entries:
                vsys_name = vsys_entry["vsys_name"]
                vsys_display_name = vsys_entry["vsys_display_name"]
                enforcement_point, _created = EnforcementPoint.objects.get_or_create(
                    management_station=management_station,
                    appliance_group=context.appliance_group,
                    vsys_name=vsys_name,
                    defaults={
                        "vsys_display_name": vsys_display_name,
                        "discovery_key": vsys_name,
                    },
                )
                enforcement_point.vsys_display_name = vsys_display_name
                enforcement_point.discovery_key = vsys_name
                enforcement_point.save()
                enforcement_points_by_id[enforcement_point.id] = enforcement_point

                enforcement_node, _created = EnforcementNode.objects.get_or_create(
                    management_station=management_station,
                    appliance=context.appliance,
                    enforcement_point=enforcement_point,
                    defaults={
                        "last_synced_at": normalized_at,
                    },
                )
                enforcement_node.last_synced_at = normalized_at
                enforcement_node.save()
                enforcement_nodes_by_id[enforcement_node.id] = enforcement_node

        # After every device in the response has been placed, so a point confirmed by one
        # appliance cannot be retired while iterating another.
        retire_superseded_enforcement_points(
            management_station, set(enforcement_points_by_id), normalized_at)

    return PANOSNormalizedCollection(
        address_objects=[],
        address_groups=[],
        appliances=list(appliances_by_id.values()),
        appliance_groups=list(groups_by_id.values()),
        enforcement_points=list(enforcement_points_by_id.values()),
        enforcement_nodes=list(enforcement_nodes_by_id.values()),
        security_rules=[],
    )
