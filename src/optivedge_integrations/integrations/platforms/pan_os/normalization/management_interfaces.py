"""Normalize every management surface on an appliance from one merged-config snapshot.

Reads three roots, which is the shape the payload contract records:

    deviceconfig/system/permitted-ip              -> the MGT surface
    deviceconfig/system/{aux-1,aux-2}/permitted-ip -> the aux surfaces
    network/interface/.../interface-management-profile + network/profiles/...
                                                  -> one surface per bound interface

The object root is the SURFACE, not the config node. That fell out of writing this rather
than being designed: a finding names `ethernet1/1`, so the row has to be the interface, and
the two config nodes that feed it (the binding and the profile) are inputs rather than
subjects. `permitted-ip` is a field group of a surface, not a root of its own.

The layer-3 traversal is the trap the guide warns about: vlan, loopback and tunnel carry
the profile directly with NO layer3 node in the path, so a uniform `.../layer3/` walk finds
ethernet and aggregate-ethernet and silently misses the other three.
"""

from __future__ import annotations

from typing import Any

from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    ManagementInterface,
    PermittedSource,
    Snapshot,
    parse_permitted_source,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import ensure_list
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)

#: Containers whose profile hangs under a `layer3` node, and those where it does not.
#: Keeping them as data rather than a branch is what stops the second group being forgotten.
LAYER3_NESTED = ("ethernet", "aggregate-ethernet")
LAYER3_DIRECT = ("vlan", "loopback", "tunnel")


def _text(node: Any) -> str:
    """A leaf may be a bare string or {'#text': v, '@loc': ...} - see the payload contract."""
    if isinstance(node, dict):
        return str(node.get("#text") or "").strip()
    return str(node or "").strip()


def _permitted_entries(node: Any) -> list[tuple[str, str]]:
    """(value, description) per entry. Absent or empty means unrestricted - the caller decides."""
    if not isinstance(node, dict):
        return []
    out = []
    for entry in ensure_list(node.get("entry")):
        if isinstance(entry, dict):
            name = str(entry.get("@name") or "").strip()
            desc = _text(entry.get("description"))
        else:
            name, desc = str(entry).strip(), ""
        if name:
            out.append((name, desc))
    return out


def _profile_permitted(device_entry: dict, profile_name: str) -> list[tuple[str, str]]:
    profiles = (((device_entry.get("network") or {}).get("profiles") or {})
                .get("interface-management-profile") or {})
    for entry in ensure_list(profiles.get("entry") if isinstance(profiles, dict) else None):
        if isinstance(entry, dict) and str(entry.get("@name") or "").strip() == profile_name:
            return _permitted_entries(entry.get("permitted-ip"))
    return []


def _bound_interfaces(device_entry: dict) -> list[tuple[str, str]]:
    """(interface_name, profile_name) for every layer-3 interface carrying a profile."""
    interfaces = (device_entry.get("network") or {}).get("interface") or {}
    if not isinstance(interfaces, dict):
        return []
    found: list[tuple[str, str]] = []

    def units(node: Any, parent: str) -> None:
        for unit in ensure_list((node or {}).get("units", {}).get("entry")):
            if isinstance(unit, dict):
                name = str(unit.get("@name") or "").strip() or parent
                profile = _text(unit.get("interface-management-profile"))
                if profile:
                    found.append((name, profile))

    for container in LAYER3_NESTED:
        for entry in ensure_list((interfaces.get(container) or {}).get("entry")):
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("@name") or "").strip()
            layer3 = entry.get("layer3")
            if not isinstance(layer3, dict):
                continue
            profile = _text(layer3.get("interface-management-profile"))
            if profile:
                found.append((name, profile))
            units(layer3, name)

    # vlan / loopback / tunnel: the profile hangs directly off the container, no layer3 node
    for container in LAYER3_DIRECT:
        node = interfaces.get(container)
        if not isinstance(node, dict):
            continue
        profile = _text(node.get("interface-management-profile"))
        if profile:
            found.append((container, profile))
        units(node, container)
    return found


def normalize_management_interfaces(appliance: Appliance) -> list[ManagementInterface]:
    """Replace every management surface for one appliance. Returns what was written."""
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")
    device_entry = device_entry_from_snapshot(snapshot)
    system = ((device_entry.get("deviceconfig") or {}).get("system") or {})

    surfaces: list[tuple[str, str, str, list[tuple[str, str]]]] = [
        (ManagementInterface.PLANE_MGT, "", "", _permitted_entries(system.get("permitted-ip"))),
    ]
    for plane, key in ((ManagementInterface.PLANE_AUX1, "aux-1"),
                       (ManagementInterface.PLANE_AUX2, "aux-2")):
        aux = system.get(key)
        if isinstance(aux, dict):
            surfaces.append((plane, "", "", _permitted_entries(aux.get("permitted-ip"))))
    for interface_name, profile_name in _bound_interfaces(device_entry):
        surfaces.append((ManagementInterface.PLANE_DATAPLANE, interface_name, profile_name,
                         _profile_permitted(device_entry, profile_name)))

    written: list[ManagementInterface] = []
    with transaction.atomic():
        ManagementInterface.objects.filter(appliance=appliance).delete()
        for plane, interface_name, profile_name, entries in surfaces:
            surface = ManagementInterface.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                source_snapshot=snapshot,
                plane=plane,
                interface_name=interface_name,
                profile_name=profile_name,
            )
            for position, (value, description) in enumerate(entries):
                family, start, end = parse_permitted_source(value)
                PermittedSource.objects.create(
                    management_interface=surface, position=position, value=value,
                    family=family, ipv4_start_int=start, ipv4_end_int=end,
                    description=description,
                )
            written.append(surface)
    return written
