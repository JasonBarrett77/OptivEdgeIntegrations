"""PAN-OS security-zone normalization.

Zones and interface addresses both come out of the already-collected
`show config merged` snapshot, so this adds no collection: the zone list is per-vsys
(`devices.entry.vsys.entry[@name=V].zone`), while interface addresses are device-wide
(`devices.entry.network.interface`) and are joined onto the zone by interface name.

**Validated against a PA-5220 (11.1.13-h3) on 2026-08-25.** The shapes below were
originally inferred from the PAN-OS schema; they have since been measured, including the
zone path, all six type subtrees, both interface-address shapes, and every container under
`network.interface` (ethernet, aggregate-ethernet, loopback, tunnel, vlan). One inferred
field was wrong - see `enable-packet-buffer-protection` below.

Nothing here raises on an unrecognised shape: it degrades to "no zones" or "no addresses".
That was the right call while the shapes were guesses and is now a liability worth knowing
about - a container type this code has not met would produce silently empty addresses,
indistinguishable from an interface that genuinely has none (see `ZoneInterface`).

Still **not** measured: DHCP-addressed interfaces, and non-layer3 zones
carrying interface members (PAN-OS refuses to put a layer3 interface in a layer2 zone, so
that pairing needs a layer2 interface to test).

`show config merged` is the firewall's local config merged with Panorama *template*
config. Network and zone configuration is exactly what templates carry, so unlike policy
objects (see CLAUDE.md, "show config merged contains no Panorama-pushed policy objects")
this source is the right one for zones - a template-pushed zone appears here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from django.db import transaction

from optivedge_integrations.integrations.models import (
    EnforcementPoint,
    Snapshot,
    Zone,
    ZoneInterface,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ensure_list,
    merged_vsys_entry,
    parse_yes_no_field,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    latest_merged_snapshot,
)


# The mutually exclusive subtrees of `zone.entry.network`. The subtree that is present is
# the only statement of the zone's type - PAN-OS has no zone type field.
ZONE_NETWORK_TYPES = (
    Zone.TYPE_LAYER3,
    Zone.TYPE_LAYER2,
    Zone.TYPE_VIRTUAL_WIRE,
    Zone.TYPE_TAP,
    Zone.TYPE_TUNNEL,
    Zone.TYPE_EXTERNAL,
)


@dataclass(slots=True)
class NormalizedZoneInterface:
    name: str
    ip_addresses: list[str]


#: UI label -> element, for the four flags under `network/prenat-identification`. Kept as
#: data because the mapping is arbitrary: "Source Lookup" is `enable-prenat-source-policy-
#: lookup` and "Enable Original ID Downstream" is `enable-prenat-source-ip-downstream`.
PRENAT_FLAGS = {
    "prenat_user_identification": "enable-prenat-user-identification",
    "prenat_device_identification": "enable-prenat-device-identification",
    "prenat_source_policy_lookup": "enable-prenat-source-policy-lookup",
    "prenat_source_ip_downstream": "enable-prenat-source-ip-downstream",
}


@dataclass(slots=True)
class NormalizedZone:
    name: str
    zone_type: str
    enable_user_identification: bool
    zone_protection_profile: str
    log_setting: str
    packet_buffer_protection: bool | None
    net_inspection: bool
    include_acl: list[str]
    exclude_acl: list[str]
    enable_device_identification: bool
    device_include_acl: list[str]
    device_exclude_acl: list[str]
    prenat_user_identification: bool
    prenat_device_identification: bool
    prenat_source_policy_lookup: bool
    prenat_source_ip_downstream: bool
    raw_entry: dict[str, Any]
    interfaces: list[NormalizedZoneInterface] = field(default_factory=list)


def _text(node: Any) -> str:
    """A PAN-OS scalar's text, whether it is a bare string or a provenance-wrapped dict."""
    if isinstance(node, str):
        return node.strip()
    value, _raw_key, _raw_prov = scalar_value(node)
    return value.strip()


def _members(node: Any) -> list[str]:
    """The `member` values under a node, de-duplicated, order preserved."""
    if not isinstance(node, dict):
        return []
    seen: set[str] = set()
    values = []
    for member in ensure_list(node.get("member")):
        text = _text(member)
        if text and text not in seen:
            seen.add(text)
            values.append(text)
    return values


def _ip_entry_names(node: Any) -> list[str]:
    """Address strings from an `ip` node - its entries are keyed by the address itself."""
    if not isinstance(node, dict):
        return []
    names = []
    for entry in ensure_list(node.get("entry")):
        name = _text(entry.get("@name")) if isinstance(entry, dict) else _text(entry)
        if name:
            names.append(name)
    return names


def _interface_addresses(entry: Any) -> list[str]:
    """Addresses configured directly on one interface or subinterface entry.

    Layer 3 physical interfaces carry them under `layer3.ip`; vlan/loopback/tunnel units
    carry them under `ip` directly. A DHCP-addressed interface has neither, and is
    correctly reported as having no configured address - the runtime lease is not config.

    IPv4 and IPv6 live under different nodes and both are collected, IPv4 first. Measured
    on 11.1.13-h3, an interface with both reports:

        {"ip":   {"entry": [{"@name": "10.201.1.1/32"}]},
         "ipv6": {"enabled": "yes", "address": {"entry": [{"@name": "2001:db8:1::1/128"}]}}}

    Reading only `ip` - as this did until 2026-08-25 - drops every IPv6 address silently,
    and an IPv6-only interface then reports no addresses at all, which `ZoneInterface`
    documents as indistinguishable from an interface that genuinely has none.

    `ipv6.enabled` is deliberately NOT consulted: this field is what is *configured*, and a
    configured address under a disabled stack is still worth showing. It does mean an
    address here is not proof the interface answers on it.
    """
    if not isinstance(entry, dict):
        return []
    layer3 = entry.get("layer3")
    holder = layer3 if isinstance(layer3, dict) else entry
    ipv6 = holder.get("ipv6")
    addresses = _ip_entry_names(holder.get("ip"))
    if isinstance(ipv6, dict):
        for address in _ip_entry_names(ipv6.get("address")):
            if address not in addresses:
                addresses.append(address)
    return addresses


def _unit_entries(node: Any) -> list[dict[str, Any]]:
    """Subinterface entries under a node, from either `units` or `layer3.units`."""
    if not isinstance(node, dict):
        return []
    units = []
    for holder in (node, node.get("layer3")):
        if not isinstance(holder, dict):
            continue
        container = holder.get("units")
        if isinstance(container, dict):
            units.extend(entry for entry in ensure_list(container.get("entry")) if isinstance(entry, dict))
    return units


def build_interface_address_index(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Map interface name -> configured addresses, from the device-wide network tree.

    Walks every container under `network.interface` the same way rather than naming
    ethernet/aggregate-ethernet/vlan/loopback/tunnel individually, so a container this
    code has not heard of still contributes its interfaces instead of silently dropping
    them.
    """
    config = payload.get("config") if isinstance(payload, dict) else None
    devices = config.get("devices") if isinstance(config, dict) else None
    device_entries = ensure_list(devices.get("entry")) if isinstance(devices, dict) else []
    device_entry = device_entries[0] if device_entries and isinstance(device_entries[0], dict) else {}
    network = device_entry.get("network") if isinstance(device_entry, dict) else None
    interfaces = network.get("interface") if isinstance(network, dict) else None
    if not isinstance(interfaces, dict):
        return {}

    index: dict[str, list[str]] = {}

    def record(name: str, addresses: list[str]) -> None:
        if not name:
            return
        existing = index.setdefault(name, [])
        for address in addresses:
            if address not in existing:
                existing.append(address)

    for container in interfaces.values():
        if not isinstance(container, dict):
            continue
        for entry in ensure_list(container.get("entry")):
            if not isinstance(entry, dict):
                continue
            record(_text(entry.get("@name")), _interface_addresses(entry))
            for unit in _unit_entries(entry):
                record(_text(unit.get("@name")), _interface_addresses(unit))
        # vlan/loopback/tunnel hold their units directly on the container, with no
        # physical entry above them.
        for unit in _unit_entries(container):
            record(_text(unit.get("@name")), _interface_addresses(unit))

    return index


def build_normalized_zones(payload: dict[str, Any], vsys_name: str) -> list[NormalizedZone]:
    vsys_entry = merged_vsys_entry(payload, vsys_name)
    zone_node = vsys_entry.get("zone") if isinstance(vsys_entry, dict) else None
    if not isinstance(zone_node, dict):
        return []

    address_index = build_interface_address_index(payload)

    zones = []
    for entry in ensure_list(zone_node.get("entry")):
        if not isinstance(entry, dict):
            continue
        name = _text(entry.get("@name"))
        if not name:
            continue

        network = entry.get("network") if isinstance(entry.get("network"), dict) else {}
        zone_type = Zone.TYPE_UNKNOWN
        interface_names: list[str] = []
        for candidate in ZONE_NETWORK_TYPES:
            if candidate in network:
                zone_type = candidate
                interface_names = _members(network.get(candidate))
                break

        user_acl = entry.get("user-acl") if isinstance(entry.get("user-acl"), dict) else {}
        # `device-acl`, NOT `device-id-acl` - measured, and the difference is invisible
        # until nothing parses.
        device_acl = entry.get("device-acl") if isinstance(entry.get("device-acl"), dict) else {}
        prenat = network.get("prenat-identification")
        prenat = prenat if isinstance(prenat, dict) else {}

        def flag(node: Any) -> bool:
            """These default OFF, unlike packet-buffer protection - absent means False."""
            value, _raw_key, _raw_prov = parse_yes_no_field(node, default_effective=False)
            return value

        enable_user_identification = flag(entry.get("enable-user-identification"))
        prenat_values = {name: flag(prenat.get(element)) for name, element in PRENAT_FLAGS.items()}
        # `enable-packet-buffer-protection`, NOT `packet-buffer-protection` - PAN-OS
        # rejects the latter outright ("packet-buffer-protection unexpected here"), so the
        # field read here for its first year was one that cannot exist and the value was
        # permanently None. Measured on 11.1.13-h3.
        packet_buffer_raw = _text(network.get("enable-packet-buffer-protection"))

        zones.append(
            NormalizedZone(
                name=name,
                zone_type=zone_type,
                enable_user_identification=enable_user_identification,
                zone_protection_profile=_text(network.get("zone-protection-profile")),
                log_setting=_text(network.get("log-setting")),
                # Tri-state, all three states measured on a live device:
                #   absent -> None   the default, which is ENABLED
                #   "no"   -> False  explicitly off; what the UI writes when you untick
                #   "yes"  -> True   explicitly on; unreachable from the UI, which writes
                #                    nothing when ticked because ticked IS the default
                # None is the normal reading for a real zone, not an edge case. Anything
                # reporting on this must not render None as disabled - it is the opposite.
                packet_buffer_protection=None if not packet_buffer_raw else packet_buffer_raw.lower() == "yes",
                net_inspection=flag(network.get("net-inspection")),
                include_acl=_members(user_acl.get("include-list")),
                exclude_acl=_members(user_acl.get("exclude-list")),
                enable_device_identification=flag(entry.get("enable-device-identification")),
                device_include_acl=_members(device_acl.get("include-list")),
                device_exclude_acl=_members(device_acl.get("exclude-list")),
                **prenat_values,
                raw_entry=entry,
                interfaces=[
                    NormalizedZoneInterface(
                        name=interface_name,
                        ip_addresses=address_index.get(interface_name, []),
                    )
                    for interface_name in interface_names
                ],
            )
        )

    zones.sort(key=lambda zone: (zone.name.lower(), zone.name))
    return zones


def normalize_zones(enforcement_point: EnforcementPoint) -> list[Zone]:
    """Rebuild this enforcement point's zones from its latest merged-config snapshot.

    Zones are replaced wholesale rather than upserted: a zone deleted on the device has to
    disappear here too, and there is no per-zone state worth preserving across a
    renormalization - every field is derived from the snapshot.
    """
    snapshot = latest_merged_snapshot(enforcement_point)
    if snapshot is None:
        return []

    normalized_zones = build_normalized_zones(snapshot.payload, enforcement_point.vsys_name)

    with transaction.atomic():
        Zone.objects.filter(enforcement_point=enforcement_point).delete()

        persisted = []
        for normalized in normalized_zones:
            zone = Zone.objects.create(
                management_station=enforcement_point.management_station,
                enforcement_point=enforcement_point,
                source_snapshot=snapshot,
                name=normalized.name,
                zone_type=normalized.zone_type,
                zone_protection_profile=normalized.zone_protection_profile,
                log_setting=normalized.log_setting,
                packet_buffer_protection=normalized.packet_buffer_protection,
                net_inspection=normalized.net_inspection,
                enable_user_identification=normalized.enable_user_identification,
                include_acl=normalized.include_acl,
                exclude_acl=normalized.exclude_acl,
                enable_device_identification=normalized.enable_device_identification,
                device_include_acl=normalized.device_include_acl,
                device_exclude_acl=normalized.device_exclude_acl,
                prenat_user_identification=normalized.prenat_user_identification,
                prenat_device_identification=normalized.prenat_device_identification,
                prenat_source_policy_lookup=normalized.prenat_source_policy_lookup,
                prenat_source_ip_downstream=normalized.prenat_source_ip_downstream,
                raw_entry=normalized.raw_entry,
            )
            ZoneInterface.objects.bulk_create(
                [
                    ZoneInterface(
                        zone=zone,
                        name=interface.name,
                        ip_addresses=interface.ip_addresses,
                        position=position,
                    )
                    for position, interface in enumerate(normalized.interfaces)
                ]
            )
            persisted.append(zone)

    return persisted


def snapshot_for(enforcement_point: EnforcementPoint) -> Snapshot | None:
    """Exposed so callers can report *why* an enforcement point produced no zones."""
    return latest_merged_snapshot(enforcement_point)
