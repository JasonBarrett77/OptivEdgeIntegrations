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

Nothing here raises on an unrecognized shape: it degrades to "no zones" or "no addresses".
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

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    EnforcementPoint,
    FieldProvenance,
    Snapshot,
    Zone,
    ZoneInterface,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ENTRY_FIELD,
    Implicit,
    ensure_list,
    entry_provenance_record,
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
    device_identification_is_narrowed: bool
    device_acl_lists_computed: bool
    prenat_user_identification: bool
    prenat_device_identification: bool
    prenat_source_policy_lookup: bool
    prenat_source_ip_downstream: bool
    raw_entry: dict[str, Any]
    #: PAN-ZON-001's three. `interface_count` and `can_receive_traffic` come out of this entry;
    #: `zone_protection_unresolved` needs the appliance's PROFILE COLLECTION, which is
    #: device-wide and sits in the same payload, so all three are resolved here rather than in
    #: a second pass over the rows.
    interface_count: int = 0
    can_receive_traffic: bool = True
    zone_protection_unresolved: bool = True
    interfaces: list[NormalizedZoneInterface] = field(default_factory=list)


def _text(node: Any) -> str:
    """A PAN-OS scalar's text, whether it is a bare string or a provenance-wrapped dict."""
    if isinstance(node, str):
        return node.strip()
    value, _raw_key, _raw_prov = scalar_value(node)
    return value.strip()


def _device_entry(payload: dict[str, Any]) -> dict[str, Any]:
    """The first device entry of a merged-config payload, or an empty dict.

    `device_configuration.device_entry_from_snapshot` RAISES on a payload it does not recognize
    and takes a Snapshot; this module is handed a bare payload and degrades to "no zones"
    rather than raising, which is the behavior its own docstring records as deliberate while
    the shapes were guesses and as a known liability now. Kept consistent rather than mixed.
    """
    config = payload.get("config") if isinstance(payload, dict) else None
    devices = config.get("devices") if isinstance(config, dict) else None
    entries = ensure_list(devices.get("entry")) if isinstance(devices, dict) else []
    return entries[0] if entries and isinstance(entries[0], dict) else {}


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


# ---------------------------------------------------------------------------
# PAN-ZON-001 - three pure functions, imported by normalization/zone_dos_protection.py
# ---------------------------------------------------------------------------

def zone_protection_profile_names(device_entry: dict[str, Any]) -> set[str]:
    """Every zone protection profile name defined on this appliance, CASE PRESERVED.

    THE COLLECTION HAS EXACTLY ONE SCOPE ON A FIREWALL and that is a measurement, not a
    simplification: `action=complete` answers code=6 Invalid sequence at both
    `/config/shared/network/profiles/zone-protection-profile` and the vsys spelling. So the
    resolution order a zone's attachment walks has a SINGLE member and there is no second scope
    to fall through to - which is the whole reason this returns a flat set rather than a
    scope-ordered mapping the way `_profiles_by_scope` has to for a policy object.

    Imported by `zone_dos_protection.py` so that the zone side of the attachment join and the
    profile side read the same bytes in the same pass. The alternative - having one normalizer
    read the other's rows back - is what `interface_management_profiles.py` had to do and had to
    raise about, because it makes one pass depend on the other having run.
    """
    network = device_entry.get("network") if isinstance(device_entry, dict) else None
    profiles = network.get("profiles") if isinstance(network, dict) else None
    collection = profiles.get("zone-protection-profile") if isinstance(profiles, dict) else None
    if not isinstance(collection, dict):
        return set()
    return {
        name
        for entry in ensure_list(collection.get("entry")) if isinstance(entry, dict)
        if (name := _text(entry.get("@name")))
    }


def zone_attachment_verdict(
    zone_protection_profile: str, profile_names: set[str],
) -> bool:
    """`Zone.zone_protection_unresolved`. True means NO profile is in force on the zone.

    TWO STATES, ONE COLUMN, and the second is what the measurement bought: the attachment leaf
    is empty, OR it names a profile that does not exist. The configuration expresses NO
    referential integrity here - stage 4 measured the leaf as a free string - so a dangling name
    reads as configured and the zone meters nothing. `is_empty` on
    `Zone.zone_protection_profile` is the clause a reviewer would write and it misses that case.

    THE COMPARISON IS CASE-SENSITIVE AND MUST STAY SO. Profile names are case-sensitive and not
    normalized (help p.663), so a case-insensitive resolution would report a profile as attached
    that the dataplane does not resolve.
    """
    name = (zone_protection_profile or "").strip()
    if not name:
        return True
    return name not in profile_names


def zone_can_receive_traffic(zone_type: str, interface_count: int) -> bool:
    """`Zone.can_receive_traffic`. Whether PAN-ZON-001 applies to this zone at all.

    A DISJUNCTION, which is why it is computed here: the zone carries one of the six type
    subtrees AND either names at least one interface OR is an EXTERNAL zone, which has no
    interfaces of its own and still offers the attachment. A predicate has no quantifier over
    related rows and this contract's clause is one conjunction.

    `unknown` IS OUTSIDE THE POPULATION RATHER THAN AT THE GENTLE END OF IT: stage 4 measured
    that a zone carrying no `network` subtree at all is a legal committable state, and such a
    zone receives no traffic. That is the one case this returns False for, and it is a FALSE
    computed from a type that was read rather than from a row nobody recomputed - the model's
    default of True is what covers the latter.
    """
    if zone_type == Zone.TYPE_UNKNOWN:
        return False
    if zone_type == Zone.TYPE_EXTERNAL:
        return True
    return interface_count > 0


def build_interface_address_index(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Map interface name -> configured addresses, from the device-wide network tree.

    Walks every container under `network.interface` the same way rather than naming
    ethernet/aggregate-ethernet/vlan/loopback/tunnel individually, so a container this
    code has not heard of still contributes its interfaces instead of silently dropping
    them.
    """
    device_entry = _device_entry(payload)
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
    # DEVICE-WIDE, and read once per build rather than once per zone: the zone protection
    # profile collection has exactly ONE scope on a firewall, measured - `action=complete`
    # answers code=6 Invalid sequence at both the shared and the vsys spellings - so there is no
    # per-vsys copy and no second scope to fall through to.
    zone_protection_profiles = zone_protection_profile_names(_device_entry(payload))

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
            """These read OFF when absent - the claim, and what is behind it, below.

            SEVEN LEAVES SHARE THIS CLOSURE and only `enable-user-identification` has been
            measured, so it reads its own declaration below and the other six keep this one.
            """
            value, _raw_key, _raw_prov = parse_yes_no_field(
                node,
                implicit=Implicit.assumed(
                    False,
                    "stated in this module since it was written - 'these default OFF, unlike "
                    "packet-buffer protection' - with no measurement recorded anywhere. OFF "
                    "reads an unmarked zone as not identifying users, the narrower claim"))
            return value

        # PAN-UID-001's leaf, and the ONE of the seven that is now measured rather than inferred.
        # The declaration is separated from `flag` above so that promoting it does not promote its
        # six neighbours, three of which are the prenat flags, one the Device-ID twin and one
        # net-inspection - none of them measured.
        #
        # THIS CHANGES NO STORED VALUE AND NO STORED ROW, and that is worth saying because the
        # stage 5 record that asked for it expected otherwise: `Zone` is declared
        # `class Zone(SyncTrackedModel)` and is NOT a `ProvenancedMixin`, so this module writes no
        # `FieldProvenance` row at all and the `Implicit` travels out of `parse_yes_no_field` and
        # is discarded. What moves is the CLAIM: the citation now names a measurement a reader can
        # go and disagree with, instead of naming this module's own prose. If Zone ever gains the
        # mixin, this leaf's row types as `pan_os_default` and its six neighbours as
        # `assumed_default`, which is the distinction this split exists to keep available.
        enable_user_identification, _uid_raw_key, _uid_raw_prov = parse_yes_no_field(
            entry.get("enable-user-identification"),
            implicit=Implicit.measured(
                False,
                "stage4-user-id.json, object security-zone, field enable-user-identification: "
                "implicit 'no', measured on serial 691665AC334B458 (PA-VM 11.2.5) 2026-10-26. A "
                "zone committed carrying nothing but its name renders the User-ID ENABLED "
                "checkbox UNTICKED in Network > Zones, read as a CSS class because innerText is "
                "empty for a ticked and an unticked box alike; the positive control was paid in "
                "BOTH directions (written yes and committed, job 250, box TICKED; deleted and "
                "committed, job 254, UNTICKED again), over a natural experiment of 50 zones "
                "across four appliances and 20 vsys, not one of which stores the key"))
        prenat_values = {name: flag(prenat.get(element)) for name, element in PRENAT_FLAGS.items()}
        # `enable-packet-buffer-protection`, NOT `packet-buffer-protection` - PAN-OS
        # rejects the latter outright ("packet-buffer-protection unexpected here"), so the
        # field read here for its first year was one that cannot exist and the value was
        # permanently None. Measured on 11.1.13-h3.
        packet_buffer_raw = _text(network.get("enable-packet-buffer-protection"))

        # PAN-IOT-002's second half. The two Device-ID lists are JSON columns and a JSON column
        # is reachable from no query, there is no count operator, and a clause cannot hold an
        # OR - so "either list has a member" is computed here or it cannot be asked at all.
        #
        # ABSENT AND EMPTY ARE ONE STATE on the device as well as in the column, measured:
        # deleting the only member leaves the `device-acl` container present and empty, and
        # PAN-OS does not store an empty member list. So false here means the vendor's own
        # INCLUDED NETWORKS `any` / EXCLUDED NETWORKS `none`, which is 48 of the 50 zones
        # measured and is the COMPLIANT state - not an absence of knowledge. The absence of
        # knowledge is the flag beside it.
        device_include_members = _members(device_acl.get("include-list"))
        device_exclude_members = _members(device_acl.get("exclude-list"))

        # PAN-ZON-001'S THREE COLUMNS. `zone_protection_profile` below is the NAIVE reading and
        # these are what the measurement bought: a zone naming a profile that does not exist
        # reads as configured and meters nothing, because the configuration expresses no
        # referential integrity at that leaf - stage 4 measured it as a free string.
        #
        # THE PROFILE NAMES COME OUT OF THIS SAME PAYLOAD, resolved by the shared reader in
        # `zone_dos_protection.py` that the profile normalizer also calls. Reading them here
        # rather than joining to `ZoneProtectionProfile` rows is what makes the two directions
        # of one comparison unable to disagree and removes the ordering dependency.
        attachment = _text(network.get("zone-protection-profile"))
        can_receive = zone_can_receive_traffic(zone_type, len(interface_names))
        zones.append(
            NormalizedZone(
                name=name,
                zone_type=zone_type,
                interface_count=len(interface_names),
                can_receive_traffic=can_receive,
                zone_protection_unresolved=zone_attachment_verdict(
                    attachment, zone_protection_profiles),
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
                device_include_acl=device_include_members,
                device_exclude_acl=device_exclude_members,
                device_identification_is_narrowed=bool(
                    device_include_members or device_exclude_members),
                # TRUE ON EVERY ROW THIS PASS WRITES, and that is the whole of its job: it
                # separates a row this normalizer computed from a row that predates the two
                # columns, which the default of false covers until a renormalization runs. It
                # cannot speak for a zone whose read never arrived - that zone has no row.
                device_acl_lists_computed=True,
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
        # THE PROVENANCE ROWS GO FIRST, and by object id rather than by cascade: a
        # `FieldProvenance` row points at its subject through a generic foreign key, so deleting
        # the zones does not take their rows with it and a renormalization would leave orphans
        # claiming the old pks - the state migration 0065 exists to clean up after.
        content_type = ContentType.objects.get_for_model(Zone)
        FieldProvenance.objects.filter(
            content_type=content_type,
            object_id__in=list(Zone.objects.filter(enforcement_point=enforcement_point)
                               .values_list("pk", flat=True)),
        ).delete()
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
                interface_count=normalized.interface_count,
                can_receive_traffic=normalized.can_receive_traffic,
                zone_protection_unresolved=normalized.zone_protection_unresolved,
                log_setting=normalized.log_setting,
                packet_buffer_protection=normalized.packet_buffer_protection,
                net_inspection=normalized.net_inspection,
                enable_user_identification=normalized.enable_user_identification,
                include_acl=normalized.include_acl,
                exclude_acl=normalized.exclude_acl,
                enable_device_identification=normalized.enable_device_identification,
                device_include_acl=normalized.device_include_acl,
                device_exclude_acl=normalized.device_exclude_acl,
                device_identification_is_narrowed=normalized.device_identification_is_narrowed,
                device_acl_lists_computed=normalized.device_acl_lists_computed,
                prenat_user_identification=normalized.prenat_user_identification,
                prenat_device_identification=normalized.prenat_device_identification,
                prenat_source_policy_lookup=normalized.prenat_source_policy_lookup,
                prenat_source_ip_downstream=normalized.prenat_source_ip_downstream,
                raw_entry=normalized.raw_entry,
            )
            # WHERE THIS ZONE WAS AUTHORED, recorded for every zone including the unmarked
            # ones. An unmarked entry is `local` - a positive statement that the firewall's own
            # configuration defines it, and the one thing a consumer cannot infer from a missing
            # row, which means only "nothing tracks this". Before this, `Zone` had NO provenance
            # at all: 50 zones on the lab, zero rows, and the remediation surface could not tell
            # a zone it may edit on the box from one a template will overwrite at the next push.
            #
            # READ OFF THE ENTRY'S OWN `@ptpl`/`@src`, which the merged-config payload carries on
            # each zone entry and `raw_entry` keeps - the same pair the interface-management,
            # zone-protection, IKE and IPSec normalizers read, through the same helper.
            provenance_type, raw_key, raw_value = entry_provenance_record(normalized.raw_entry)
            FieldProvenance.objects.create(
                content_type=content_type, object_id=zone.pk,
                field_name=ENTRY_FIELD, provenance_type=provenance_type,
                raw_key=raw_key, raw_value=raw_value[:128],
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
