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

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    FieldProvenance,
    ManagementInterface,
    ManagementService,
    PermittedSource,
    Snapshot,
    parse_permitted_source,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    classify_prov_type,
    ensure_list,
    entry_provenance,
    parse_yes_no_field,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.interfaces import (
    bound_management_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)

#: The ten service keys a deviceconfig plane accepts, and the eleven a profile accepts.
#: Measured 2026-08-31 with `action=complete` on a PA-5220 - and aux-1 carries its own
#: `service` node with the same ten, so the aux planes control their services independently
#: rather than inheriting MGT's. Assuming otherwise would have silently given every aux
#: surface the wrong answer.
MGT_SERVICE_KEYS = (
    "disable-http", "disable-https", "disable-ssh", "disable-telnet", "disable-snmp",
    "disable-icmp", "disable-http-ocsp", "disable-userid-service",
    "disable-userid-syslog-listener-ssl", "disable-userid-syslog-listener-udp",
)
PROFILE_SERVICE_KEYS = (
    "http", "https", "ssh", "telnet", "snmp", "ping", "response-pages", "http-ocsp",
    "userid-service", "userid-syslog-listener-ssl", "userid-syslog-listener-udp",
)

#: Services a deviceconfig plane runs when its `disable-*` key is ABSENT. Everything else
#: on that plane is off by default.
#:
#: Measured 2026-08-31: tpa-a carries no `service` node at all and tpa-b carries
#: `disable-telnet: yes, disable-http: yes`, yet both report the same effective services -
#: icmp, ssh, https. Two different configurations agreeing on the outcome is what makes
#: this a default rather than a coincidence of one device. The remaining four keys are
#: reported by neither `show system services` nor the running config; they were established
#: from the compiled ACL, which is the only oracle that sees them, and all four are off.
#:
#: An absent key is not an absent setting: the three below are ON when nothing is written.
MGT_IMPLICIT_ENABLED = frozenset({"https", "ssh", "icmp"})

#: A profile stores as a bare entry with every service absent, and absent means OFF - the
#: opposite polarity to the keys above. Measured 2026-08-27/28.
PROFILE_IMPLICIT_ENABLED: frozenset[str] = frozenset()


def _text(node: Any) -> str:
    """A leaf may be a bare string or {'#text': v, '@loc': ...} - see the payload contract."""
    if isinstance(node, dict):
        return str(node.get("#text") or "").strip()
    return str(node or "").strip()


def _permitted_entries(node: Any) -> list[tuple[str, str, Any, str | None]]:
    """(value, description, provenance) per entry.

    Absent or empty means unrestricted - the caller decides. Each entry carries its own
    provenance: on a management plane the list can mix pushed and local entries, and the
    container's marker does not speak for them.
    """
    if not isinstance(node, dict):
        return []
    out = []
    for entry in ensure_list(node.get("entry")):
        if isinstance(entry, dict):
            name = str(entry.get("@name") or "").strip()
            desc = _text(entry.get("description"))
            # A value's own marker only. Falling back to the container would give an
            # overridden entry its container's source and erase the override, which is the
            # one thing this field exists to show - a pushed list can contain locally added
            # entries, and each states its own origin.
            raw_key, raw_value = entry_provenance(entry)
        else:
            name, desc, raw_key, raw_value = str(entry).strip(), "", None, None
        if name:
            out.append((name, desc, raw_key, raw_value))
    return out


def _mgt_services(system_node: Any) -> dict[str, tuple[bool, Any, str | None]]:
    """Effective service states for a deviceconfig plane, polarity inverted.

    `disable-telnet: yes` means telnet is OFF, so the stored value is the negation of the
    key. Anything that is not literally "yes" is treated as not-disabled, which matches how
    PAN-OS writes the leaf - it emits `yes` or omits the element.
    """
    node = system_node if isinstance(system_node, dict) else {}
    service = node.get("service")
    service = service if isinstance(service, dict) else {}
    out: dict[str, tuple[bool, Any, str | None]] = {}
    for key in MGT_SERVICE_KEYS:
        name = key[len("disable-"):]
        # `disable-X: yes` means the service is OFF, so the effective value is the negation.
        # parse_yes_no_field carries the leaf's own provenance out with it, and returns
        # ABSENT when the key is missing - which is PAN-OS's default rather than anyone's
        # push, and therefore gets no provenance row at all.
        disabled, raw_key, raw_value = parse_yes_no_field(
            service.get(key), default_effective=name not in MGT_IMPLICIT_ENABLED)
        out[name] = (not disabled, raw_key, raw_value)
    return out


def _profile_services(profile_entry: dict) -> dict[str, tuple[bool, Any, str | None]]:
    """Effective service states for an interface management profile.

    Positive keys: present-and-yes is on, absent is off. No inversion.
    """
    node = profile_entry if isinstance(profile_entry, dict) else {}
    entry_key, entry_value = entry_provenance(node)
    out: dict[str, tuple[bool, Any, str | None]] = {}
    for key in PROFILE_SERVICE_KEYS:
        enabled, raw_key, raw_value = parse_yes_no_field(
            node.get(key), default_effective=key in PROFILE_IMPLICIT_ENABLED)
        if raw_key is not ABSENT and raw_key is None and entry_key is not None:
            # A profile overrides at the ENTRY: its leaves either all carry the profile's
            # source or none do, measured on hardware. So the entry's source is the honest
            # answer for a present leaf carrying none of its own - unlike a management
            # plane, where a bare leaf means that leaf alone was overridden.
            raw_key, raw_value = entry_key, entry_value
        out[key] = (enabled, raw_key, raw_value)
    return out


def _profile_entry(device_entry: dict, profile_name: str) -> dict:
    profiles = (((device_entry.get("network") or {}).get("profiles") or {})
                .get("interface-management-profile") or {})
    for entry in ensure_list(profiles.get("entry") if isinstance(profiles, dict) else None):
        if isinstance(entry, dict) and str(entry.get("@name") or "").strip() == profile_name:
            return entry
    return {}


def _bound_interfaces(device_entry: dict) -> list[tuple[str, str, Any, str | None]]:
    """(interface_name, profile_name) for every interface carrying a profile.

    Delegates to the interface normalizer's container-agnostic walk. This used to hard-code
    five containers and silently miss `sdwan`, which both a PA-5220 and a PA-VM offer - an
    sdwan interface with a profile bound was not a management surface as far as this code
    was concerned, and its profile looked unused.
    """
    return bound_management_profiles(device_entry)


def _record(instance, raw_key: Any, raw_value: str | None, *,
            field_name: str = "__entry__") -> None:
    """Write the object's own provenance, or none when the key was absent.

    `field_name="__entry__"` is the established name for an object's own annotation. These
    models are one row per value, so the row's own provenance IS that value's.

    ABSENT means the key was not in the payload at all - PAN-OS supplied its default and
    nobody pushed or wrote anything - so no row is written, and its absence is the answer.
    A key present with no marker gets a row typed `local`, which is a different fact from
    a default and one the previous name-only column could not hold.
    """
    if raw_key is ABSENT:
        return
    FieldProvenance.objects.create(
        content_type=ContentType.objects.get_for_model(type(instance)),
        object_id=instance.pk,
        field_name=field_name,
        provenance_type=classify_prov_type(raw_key),
        raw_key=(raw_key or "")[:32],
        raw_value=(raw_value or "")[:128],
    )


def normalize_management_interfaces(appliance: Appliance) -> list[ManagementInterface]:
    """Replace every management surface for one appliance. Returns what was written."""
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")
    device_entry = device_entry_from_snapshot(snapshot)
    system = ((device_entry.get("deviceconfig") or {}).get("system") or {})

    surfaces: list[tuple[str, str, str, str, list, dict]] = [
        (ManagementInterface.PLANE_MGT, "", "", entry_provenance(system),
         _permitted_entries(system.get("permitted-ip")), _mgt_services(system),
         (ABSENT, None)),
    ]
    for plane, key in ((ManagementInterface.PLANE_AUX1, "aux-1"),
                       (ManagementInterface.PLANE_AUX2, "aux-2")):
        aux = system.get(key)
        if isinstance(aux, dict):
            # An aux plane carries its own `service` node, so its services are read from the
            # aux subtree and never from `system`.
            surfaces.append((plane, "", "", entry_provenance(aux),
                             _permitted_entries(aux.get("permitted-ip")), _mgt_services(aux),
                             (ABSENT, None)))
    for interface_name, profile_name, bind_key, bind_value in _bound_interfaces(device_entry):
        entry = _profile_entry(device_entry, profile_name)
        # A data-plane surface exists because a profile is bound, so the profile entry is
        # what the surface came from.
        surfaces.append((ManagementInterface.PLANE_DATAPLANE, interface_name, profile_name,
                         entry_provenance(entry), _permitted_entries(entry.get("permitted-ip")),
                         _profile_services(entry), (bind_key, bind_value)))

    written: list[ManagementInterface] = []
    with transaction.atomic():
        ManagementInterface.objects.filter(appliance=appliance).delete()
        for (plane, interface_name, profile_name, surface_prov, entries, services,
             binding_prov) in surfaces:
            surface = ManagementInterface.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                source_snapshot=snapshot,
                plane=plane,
                interface_name=interface_name,
                profile_name=profile_name,
            )
            _record(surface, *surface_prov)
            # The binding is a field OF the surface, so it is a named field rather than
            # "__entry__" - which the surface's own provenance already uses. A management
            # plane has no binding at all and gets no row.
            _record(surface, *binding_prov, field_name="profile_name")

            for position, (value, description, raw_key, raw_value) in enumerate(entries):
                family, start, end = parse_permitted_source(value)
                source = PermittedSource.objects.create(
                    management_interface=surface, position=position, value=value,
                    family=family, ipv4_start_int=start, ipv4_end_int=end,
                    description=description,
                )
                _record(source, raw_key, raw_value)

            for name, (enabled, raw_key, raw_value) in sorted(services.items()):
                service = ManagementService.objects.create(
                    management_interface=surface, name=name, enabled=enabled)
                _record(service, raw_key, raw_value)
            written.append(surface)
    return written
