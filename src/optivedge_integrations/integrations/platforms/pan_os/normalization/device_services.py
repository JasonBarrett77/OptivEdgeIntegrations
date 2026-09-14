"""NTP, SNMP and system identity - PAN-SVC-001, 002, 004, 005, 007 and 009.

One walk of `deviceconfig/system` fills three models, the way `services_settings.py` fills two:
the clusters are separate screens but they are one read.

MUST RUN AFTER `normalize_appliance_management_interfaces`. `SnmpSettings.is_exposed` asks
whether the `snmp` service is enabled on any management surface, which is a `ManagementService`
row written by that normalizer. Run first, this would find last run's rows - or none - and report
a device with SNMP reachable as unexposed. The renormalize flow normalizes surfaces before it
reaches the object-normalizer tuple, which is what makes the ordering hold.
"""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, FieldProvenance, ManagementService, NtpSettings, SnmpSettings, SystemIdentity)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT, classify_prov_type, ensure_list, entry_provenance, parse_yes_no_field, scalar_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot, latest_merged_snapshot)

#: The community strings the corpus names, and Help p.740 warns about by name. Compared
#: case-insensitively: PAN-OS accepts all characters and is case-sensitive itself, but `Public`
#: is the default string with the shift key held and not a different secret.
DEFAULT_COMMUNITY_STRINGS = frozenset({"public", "private"})

#: `authentication-type` completes to exactly these three on 11.1 and 11.2. Help p.751 states
#: "None (default)".
AUTH_TYPES = ("symmetric-key", "autokey", "none")


def _choice_child(node: Any, valid: tuple[str, ...]) -> tuple[str, dict[str, Any]]:
    """(which child is present, its content) for a node PAN-OS models as a choice.

    PAN-OS spells several of these settings as WHICH CHILD EXISTS rather than as a value -
    `type` is `{"static": None}` or `{"dhcp-client": {...}}`, and `authentication-type` is
    `{"none": None}`. Returns ("", {}) when the node is absent or holds none of them, which the
    caller must resolve to a default it has measured rather than guessing here.

    Two private copies of this idea already exist - `security_profiles._choice` and
    `management_ssh._host_key` - and they are left alone: both are load-bearing for shipped
    controls and neither is broken. This one is written against the same shape.
    """
    if not isinstance(node, dict):
        return "", {}
    for name in valid:
        if name in node:
            child = node[name]
            return name, child if isinstance(child, dict) else {}
    return "", {}


def _server(node: Any) -> tuple[str, str, str, Any, str | None]:
    """(address, auth type, algorithm, address raw key, address raw value) for one NTP slot."""
    if not isinstance(node, dict):
        return "", "", "", ABSENT, None
    address, raw_key, raw_value = scalar_value(node.get("ntp-server-address"))
    auth_type, auth_body = _choice_child(node.get("authentication-type"), AUTH_TYPES)
    algorithm, _, _ = scalar_value(auth_body.get("algorithm")) if auth_body else ("", None, None)
    return address, auth_type, algorithm, raw_key, raw_value


def _provenance(model, obj, rows: list[tuple[str, Any, str | None]]) -> None:
    """Replace this object's provenance with `rows` of (field, raw key, raw value).

    A row is written only where the payload carried a key, so an absent setting gets no row -
    which is how `FieldProvenance` distinguishes "never written" from "written locally".
    """
    content_type = ContentType.objects.get_for_model(model)
    FieldProvenance.objects.filter(content_type=content_type, object_id=obj.pk).delete()
    for field_name, raw_key, raw_value in rows:
        if raw_key is ABSENT:
            continue
        FieldProvenance.objects.create(
            content_type=content_type, object_id=obj.pk, field_name=field_name,
            provenance_type=classify_prov_type(raw_key),
            raw_key=raw_key or "", raw_value=raw_value or "")


def _exposed_surfaces(appliance: Appliance) -> list[str]:
    """Which management surfaces have the `snmp` service enabled.

    Reads the rows `normalize_appliance_management_interfaces` wrote, which have already
    resolved each plane's polarity - the deviceconfig planes spell it `disable-snmp` and an
    interface profile spells it `snmp`, and both arrive here as `enabled`.
    """
    services = (ManagementService.objects
                .filter(management_interface__appliance=appliance, name="snmp", enabled=True)
                .select_related("management_interface"))
    return [(service.management_interface.interface_name
             or service.management_interface.plane) for service in services]


def _ntp(appliance, snapshot, system) -> None:
    servers = system.get("ntp-servers") if isinstance(system.get("ntp-servers"), dict) else {}
    primary, p_auth, p_algo, p_rk, p_rv = _server(servers.get("primary-ntp-server"))
    secondary, s_auth, s_algo, s_rk, s_rv = _server(servers.get("secondary-ntp-server"))

    configured = [(name, auth) for name, auth in
                  ((primary, p_auth), (secondary, s_auth)) if name]
    unauthenticated = [name for name, auth in configured if auth != "symmetric-key"]

    row, _ = NtpSettings.objects.update_or_create(
        appliance=appliance,
        defaults={
            "management_station": appliance.management_station,
            "appliance_group": appliance.appliance_group,
            "source_snapshot": snapshot,
            "primary_server": primary[:255],
            "secondary_server": secondary[:255],
            "server_count": len(configured),
            "primary_auth_type": p_auth or NtpSettings.AuthType.NONE,
            "secondary_auth_type": s_auth or NtpSettings.AuthType.NONE,
            "primary_algorithm": (p_algo or "")[:8],
            "secondary_algorithm": (s_algo or "")[:8],
            # Vacuously true on a device with no servers would report an unconfigured device as
            # authenticated, so an empty list is False here rather than all().
            "all_servers_symmetric_key": bool(configured) and not unauthenticated,
            "unauthenticated_servers": unauthenticated,
        },
    )
    _provenance(NtpSettings, row, [("primary_server", p_rk, p_rv),
                                   ("secondary_server", s_rk, s_rv)])


def _snmp(appliance, snapshot, system) -> None:
    # PRESENCE IS KEY MEMBERSHIP, NOT TRUTHINESS. An empty `<snmp-setting/>` parses to None and
    # an element with no children to `{}`, and both are FALSY while both mean the node exists.
    # Testing truthiness reported a configured device as having no SNMP at all, and read an
    # empty access-setting as "no access-setting" - which silently skipped the implicit-version
    # branch below. Caught by its own test before it shipped; absent, empty and default are
    # three states here as everywhere else in this payload.
    configured = "snmp-setting" in system
    node = system.get("snmp-setting")
    node = node if isinstance(node, dict) else {}
    has_access = "access-setting" in node
    access = node.get("access-setting")
    access = access if isinstance(access, dict) else {}
    version_name, version_body = _choice_child(access.get("version"), ("v2c", "v3"))

    # An access-setting with no version child: Help p.740 says the dialog's default is V2c.
    # Recorded as v2c and FLAGGED, because the control then rests on a vendor sentence rather
    # than on something read off this device.
    implicit = has_access and not version_name
    effective = version_name or ("v2c" if implicit else "")

    community, community_rk, community_rv = scalar_value(
        version_body.get("snmp-community-string")) if version_body else ("", ABSENT, None)
    users = ensure_list((version_body.get("users") or {}).get("entry")) if version_body else []
    views = ensure_list((version_body.get("views") or {}).get("entry")) if version_body else []

    surfaces = _exposed_surfaces(appliance)
    row, _ = SnmpSettings.objects.update_or_create(
        appliance=appliance,
        defaults={
            "management_station": appliance.management_station,
            "appliance_group": appliance.appliance_group,
            "source_snapshot": snapshot,
            "is_configured": configured,
            "version": effective,
            "version_implicit": implicit,
            "uses_v2c": effective == "v2c",
            "community_set": bool(community),
            "community_is_default": community.strip().lower() in DEFAULT_COMMUNITY_STRINGS,
            "v3_user_count": len(users),
            "v3_view_count": len(views),
            "is_exposed": bool(surfaces),
            "exposed_surfaces": surfaces,
        },
    )
    # The community string's VALUE is not stored; its provenance is, because "who set this" is
    # exactly what an assessor asks about a credential they can see in a backup.
    _provenance(SnmpSettings, row, [("community_is_default", community_rk, community_rv)])


def _identity(appliance, snapshot, system) -> None:
    hostname, host_rk, host_rv = scalar_value(system.get("hostname"))
    timezone, tz_rk, tz_rv = scalar_value(system.get("timezone"))
    mode, mode_body = _choice_child(system.get("type"), ("static", "dhcp-client"))
    type_rk, type_rv = entry_provenance(system.get("type")) if isinstance(
        system.get("type"), dict) else (ABSENT, None)

    accept_hostname, _, _ = parse_yes_no_field(
        mode_body.get("accept-dhcp-hostname"), default_effective=False)
    accept_domain, _, _ = parse_yes_no_field(
        mode_body.get("accept-dhcp-domain"), default_effective=False)

    # Help p.700: with no hostname written, PAN-OS uses the model - "for example, PA-5220_2".
    # So the default name is the model, optionally suffixed; an absent hostname is the same
    # state spelled differently.
    model_name = (appliance.model or "").strip().lower()
    stored = hostname.strip().lower()
    factory = (not stored) or (bool(model_name) and (
        stored == model_name or stored.startswith(f"{model_name}_")))

    row, _ = SystemIdentity.objects.update_or_create(
        appliance=appliance,
        defaults={
            "management_station": appliance.management_station,
            "appliance_group": appliance.appliance_group,
            "source_snapshot": snapshot,
            "hostname": hostname[:64],
            "hostname_is_factory_default": factory,
            "timezone": timezone[:64],
            "timezone_is_utc": timezone.strip().upper() == "UTC",
            # Absent resolves to static - measured, not assumed. See the model docstring.
            "addressing_mode": mode or SystemIdentity.AddressingMode.STATIC,
            "addressing_mode_explicit": bool(mode),
            "accept_dhcp_hostname": accept_hostname,
            "accept_dhcp_domain": accept_domain,
        },
    )
    _provenance(SystemIdentity, row, [("hostname", host_rk, host_rv),
                                      ("timezone", tz_rk, tz_rv),
                                      ("addressing_mode", type_rk, type_rv)])


def normalize_device_services(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"ntp_settings": 0, "snmp_settings": 0, "system_identities": 0}
    entry = device_entry_from_snapshot(snapshot)
    deviceconfig = entry.get("deviceconfig") if isinstance(entry, dict) else None
    deviceconfig = deviceconfig if isinstance(deviceconfig, dict) else {}
    system = deviceconfig.get("system")
    system = system if isinstance(system, dict) else {}

    with transaction.atomic():
        _ntp(appliance, snapshot, system)
        _snmp(appliance, snapshot, system)
        _identity(appliance, snapshot, system)
    return {"ntp_settings": 1, "snmp_settings": 1, "system_identities": 1}
