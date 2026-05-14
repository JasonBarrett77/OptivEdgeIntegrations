"""PAN-OS management-plane normalization helpers."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any

from django.db import transaction

from optivedge.integrations.models import (
    Appliance,
    ApplianceGroup,
    ManagementPlaneProfile,
    SecurityRule,
    Snapshot,
)
from optivedge.integrations.platforms.pan_os.normalization.common import ensure_list
from optivedge.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection


LOCAL_PROVENANCE = "local"
DEFAULT_IDLE_TIMEOUT_MINUTES = 60


@dataclass(slots=True)
class NormalizedManagementPlaneProfile:
    source_snapshot: Snapshot
    config_source: str
    provenance: str
    ha_required: bool
    ha_enabled: bool
    ha_enabled_explicit: bool
    ha_enabled_prov: str
    ha_state_sync_enabled: bool
    ha_state_sync_explicit: bool
    ha_state_sync_prov: str
    ha_link_monitoring_enabled: bool
    ha_link_monitoring_explicit: bool
    ha_link_monitoring_prov: str
    ntp_primary_server: str
    ntp_primary_server_prov: str
    ntp_secondary_server: str
    ntp_secondary_server_prov: str
    http_disabled: bool
    http_disabled_explicit: bool
    http_disabled_prov: str
    https_disabled: bool
    https_disabled_explicit: bool
    https_disabled_prov: str
    telnet_disabled: bool
    telnet_disabled_explicit: bool
    telnet_disabled_prov: str
    ssh_disabled: bool
    ssh_disabled_explicit: bool
    ssh_disabled_prov: str
    icmp_disabled: bool
    icmp_disabled_explicit: bool
    icmp_disabled_prov: str
    snmp_disabled: bool
    snmp_disabled_explicit: bool
    snmp_disabled_prov: str
    permitted_ip_values: list[str]
    permitted_ip_count: int
    has_permitted_ip_restrictions: bool
    has_unrestricted_permitted_ips: bool
    login_banner: str
    login_banner_prov: str
    idle_timeout_minutes: int
    idle_timeout_explicit: bool
    idle_timeout_prov: str
    raw_profile: dict[str, Any]


def latest_merged_snapshot(appliance: Appliance) -> Snapshot | None:
    return (
        Snapshot.objects.filter(
            appliance=appliance,
            source_type="show_merged_config",
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def device_entry_from_snapshot(snapshot: Snapshot) -> dict[str, Any]:
    payload = snapshot.payload or {}
    config = payload.get("config", {})
    if not isinstance(config, dict):
        raise ValueError(f"unexpected merged config root type: {type(config).__name__}")
    devices = config.get("devices", {})
    if not isinstance(devices, dict):
        raise ValueError(f"unexpected merged config devices type: {type(devices).__name__}")
    entries = ensure_list(devices.get("entry"))
    if not entries or not isinstance(entries[0], dict):
        raise ValueError("merged config does not contain a device entry")
    return entries[0]


def scalar_value(node: Any, default_prov: str = LOCAL_PROVENANCE) -> tuple[str, str]:
    if node is None:
        return "", ""
    if isinstance(node, dict):
        value = node.get("#text")
        return (str(value or "").strip(), str(node.get("@ptpl") or node.get("@loc") or default_prov or ""))
    return str(node).strip(), default_prov


def parse_yes_no_field(
    node: Any,
    *,
    default_effective: bool,
    default_prov: str = LOCAL_PROVENANCE,
) -> tuple[bool, bool, str]:
    raw_value, provenance = scalar_value(node, default_prov)
    if not raw_value:
        return default_effective, False, provenance
    normalized = raw_value.lower()
    return normalized == "yes", True, provenance


def parse_integer_field(
    node: Any,
    *,
    default_effective: int,
    default_prov: str = LOCAL_PROVENANCE,
) -> tuple[int, bool, str]:
    raw_value, provenance = scalar_value(node, default_prov)
    if not raw_value:
        return default_effective, False, provenance
    try:
        parsed = int(raw_value)
    except ValueError:
        return default_effective, True, provenance
    return parsed, True, provenance


def entry_names(node: Any) -> list[str]:
    if node is None:
        return []
    if isinstance(node, dict):
        entries = ensure_list(node.get("entry"))
        values: list[str] = []
        for entry in entries:
            if isinstance(entry, dict):
                value = str(entry.get("@name") or "").strip()
            else:
                value = str(entry).strip()
            if value:
                values.append(value)
        return values
    if isinstance(node, list):
        return [str(value).strip() for value in node if str(value).strip()]
    text = str(node).strip()
    return [text] if text else []


def value_is_unrestricted(value: str) -> bool:
    normalized = value.strip()
    if not normalized:
        return False
    if normalized == "0.0.0.0/0":
        return True
    if "-" in normalized:
        start_text, end_text = [part.strip() for part in normalized.split("-", 1)]
        try:
            start = int(ipaddress.IPv4Address(start_text))
            end = int(ipaddress.IPv4Address(end_text))
        except ipaddress.AddressValueError:
            return False
        return start == 0 and end == 4_294_967_295
    try:
        network = ipaddress.ip_network(normalized, strict=False)
    except ValueError:
        return False
    return (
        isinstance(network, ipaddress.IPv4Network)
        and int(network.network_address) == 0
        and int(network.broadcast_address) == 4_294_967_295
    )


def normalize_management_plane_profile(appliance: Appliance) -> PANOSNormalizedCollection:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return PANOSNormalizedCollection(
            address_objects=[],
            address_groups=[],
            appliances=[],
            appliance_groups=[],
            enforcement_points=[],
            enforcement_nodes=[],
            management_plane_profiles=[],
            security_rules=[],
        )

    device_entry = device_entry_from_snapshot(snapshot)
    deviceconfig = device_entry.get("deviceconfig", {}) if isinstance(device_entry, dict) else {}
    if not isinstance(deviceconfig, dict):
        raise ValueError(f"unexpected deviceconfig type: {type(deviceconfig).__name__}")
    system = deviceconfig.get("system", {}) if isinstance(deviceconfig, dict) else {}
    if not isinstance(system, dict):
        raise ValueError(f"unexpected system config type: {type(system).__name__}")
    service = system.get("service", {})
    if not isinstance(service, dict):
        service = {}
    high_availability = deviceconfig.get("high-availability", {})
    if not isinstance(high_availability, dict):
        high_availability = {}
    ha_group = high_availability.get("group", {})
    if not isinstance(ha_group, dict):
        ha_group = {}
    ha_state = ha_group.get("state-synchronization", {})
    if not isinstance(ha_state, dict):
        ha_state = {}
    ha_monitoring = ha_group.get("monitoring", {})
    if not isinstance(ha_monitoring, dict):
        ha_monitoring = {}
    ha_link_monitoring = ha_monitoring.get("link-monitoring", {})
    if not isinstance(ha_link_monitoring, dict):
        ha_link_monitoring = {}
    ntp_servers = system.get("ntp-servers", {})
    if not isinstance(ntp_servers, dict):
        ntp_servers = {}
    primary_ntp = ntp_servers.get("primary-ntp-server", {})
    if not isinstance(primary_ntp, dict):
        primary_ntp = {}
    secondary_ntp = ntp_servers.get("secondary-ntp-server", {})
    if not isinstance(secondary_ntp, dict):
        secondary_ntp = {}
    setting = deviceconfig.get("setting", {})
    if not isinstance(setting, dict):
        setting = {}
    management = setting.get("management", {})
    if not isinstance(management, dict):
        management = {}

    appliance_group = appliance.appliance_group
    ha_required = appliance_group is not None and appliance_group.group_type == ApplianceGroup.TYPE_HA_PAIR

    ha_enabled, ha_enabled_explicit, ha_enabled_prov = parse_yes_no_field(
        high_availability.get("enabled"),
        default_effective=False,
    )
    ha_state_sync_enabled, ha_state_sync_explicit, ha_state_sync_prov = parse_yes_no_field(
        ha_state.get("enabled"),
        default_effective=ha_enabled,
    )
    ha_link_monitoring_enabled, ha_link_monitoring_explicit, ha_link_monitoring_prov = parse_yes_no_field(
        ha_link_monitoring.get("enabled"),
        default_effective=False,
    )

    ntp_primary_server, ntp_primary_server_prov = scalar_value(primary_ntp.get("ntp-server-address"))
    ntp_secondary_server, ntp_secondary_server_prov = scalar_value(secondary_ntp.get("ntp-server-address"))

    http_disabled, http_disabled_explicit, http_disabled_prov = parse_yes_no_field(
        service.get("disable-http"),
        default_effective=True,
    )
    https_disabled, https_disabled_explicit, https_disabled_prov = parse_yes_no_field(
        service.get("disable-https"),
        default_effective=False,
    )
    telnet_disabled, telnet_disabled_explicit, telnet_disabled_prov = parse_yes_no_field(
        service.get("disable-telnet"),
        default_effective=True,
    )
    ssh_disabled, ssh_disabled_explicit, ssh_disabled_prov = parse_yes_no_field(
        service.get("disable-ssh"),
        default_effective=False,
    )
    icmp_disabled, icmp_disabled_explicit, icmp_disabled_prov = parse_yes_no_field(
        service.get("disable-icmp"),
        default_effective=False,
    )
    snmp_disabled, snmp_disabled_explicit, snmp_disabled_prov = parse_yes_no_field(
        service.get("disable-snmp"),
        default_effective=True,
    )

    permitted_ip_values = entry_names(system.get("permitted-ip"))
    permitted_ip_count = len(permitted_ip_values)
    has_permitted_ip_restrictions = permitted_ip_count > 0
    has_unrestricted_permitted_ips = any(value_is_unrestricted(value) for value in permitted_ip_values)

    login_banner, login_banner_prov = scalar_value(system.get("login-banner"))
    idle_timeout_minutes, idle_timeout_explicit, idle_timeout_prov = parse_integer_field(
        management.get("idle-timeout"),
        default_effective=DEFAULT_IDLE_TIMEOUT_MINUTES,
    )

    normalized = NormalizedManagementPlaneProfile(
        source_snapshot=snapshot,
        config_source=SecurityRule.SOURCE_LOCAL,
        provenance=LOCAL_PROVENANCE,
        ha_required=ha_required,
        ha_enabled=ha_enabled,
        ha_enabled_explicit=ha_enabled_explicit,
        ha_enabled_prov=ha_enabled_prov,
        ha_state_sync_enabled=ha_state_sync_enabled,
        ha_state_sync_explicit=ha_state_sync_explicit,
        ha_state_sync_prov=ha_state_sync_prov,
        ha_link_monitoring_enabled=ha_link_monitoring_enabled,
        ha_link_monitoring_explicit=ha_link_monitoring_explicit,
        ha_link_monitoring_prov=ha_link_monitoring_prov,
        ntp_primary_server=ntp_primary_server,
        ntp_primary_server_prov=ntp_primary_server_prov,
        ntp_secondary_server=ntp_secondary_server,
        ntp_secondary_server_prov=ntp_secondary_server_prov,
        http_disabled=http_disabled,
        http_disabled_explicit=http_disabled_explicit,
        http_disabled_prov=http_disabled_prov,
        https_disabled=https_disabled,
        https_disabled_explicit=https_disabled_explicit,
        https_disabled_prov=https_disabled_prov,
        telnet_disabled=telnet_disabled,
        telnet_disabled_explicit=telnet_disabled_explicit,
        telnet_disabled_prov=telnet_disabled_prov,
        ssh_disabled=ssh_disabled,
        ssh_disabled_explicit=ssh_disabled_explicit,
        ssh_disabled_prov=ssh_disabled_prov,
        icmp_disabled=icmp_disabled,
        icmp_disabled_explicit=icmp_disabled_explicit,
        icmp_disabled_prov=icmp_disabled_prov,
        snmp_disabled=snmp_disabled,
        snmp_disabled_explicit=snmp_disabled_explicit,
        snmp_disabled_prov=snmp_disabled_prov,
        permitted_ip_values=permitted_ip_values,
        permitted_ip_count=permitted_ip_count,
        has_permitted_ip_restrictions=has_permitted_ip_restrictions,
        has_unrestricted_permitted_ips=has_unrestricted_permitted_ips,
        login_banner=login_banner,
        login_banner_prov=login_banner_prov,
        idle_timeout_minutes=idle_timeout_minutes,
        idle_timeout_explicit=idle_timeout_explicit,
        idle_timeout_prov=idle_timeout_prov,
        raw_profile=deviceconfig,
    )

    with transaction.atomic():
        profile, _created = ManagementPlaneProfile.objects.update_or_create(
            appliance=appliance,
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": normalized.source_snapshot,
                "config_source": normalized.config_source,
                "provenance": normalized.provenance,
                "ha_required": normalized.ha_required,
                "ha_enabled": normalized.ha_enabled,
                "ha_enabled_explicit": normalized.ha_enabled_explicit,
                "ha_enabled_prov": normalized.ha_enabled_prov,
                "ha_state_sync_enabled": normalized.ha_state_sync_enabled,
                "ha_state_sync_explicit": normalized.ha_state_sync_explicit,
                "ha_state_sync_prov": normalized.ha_state_sync_prov,
                "ha_link_monitoring_enabled": normalized.ha_link_monitoring_enabled,
                "ha_link_monitoring_explicit": normalized.ha_link_monitoring_explicit,
                "ha_link_monitoring_prov": normalized.ha_link_monitoring_prov,
                "ntp_primary_server": normalized.ntp_primary_server,
                "ntp_primary_server_prov": normalized.ntp_primary_server_prov,
                "ntp_secondary_server": normalized.ntp_secondary_server,
                "ntp_secondary_server_prov": normalized.ntp_secondary_server_prov,
                "http_disabled": normalized.http_disabled,
                "http_disabled_explicit": normalized.http_disabled_explicit,
                "http_disabled_prov": normalized.http_disabled_prov,
                "https_disabled": normalized.https_disabled,
                "https_disabled_explicit": normalized.https_disabled_explicit,
                "https_disabled_prov": normalized.https_disabled_prov,
                "telnet_disabled": normalized.telnet_disabled,
                "telnet_disabled_explicit": normalized.telnet_disabled_explicit,
                "telnet_disabled_prov": normalized.telnet_disabled_prov,
                "ssh_disabled": normalized.ssh_disabled,
                "ssh_disabled_explicit": normalized.ssh_disabled_explicit,
                "ssh_disabled_prov": normalized.ssh_disabled_prov,
                "icmp_disabled": normalized.icmp_disabled,
                "icmp_disabled_explicit": normalized.icmp_disabled_explicit,
                "icmp_disabled_prov": normalized.icmp_disabled_prov,
                "snmp_disabled": normalized.snmp_disabled,
                "snmp_disabled_explicit": normalized.snmp_disabled_explicit,
                "snmp_disabled_prov": normalized.snmp_disabled_prov,
                "permitted_ip_values": normalized.permitted_ip_values,
                "permitted_ip_count": normalized.permitted_ip_count,
                "has_permitted_ip_restrictions": normalized.has_permitted_ip_restrictions,
                "has_unrestricted_permitted_ips": normalized.has_unrestricted_permitted_ips,
                "login_banner": normalized.login_banner,
                "login_banner_prov": normalized.login_banner_prov,
                "idle_timeout_minutes": normalized.idle_timeout_minutes,
                "idle_timeout_explicit": normalized.idle_timeout_explicit,
                "idle_timeout_prov": normalized.idle_timeout_prov,
                "raw_profile": normalized.raw_profile,
            },
        )

    return PANOSNormalizedCollection(
        address_objects=[],
        address_groups=[],
        appliances=[],
        appliance_groups=[],
        enforcement_points=[],
        enforcement_nodes=[],
        management_plane_profiles=[profile],
        security_rules=[],
    )
