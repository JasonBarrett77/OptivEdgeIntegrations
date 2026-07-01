"""PAN-OS device-configuration normalization helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge.integrations.models import (
    Appliance,
    ApplianceGroup,
    DeviceConfigurationProfile,
    FieldProvenance,
    SecurityRule,
    Snapshot,
)
from optivedge.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    classify_prov_type,
    ensure_list,
    entry_provenance,
    parse_integer_field,
    parse_yes_no_field,
    scalar_value,
)
from optivedge.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection


DEFAULT_IDLE_TIMEOUT_MINUTES = 60


@dataclass(slots=True)
class NormalizedDeviceConfigurationProfile:
    source_snapshot: Snapshot
    config_source: str
    ha_required: bool
    ha_enabled: bool
    ha_state_sync_enabled: bool
    ha_link_monitoring_enabled: bool
    ntp_primary_server: str
    ntp_secondary_server: str
    http_disabled: bool
    https_disabled: bool
    telnet_disabled: bool
    ssh_disabled: bool
    icmp_disabled: bool
    snmp_disabled: bool
    permitted_ip_values: list[str]
    permitted_ip_count: int
    has_permitted_ip_restrictions: bool
    has_unrestricted_permitted_ips: bool
    login_banner: str
    idle_timeout_minutes: int
    raw_profile: dict[str, Any]
    # Each tuple: (field_name, raw_key_orABSENT, raw_provenance_value)
    field_provenance_data: list[tuple[str, Any, str | None]] = field(default_factory=list)


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


def normalize_device_configuration_profile(appliance: Appliance) -> PANOSNormalizedCollection:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return PANOSNormalizedCollection(
            address_objects=[],
            address_groups=[],
            appliances=[],
            appliance_groups=[],
            enforcement_points=[],
            enforcement_nodes=[],
            device_configuration_profiles=[],
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

    ha_enabled, ha_enabled_rk, ha_enabled_rv = parse_yes_no_field(
        high_availability.get("enabled"),
        default_effective=False,
    )
    ha_state_sync_enabled, ha_state_sync_rk, ha_state_sync_rv = parse_yes_no_field(
        ha_state.get("enabled"),
        default_effective=ha_enabled,
    )
    ha_link_monitoring_enabled, ha_link_monitoring_rk, ha_link_monitoring_rv = parse_yes_no_field(
        ha_link_monitoring.get("enabled"),
        default_effective=False,
    )

    ntp_primary_server, ntp_primary_rk, ntp_primary_rv = scalar_value(
        primary_ntp.get("ntp-server-address")
    )
    ntp_secondary_server, ntp_secondary_rk, ntp_secondary_rv = scalar_value(
        secondary_ntp.get("ntp-server-address")
    )

    http_disabled, http_disabled_rk, http_disabled_rv = parse_yes_no_field(
        service.get("disable-http"),
        default_effective=True,
    )
    https_disabled, https_disabled_rk, https_disabled_rv = parse_yes_no_field(
        service.get("disable-https"),
        default_effective=False,
    )
    telnet_disabled, telnet_disabled_rk, telnet_disabled_rv = parse_yes_no_field(
        service.get("disable-telnet"),
        default_effective=True,
    )
    ssh_disabled, ssh_disabled_rk, ssh_disabled_rv = parse_yes_no_field(
        service.get("disable-ssh"),
        default_effective=False,
    )
    icmp_disabled, icmp_disabled_rk, icmp_disabled_rv = parse_yes_no_field(
        service.get("disable-icmp"),
        default_effective=False,
    )
    snmp_disabled, snmp_disabled_rk, snmp_disabled_rv = parse_yes_no_field(
        service.get("disable-snmp"),
        default_effective=True,
    )

    permitted_ip_values = entry_names(system.get("permitted-ip"))
    permitted_ip_count = len(permitted_ip_values)
    has_permitted_ip_restrictions = permitted_ip_count > 0
    has_unrestricted_permitted_ips = any(value_is_unrestricted(v) for v in permitted_ip_values)

    login_banner, login_banner_rk, login_banner_rv = scalar_value(system.get("login-banner"))
    idle_timeout_minutes, idle_timeout_rk, idle_timeout_rv = parse_integer_field(
        management.get("idle-timeout"),
        default_effective=DEFAULT_IDLE_TIMEOUT_MINUTES,
    )

    normalized = NormalizedDeviceConfigurationProfile(
        source_snapshot=snapshot,
        config_source=SecurityRule.SOURCE_LOCAL,
        ha_required=ha_required,
        ha_enabled=ha_enabled,
        ha_state_sync_enabled=ha_state_sync_enabled,
        ha_link_monitoring_enabled=ha_link_monitoring_enabled,
        ntp_primary_server=ntp_primary_server,
        ntp_secondary_server=ntp_secondary_server,
        http_disabled=http_disabled,
        https_disabled=https_disabled,
        telnet_disabled=telnet_disabled,
        ssh_disabled=ssh_disabled,
        icmp_disabled=icmp_disabled,
        snmp_disabled=snmp_disabled,
        permitted_ip_values=permitted_ip_values,
        permitted_ip_count=permitted_ip_count,
        has_permitted_ip_restrictions=has_permitted_ip_restrictions,
        has_unrestricted_permitted_ips=has_unrestricted_permitted_ips,
        login_banner=login_banner,
        idle_timeout_minutes=idle_timeout_minutes,
        raw_profile=deviceconfig,
        field_provenance_data=[
            ("ha_enabled",               ha_enabled_rk,            ha_enabled_rv),
            ("ha_state_sync_enabled",    ha_state_sync_rk,         ha_state_sync_rv),
            ("ha_link_monitoring_enabled", ha_link_monitoring_rk,  ha_link_monitoring_rv),
            ("ntp_primary_server",       ntp_primary_rk,           ntp_primary_rv),
            ("ntp_secondary_server",     ntp_secondary_rk,         ntp_secondary_rv),
            ("http_disabled",            http_disabled_rk,         http_disabled_rv),
            ("https_disabled",           https_disabled_rk,        https_disabled_rv),
            ("telnet_disabled",          telnet_disabled_rk,       telnet_disabled_rv),
            ("ssh_disabled",             ssh_disabled_rk,          ssh_disabled_rv),
            ("icmp_disabled",            icmp_disabled_rk,         icmp_disabled_rv),
            ("snmp_disabled",            snmp_disabled_rk,         snmp_disabled_rv),
            ("login_banner",             login_banner_rk,          login_banner_rv),
            ("idle_timeout_minutes",     idle_timeout_rk,          idle_timeout_rv),
        ],
    )

    with transaction.atomic():
        profile, _created = DeviceConfigurationProfile.objects.update_or_create(
            appliance=appliance,
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": normalized.source_snapshot,
                "config_source": normalized.config_source,
                "ha_required": normalized.ha_required,
                "ha_enabled": normalized.ha_enabled,
                "ha_state_sync_enabled": normalized.ha_state_sync_enabled,
                "ha_link_monitoring_enabled": normalized.ha_link_monitoring_enabled,
                "ntp_primary_server": normalized.ntp_primary_server,
                "ntp_secondary_server": normalized.ntp_secondary_server,
                "http_disabled": normalized.http_disabled,
                "https_disabled": normalized.https_disabled,
                "telnet_disabled": normalized.telnet_disabled,
                "ssh_disabled": normalized.ssh_disabled,
                "icmp_disabled": normalized.icmp_disabled,
                "snmp_disabled": normalized.snmp_disabled,
                "permitted_ip_values": normalized.permitted_ip_values,
                "permitted_ip_count": normalized.permitted_ip_count,
                "has_permitted_ip_restrictions": normalized.has_permitted_ip_restrictions,
                "has_unrestricted_permitted_ips": normalized.has_unrestricted_permitted_ips,
                "login_banner": normalized.login_banner,
                "idle_timeout_minutes": normalized.idle_timeout_minutes,
                "raw_profile": normalized.raw_profile,
            },
        )

        ct = ContentType.objects.get_for_model(DeviceConfigurationProfile)
        FieldProvenance.objects.filter(content_type=ct, object_id=profile.pk).delete()

        prov_rows = []
        for fname, rk, rv in normalized.field_provenance_data:
            if rk is ABSENT:
                continue
            prov_rows.append(FieldProvenance(
                content_type=ct,
                object_id=profile.pk,
                field_name=fname,
                provenance_type=classify_prov_type(rk),
                raw_key=rk or "",
                raw_value=rv or "",
            ))
        if prov_rows:
            FieldProvenance.objects.bulk_create(prov_rows)

    return PANOSNormalizedCollection(
        address_objects=[],
        address_groups=[],
        appliances=[],
        appliance_groups=[],
        enforcement_points=[],
        enforcement_nodes=[],
        device_configuration_profiles=[profile],
        security_rules=[],
    )
