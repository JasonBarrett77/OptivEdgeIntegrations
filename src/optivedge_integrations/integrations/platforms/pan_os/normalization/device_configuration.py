"""PAN-OS device-configuration normalization helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    DeviceConfigurationProfile,
    FieldProvenance,
    NormalizationIssue,
    SecurityRule,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    classify_prov_type,
    ensure_list,
    entry_provenance,
    parse_integer_field,
    parse_yes_no_field,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection


DEFAULT_IDLE_TIMEOUT_MINUTES = 60

#: Raised when deviceconfig/system names an SSL/TLS profile no collected scope defines.
SSL_TLS_ISSUE_KIND = "ssl_tls_service_profile_unresolved"


@dataclass(slots=True)
class NormalizedDeviceConfigurationProfile:
    source_snapshot: Snapshot
    config_source: str
    ha_required: bool
    ha_enabled: bool
    ha_state_sync_enabled: bool
    ha_link_monitoring_enabled: bool
    ack_login_banner: bool
    server_verification_enabled: bool
    log_on_high_dp_load: bool
    ntp_primary_server: str
    ntp_secondary_server: str
    ssl_tls_service_profile_name: str
    ssl_tls_profile_scope: str
    ssl_tls_min_version: str
    ssl_tls_max_version: str
    ssl_tls_certificate_name: str
    ssl_tls_certificate_trust: str
    ssl_tls_certificate_issuer: str
    ssl_tls_certificate_scope: str
    master_key_state: str
    master_key_expires_at: str
    master_key_auto_renew_hours: int
    master_key_on_hsm: bool
    password_complexity: dict[str, Any]
    permitted_ip_values: list[str]
    permitted_ip_count: int
    login_banner: str
    idle_timeout_minutes: int
    admin_lockout_failed_attempts: int
    admin_lockout_time_minutes: int
    api_key_lifetime_minutes: int
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


def latest_predefined_ssl_tls_snapshot(appliance: Appliance) -> Snapshot | None:
    """The vendor-shipped SSL/TLS profiles, collected separately from the merged config.

    Separate because `show config merged` does not carry /config/predefined at all - measured
    2026-09-02, its top level is devices, mgt-config and shared. Absent entirely on any
    appliance collected before that collector existed, which is why a missing snapshot is
    treated as "predefined unknown" rather than "no predefined profiles exist".
    """
    return (
        Snapshot.objects.filter(
            appliance=appliance,
            source_type="config_predefined_ssl_tls_service_profiles",
        )
        .order_by("-collected_at", "-pk")
        .first()
    )


def _profiles_by_name(node: Any) -> dict[str, dict[str, Any]]:
    """Index an ssl-tls-service-profile container by entry name."""
    if not isinstance(node, dict):
        return {}
    profiles: dict[str, dict[str, Any]] = {}
    for entry in ensure_list(node.get("entry")):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("@name") or "").strip()
        if name:
            profiles[name] = entry
    return profiles


def shared_ssl_tls_profiles(snapshot: Snapshot) -> dict[str, dict[str, Any]]:
    """Shared-scope profiles, which DO travel in the merged config."""
    payload = snapshot.payload or {}
    config = payload.get("config", {})
    if not isinstance(config, dict):
        return {}
    shared = config.get("shared", {})
    if not isinstance(shared, dict):
        return {}
    return _profiles_by_name(shared.get("ssl-tls-service-profile"))


def predefined_ssl_tls_profiles(snapshot: Snapshot | None) -> dict[str, dict[str, Any]]:
    """Predefined-scope profiles from their own snapshot."""
    if snapshot is None:
        return {}
    # Snapshots store `response.result` itself, so the payload IS the subtree the xpath
    # named - here `{"ssl-tls-service-profile": {"entry": [...]}}`.
    payload = snapshot.payload or {}
    if not isinstance(payload, dict):
        return {}
    return _profiles_by_name(payload.get("ssl-tls-service-profile"))


def resolve_ssl_tls_profile(
    name: str,
    *,
    predefined: dict[str, dict[str, Any]],
    shared: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    """Which definition of `name` is actually in force, and where it came from.

    PREDEFINED FIRST. Measured 2026-09-02: a custom entry written to /config/shared under the
    predefined name `TLSv1.3_Default` was accepted, committed, and then ignored completely -
    the device kept negotiating TLS 1.3 and kept serving the predefined certificate, while a
    second profile with a UNIQUE name and the same custom certificate took effect immediately.
    So the custom entry was not merely outranked on protocol settings, it was discarded whole.

    This is the OPPOSITE of `region`, where a custom definition extends its predefined
    namesake, and the opposite of the assumed ordering in policy/base.py, where PREDEFINED is
    the weakest rank. Neither of those governs this object, and this measurement does not
    govern them - name-collision behaviour is per object type, and all three have to be
    measured separately.

    The vsys scope is deliberately absent: `deviceconfig/system` cannot reference a vsys
    profile at all. Measured the same day with `action=complete` on the binding field, which
    lists valid target names - writing a vsys profile to the candidate did not add it.
    """
    if name in predefined:
        return DeviceConfigurationProfile.SSL_TLS_SCOPE_PREDEFINED, predefined[name]
    if name in shared:
        return DeviceConfigurationProfile.SSL_TLS_SCOPE_SHARED, shared[name]
    return DeviceConfigurationProfile.SSL_TLS_SCOPE_UNRESOLVED, {}


#: (model field, config key, kind). The four password-change keys are nested one level down.
PASSWORD_COMPLEXITY_FIELDS = (
    ("password_complexity_enabled", "enabled", "bool", None),
    ("password_minimum_length", "minimum-length", "int", None),
    ("password_minimum_uppercase", "minimum-uppercase-letters", "int", None),
    ("password_minimum_lowercase", "minimum-lowercase-letters", "int", None),
    ("password_minimum_numeric", "minimum-numeric-letters", "int", None),
    ("password_minimum_special", "minimum-special-characters", "int", None),
    ("password_block_username_inclusion", "block-username-inclusion", "bool", None),
    ("password_new_differs_by_characters", "new-password-differs-by-characters", "int", None),
    ("password_history_count", "password-history-count", "int", None),
    ("password_block_repeated_characters", "block-repeated-characters", "int", None),
    ("password_change_on_first_login", "password-change-on-first-login", "bool", None),
    ("password_change_period_block", "password-change-period-block", "int", None),
    ("password_expiration_period", "expiration-period", "int", "password-change"),
    ("password_expiration_warning_period", "expiration-warning-period", "int", "password-change"),
    ("password_post_expiration_admin_login_count",
     "post-expiration-admin-login-count", "int", "password-change"),
    ("password_post_expiration_grace_period",
     "post-expiration-grace-period", "int", "password-change"),
)


def password_complexity_from_snapshot(snapshot: Snapshot) -> tuple[dict[str, Any], list]:
    """mgt-config/password-complexity, with every absent key resolved to its measured default.

    `mgt-config` sits at the TOP of the merged config beside `devices` and `shared`, not under
    a device entry, so it needs its own accessor rather than reusing device_entry_from_snapshot.

    Every default is the insecure one - flag off, every number 0 - measured from the
    unconfigured form. Absent is expanded rather than left null because PAN-OS never writes
    these values: the UI stores only the flag when an administrator enables complexity, and a
    commit does not materialise the rest. So there is no state where a null would mean
    something a 0 does not.
    """
    values = {field: (False if kind == "bool" else 0)
              for field, _, kind, _ in PASSWORD_COMPLEXITY_FIELDS}
    provenance: list[tuple[str, Any, str | None]] = []
    payload = snapshot.payload or {}
    config = payload.get("config") if isinstance(payload, dict) else None
    if not isinstance(config, dict):
        return values, provenance
    node = config.get("mgt-config")
    if not isinstance(node, dict):
        return values, provenance
    complexity = node.get("password-complexity")
    if not isinstance(complexity, dict):
        return values, provenance
    change = complexity.get("password-change")
    if not isinstance(change, dict):
        change = {}

    for field, key, kind, parent in PASSWORD_COMPLEXITY_FIELDS:
        source = change if parent else complexity
        raw = source.get(key)
        if kind == "bool":
            values[field], raw_key, raw_value = parse_yes_no_field(
                raw, default_effective=False)
        else:
            values[field], raw_key, raw_value = parse_integer_field(
                raw, default_effective=0)
        # mgt-config is template-managed - the users node on tpa-a arrives carrying @ptpl - so
        # these values can be pushed and the provenance has to be captured like any other.
        # Absent keys produce no row, which is what makes "local" and "defaulted" different
        # facts rather than the same blank.
        provenance.append((field, raw_key, raw_value))
    return values, provenance


def latest_masterkey_snapshot(appliance: Appliance) -> Snapshot | None:
    return (
        Snapshot.objects.filter(appliance=appliance, source_type="show_masterkey_properties")
        .order_by("-collected_at", "-pk")
        .first()
    )


def read_master_key(snapshot: Snapshot | None) -> tuple[str, str, int, bool]:
    """(state, expires_at, auto_renew_hours, on_hsm) from a masterkey-properties snapshot.

    A MISSING snapshot is UNDETERMINED, not default. The device is almost certainly using the
    factory key - every device observed is - but "we never asked" and "we asked and it was
    default" are different facts, and only one of them is a finding this control can stand
    behind.
    """
    if snapshot is None:
        return DeviceConfigurationProfile.MASTER_KEY_UNDETERMINED, "", 0, False
    payload = snapshot.payload or {}
    if not isinstance(payload, dict):
        return DeviceConfigurationProfile.MASTER_KEY_UNDETERMINED, "", 0, False
    expires_at, _, _ = scalar_value(payload.get("expire-at"))
    auto_renew, _, _ = parse_integer_field(payload.get("auto-renew-mkey"), default_effective=0)
    on_hsm, _, _ = parse_yes_no_field(payload.get("on-hsm"), default_effective=False)
    if not expires_at:
        # The key is absent from the reply entirely - a shape nobody has seen. Not read as
        # default: that verdict rests on expire-at being present and zero.
        return DeviceConfigurationProfile.MASTER_KEY_UNDETERMINED, "", auto_renew, on_hsm
    state = (DeviceConfigurationProfile.MASTER_KEY_DEFAULT if expires_at.strip() == "0"
             else DeviceConfigurationProfile.MASTER_KEY_SET)
    return state, expires_at, auto_renew, on_hsm


def latest_predefined_certificate_snapshot(appliance: Appliance) -> Snapshot | None:
    return (
        Snapshot.objects.filter(
            appliance=appliance, source_type="config_predefined_certificates")
        .order_by("-collected_at", "-pk")
        .first()
    )


def _certificates_by_name(node: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(node, dict):
        return {}
    certificates: dict[str, dict[str, Any]] = {}
    for entry in ensure_list(node.get("entry")):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("@name") or "").strip()
        if name:
            certificates[name] = entry
    return certificates


def shared_certificates(snapshot: Snapshot) -> dict[str, dict[str, Any]]:
    payload = snapshot.payload or {}
    config = payload.get("config", {})
    if not isinstance(config, dict):
        return {}
    shared = config.get("shared", {})
    if not isinstance(shared, dict):
        return {}
    return _certificates_by_name(shared.get("certificate"))


def predefined_certificates(snapshot: Snapshot | None) -> dict[str, dict[str, Any]]:
    if snapshot is None:
        return {}
    payload = snapshot.payload or {}
    if not isinstance(payload, dict):
        return {}
    return _certificates_by_name(payload.get("certificate"))


def resolve_certificate(
    name: str,
    *,
    predefined: dict[str, dict[str, Any]],
    shared: dict[str, dict[str, Any]],
) -> tuple[str, str, str]:
    """Resolve a certificate name to (scope, trust, issuer).

    Predefined first, matching the profile's own resolution order. The certificate and the
    profile that names it are resolved SEPARATELY, because they need not come from the same
    scope: a shared profile may name a certificate that only exists predefined.

    Self-signed is `subject-hash == issuer-hash`, which PAN-OS computes for us. The DN strings
    are NOT usable for this - measured 2026-09-02, shared certificates report "/CN=name" while
    predefined ones report a bare "name", so comparing subject to issuer as text would be
    scope-dependent and would silently stop working when a certificate moved scope.

    Returns UNDETERMINED when the name resolves nowhere, or resolves to an entry with no
    hashes. That is a real answer meaning "an engineer must look", never "satisfied".
    """
    entry = predefined.get(name)
    scope = DeviceConfigurationProfile.SSL_TLS_SCOPE_PREDEFINED
    if entry is None:
        entry = shared.get(name)
        scope = DeviceConfigurationProfile.SSL_TLS_SCOPE_SHARED
    if entry is None:
        return (DeviceConfigurationProfile.SSL_TLS_SCOPE_UNRESOLVED,
                DeviceConfigurationProfile.TRUST_UNDETERMINED, "")
    subject_hash, _, _ = scalar_value(entry.get("subject-hash"))
    issuer_hash, _, _ = scalar_value(entry.get("issuer-hash"))
    issuer, _, _ = scalar_value(entry.get("issuer"))
    if not subject_hash or not issuer_hash:
        # Present but unhashed. Not determinable rather than assumed either way.
        return scope, DeviceConfigurationProfile.TRUST_UNDETERMINED, issuer
    trust = (DeviceConfigurationProfile.TRUST_SELF_SIGNED if subject_hash == issuer_hash
             else DeviceConfigurationProfile.TRUST_CA_ISSUED)
    return scope, trust, issuer


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

    # Measured 2026-09-01: absent means ticked for server-verification and unticked for the
    # other two. Neighbouring settings, opposite defaults - see the payload contract.
    ack_login_banner, ack_banner_rk, ack_banner_rv = parse_yes_no_field(
        system.get("ack-login-banner"), default_effective=False)
    server_verification, server_verification_rk, server_verification_rv = parse_yes_no_field(
        system.get("server-verification"), default_effective=True)
    log_high_dp, log_high_dp_rk, log_high_dp_rv = parse_yes_no_field(
        management.get("enable-log-high-dp-load"), default_effective=False)

    ntp_primary_server, ntp_primary_rk, ntp_primary_rv = scalar_value(
        primary_ntp.get("ntp-server-address")
    )
    ntp_secondary_server, ntp_secondary_rk, ntp_secondary_rv = scalar_value(
        secondary_ntp.get("ntp-server-address")
    )


    # The binding is a NAME. Resolving it needs both scopes, and they arrive from different
    # collections - shared travels in the merged config, predefined does not travel at all
    # and has its own snapshot.
    ssl_tls_name, ssl_tls_rk, ssl_tls_rv = scalar_value(system.get("ssl-tls-service-profile"))
    ssl_tls_scope = ""
    ssl_tls_min_version = ""
    ssl_tls_max_version = ""
    ssl_tls_certificate = ""
    ssl_tls_certificate_scope = ""
    ssl_tls_certificate_trust = ""
    ssl_tls_certificate_issuer = ""
    if ssl_tls_name:
        ssl_tls_scope, resolved = resolve_ssl_tls_profile(
            ssl_tls_name,
            predefined=predefined_ssl_tls_profiles(latest_predefined_ssl_tls_snapshot(appliance)),
            shared=shared_ssl_tls_profiles(snapshot),
        )
        protocol_settings = resolved.get("protocol-settings") if isinstance(resolved, dict) else None
        if not isinstance(protocol_settings, dict):
            protocol_settings = {}
        ssl_tls_min_version, _, _ = scalar_value(protocol_settings.get("min-version"))
        ssl_tls_max_version, _, _ = scalar_value(protocol_settings.get("max-version"))
        ssl_tls_certificate, _, _ = scalar_value(resolved.get("certificate")
                                                 if isinstance(resolved, dict) else None)
        if ssl_tls_certificate:
            (ssl_tls_certificate_scope,
             ssl_tls_certificate_trust,
             ssl_tls_certificate_issuer) = resolve_certificate(
                ssl_tls_certificate,
                predefined=predefined_certificates(
                    latest_predefined_certificate_snapshot(appliance)),
                shared=shared_certificates(snapshot),
            )

    password_complexity, password_complexity_provenance = password_complexity_from_snapshot(
        snapshot)

    (master_key_state, master_key_expires_at,
     master_key_auto_renew, master_key_on_hsm) = read_master_key(
        latest_masterkey_snapshot(appliance))

    permitted_ip_values = entry_names(system.get("permitted-ip"))
    permitted_ip_count = len(permitted_ip_values)

    login_banner, login_banner_rk, login_banner_rv = scalar_value(system.get("login-banner"))
    idle_timeout_minutes, idle_timeout_rk, idle_timeout_rv = parse_integer_field(
        management.get("idle-timeout"),
        default_effective=DEFAULT_IDLE_TIMEOUT_MINUTES,
    )
    # admin-lockout is a CONTAINER, and the whole setting/management node is absent on a
    # device that has never had one of its keys set - measured on both PA-5220s - so this
    # tolerates the parent missing, not just the key.
    admin_lockout = management.get("admin-lockout")
    if not isinstance(admin_lockout, dict):
        admin_lockout = {}
    api_node = management.get("api")
    api_key = api_node.get("key") if isinstance(api_node, dict) else None
    if not isinstance(api_key, dict):
        api_key = {}

    failed_attempts, failed_rk, failed_rv = parse_integer_field(
        admin_lockout.get("failed-attempts"), default_effective=0)
    lockout_time, lockout_rk, lockout_rv = parse_integer_field(
        admin_lockout.get("lockout-time"), default_effective=0)
    api_key_lifetime, api_life_rk, api_life_rv = parse_integer_field(
        api_key.get("lifetime"), default_effective=0)

    normalized = NormalizedDeviceConfigurationProfile(
        source_snapshot=snapshot,
        config_source=SecurityRule.SOURCE_LOCAL,
        ha_required=ha_required,
        ha_enabled=ha_enabled,
        ha_state_sync_enabled=ha_state_sync_enabled,
        ha_link_monitoring_enabled=ha_link_monitoring_enabled,
        ack_login_banner=ack_login_banner,
        server_verification_enabled=server_verification,
        log_on_high_dp_load=log_high_dp,
        ntp_primary_server=ntp_primary_server,
        ntp_secondary_server=ntp_secondary_server,
        ssl_tls_service_profile_name=ssl_tls_name,
        ssl_tls_profile_scope=ssl_tls_scope,
        ssl_tls_min_version=ssl_tls_min_version,
        ssl_tls_max_version=ssl_tls_max_version,
        ssl_tls_certificate_name=ssl_tls_certificate,
        ssl_tls_certificate_trust=ssl_tls_certificate_trust,
        ssl_tls_certificate_issuer=ssl_tls_certificate_issuer,
        ssl_tls_certificate_scope=ssl_tls_certificate_scope,
        master_key_state=master_key_state,
        master_key_expires_at=master_key_expires_at,
        master_key_auto_renew_hours=master_key_auto_renew,
        master_key_on_hsm=master_key_on_hsm,
        password_complexity=password_complexity,
        permitted_ip_values=permitted_ip_values,
        permitted_ip_count=permitted_ip_count,
        login_banner=login_banner,
        idle_timeout_minutes=idle_timeout_minutes,
        admin_lockout_failed_attempts=failed_attempts,
        admin_lockout_time_minutes=lockout_time,
        api_key_lifetime_minutes=api_key_lifetime,
        raw_profile=deviceconfig,
        field_provenance_data=[
            ("ha_enabled",               ha_enabled_rk,            ha_enabled_rv),
            ("ha_state_sync_enabled",    ha_state_sync_rk,         ha_state_sync_rv),
            ("ha_link_monitoring_enabled", ha_link_monitoring_rk,  ha_link_monitoring_rv),
            ("ack_login_banner",         ack_banner_rk,            ack_banner_rv),
            ("server_verification_enabled", server_verification_rk, server_verification_rv),
            ("log_on_high_dp_load",       log_high_dp_rk,           log_high_dp_rv),
            ("ntp_primary_server",       ntp_primary_rk,           ntp_primary_rv),
            ("ntp_secondary_server",     ntp_secondary_rk,         ntp_secondary_rv),
            ("login_banner",             login_banner_rk,          login_banner_rv),
            ("ssl_tls_service_profile_name", ssl_tls_rk,            ssl_tls_rv),
            ("idle_timeout_minutes",     idle_timeout_rk,          idle_timeout_rv),
            ("admin_lockout_failed_attempts", failed_rk,            failed_rv),
            ("admin_lockout_time_minutes",    lockout_rk,           lockout_rv),
            ("api_key_lifetime_minutes",      api_life_rk,          api_life_rv),
            *password_complexity_provenance,
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
                "ack_login_banner": normalized.ack_login_banner,
                "server_verification_enabled": normalized.server_verification_enabled,
                "log_on_high_dp_load": normalized.log_on_high_dp_load,
                "ntp_primary_server": normalized.ntp_primary_server,
                "ntp_secondary_server": normalized.ntp_secondary_server,
                "ssl_tls_service_profile_name": normalized.ssl_tls_service_profile_name,
                "ssl_tls_profile_scope": normalized.ssl_tls_profile_scope,
                "ssl_tls_min_version": normalized.ssl_tls_min_version,
                "ssl_tls_max_version": normalized.ssl_tls_max_version,
                "ssl_tls_certificate_name": normalized.ssl_tls_certificate_name,
                "ssl_tls_certificate_trust": normalized.ssl_tls_certificate_trust,
                "ssl_tls_certificate_issuer": normalized.ssl_tls_certificate_issuer,
                "ssl_tls_certificate_scope": normalized.ssl_tls_certificate_scope,
                "master_key_state": normalized.master_key_state,
                "master_key_expires_at": normalized.master_key_expires_at,
                "master_key_auto_renew_hours": normalized.master_key_auto_renew_hours,
                "master_key_on_hsm": normalized.master_key_on_hsm,
                **normalized.password_complexity,
                "permitted_ip_values": normalized.permitted_ip_values,
                "permitted_ip_count": normalized.permitted_ip_count,
                "login_banner": normalized.login_banner,
                "idle_timeout_minutes": normalized.idle_timeout_minutes,
                "admin_lockout_failed_attempts": normalized.admin_lockout_failed_attempts,
                "admin_lockout_time_minutes": normalized.admin_lockout_time_minutes,
                "api_key_lifetime_minutes": normalized.api_key_lifetime_minutes,
                "raw_profile": normalized.raw_profile,
            },
        )

        # A binding naming a profile no collected scope defines. Reported rather than left as
        # a bare "unresolved" scope, because the two causes need different responses and the
        # row alone cannot tell them apart: either the predefined snapshot was never collected
        # for this appliance - true of everything collected before that collector existed -
        # or the device really does reference a profile that is not there. Silence here would
        # make a control report "cannot determine" with nothing pointing at why.
        NormalizationIssue.objects.filter(appliance=appliance, kind=SSL_TLS_ISSUE_KIND).delete()
        if normalized.ssl_tls_profile_scope == DeviceConfigurationProfile.SSL_TLS_SCOPE_UNRESOLVED:
            NormalizationIssue.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                kind=SSL_TLS_ISSUE_KIND,
                name=normalized.ssl_tls_service_profile_name,
                severity=NormalizationIssue.Severity.WARNING,
                disposition=NormalizationIssue.Disposition.KEPT,
                reason=(
                    f"deviceconfig/system binds SSL/TLS service profile "
                    f"{normalized.ssl_tls_service_profile_name!r}, which is defined in neither "
                    "the shared scope of the merged config nor the collected predefined "
                    "profiles. Most often this means the predefined catalog has not been "
                    "collected for this appliance - it does NOT travel in `show config "
                    "merged` and needs its own read - rather than that the reference is "
                    "genuinely dangling. The binding is kept as recorded; its protocol floor "
                    "is left blank rather than guessed."),
                node="deviceconfig/system/ssl-tls-service-profile",
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
