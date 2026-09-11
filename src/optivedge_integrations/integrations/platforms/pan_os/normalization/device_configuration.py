"""Shared PAN-OS readers for the device's own settings. The module name is historical.

This file used to hold `DeviceConfigurationProfile`'s normalizer - one row per appliance
spanning three PAN-OS screens. That model was split into seven, one per control cluster, on
2026-09-10 and deleted on 2026-09-11. What remains are the readers the seven share: each new
model calls the same parser the aggregate called, which is what kept them from disagreeing while
both existed. Worth moving to a neutral name the next time this file is opened for another
reason; not worth a risky move on its own.
"""

from __future__ import annotations

from typing import Any

from optivedge_integrations.integrations.models import (
    Appliance,
    ManagementTlsBinding,
    MasterKey,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ensure_list,
    parse_integer_field,
    parse_yes_no_field,
    scalar_value,
)


DEFAULT_IDLE_TIMEOUT_MINUTES = 60

#: Raised when deviceconfig/system names an SSL/TLS profile no collected scope defines.
SSL_TLS_ISSUE_KIND = "ssl_tls_service_profile_unresolved"


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


def login_banner_from_node(system: Any) -> tuple[dict[str, Any], list]:
    """Device > Setup > Management > General Settings, the banner pair. PAN-MGT-007 and 008.

    Shared by `LoginBanner` and, until it was deleted on 2026-09-11, `DeviceConfigurationProfile`. One parse
    for both, deliberately: while two models carry the same two values, the only thing stopping
    them disagreeing is that neither reads the payload for itself.

    `ack-login-banner` is implicit NO, and the checkbox is GREYED OUT until a banner exists -
    measured 2026-09-01 - so acknowledgement cannot be required without text, and the pair has
    to be read together to be interpreted at all.
    """
    if not isinstance(system, dict):
        system = {}
    text, text_rk, text_rv = scalar_value(system.get("login-banner"))
    ack, ack_rk, ack_rv = parse_yes_no_field(
        system.get("ack-login-banner"), default_effective=False)
    return ({"text": text, "acknowledgement_required": ack},
            [("text", text_rk, text_rv), ("acknowledgement_required", ack_rk, ack_rv)])


def authentication_settings_from_node(management: Any) -> tuple[dict[str, Any], list]:
    """Device > Setup > Management > Authentication Settings, from the `setting/management` node.

    PAN-AUTH-014 to 017's subject, and shared by `AuthenticationSettings` and, until it was
    deleted on 2026-09-11, `DeviceConfigurationProfile`. ONE parse, deliberately: while two models carry the
    same four numbers, the only thing that stops them disagreeing is that neither reads the
    payload for itself.

    Takes the node rather than the snapshot because the caller has already walked
    deviceconfig/setting/management and that walk is not free to duplicate.

    `admin-lockout` is a CONTAINER, and the whole `setting/management` node is absent on a device
    that has never had one of its keys set - measured on both PA-5220s - so this tolerates the
    parent missing, not just the key. Idle timeout defaults to 60, which the vendor sets; the
    other three default to 0, and 0 is the WEAKEST value on all three - unlimited attempts, no
    lockout, and an API key that never expires.
    """
    if not isinstance(management, dict):
        management = {}
    admin_lockout = management.get("admin-lockout")
    if not isinstance(admin_lockout, dict):
        admin_lockout = {}
    api_node = management.get("api")
    api_key = api_node.get("key") if isinstance(api_node, dict) else None
    if not isinstance(api_key, dict):
        api_key = {}

    reads = (
        ("idle_timeout_minutes", management.get("idle-timeout"), DEFAULT_IDLE_TIMEOUT_MINUTES),
        ("lockout_failed_attempts", admin_lockout.get("failed-attempts"), 0),
        ("lockout_time_minutes", admin_lockout.get("lockout-time"), 0),
        ("api_key_lifetime_minutes", api_key.get("lifetime"), 0),
    )
    values: dict[str, Any] = {}
    provenance: list[tuple[str, Any, str | None]] = []
    for field, raw, default in reads:
        values[field], raw_key, raw_value = parse_integer_field(raw, default_effective=default)
        provenance.append((field, raw_key, raw_value))
    return values, provenance


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
        return MasterKey.STATE_UNDETERMINED, "", 0, False
    payload = snapshot.payload or {}
    if not isinstance(payload, dict):
        return MasterKey.STATE_UNDETERMINED, "", 0, False
    expires_at, _, _ = scalar_value(payload.get("expire-at"))
    auto_renew, _, _ = parse_integer_field(payload.get("auto-renew-mkey"), default_effective=0)
    on_hsm, _, _ = parse_yes_no_field(payload.get("on-hsm"), default_effective=False)
    if not expires_at:
        # The key is absent from the reply entirely - a shape nobody has seen. Not read as
        # default: that verdict rests on expire-at being present and zero.
        return MasterKey.STATE_UNDETERMINED, "", auto_renew, on_hsm
    state = (MasterKey.STATE_DEFAULT if expires_at.strip() == "0"
             else MasterKey.STATE_SET)
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
    scope = ManagementTlsBinding.SCOPE_PREDEFINED
    if entry is None:
        entry = shared.get(name)
        scope = ManagementTlsBinding.SCOPE_SHARED
    if entry is None:
        return (ManagementTlsBinding.SCOPE_UNRESOLVED,
                ManagementTlsBinding.TRUST_UNDETERMINED, "")
    subject_hash, _, _ = scalar_value(entry.get("subject-hash"))
    issuer_hash, _, _ = scalar_value(entry.get("issuer-hash"))
    issuer, _, _ = scalar_value(entry.get("issuer"))
    if not subject_hash or not issuer_hash:
        # Present but unhashed. Not determinable rather than assumed either way.
        return scope, ManagementTlsBinding.TRUST_UNDETERMINED, issuer
    if subject_hash == issuer_hash:
        return scope, ManagementTlsBinding.TRUST_SELF_SIGNED, issuer
    trust = _issuer_chain_trust(issuer_hash, predefined=predefined, shared=shared)
    return scope, trust, issuer


def _issuer_chain_trust(issuer_hash: str, *, predefined: dict, shared: dict) -> str:
    """Walk the issuer chain through the certificates PRESENT ON THIS DEVICE.

    A chain that terminates at a self-signed CA which is itself on the device is a PRIVATE
    root: nothing trusts it by default, and a browser rejects it exactly as it rejects a
    self-signed leaf. A chain that leaves the device may reach a public root, which this cannot
    confirm and does not claim - it only records that the distinction exists.

    Hashes are compared WITHIN one merged-config surface, where the equality relation holds.
    They are not portable across surfaces, which is why nothing here compares them to anything
    collected separately.
    """
    by_subject: dict[str, dict] = {}
    for source in (shared, predefined):
        for entry in source.values():
            subject, _, _ = scalar_value(entry.get("subject-hash"))
            if subject:
                by_subject.setdefault(subject, entry)

    seen: set[str] = set()
    current = issuer_hash
    while current and current not in seen:
        seen.add(current)
        entry = by_subject.get(current)
        if entry is None:
            # The chain left this device. It may reach a public root; that is not decidable
            # here, and claiming either way would be the error this function exists to avoid.
            return ManagementTlsBinding.TRUST_CA_ISSUED
        subject, _, _ = scalar_value(entry.get("subject-hash"))
        parent, _, _ = scalar_value(entry.get("issuer-hash"))
        if not parent or not subject:
            return ManagementTlsBinding.TRUST_UNDETERMINED
        if parent == subject:
            # A self-signed CA on this device: a private root.
            return ManagementTlsBinding.TRUST_PRIVATE_CA
        current = parent
    # A loop, which a valid chain cannot contain.
    return ManagementTlsBinding.TRUST_UNDETERMINED
