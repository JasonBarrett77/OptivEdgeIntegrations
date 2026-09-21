"""Administrator accounts - PAN-AUTH-019, 021, 022.

Reads `/config/mgt-config/users`, which sits at the TOP of the merged config beside `devices`
and `shared` rather than under a device entry - the same place `password-complexity` and
`password-profile` live, and the same trap: the obvious xpath is wrong.

Two passes over the entries, because `superuser_cohort_size` is an appliance total and cannot
be known while the first account is still being written.

RUNS AFTER `normalize_authentication_profiles` and depends on it. PAN-AUTH-020 asks whether the
profile governing an administrator carries MFA, and that is a value on the profile read through
a binding on the account - so an appliance whose profiles have not been normalized yet would
report every administrator as unresolved. The ordering is declared in
`flows.APPLIANCE_OBJECT_NORMALIZERS`, not left to import order.
"""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    AdminUser, Appliance, AuthenticationProfile, AuthenticationSequence, FieldProvenance,
    NormalizationIssue, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ABSENT, classify_prov_type, provenance_raw_key, provenance_value, entry_provenance, ensure_list, iter_member_values,
    parse_yes_no_field, scalar_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot)


def _device_system(snapshot: Snapshot) -> dict[str, Any]:
    """`deviceconfig/system` off the merged payload, or {}."""
    payload = snapshot.payload or {}
    config = payload.get("config") if isinstance(payload, dict) else None
    if not isinstance(config, dict):
        return {}
    devices = config.get("devices")
    entry = (devices or {}).get("entry") if isinstance(devices, dict) else None
    entries = ensure_list(entry)
    if not entries or not isinstance(entries[0], dict):
        return {}
    system = (entries[0].get("deviceconfig") or {}).get("system")
    return system if isinstance(system, dict) else {}


def _profiles_by_name(appliance: Appliance) -> dict[str, AuthenticationProfile]:
    """{name: profile}, shared preferred over any vsys definition of the same name.

    An administrator binding is appliance-level - `mgt-config` is neither shared nor per-vsys -
    so a shared definition is the one it reaches. A vsys-scoped profile of the same name is
    kept only as a fallback, so a reference resolves to SOMETHING rather than being reported
    unresolved on a device where the only definition sits in a vsys.
    """
    resolved: dict[str, AuthenticationProfile] = {}
    for profile in AuthenticationProfile.objects.filter(appliance=appliance):
        existing = resolved.get(profile.name)
        if existing is None or (profile.scope == "shared" and existing.scope != "shared"):
            resolved[profile.name] = profile
    return resolved


def _sequences_by_name(appliance: Appliance) -> dict[str, AuthenticationSequence]:
    """{name: sequence}, shared preferred - the same rule as `_profiles_by_name`.

    Every administrative binding accepts a sequence as well as a profile (measured 2026-09-11),
    and a name is unique across the two in one location. Until this existed an administrator
    bound to a sequence read as "profile not found" and not external, so PAN-AUTH-019 fired on
    one whose sequence was RADIUS then TACACS+.
    """
    resolved: dict[str, AuthenticationSequence] = {}
    for sequence in AuthenticationSequence.objects.filter(appliance=appliance):
        existing = resolved.get(sequence.name)
        if existing is None or (sequence.scope == "shared" and existing.scope != "shared"):
            resolved[sequence.name] = sequence
    return resolved


def _entries(snapshot: Snapshot) -> list[dict[str, Any]]:
    payload = snapshot.payload or {}
    config = payload.get("config") if isinstance(payload, dict) else None
    if not isinstance(config, dict):
        return []
    node = config.get("mgt-config")
    if not isinstance(node, dict):
        return []
    users = node.get("users")
    if not isinstance(users, dict):
        # An EMPTY users container parses to None - that is the shape a template push of an
        # empty node leaves behind, and it is not an error.
        return []
    return [e for e in ensure_list(users.get("entry")) if isinstance(e, dict)]


def _flag_set(node: Any) -> bool:
    """A yes/no role leaf. Present-but-"no" is not the role."""
    if node is None:
        return False
    value, _, _ = scalar_value(node)
    return value.lower() != "no"


def _member_names(node: Any) -> list[str]:
    """The device or vsys names on a member list. An empty element is a valid, bare role."""
    return [value for value, _ in iter_member_values(node) if value]


def _vsys_scope(node: Any) -> str:
    """`vsysadmin`/`vsysreader` carry an ENTRY PER DEVICE, each with its own vsys member list."""
    parts: list[str] = []
    if not isinstance(node, dict):
        return ""
    for entry in ensure_list(node.get("entry")):
        if not isinstance(entry, dict):
            continue
        names = _member_names(entry.get("vsys"))
        device = str(entry.get("@name") or "").strip()
        parts.append(f"{device}: {', '.join(names)}" if names else device)
    return "; ".join(p for p in parts if p)


def resolve_role(role_based: Any) -> tuple[str, str, str]:
    """Return (role_type, role_scope, custom_role_profile) for a `permissions/role-based` node.

    Three wire shapes, measured on hardware, and one enum column cannot hold them:
    a yes/no leaf, a member list of device names, and an entry per device carrying a vsys
    member list. `custom` is a fourth - `vsys` plus `profile`.

    Where a payload somehow carries two roles the MOST PRIVILEGED wins, so a parser bug can
    only ever over-report privilege.
    """
    if not isinstance(role_based, dict):
        return AdminUser.RoleType.NONE, "", ""

    found: dict[str, tuple[str, str]] = {}
    for key in ("superuser", "superreader"):
        if key in role_based and _flag_set(role_based[key]):
            found[key] = ("", "")
    for key in ("deviceadmin", "devicereader"):
        if key in role_based:
            found[key] = (", ".join(_member_names(role_based[key])), "")
    for key in ("vsysadmin", "vsysreader"):
        if key in role_based:
            found[key] = (_vsys_scope(role_based[key]), "")
    custom = role_based.get("custom")
    if isinstance(custom, dict):
        profile, _, _ = scalar_value(custom.get("profile"))
        found["custom"] = (", ".join(_member_names(custom.get("vsys"))), profile)

    for role in AdminUser.ROLE_PRECEDENCE:
        if role.value in found:
            scope, profile = found[role.value]
            return role.value, scope, profile
    return AdminUser.RoleType.NONE, "", ""


def normalize_admin_users(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"admin_users": 0}

    entries = _entries(snapshot)
    # The device-wide binding covers every account that names no profile of its own. It is
    # NULL on all three lab devices, and is read anyway: an unread fallback is invisible
    # exactly when it is doing the work.
    device_wide, _, _ = scalar_value(_device_system(snapshot).get("authentication-profile"))
    profiles = _profiles_by_name(appliance)
    sequences = _sequences_by_name(appliance)

    # Pass one: resolve every account, so the superuser total is known before any row is
    # written. PAN-AUTH-022 grades on that total and a row written before it is counted would
    # carry a cohort size of whatever had been seen so far.
    rows: list[dict[str, Any]] = []
    for entry in entries:
        name = str(entry.get("@name") or "").strip()
        if not name:
            NormalizationIssue.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                kind="admin user",
                name="",
                severity=NormalizationIssue.Severity.ERROR,
                disposition=NormalizationIssue.Disposition.SKIPPED,
                reason="mgt-config/users entry has no @name",
                raw_entry=entry,
            )
            continue
        permissions = entry.get("permissions")
        role_based = permissions.get("role-based") if isinstance(permissions, dict) else None
        role_type, role_scope, custom_profile = resolve_role(role_based)

        auth_profile, auth_key, auth_value = scalar_value(entry.get("authentication-profile"))
        pwd_profile, pwd_key, pwd_value = scalar_value(entry.get("password-profile"))
        cert_only, cert_key, cert_value = parse_yes_no_field(
            entry.get("client-certificate-only"),
        implicit=Implicit.measured(
            False,
            "payload contract, admin-user.client-certificate-only: implicit 'no'"))

        has_password = bool(str(entry.get("phash") or "").strip())
        has_public_key = bool(str(entry.get("public-key") or "").strip())

        if auth_profile:
            effective, binding = auth_profile, AdminUser.AuthenticationBinding.USER
        elif device_wide:
            effective, binding = device_wide, AdminUser.AuthenticationBinding.DEVICE
        else:
            effective, binding = "", AdminUser.AuthenticationBinding.NONE
        bound_profile = profiles.get(effective) if effective else None
        bound_sequence = (sequences.get(effective) if effective and bound_profile is None
                          else None)
        # A sequence counts as external only when EVERY member is: a local-database member is a
        # way in with a password the device stores, which is what 019 exists to report.
        external = (bool(bound_profile and bound_profile.method_is_external)
                    or bool(bound_sequence and bound_sequence.all_members_external))
        rows.append({
            "name": name,
            "description": str(entry.get("description") or "").strip()[:255],
            "role_type": role_type,
            "role_scope": role_scope[:255],
            "custom_role_profile": custom_profile[:64],
            "is_superuser": role_type == AdminUser.RoleType.SUPERUSER,
            "authentication_profile_name": auth_profile[:64],
            "effective_authentication_profile": effective[:64],
            "authentication_binding": binding,
            # No profile means no second factor, which is the finding rather than a gap in
            # the data - an administrator on the local database is reached by a password alone.
            "admin_mfa_enabled": bool(bound_profile and bound_profile.mfa_enabled),
            "admin_mfa_factors": (list(bound_profile.mfa_factor_names)
                                  if bound_profile else []),
            "authentication_profile_unresolved": (bool(effective) and bound_profile is None
                                                  and bound_sequence is None),
            "authentication_sequence": bound_sequence is not None,
            "password_profile_name": pwd_profile[:64],
            "client_certificate_only": cert_only,
            "has_password": has_password,
            "has_public_key": has_public_key,
            # BOTH halves, and neither is redundant. A profile whose method is
            # `local-database` or `none` authenticates against the device, so a bound profile
            # is not evidence of centralization; and a stored credential outlives the binding
            # that currently makes it unreachable.
            "authentication_is_external": external,
            "centrally_authenticated": external and not has_password and not has_public_key,
            "_entry": entry,
            "_provenance": [
                ("authentication_profile_name", auth_key, auth_value),
                ("password_profile_name", pwd_key, pwd_value),
                ("client_certificate_only", cert_key, cert_value),
            ],
        })

    cohort = sum(1 for row in rows if row["is_superuser"])

    content_type = ContentType.objects.get_for_model(AdminUser)
    seen = []
    with transaction.atomic():
        for row in rows:
            entry = row.pop("_entry")
            provenance = row.pop("_provenance")
            name = row.pop("name")
            obj, _ = AdminUser.objects.update_or_create(
                appliance=appliance, name=name,
                defaults={
                    "management_station": appliance.management_station,
                    "appliance_group": appliance.appliance_group,
                    "source_snapshot": snapshot,
                    "superuser_cohort_size": cohort if row["is_superuser"] else 0,
                    **row,
                },
            )
            seen.append(obj.pk)

            FieldProvenance.objects.filter(
                content_type=content_type, object_id=obj.pk).delete()
            # The ENTRY's own marker, never the container's: fw-core-tpa-a reports
            # `"users": {"@ptpl": "shared"}` over three entries that are all device-local,
            # because a template named `shared` pushes an EMPTY users node.
            raw_key, raw_value = entry_provenance(entry)
            if raw_key is not None:
                FieldProvenance.objects.create(
                    content_type=content_type, object_id=obj.pk, field_name="__entry__",
                    provenance_type=classify_prov_type(raw_key),
                    raw_key=provenance_raw_key(raw_key), raw_value=provenance_value(raw_key, raw_value))
            for field, rk, rv in provenance:
                if rk is not ABSENT:
                    FieldProvenance.objects.create(
                        content_type=content_type, object_id=obj.pk, field_name=field,
                        provenance_type=classify_prov_type(rk),
                        raw_key=provenance_raw_key(rk), raw_value=provenance_value(rk, rv))

        # An account deleted on the device must not linger: every one of these controls is
        # about who CAN log in, and a stale row is a finding about somebody who cannot.
        AdminUser.objects.filter(appliance=appliance).exclude(pk__in=seen).delete()
    return {"admin_users": len(seen), "superusers": cohort}
