"""Authentication profiles - PAN-AUTH-018, 020 and 025.

Reads every scope the object can occupy by reusing `scoped_entries`, which walks shared and
every vsys. Authentication profiles have no predefined namespace, so none is passed.
"""

from __future__ import annotations

from typing import Any

from optivedge_integrations.integrations.models import (
    Appliance, AuthenticationProfile)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ensure_list, parse_integer_field, parse_yes_no_field, scalar_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
    scoped_entries, write_scoped_objects)
# NOT normalization.snapshots, which has a function of the SAME NAME taking an
# EnforcementPoint. This one takes an Appliance. Importing the wrong one fails with
# "'Appliance' object has no attribute 'appliance'", which reads like a model problem.
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot)


def _method_of(entry: dict[str, Any]) -> str:
    """The single key under `method`, or blank when the node is absent.

    PAN-OS models the choice as WHICH CHILD EXISTS rather than as a value - `local-database`
    arrives as `{'method': {'local-database': None}}`. A blank result is not the same as
    `none`: one is a profile nobody finished, the other is a deliberate choice to authenticate
    nothing, and only the second is a real configuration.
    """
    method = entry.get("method")
    if not isinstance(method, dict):
        return ""
    keys = [k for k in method if not k.startswith("@")]
    return keys[0] if len(keys) == 1 else ""


def _profile_fields(entry: dict[str, Any]) -> tuple[dict[str, Any], list]:
    lockout = entry.get("lockout")
    if not isinstance(lockout, dict):
        lockout = {}
    mfa = entry.get("multi-factor-auth")
    if not isinstance(mfa, dict):
        mfa = {}

    failed, failed_rk, failed_rv = parse_integer_field(
        lockout.get("failed-attempts"), default_effective=0)
    locktime, lock_rk, lock_rv = parse_integer_field(
        lockout.get("lockout-time"), default_effective=0)
    mfa_on, mfa_rk, mfa_rv = parse_yes_no_field(
        mfa.get("mfa-enable"), default_effective=False)
    domain, domain_rk, domain_rv = scalar_value(entry.get("user-domain"))
    modifier, mod_rk, mod_rv = scalar_value(entry.get("username-modifier"))

    factors = [str(f) for f in ensure_list((mfa.get("factors") or {}).get("member"))
               if f is not None] if isinstance(mfa.get("factors"), dict) else []
    allow = [str(a) for a in ensure_list((entry.get("allow-list") or {}).get("member"))
             if a is not None] if isinstance(entry.get("allow-list"), dict) else []

    fields = {
        "method": _method_of(entry),
        "lockout_failed_attempts": failed,
        "lockout_time_minutes": locktime,
        "mfa_enabled": mfa_on,
        "mfa_factor_count": len(factors),
        "mfa_factor_names": factors,
        "allow_list_members": allow,
        "allow_list_count": len(allow),
        "user_domain": domain or "",
        "username_modifier": modifier or "",
    }
    provenance = [
        ("lockout_failed_attempts", failed_rk, failed_rv),
        ("lockout_time_minutes", lock_rk, lock_rv),
        ("mfa_enabled", mfa_rk, mfa_rv),
        ("user_domain", domain_rk, domain_rv),
        ("username_modifier", mod_rk, mod_rv),
    ]
    return fields, provenance


def normalize_authentication_profiles(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"authentication_profiles": 0}
    rows = []
    for scoped in scoped_entries(snapshot, "authentication-profile"):
        fields, _provenance = _profile_fields(scoped.entry)
        rows.append((scoped, fields))
    return {"authentication_profiles": write_scoped_objects(
        AuthenticationProfile, appliance, snapshot, rows)}
