"""Authentication profiles - PAN-AUTH-018, 020 and 025.

Reads every scope the object can occupy by reusing `scoped_entries`, which walks shared and
every vsys. Authentication profiles have no predefined namespace, so none is passed.
"""

from __future__ import annotations

from typing import Any

from optivedge_integrations.integrations.models import (
    Appliance, AuthenticationProfile)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
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
        lockout.get("failed-attempts"),
        implicit=Implicit.assumed(
            0,
            "the authentication-PROFILE lockout is not in the contract - what was measured "
            "2026-09-04 is the device-wide admin-lockout under deviceconfig/setting/management. "
            "0 mirrors that one, where it means UNLIMITED attempts, so this errs toward "
            "reporting a profile as unprotected rather than protected"))
    locktime, lock_rk, lock_rv = parse_integer_field(
        lockout.get("lockout-time"),
        implicit=Implicit.assumed(
            0,
            "same node as failed-attempts above, and unmeasured for the same reason"))
    mfa_on, mfa_rk, mfa_rv = parse_yes_no_field(
        mfa.get("mfa-enable"),
        implicit=Implicit.assumed(
            False,
            "the discovery log records that mfa-enable has no implicit value to measure - the "
            "factor list is what makes MFA real. False reads a profile with no factors as not "
            "enforcing MFA, which is what PAN-AUTH-020 needs"))
    domain, domain_rk, domain_rv = scalar_value(entry.get("user-domain"))
    modifier, mod_rk, mod_rv = scalar_value(entry.get("username-modifier"))

    factors = [str(f) for f in ensure_list((mfa.get("factors") or {}).get("member"))
               if f is not None] if isinstance(mfa.get("factors"), dict) else []
    allow = [str(a) for a in ensure_list((entry.get("allow-list") or {}).get("member"))
             if a is not None] if isinstance(entry.get("allow-list"), dict) else []
    allow_is_all = any(a.strip().lower() == "all" for a in allow)

    fields = {
        "method": _method_of(entry),
        "lockout_failed_attempts": failed,
        "lockout_time_minutes": locktime,
        "mfa_enabled": mfa_on,
        "mfa_factor_count": len(factors),
        "mfa_factor_names": factors,
        "allow_list_members": allow,
        "allow_list_count": len(allow),
        "allow_list_is_all": allow_is_all,
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


#: Keys whose VALUE is a profile name. `non-ui-authentication-profile` is the second
#: device-wide leaf, undocumented in the Help and found only in the CLI grammar.
#: The same two keys name a SEQUENCE too - every administrative binding offers both, measured
#: 2026-09-11 - so these are also what the sequence normalizer walks for its own referrers.
BINDING_KEYS = ("authentication-profile", "non-ui-authentication-profile")
#: Plus `authentication-profiles`, a sequence's MEMBER LIST. Missing until 2026-09-11, and the
#: same class of gap as the MFA factor list: the walk keyed on a leaf and a member list under a
#: different key named profiles it never saw. A profile used only through a sequence reported
#: unused to PAN-AUTH-025, whose remediation is deletion.
REFERRER_KEYS = BINDING_KEYS + ("authentication-profiles",)
#: A referrer path containing either is on the management plane: the per-account binding and
#: the two device-wide leaves. Captive portal, GlobalProtect and authentication objects are not.
ADMINISTRATIVE_MARKERS = ("/mgt-config/users", "/deviceconfig/system")


def _referenced_names(value: Any) -> list[tuple[str, str]]:
    """The name(s) a referring key holds, as (name, path suffix).

    A referring key is USUALLY a scalar leaf and was assumed to be one always. It is not:
    an authentication profile names its MFA server profiles as
    `multi-factor-auth/factors/member`, a member LIST, and `scalar_value` returns "" for a dict
    with no `#text`. So the key was in the walk's key set, matched, and contributed nothing -
    a silent zero rather than an error. PAN-AAA-013 reported `oep-mfa-duo` as an unused server
    profile while `oep-auth-hardened` was invoking it, and the remediation that control prints
    is "delete the profile".

    Found by searching the merged payload for the profile NAMES rather than for the keys: the
    key-based walk can only find shapes it already believes in, and this is the shape it did
    not. That search is the cross-check to run whenever a referrer key set changes.
    """
    text, _, _ = scalar_value(value)
    if text:
        return [(text, "")]
    if isinstance(value, dict) and "member" in value:
        members = value["member"]
        members = members if isinstance(members, list) else [members]
        return [(str(m).strip(), "/member") for m in members if str(m).strip()]
    return []


def find_references(node: Any, path: str = "",
                    keys: tuple[str, ...] = REFERRER_KEYS) -> list[tuple[str, str, str]]:
    """Every profile reference under `node`, as (vsys, name, where).

    Walks the WHOLE payload rather than visiting the eight paths the CLI grammar lists.
    PAN-AUTH-025 says "nobody references this profile", and that claim is only as good as the
    list of places a reference could hide: a path the grammar missed would make the control
    report an in-use profile as unused. Walking everything cannot miss one, and the grammar
    list stays useful as a cross-check on what the walk finds.

    `vsys` is the enclosing vsys name, or "" for an appliance-level referrer. It decides which
    definition of a name the reference resolves to when both a vsys and shared hold one.
    """
    found: list[tuple[str, str, str]] = []
    if isinstance(node, list):
        for item in node:
            found += find_references(item, path, keys)
        return found
    if not isinstance(node, dict):
        return found

    # Name this node if it IS a named entry. Reading `@name` off the parent instead loses every
    # entry name in the path - which read as a cosmetic flaw and was not: `_enclosing_vsys` then
    # never found a vsys, so every vsys-scoped reference was attributed to the SHARED profile of
    # that name. Invisible on a lab where all nine profiles are shared, and wrong the moment a
    # vsys defines one of its own.
    name = str(node.get("@name") or "")
    here = f"{path}[{name}]" if name else path

    for key, value in node.items():
        if key.startswith("@"):
            continue
        if key in keys:
            for text, suffix in _referenced_names(value):
                found.append((_enclosing_vsys(here), text, f"{here}/{key}{suffix}"))
            continue
        found += find_references(value, f"{here}/{key}", keys)
    return found


def _enclosing_vsys(path: str) -> str:
    """The vsys a reference sits under, read back out of the path it was found at."""
    marker = "/vsys/entry["
    if marker not in path:
        return ""
    return path.split(marker, 1)[1].split("]", 1)[0]


def attribute_references(references, definitions):
    """{(scope-key, name): [where]} - each reference put on the definition it resolves to.

    `references` is what `find_references` returned: (vsys, name, where). `definitions` is
    {(vsys_name, name)} for every VSYS-scoped definition that exists; a reference from inside a
    vsys resolves to that vsys's object of the name when one exists, and to the shared one
    otherwise. Measured for certificates and applied unchanged here.

    Getting it wrong is two errors in one move: the real object reports unused and the
    same-named orphan reports in use. Shared by authentication profiles and AAA server profiles
    so the rule has ONE home - a second copy is the thing most likely to drift.
    """
    attributed: dict[tuple[str, str], list[str]] = {}
    for vsys, name, where in references:
        key = (vsys, name) if vsys and (vsys, name) in definitions else ("", name)
        attributed.setdefault(key, []).append(where)
    return attributed


def reference_counts(snapshot) -> dict[tuple[str, str], list[str]]:
    """Authentication-profile references, attributed to the definition each resolves to."""
    payload = snapshot.payload if isinstance(snapshot.payload, dict) else {}
    # Vsys SEQUENCES are definitions too: a binding naming one from inside its vsys has to land
    # on that vsys's sequence, or `_administrative_sequences` misses it.
    definitions = {(e.vsys_name, str(e.entry.get("@name") or ""))
                   for key in ("authentication-profile", "authentication-sequence")
                   for e in scoped_entries(snapshot, key)
                   if e.scope != "shared"}
    return attribute_references(find_references(payload.get("config")), definitions)


def _administrative_sequences(snapshot, references) -> tuple[str, ...]:
    """Path fragments identifying every sequence something administrative names.

    A profile an administrator reaches THROUGH a sequence is administrative, and the only trace
    of that on the profile is a referrer path inside the sequence. So the sequence's own status
    is worked out here, from the same references, and matched against those paths.
    """
    fragments = []
    for scoped in scoped_entries(snapshot, "authentication-sequence"):
        name = str(scoped.entry.get("@name") or "")
        vsys = scoped.vsys_name if scoped.scope != "shared" else ""
        if any(marker in path for path in references.get((vsys, name), [])
               for marker in ADMINISTRATIVE_MARKERS):
            fragments.append(f"/vsys/entry[{vsys}]/authentication-sequence/entry[{name}]/" if vsys
                             else f"/shared/authentication-sequence/entry[{name}]/")
    return tuple(fragments)


def normalize_authentication_profiles(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"authentication_profiles": 0}
    references = reference_counts(snapshot)
    admin_sequences = _administrative_sequences(snapshot, references)
    rows = []
    for scoped in scoped_entries(snapshot, "authentication-profile"):
        fields, _provenance = _profile_fields(scoped.entry)
        name = str(scoped.entry.get("@name") or "")
        where = references.get((scoped.vsys_name if scoped.scope != "shared" else "", name), [])
        fields["referrer_paths"] = sorted(set(where))
        fields["referrer_count"] = len(set(where))
        # Administrative iff something on the management plane names it. `mgt-config/users` is
        # the per-account binding and `deviceconfig/system` carries both device-wide leaves;
        # captive portal, GlobalProtect and authentication objects are other people's controls.
        #
        # Or a member of a sequence that does: the administrator reaches this profile through it.
        fields["is_administrative"] = any(
            any(marker in path for marker in ADMINISTRATIVE_MARKERS + admin_sequences)
            for path in fields["referrer_paths"])
        rows.append((scoped, fields))
    return {"authentication_profiles": write_scoped_objects(
        AuthenticationProfile, appliance, snapshot, rows)}
