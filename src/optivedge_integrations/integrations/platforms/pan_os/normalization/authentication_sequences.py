"""Authentication sequences - PAN-AAA-012.

RUNS AFTER `normalize_authentication_profiles` and BEFORE `normalize_admin_users`. Members are
resolved over the profile rows to read each one's method, and an administrator bound to a
sequence is resolved over the rows this writes. The ordering is declared in
`flows.APPLIANCE_OBJECT_NORMALIZERS`.
"""

from __future__ import annotations

from typing import Any

from optivedge_integrations.integrations.models import (
    Appliance, AuthenticationProfile, AuthenticationSequence)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication import (
    ADMINISTRATIVE_MARKERS, BINDING_KEYS, attribute_references, find_references)
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
    scoped_entries, write_scoped_objects)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    iter_member_values, parse_yes_no_field)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot)

LOCAL_METHODS = (AuthenticationProfile.METHOD_LOCAL_DATABASE, AuthenticationProfile.METHOD_NONE)


def _member_names(entry: dict[str, Any]) -> list[str]:
    """`authentication-profiles/member`, in order - a MEMBER LIST, not a leaf."""
    node = entry.get("authentication-profiles")
    members = node.get("member") if isinstance(node, dict) else None
    return [str(v).strip() for v, _prov in iter_member_values(members) if str(v).strip()]


def _methods_by_name(appliance: Appliance) -> dict[tuple[str, str], str]:
    """{(vsys or "", name): method} over this appliance's profile rows."""
    return {((p.vsys_name if p.scope != "shared" else ""), p.name): p.method
            for p in AuthenticationProfile.objects.filter(appliance=appliance)}


def normalize_authentication_sequences(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"authentication_sequences": 0}
    payload = snapshot.payload if isinstance(snapshot.payload, dict) else {}
    entries = scoped_entries(snapshot, "authentication-sequence")
    methods = _methods_by_name(appliance)

    definitions = {(e.vsys_name, str(e.entry.get("@name") or ""))
                   for e in entries if e.scope != "shared"}
    references = attribute_references(
        find_references(payload.get("config"), keys=BINDING_KEYS), definitions)

    rows = []
    for scoped in entries:
        name = str(scoped.entry.get("@name") or "")
        vsys = scoped.vsys_name if scoped.scope != "shared" else ""
        members = _member_names(scoped.entry)
        # A member resolves within the sequence's own vsys first, then shared - the rule every
        # other reference on this device follows.
        resolved = [methods.get((vsys, m)) if (vsys, m) in methods else methods.get(("", m))
                    for m in members]
        local = [m for m, method in zip(members, resolved) if method in LOCAL_METHODS]
        unresolved = sum(1 for method in resolved if method is None)
        exit_on_failure, _, _ = parse_yes_no_field(
            scoped.entry.get("exit-sequence-on-failure"), default_effective=False)
        use_domain, _, _ = parse_yes_no_field(
            scoped.entry.get("use-domain-find-profile"), default_effective=True)
        use_userid, _, _ = parse_yes_no_field(
            scoped.entry.get("use-userid-domain"), default_effective=False)
        where = sorted(set(references.get((vsys, name), [])))
        rows.append((scoped, {
            "member_names": members,
            "member_count": len(members),
            "member_methods": [method or "" for method in resolved],
            "local_member_names": local,
            "has_local_member": bool(local),
            "unresolved_member_count": unresolved,
            "all_members_external": bool(members) and not unresolved and all(
                method in AuthenticationProfile.EXTERNAL_METHODS for method in resolved),
            "exit_sequence_on_failure": exit_on_failure,
            "use_domain_find_profile": use_domain,
            "use_userid_domain": use_userid,
            "referrer_paths": where,
            "referrer_count": len(where),
            "is_administrative": any(marker in path for path in where
                                     for marker in ADMINISTRATIVE_MARKERS),
        }))
    return {"authentication_sequences": write_scoped_objects(
        AuthenticationSequence, appliance, snapshot, rows)}
