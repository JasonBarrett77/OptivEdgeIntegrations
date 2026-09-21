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
    Implicit,
    iter_member_values, parse_yes_no_field)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot)

LOCAL_METHODS = (AuthenticationProfile.METHOD_LOCAL_DATABASE, AuthenticationProfile.METHOD_NONE)


#: The payload contract node whose $implicit_values block backs the three flags below.
CONTRACT_NODE = "payload contract, authentication-sequence"


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
        exit_on_failure, exit_on_failure_rk, exit_on_failure_rv = parse_yes_no_field(
            scoped.entry.get("exit-sequence-on-failure"),
            implicit=Implicit.measured(
                False,
                f"{CONTRACT_NODE}.exit-sequence-on-failure: 'no', measured 2026-09-11 from a "
                "committed sequence the form had not touched"))
        use_domain, use_domain_rk, use_domain_rv = parse_yes_no_field(
            scoped.entry.get("use-domain-find-profile"),
            implicit=Implicit.measured(
                True,
                f"{CONTRACT_NODE}.use-domain-find-profile: 'yes', measured 2026-09-11 and "
                "agreeing with Help p.844 'enabled by default'"))
        use_userid, use_userid_rk, use_userid_rv = parse_yes_no_field(
            scoped.entry.get("use-userid-domain"),
            implicit=Implicit.measured(
                False,
                f"{CONTRACT_NODE}.use-userid-domain: 'no', measured 2026-09-11"))
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
        }, [
            # All three measured 2026-09-11, and all three normally ABSENT - the form stores
            # none of them until it is touched. Without these rows a reader cannot tell a
            # sequence that was configured to exit on failure from one that never was.
            ("exit_sequence_on_failure", exit_on_failure_rk, exit_on_failure_rv),
            ("use_domain_find_profile", use_domain_rk, use_domain_rv),
            ("use_userid_domain", use_userid_rk, use_userid_rv),
        ]))
    return {"authentication_sequences": write_scoped_objects(
        AuthenticationSequence, appliance, snapshot, rows)}
