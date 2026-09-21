"""AAA server profiles - the auth-servers domain, PAN-AAA-001 through 013.

Reuses `scoped_entries` and `write_scoped_objects`, which walk shared and every vsys - all six
kinds are vsys-scopable, tested by completing a made-up ENTRY rather than the container.

The three shapes that would bite a normalizer written from one kind:

    the address key has THREE NAMES   `address` on ldap and tacplus, `ip-address` on radius,
                                      `host` on kerberos
    `protocol` has TWO WIRE FORMS     radius stores {"PAP": null}, tacplus stores "PAP"
    two of three implicit values      `ssl` and both SAML flags are implicit YES; only
      INVERT the obvious reading      `verify-server-certificate` is implicit NO
"""

from __future__ import annotations

from typing import Any

from optivedge_integrations.integrations.models import (
    Appliance, NormalizationIssue, ServerProfile, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication import (
    attribute_references, find_references)
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
    ScopedEntry, scoped_nodes, write_scoped_objects)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ensure_list, parse_yes_no_field, scalar_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot)

#: kind -> the key its server entries use for an address. Reading one name loses the others.
ADDRESS_KEY = {
    "ldap": "address",
    "tacplus": "address",
    "radius": "ip-address",
    "kerberos": "host",
}

#: Measured 2026-09-09 by writing the profile WITHOUT the key and opening it in the UI. Two of
#: these three are the opposite of what a checkbox suggests; see the model for the method.
IMPLICIT = {
    "ldap_ssl": True,
    "ldap_verify_server_certificate": False,
    "saml_validate_idp_certificate": True,
    "saml_want_auth_requests_signed": True,
}


def _protocol_of(entry: dict[str, Any]) -> str:
    """The protocol, from either wire form.

    radius models the choice as WHICH CHILD EXISTS - `{"protocol": {"PAP": null}}` - and tacplus
    as text, `{"protocol": "PAP"}`. `action=complete` returns the same value list for both, so a
    reader written against one silently returns blank for the other.
    """
    node = entry.get("protocol")
    if isinstance(node, dict):
        keys = [k for k in node if not k.startswith("@")]
        if len(keys) == 1:
            return keys[0]
        text, _, _ = scalar_value(node)
        return text
    text, _, _ = scalar_value(node)
    return text


def _servers(entry: dict[str, Any], kind: str) -> list[str]:
    node = entry.get("server")
    if not isinstance(node, dict):
        return []
    key = ADDRESS_KEY.get(kind)
    out = []
    for server in ensure_list(node.get("entry")):
        if not isinstance(server, dict):
            continue
        if key:
            value, _, _ = scalar_value(server.get(key))
        else:
            # An unfamiliar kind: take whichever of the three names it happens to use rather
            # than recording no servers at all.
            value = next((scalar_value(server.get(k))[0]
                          for k in ("address", "ip-address", "host") if server.get(k)), "")
        out.append(value or str(server.get("@name") or ""))
    return [v for v in out if v]


def _fields(entry: dict[str, Any], kind: str, raw_kind: str) -> dict[str, Any]:
    def flag(key, field):
        value, _, _ = parse_yes_no_field(
                entry.get(key),
                implicit=Implicit.measured(
                    IMPLICIT[field],
                    "payload contract, aaa-server-profile $implicit_values: measured 2026-09-09 "
                    "on fw-core-tpa-b by writing the profile without the key and reading the "
                    "checkbox the UI renders"))
        return value

    servers = _servers(entry, kind)
    bind_dn, _, _ = scalar_value(entry.get("bind-dn"))
    ldap_type, _, _ = scalar_value(entry.get("ldap-type"))
    vendor, _, _ = scalar_value(entry.get("mfa-vendor-type"))
    saml_cert, _, _ = scalar_value(entry.get("certificate"))
    mfa_cert, _, _ = scalar_value(entry.get("mfa-cert-profile"))
    admin_only, _, _ = parse_yes_no_field(
            entry.get("admin-use-only"),
            implicit=Implicit.assumed(
                False,
                "not in the aaa-server-profile implicit block, which measured four other keys on "
                "this object; False reads an unmarked profile as available to every consumer, "
                "which is the broader and therefore safer reading for a referrer walk"))

    return {
        "kind": kind,
        "raw_kind": raw_kind if kind == ServerProfile.Kind.UNKNOWN else "",
        "admin_use_only": admin_only,
        "server_addresses": servers,
        "server_count": len(servers),
        "ldap_ssl": flag("ssl", "ldap_ssl"),
        "ldap_verify_server_certificate": flag(
            "verify-server-certificate", "ldap_verify_server_certificate"),
        "ldap_bind_dn": bind_dn[:255],
        "ldap_type": ldap_type[:32],
        "protocol": _protocol_of(entry)[:32],
        "saml_validate_idp_certificate": flag(
            "validate-idp-certificate", "saml_validate_idp_certificate"),
        "saml_want_auth_requests_signed": flag(
            "want-auth-requests-signed", "saml_want_auth_requests_signed"),
        "mfa_vendor_type": vendor[:64],
        "certificate_reference": (saml_cert or mfa_cert)[:64],
    }


def _kind_entries(snapshot: Snapshot, appliance: Appliance) -> list[tuple[ScopedEntry, str, str]]:
    """(scoped entry, kind, raw kind) for every profile of every kind, in every scope."""
    known = {k.value for k in ServerProfile.Kind if k != ServerProfile.Kind.UNKNOWN}
    out = []
    for scope, vsys_name, container in scoped_nodes(snapshot, "server-profile"):
        # `server-profile` holds six SIBLING CONTAINERS, one per kind, and the entries are one
        # level below those - which is why this reads nodes rather than entries.
        for raw_kind, node in (container or {}).items():
            if raw_kind.startswith("@") or not isinstance(node, dict):
                continue
            kind = raw_kind if raw_kind in known else ServerProfile.Kind.UNKNOWN
            if kind == ServerProfile.Kind.UNKNOWN:
                NormalizationIssue.objects.create(
                    management_station=appliance.management_station, appliance=appliance,
                    kind="server profile", name=raw_kind,
                    severity=NormalizationIssue.Severity.WARNING,
                    disposition=NormalizationIssue.Disposition.KEPT,
                    reason=f"unrecognised server-profile kind {raw_kind!r}; rows kept",
                    raw_entry={})
            for entry in ensure_list(node.get("entry")):
                if isinstance(entry, dict):
                    out.append((ScopedEntry(scope, vsys_name, entry), kind, raw_kind))
    return out


def normalize_server_profiles(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"server_profiles": 0}

    payload = snapshot.payload if isinstance(snapshot.payload, dict) else {}
    entries = _kind_entries(snapshot, appliance)

    # PAN-AAA-013 counts the same way PAN-AUTH-025 does, and for the same reason: an "unused"
    # claim is only as good as the list of hiding places, so walk everything. The scope
    # resolution is the shared helper, not a second copy of the rule.
    definitions = {(scoped.vsys_name, str(scoped.entry.get("@name") or ""))
                   for scoped, _, _ in entries if scoped.scope != "shared"}
    # TWO keys, because a server profile is named two ways. `server-profile` is the scalar leaf
    # every authentication method uses. `factors` is the MFA one - a member list under
    # `multi-factor-auth`, naming MFA server profiles - and it was missing, so the one MFA
    # profile on the lab reported unused while a profile was invoking it. Confirmed complete by
    # searching the merged payload for the 22 profile NAMES and finding no third shape.
    references = attribute_references(
        find_references(payload.get("config"), keys=("server-profile", "factors")), definitions)

    rows = []
    for scoped, kind, raw_kind in entries:
        fields = _fields(scoped.entry, kind, raw_kind)
        name = str(scoped.entry.get("@name") or "")
        vsys = scoped.vsys_name if scoped.scope != "shared" else ""
        where = sorted(set(references.get((vsys, name), [])))
        fields["referrer_paths"] = where
        fields["referrer_count"] = len(where)
        rows.append((scoped, fields))

    return {"server_profiles": write_scoped_objects(
        ServerProfile, appliance, snapshot, rows, extra_key="kind")}
