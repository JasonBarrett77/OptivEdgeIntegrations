"""AAA server profiles - the auth-servers domain, PAN-AAA-001 through 013.

Reuses `scoped_entries` and `write_scoped_objects`, which walk shared and every vsys - all six
kinds are vsys-scopable, tested by completing a made-up ENTRY rather than the container.

The three shapes that would bite a normalizer written from one kind:

    the address key has THREE NAMES   `address` on ldap and tacplus, `ip-address` on radius,
                                      `host` on kerberos
    `protocol` has TWO WIRE FORMS     radius stores {"PAP": null}, tacplus stores "PAP"
    two of three implicit values      `ssl` and both SAML flags are implicit YES; only
      INVERT the obvious reading      `verify-server-certificate` is implicit NO
    a SECRET is per SERVER ENTRY      `server/entry/secret`, so a profile holds a LIST - of
                                      EQUALITY-GROUP IDS, never of secrets - and the column a
                                      control reads is a verdict over it
    SAML SIGNING SPANS TWO OBJECTS    the flag is here, the certificate it signs with is on the
                                      authentication profile

RUNS AFTER `normalize_authentication_profiles`, and that order is declared in
`flows.APPLIANCE_OBJECT_NORMALIZERS`. `message_signing_effective` is read from the
authentication profiles' own `method/saml-idp` branches in THIS payload rather than from their
rows, so the dependency is on the payload and not on the ordering - but the reader should know
which way round the two run.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from optivedge_integrations.integrations.models import (
    Appliance, NormalizationIssue, SecretFingerprintKey, ServerProfile, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication import (
    attribute_references, find_references)
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
    ScopedEntry, scoped_entries, scoped_nodes, write_scoped_objects)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ensure_list, parse_text_field, parse_yes_no_field, scalar_value)
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
#: THE STORED FORM OF A SHARED SECRET, and how long it is for a given plaintext.
#:
#: The form is `-AQ==` + base64(unsalted SHA-1 of the plaintext) + base64(ciphertext) - 33
#: characters before the ciphertext - verified by RECOMPUTATION on a 31-character plaintext
#: whose stored form is 77 characters and whose characters 6..33 are exactly
#: base64(sha1(plaintext)).
#:
#: THE LENGTH BAND IS MEASURED AT THE BOUNDARY AND NOT INFERRED. Stage 6 left five committed
#: RADIUS profiles on pan-fw-111 (PA-VM 11.2.3) whose plaintext lengths it recorded, and this
#: run read their stored forms back off the device on 2026-10-29:
#:
#:     plaintext  8 chars (oep-aaa6-s10) -> stored 57     15 chars (oep-aaa6-s26) -> stored 57
#:     plaintext 16 chars (oep-aaa6-s27) -> stored 77     20 chars (oep-aaa6-s05) -> stored 77
#:
#: So the ciphertext is padded to 16-byte blocks and ONE BLOCK stores as 57 characters: a
#: stored form of 57 characters or fewer is a plaintext of fifteen characters or fewer, which is
#: the band PAN-AAA-005's severity grading places as `below_sixteen_characters`. The step was
#: declared UNMEASURABLE by stage 5, which had one length pair and could not establish a step
#: from it; the boundary pair is what settles it.
SECRET_STORED_LENGTH_FOR_ONE_BLOCK = 57

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


def _secret_forms(entry: dict[str, Any]) -> list[str]:
    """The stored form of each server entry's secret, in the entries' own order.

    PRIVATE AND NEVER RETURNED TO A ROW. Its two callers take a LENGTH and an equality-group id
    from it and drop it; `ServerProfile.secret_digests` holds the ids. Jason's standing ruling is
    that a shared secret's value is never stored - `ike.py::IkeGateway` and
    `device_services.py::SnmpSettings` are the shipped precedents - and the stored form IS the
    value for every purpose that matters: it is deterministic for one plaintext, so it is a
    credential equivalent in a backup and in any report a row reaches.

    A server entry carrying NO secret contributes NOTHING rather than an empty string: stage 4
    never read an absent `secret` - the key was written on both of its subjects - so whether a
    server entry commits without one was not isolated, and a "" here would read as a zero-length
    secret, which is the firing side of a reading nobody took.

    Read through `scalar_value` and not off the string, because a template-pushed secret arrives
    as a dict carrying `@ptpl` beside its `#text` - the shape a pushed `bind-password` on this
    lab's template-contributed LDAP profile has.
    """
    node = entry.get("server")
    if not isinstance(node, dict):
        return []
    out = []
    for server in ensure_list(node.get("entry")):
        if not isinstance(server, dict):
            continue
        text, _, _ = scalar_value(server.get("secret"))
        if text:
            out.append(text)
    return out


def _equality_group(stored_form: str, key: bytes) -> str:
    """An id two identical secrets share and nothing else does, computed with the station key.

    KEYED, NOT HASHED. The stored form's first 33 characters are `-AQ==` plus base64 of an
    UNSALTED SHA-1 of the plaintext, so a bare digest of it is brute-forceable from a word list
    with no device key involved. The key comes from `SecretFingerprintKey`, which is one random
    value per management station - the same one for every appliance it owns, because two
    appliances holding one secret have to compare equal, which is the whole reading PAN-AAA-005
    rests on.

    Truncated to 32 hex characters: 128 bits is far past any collision this estate can produce,
    and a fixed width is what `ServerProfile.clean()` checks to refuse a stored form.
    """
    return hmac.new(key, stored_form.encode("utf-8"), hashlib.sha256).hexdigest()[
        :ServerProfile.EQUALITY_GROUP_HEX_LENGTH]


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


def _fields(entry: dict[str, Any], kind: str, raw_kind: str,
            secret_key: bytes) -> tuple[dict[str, Any], list[tuple]]:
    """(values, provenance triples). The four flags below are the reason this returns both:
    each defaults to a MEASURED vendor value when its key is absent, and two of them default the
    opposite way to what the checkbox suggests - so which profiles were never configured is not
    something a reader can infer from the value."""
    provenance: list[tuple] = []

    def flag(key, field):
        value, rk, rv = parse_yes_no_field(
                entry.get(key),
                implicit=Implicit.measured(
                    IMPLICIT[field],
                    "payload contract, aaa-server-profile $implicit_values: measured 2026-09-09 "
                    "on fw-core-tpa-b by writing the profile without the key and reading the "
                    "checkbox the UI renders"))
        provenance.append((field, rk, rv))
        return value

    servers = _servers(entry, kind)
    # RADIUS ONLY, AND THE READBACK IS WHY. `server/entry/secret` exists on the tacplus kind
    # too and stores the BYTE-IDENTICAL form for the same plaintext - stage 4 measured that and
    # this run read it back off three committed TACACS+ profiles on pan-fw-111. But PAN-AAA-005
    # is a RADIUS assertion and stage 5 declares all three secret columns on the
    # radius-server-profile subject alone, so a tacplus row that carried digests and a shortest
    # length would carry NO verdict beside them - a reader meeting the pair would see a secret
    # recorded and no finding about it, which is worse than not recording it. If the assertion
    # is ever widened to TACACS+, this line and `recompute_secret_weakness`'s filter are the
    # whole change.
    # THE LENGTH IS TAKEN BEFORE THE ID, which is the only order that works: the id is fixed
    # width, so a length read off the column afterwards would measure the id. The forms
    # themselves go no further than these two lines.
    forms = _secret_forms(entry) if kind == ServerProfile.Kind.RADIUS else []
    shortest = min((len(form) for form in forms), default=0)
    digests = [_equality_group(form, secret_key) for form in forms]
    # Text keys whose ABSENCE a reader has to be able to see: an unbound certificate profile on
    # an MFA server profile is what PAN-AUTH-020's prerequisite turned on.
    unbound = Implicit.measured(
        None,
        "aaa-server-profile: an absent reference key binds nothing - the same reading the "
        "contract records for ssl-tls-service-profile.certificate")
    bind_dn, bind_rk, bind_rv = parse_text_field(entry.get("bind-dn"), implicit=unbound)
    ldap_type, type_rk, type_rv = parse_text_field(entry.get("ldap-type"), implicit=unbound)
    vendor, vendor_rk, vendor_rv = parse_text_field(
        entry.get("mfa-vendor-type"), implicit=unbound)
    saml_cert, saml_rk, saml_rv = parse_text_field(entry.get("certificate"), implicit=unbound)
    mfa_cert, mfa_rk, mfa_rv = parse_text_field(
        entry.get("mfa-cert-profile"), implicit=unbound)
    admin_only, admin_rk, admin_rv = parse_yes_no_field(
            entry.get("admin-use-only"),
            implicit=Implicit.assumed(
                False,
                "not in the aaa-server-profile implicit block, which measured four other keys on "
                "this object; False reads an unmarked profile as available to every consumer, "
                "which is the broader and therefore safer reading for a referrer walk"))

    provenance.extend([
        ("admin_use_only", admin_rk, admin_rv),
        ("ldap_bind_dn", bind_rk, bind_rv),
        ("ldap_type", type_rk, type_rv),
        ("mfa_vendor_type", vendor_rk, vendor_rv),
        # One column fed by whichever of the two reference keys the profile carries, so the row
        # names the one that answered - or, absent both, that nothing is bound.
        ("certificate_reference", saml_rk if saml_cert else mfa_rk,
         saml_rv if saml_cert else mfa_rv),
    ])

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
        "secret_digests": digests,
        # The minimum over the server entries nested inside one profile. A clause has no
        # aggregate and no quantifier over a nested list, so it is a column. 0 for a profile
        # with no secret, which is every kind but radius and tacplus - `secret_weakness` is
        # blank on those rows, and that is what keeps the 0 from reading as a short secret.
        "secret_shortest_stored_length": shortest,
    }, provenance


def _saml_signing_certificates(snapshot: Snapshot, definitions: set) -> dict:
    """{(vsys, IdP profile name): [signing certificate, ...]} - one entry per authentication
    profile whose `method/saml-idp/server-profile` names that profile.

    PAN-AAA-009 spans two objects: the IdP profile holds `want-auth-requests-signed` and the
    authentication profile holds the certificate the firewall signs WITH. Help p.939 - the
    firewall signs "using the Certificate for Signing Requests that you specify in an
    authentication profile" - so the flag on with no certificate named is a request to sign
    with nothing, and a reader of the flag alone calls that compliant.

    `attribute_references` is reused rather than re-deriving the resolution rule: it puts each
    reference on the definition it resolves to - the referrer's own vsys when that vsys defines
    the name, and shared otherwise. Its third element is whatever the caller wants carried, and
    here that is the SIGNING CERTIFICATE rather than a path; the grouping is the part being
    reused, and a second copy of the vsys-then-shared rule is the thing most likely to drift.
    """
    carried = []
    for scoped in scoped_entries(snapshot, "authentication-profile"):
        method = scoped.entry.get("method")
        saml = method.get("saml-idp") if isinstance(method, dict) else None
        if not isinstance(saml, dict):
            continue
        target, _, _ = scalar_value(saml.get("server-profile"))
        if not target:
            continue
        certificate, _, _ = scalar_value(saml.get("request-signing-certificate"))
        vsys = scoped.vsys_name if scoped.scope != "shared" else ""
        carried.append((vsys, target, certificate))
    return attribute_references(carried, definitions)


def recompute_secret_weakness(management_station) -> int:
    """PAN-AAA-005's verdict, over EVERY appliance of one station. Returns the rows changed.

    WHY IT IS NOT IN THE PER-APPLIANCE PASS. `reused_across_appliances` is a comparison between
    two rows on DIFFERENT appliances: a clause has no second field slot and no cross-row
    quantifier, and one appliance's rows cannot answer it either. So this runs at the end of
    every appliance's pass and re-derives the verdict for the whole station from the digests
    already stored. The last appliance of a run leaves every row consistent whatever order the
    appliances were normalized in - an asymmetric answer that depends on which appliance was
    first is the failure this shape avoids.

    It touches ONE COLUMN through `bulk_update` and writes no provenance row, so it is not a
    second writer of this model in the sense `write_scoped_objects` forbids: no row is created,
    none is deleted, and nothing else on the row is read back or rewritten.

    IT COMPARES EQUALITY-GROUP IDS AND NEVER A SECRET. `secret_digests` holds one keyed id per
    server entry and the key is the station's, so two ids are equal exactly when the secrets are
    - which is the only thing this verdict needs and the only thing the column carries.

    REUSE IS COUNTED ACROSS APPLIANCES AND NOT WITHIN ONE, which is stage 3's assertion as
    stage 5 carried it. A TEMPLATE-PUSHED SECRET LANDS ON EVERY FIREWALL THE TEMPLATE REACHES
    and is reported here as reuse; `reference/panos-payload-contract.json` records Jason's
    ruling of 2026-09-11 that it is not. The entry's own `@ptpl` marker is what would tell them
    apart and this does not read it - see the stage 7 artifact's `spec_gaps`.
    """
    rows = list(ServerProfile.objects.filter(
        management_station=management_station, kind=ServerProfile.Kind.RADIUS))
    appliances_by_digest: dict[str, set] = {}
    for row in rows:
        for digest in row.secret_digests or []:
            appliances_by_digest.setdefault(str(digest), set()).add(row.appliance_id)

    changed = []
    for row in rows:
        digests = [str(d) for d in (row.secret_digests or [])]
        if not digests:
            # No secret was read, so there is no verdict. Blank matches no placement, which
            # leaves PAN-AAA-005's baseline severity rather than inventing a band.
            verdict = ""
        elif any(len(appliances_by_digest.get(d, ())) > 1 for d in digests):
            verdict = ServerProfile.SecretWeakness.REUSED_ACROSS_APPLIANCES
        elif row.secret_shortest_stored_length <= SECRET_STORED_LENGTH_FOR_ONE_BLOCK:
            verdict = ServerProfile.SecretWeakness.BELOW_SIXTEEN_CHARACTERS
        else:
            verdict = ServerProfile.SecretWeakness.MEETS_FLOOR
        if row.secret_weakness != verdict:
            row.secret_weakness = verdict
            changed.append(row)
    if changed:
        ServerProfile.objects.bulk_update(changed, ["secret_weakness"])
    return len(changed)


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
    signing = _saml_signing_certificates(snapshot, definitions)

    rows = []
    # One key per station, generated on first use, the same for every appliance it owns.
    secret_key = SecretFingerprintKey.key_for(appliance.management_station)
    for scoped, kind, raw_kind in entries:
        fields, provenance = _fields(scoped.entry, kind, raw_kind, secret_key)
        name = str(scoped.entry.get("@name") or "")
        vsys = scoped.vsys_name if scoped.scope != "shared" else ""
        where = sorted(set(references.get((vsys, name), [])))
        fields["referrer_paths"] = where
        fields["referrer_count"] = len(where)
        # PAN-AAA-009: the flag AND a certificate named on every authentication profile that
        # reaches this IdP profile. FALSE WHERE NOTHING REACHES IT - no message is sent, so none
        # is signed, and an unreferenced profile reporting "signing is effective" is the
        # reassuring side of a state the firewall cannot be in. Only a saml-idp profile is ever
        # named through that branch, so every other kind holds the column's False.
        certificates = signing.get((vsys, name), [])
        fields["message_signing_effective"] = bool(
            fields["saml_want_auth_requests_signed"] and certificates
            and all(certificate for certificate in certificates))
        rows.append((scoped, fields, provenance))

    written = write_scoped_objects(
        ServerProfile, appliance, snapshot, rows, extra_key="kind")
    # AFTER the rows are written, because it reads the digests they carry. Station-wide: see
    # the function.
    verdicts = recompute_secret_weakness(appliance.management_station)
    return {"server_profiles": written, "server_profile_secret_verdicts": verdicts}
