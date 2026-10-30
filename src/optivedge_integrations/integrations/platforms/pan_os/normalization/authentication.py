"""Authentication profiles - PAN-AUTH-018, 020 and 025, and PAN-AAA-007 to 011.

Reads every scope the object can occupy by reusing `scoped_entries`, which walks shared and
every vsys. Authentication profiles have no predefined namespace, so none is passed.

THREE SHAPES ON THIS OBJECT THAT A READER WRITTEN FROM ONE SCREEN GETS WRONG:

    a realm lives on TWO keys     `single-sign-on/realm` has a labelled control on the first
                                  tab; `method/kerberos/realm` has no vendor page at all
    an EMPTY allow list is not    an empty list admits NOBODY (Help p.839) and `all` admits
      the same as `all`           everyone, and both are "no named group"
    the SAML trust anchor is on   the IdP server profile's validation switch does nothing
      THIS object                 unless an authentication profile naming it also names a
                                  certificate profile - Help p.937
"""

from __future__ import annotations

from typing import Any

from optivedge_integrations.integrations.models import (
    Appliance, AuthenticationProfile)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ensure_list, parse_integer_field, parse_yes_no_field, scalar_value, parse_text_field)
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
    scoped_entries, write_scoped_objects)
# NOT normalization.snapshots, which has a function of the SAME NAME taking an
# EnforcementPoint. This one takes an Appliance. Importing the wrong one fails with
# "'Appliance' object has no attribute 'appliance'", which reads like a model problem.
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot)


#: A realm, a certificate profile and a signing certificate all store NULL when their key is
#: absent rather than a blank. Stage 4 held every one of these readings back - two are
#: `not_reached` because no subject carrying the key could be built on the estate, and the two
#: realms' positive controls were never paid - so nothing is assumed about what an absent key
#: means. `is_empty` compiles to `field=""` and matches a blank but NOT a null, so a blank here
#: would answer a question nobody settled, in whichever direction that clause happens to fall.
NOT_ASSUMED_REALM = Implicit.not_assumed(
    "stage4-auth-servers.json objects.authentication-profile.fields.single-sign-on/realm: the "
    "Kerberos Realm control renders EMPTY with the reader's is_hint flag TRUE on a committed "
    "profile carrying no single-sign-on branch, but the positive control was HELD BACK, so "
    "whether an absent key means no realm or an unread one was never settled. "
    "method/kerberos/realm is `not_reached` outright: no subject with a kerberos method branch "
    "existed when it was measured")
NOT_ASSUMED_SAML_REFERENCE = Implicit.not_assumed(
    "stage4-auth-servers.json objects.authentication-profile.fields."
    "method/saml-idp/certificate-profile and .../request-signing-certificate are both "
    "`not_reached`: no certificate profile existed on any appliance that run read, so no "
    "subject carrying either key could be built and an absence on a profile with no saml-idp "
    "branch asserts nothing about it")


def _branch(node: Any, *names: str) -> dict[str, Any]:
    """A nested container, or {} - so a reader never has to guard each level by hand."""
    for name in names:
        if not isinstance(node, dict):
            return {}
        node = node.get(name)
    return node if isinstance(node, dict) else {}


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
    domain, domain_rk, domain_rv = parse_text_field(
        entry.get("user-domain"),
        implicit=Implicit.not_assumed(
            "the authentication-profile contract node lists user-domain among its children and "
            "measures nothing about it - its `fields` map is empty. An absent key may mean no "
            "domain is prepended or may mean the device supplies one, and the three sibling "
            "fields on this object are already Implicit.assumed for the same reason"))
    modifier, mod_rk, mod_rv = parse_text_field(
        entry.get("username-modifier"),
        implicit=Implicit.not_assumed(
            "username-modifier is a DROPDOWN with a non-empty first entry, and the "
            "authentication-profile contract node measures nothing about an absent key. An empty "
            "string is a plausible-looking guess that would read as 'no modification' - the one "
            "answer a wrong guess must not fabricate, because the modifier decides what username "
            "is actually presented to the directory"))

    # PAN-AAA-007. TWO KEYS, and a reader that knows one misses every profile using the other.
    sso_realm, sso_rk, sso_rv = parse_text_field(
        _branch(entry, "single-sign-on").get("realm"), implicit=NOT_ASSUMED_REALM)
    method_realm, mrealm_rk, mrealm_rv = parse_text_field(
        _branch(entry, "method", "kerberos").get("realm"), implicit=NOT_ASSUMED_REALM)
    # PAN-AAA-008 and 009, both on the saml-idp METHOD BRANCH of this object.
    saml = _branch(entry, "method", "saml-idp")
    cert_profile, cert_rk, cert_rv = parse_text_field(
        saml.get("certificate-profile"), implicit=NOT_ASSUMED_SAML_REFERENCE)
    signing_cert, signing_rk, signing_rv = parse_text_field(
        saml.get("request-signing-certificate"), implicit=NOT_ASSUMED_SAML_REFERENCE)

    factors = [str(f) for f in ensure_list((mfa.get("factors") or {}).get("member"))
               if f is not None] if isinstance(mfa.get("factors"), dict) else []
    allow = [str(a) for a in ensure_list((entry.get("allow-list") or {}).get("member"))
             if a is not None] if isinstance(entry.get("allow-list"), dict) else []
    allow_is_all = any(a.strip().lower() == "all" for a in allow)
    # PAN-AAA-010's grading. The three states do not order, so this is a classification and not
    # a comparison - and EMPTY has to be placed explicitly rather than falling out of a
    # comparison, because an empty list is the state that admits nobody and `all` is the state
    # that admits everyone.
    allow_width = (AuthenticationProfile.AllowListWidth.ALL if allow_is_all
                   else AuthenticationProfile.AllowListWidth.EMPTY if not allow
                   else AuthenticationProfile.AllowListWidth.NAMED_GROUP)
    # PAN-AAA-007. The realm the device holds is compared against its OWN upper-cased form,
    # character for character, because every text operator in the field registry is
    # case-insensitive and no clause can tell EXAMPLE.COM from example.com.
    #
    # WHERE BOTH KEYS HOLD A REALM, BOTH HAVE TO BE UPPERCASE. Stage 5 says only "the realm
    # string this profile stores", which does not settle a profile carrying two - so this takes
    # the firing side: a lower-case realm on either key reports, because either can be the one
    # the firewall uses and the control is about the form a realm is stored in.
    realms = [r for r in (sso_realm.strip(), method_realm.strip()) if r]
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
        "allow_list_width": allow_width,
        # `parse_text_field` reads an absent key and an empty element alike as "". The device
        # refuses an empty element on all four of these keys, so the absent case is the only
        # one reachable and `or None` is exact rather than a convenience.
        "sso_realm": sso_realm or None,
        "kerberos_method_realm": method_realm or None,
        "kerberos_realm_configured": bool(realms),
        "kerberos_realm_is_uppercase": bool(realms) and all(r == r.upper() for r in realms),
        "saml_certificate_profile": cert_profile or None,
        "saml_request_signing_certificate": signing_cert or None,
    }
    provenance = [
        ("lockout_failed_attempts", failed_rk, failed_rv),
        ("lockout_time_minutes", lock_rk, lock_rv),
        ("mfa_enabled", mfa_rk, mfa_rv),
        ("user_domain", domain_rk, domain_rv),
        ("username_modifier", mod_rk, mod_rv),
        ("sso_realm", sso_rk, sso_rv),
        ("kerberos_method_realm", mrealm_rk, mrealm_rv),
        ("saml_certificate_profile", cert_rk, cert_rv),
        ("saml_request_signing_certificate", signing_rk, signing_rv),
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
        fields, provenance = _profile_fields(scoped.entry)
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
        # `_profile_fields` has always built this list and the caller has always dropped it,
        # so an AuthenticationProfile carried no field provenance at all - including for the
        # lockout pair, whose absence PAN-AUTH-018 reads as "no lockout configured".
        rows.append((scoped, fields, provenance))
    return {"authentication_profiles": write_scoped_objects(
        AuthenticationProfile, appliance, snapshot, rows)}
