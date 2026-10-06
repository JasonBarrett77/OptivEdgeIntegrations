"""The management SSH server's configured offer - PAN-MCR-001 to 005.

Reads `deviceconfig/system/ssh`: the `mgmt/server-profile` binding, and the bound entry under
`profiles/mgmt-profiles/server-profiles`. Each algorithm list is the profile's when it sets one
and the device's measured DEFAULT OFFER when it does not - see the model docstring for the three
measurements behind that rule.
"""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, FieldProvenance, ManagementSshSettings)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    Implicit,
    parse_text_field, classify_prov_type, provenance_raw_key, provenance_value, ensure_list, iter_member_values, scalar_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot, latest_merged_snapshot)

#: What the management SSH server offers with nothing bound, read from its KEXINIT proposal.
#: Keyed by release. MEASURED 2026-09-11 on two PA-5220s, 11.1.13-h3, server OpenSSH_8.0. Names
#: are the wire names, which is why the MACs carry `@openssh.com` and the profile's do not.
DEFAULT_OFFER = {
    "11.1": {
        "ciphers": ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
                    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"],
        "kex": ["curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
                "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256",
                "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256",
                "diffie-hellman-group14-sha1"],
        "macs": ["umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
                 "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
                 "hmac-sha1-etm@openssh.com", "umac-64@openssh.com", "umac-128@openssh.com",
                 "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"],
    },
}
#: MEASURED 2026-09-11 on pan-fw-111, a PA-VM on 11.2.3, same server build: IDENTICAL to 11.1 on
#: every list. Two releases and two platforms, one offer.
DEFAULT_OFFER["11.2"] = DEFAULT_OFFER["11.1"]
#: Stands in for a release nobody has measured; `defaults_measured` says it did.
FALLBACK_RELEASE = "11.1"
#: Below PAN-MCR-002's corpus minimum. RFC 9142: group1 is "too weak to be retained" and
#: group-exchange-sha1 "SHOULD NOT be used".
WEAK_KEX = frozenset({"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"})
#: The corpus minimum for PAN-MCR-003 restricts session integrity to SHA-2. No control asserts
#: this any more; it colours the finding sentence. See the model for why it was kept.
STRONG_MACS = frozenset({"hmac-sha2-256", "hmac-sha2-512",
                         "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"})

#: WHAT PAN-MCR-001, 002 and 003 ASSERT, since 2026-09-14: the corpus PREFERRED value, with the
#: set that value's description explicitly allows alongside it. Two of the three ADD a
#: compatibility algorithm to the preferred one and one names ALTERNATES to it - see the model
#: for the wording. Where PREFERRED holds a single name, a list lacking it fires even when
#: everything in the list is allowed; where it holds several, any one of them satisfies it.
#:
#: Compared on the BARE name: the device's wire names carry `@openssh.com` or `@libssh.org` and
#: a profile's do not, and `aes256-gcm@openssh.com` is `aes256-gcm`.
PREFERRED_CIPHERS = frozenset({"aes256-gcm"})
ALLOWED_CIPHERS = PREFERRED_CIPHERS | {"aes256-ctr"}
PREFERRED_KEX = frozenset({"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
                           "curve25519-sha256"})
ALLOWED_KEX = PREFERRED_KEX
PREFERRED_MACS = frozenset({"hmac-sha2-512", "hmac-sha2-512-etm"})
ALLOWED_MACS = PREFERRED_MACS | {"hmac-sha2-256", "hmac-sha2-256-etm"}


def _bare(algorithm: str) -> str:
    """`aes256-gcm@openssh.com` -> `aes256-gcm`; the suffix names a source, not an algorithm."""
    return str(algorithm).split("@", 1)[0]


def _preferred_state(offer: list[str], preferred: frozenset[str],
                     allowed: frozenset[str]) -> tuple[bool, list[str]]:
    """(the control fires, the offered members outside `allowed`).

    Either fault fires it: something outside the allowed set is offered, or nothing from the
    preferred set is. The list is empty in the second case, which is how the finding tells
    "remove this" apart from "add that".
    """
    beyond = [a for a in offer if _bare(a) not in allowed]
    return bool(beyond) or not any(_bare(a) in preferred for a in offer), beyond


def _release(appliance: Appliance) -> str:
    parts = (appliance.software_version or "").split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else ""


def _members(node: Any) -> list[str]:
    members = node.get("member") if isinstance(node, dict) else None
    return [str(v).strip() for v, _prov in iter_member_values(members) if str(v).strip()]


def _host_key(profile: dict[str, Any]) -> tuple[str, int, Any, str | None]:
    """(type, bits, raw_key, raw_value) from `default-hostkey/key-type`, a nested choice.

    RSA 2048 when unset, and the provenance for that case is deliberately ABSENT rather than a
    declared default. `discovery-log.md`, 2026-09-14: writing `<all/>` GENERATES ECDSA keys and
    deleting the setting does not withdraw them, so "on a device that has ever been set to
    `all`, an absent default-hostkey no longer means RSA 2048 only". Recording
    `pan_os_default` would state a vendor fact that is measured FALSE on such a device, and
    `assumed_default` would still carry a value the device may not be serving. Until that is
    settled the stored value stays as it is and no row is written, so nothing claims to know
    where it came from.

    A value that IS configured carries its marker, which is pure gain: it says which template
    or stack to change, and makes no claim about absence.
    """
    key_type = (profile.get("default-hostkey") or {}).get("key-type")
    if isinstance(key_type, dict):
        for kind in ("ECDSA", "RSA", "all"):
            if kind in key_type:
                bits, raw_key, raw_value = scalar_value(key_type[kind])
                return (kind, int(bits) if str(bits).isdigit() else 0, raw_key, raw_value)
    return "", None, Implicit.not_assumed(
        "Help p.904 gives the default as RSA 2048, and 2026-09-14 measured that false on a "
        "device ever set to `all`: the ECDSA keys it generated are still served after the "
        "setting is deleted. Only the live SSH offer can say what is presented."), None


def _int(node: Any) -> int:
    text, _, _ = scalar_value(node)
    return int(text) if str(text).isdigit() else 0


def _int_with_provenance(node: Any) -> tuple[int, Any, str | None]:
    """`_int`, keeping the marker. ABSENT when the key is not there: the rekey defaults are
    unmeasured, and 0 is this module's own stand-in rather than a vendor fact."""
    text, raw_key, raw_value = scalar_value(node)
    return (int(text) if str(text).isdigit() else 0), raw_key, raw_value


def normalize_management_ssh(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"management_ssh_settings": 0}
    entry = device_entry_from_snapshot(snapshot)
    system = ((entry.get("deviceconfig") or {}).get("system") or {}) if isinstance(entry, dict) else {}
    ssh = system.get("ssh") if isinstance(system.get("ssh"), dict) else {}
    name, name_rk, name_rv = parse_text_field(
        (ssh.get("mgmt") or {}).get("server-profile"),
        implicit=Implicit.measured(
            None,
            "deviceconfig/system/ssh/mgmt/server-profile holds a NAME; with no key bound the "
            "device serves its release's built-in offer - which is what `ciphers_default` and "
            "the DEFAULT_OFFER table in this module record"))

    profiles = (((ssh.get("profiles") or {}).get("mgmt-profiles") or {})
                .get("server-profiles") or {}).get("entry")
    profile = next((p for p in ensure_list(profiles)
                    if isinstance(p, dict) and str(p.get("@name") or "") == name), None) if name else None

    release = _release(appliance)
    defaults = DEFAULT_OFFER.get(release) or DEFAULT_OFFER[FALLBACK_RELEASE]
    offer, from_default = {}, {}
    for key, leaf in (("ciphers", "ciphers"), ("kex", "kex"), ("macs", "mac")):
        configured = _members(profile.get(leaf)) if profile else []
        offer[key] = configured or list(defaults[key])
        from_default[key] = not configured

    key_type, key_bits, hostkey_rk, hostkey_rv = (
        _host_key(profile) if profile else _host_key({}))
    rekey = (profile or {}).get("session-rekey") or {}
    rekey_seconds, rekey_rk, rekey_rv = _int_with_provenance(rekey.get("interval"))
    weak = [m for m in offer["macs"] if m not in STRONG_MACS]
    ciphers_below, beyond_ciphers = _preferred_state(
        offer["ciphers"], PREFERRED_CIPHERS, ALLOWED_CIPHERS)
    kex_below, beyond_kex = _preferred_state(offer["kex"], PREFERRED_KEX, ALLOWED_KEX)
    macs_below, beyond_macs = _preferred_state(offer["macs"], PREFERRED_MACS, ALLOWED_MACS)

    content_type = ContentType.objects.get_for_model(ManagementSshSettings)
    with transaction.atomic():
        row, _ = ManagementSshSettings.objects.update_or_create(
            appliance=appliance,
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": snapshot,
                "profile_name": name[:64],
                "profile_found": profile is not None,
                "ciphers": offer["ciphers"],
                "kex": offer["kex"],
                "macs": offer["macs"],
                "ciphers_default": from_default["ciphers"],
                "kex_default": from_default["kex"],
                "macs_default": from_default["macs"],
                "defaults_measured": release in DEFAULT_OFFER,
                "ciphers_below_preferred": ciphers_below,
                "non_preferred_ciphers": beyond_ciphers,
                "kex_below_preferred": kex_below,
                "non_preferred_kex": beyond_kex,
                "macs_below_preferred": macs_below,
                "non_preferred_macs": beyond_macs,
                "offers_cbc_cipher": any(c.endswith("-cbc") for c in offer["ciphers"]),
                "offers_weak_mac": bool(weak),
                "weak_macs": weak,
                "offers_sha1_kex": any(k.endswith("-sha1") for k in offer["kex"]),
                "offers_weak_kex": any(k in WEAK_KEX for k in offer["kex"]),
                "offers_sha2_256_mac": any(m in ("hmac-sha2-256", "hmac-sha2-256-etm@openssh.com")
                                           for m in offer["macs"]),
                "host_key_type": key_type,
                "host_key_bits": key_bits,
                "rekey_interval_seconds": rekey_seconds,
                "rekey_data_mb": _int(rekey.get("data")),
                "rekey_packets_exponent": _int(rekey.get("packets")),
            },
        )
        # This module worked out the same distinction before FieldProvenance could hold it:
        # `ciphers_default` says the list came from the release's built-in offer rather than
        # from a profile, and `defaults_measured` says whether that offer was measured on this
        # release or fell back to another one. Those are exactly `pan_os_default` and
        # `assumed_default`, so the three lists say it the way every other field does and a
        # reader does not need to know this object has its own vocabulary.
        list_rows = []
        for field in ("ciphers", "kex", "macs"):
            if not from_default[field]:
                # Configured in the profile: the binding's own provenance is the honest source,
                # since the list was read out of the profile that name resolved to.
                list_rows.append((field, name_rk if profile is not None else ABSENT, name_rv))
            elif release in DEFAULT_OFFER:
                list_rows.append((field, Implicit.measured(
                    ", ".join(defaults[field])[:120],
                    f"DEFAULT_OFFER in this module: the {release} built-in offer, measured by "
                    f"negotiating with the device"), None))
            else:
                list_rows.append((field, Implicit.assumed(
                    ", ".join(defaults[field])[:120],
                    f"no measured offer for release {release!r}; falling back to "
                    f"{FALLBACK_RELEASE}'s, which is what `defaults_measured` records as false"),
                    None))

        FieldProvenance.objects.filter(content_type=content_type, object_id=row.pk).delete()
        entries = [
            ("profile_name", name_rk, name_rv),
            # Configured host key and rekey interval carry their marker, so a control firing on
            # them can say which template or stack to change. ABSENT where the key is not
            # there - see `_host_key` for why neither default is declared.
            ("host_key_type", hostkey_rk, hostkey_rv),
            ("host_key_bits", hostkey_rk, hostkey_rv),
            ("rekey_interval_seconds", rekey_rk, rekey_rv),
            *list_rows,
        ]
        FieldProvenance.objects.bulk_create([
            FieldProvenance(
                content_type=content_type, object_id=row.pk, field_name=field_name,
                provenance_type=classify_prov_type(rk),
                raw_key=provenance_raw_key(rk), raw_value=provenance_value(rk, rv)[:128])
            for field_name, rk, rv in entries if rk is not ABSENT])
    return {"management_ssh_settings": 1}
