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
    ABSENT, classify_prov_type, provenance_raw_key, provenance_value, ensure_list, iter_member_values, scalar_value)
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


def _host_key(profile: dict[str, Any]) -> tuple[str, int]:
    """(type, bits) from `default-hostkey/key-type`, a nested choice - RSA 2048 when unset."""
    key_type = (profile.get("default-hostkey") or {}).get("key-type")
    if isinstance(key_type, dict):
        for kind in ("ECDSA", "RSA", "all"):
            if kind in key_type:
                bits, _, _ = scalar_value(key_type[kind])
                return kind, int(bits) if str(bits).isdigit() else 0
    return "RSA", 2048


def _int(node: Any) -> int:
    text, _, _ = scalar_value(node)
    return int(text) if str(text).isdigit() else 0


def normalize_management_ssh(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"management_ssh_settings": 0}
    entry = device_entry_from_snapshot(snapshot)
    system = ((entry.get("deviceconfig") or {}).get("system") or {}) if isinstance(entry, dict) else {}
    ssh = system.get("ssh") if isinstance(system.get("ssh"), dict) else {}
    name, name_rk, name_rv = scalar_value((ssh.get("mgmt") or {}).get("server-profile"))

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

    key_type, key_bits = _host_key(profile) if profile else ("RSA", 2048)
    rekey = (profile or {}).get("session-rekey") or {}
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
                "rekey_interval_seconds": _int(rekey.get("interval")),
                "rekey_data_mb": _int(rekey.get("data")),
                "rekey_packets_exponent": _int(rekey.get("packets")),
            },
        )
        # Only the BINDING has provenance; the lists are the profile's, or the device's.
        FieldProvenance.objects.filter(content_type=content_type, object_id=row.pk).delete()
        if name_rk is not ABSENT:
            FieldProvenance.objects.create(
                content_type=content_type, object_id=row.pk, field_name="profile_name",
                provenance_type=classify_prov_type(name_rk),
                raw_key=provenance_raw_key(name_rk), raw_value=provenance_value(name_rk, name_rv))
    return {"management_ssh_settings": 1}
