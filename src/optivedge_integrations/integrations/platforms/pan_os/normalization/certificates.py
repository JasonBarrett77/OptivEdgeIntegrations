"""Normalize SSL/TLS service profiles and certificate profiles as OBJECTS.

Both types are read from every scope they can occupy - shared, each vsys, and (for SSL/TLS
profiles) predefined - because PAN-CRT-004 and PAN-CRT-005 ask about every profile on the
device rather than the one some surface has bound.

The predefined scope needs its own snapshot: `show config merged` does not carry
/config/predefined, measured 2026-09-02. Its absence is treated as "not collected" rather
than "none exist", which are different facts and only one of them is a finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from optivedge_integrations.integrations.models import (
    Appliance,
    Certificate,
    CertificateProfile,
    FieldProvenance,
    Snapshot,
    SslTlsServiceProfile,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    classify_prov_type,
    ensure_list,
    entry_provenance,
    parse_integer_field,
    parse_yes_no_field,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
    latest_predefined_certificate_snapshot,
    latest_predefined_ssl_tls_snapshot,
)

#: The thirteen algorithm keys the SSL/TLS profile dialog exposes. Measured 2026-09-02 by
#: `action=complete`, identical on a PA-5220 and a PA-VM.
#:
#: `enc-algo-camellia128`, `enc-algo-camellia256` and `enc-algo-seed` are in the schema and
#: have NO control on that dialog, so their implicit value was never established. They are
#: deliberately NOT expanded below: writing a value for a key whose default is unknown would
#: manufacture a fact. They appear in `explicit_algorithms` when the config sets them and are
#: otherwise simply absent.
ALGORITHM_KEYS = (
    "keyxchg-algo-rsa", "keyxchg-algo-dhe", "keyxchg-algo-ecdhe",
    "enc-algo-aes-128-cbc", "enc-algo-aes-128-gcm",
    "enc-algo-aes-256-cbc", "enc-algo-aes-256-gcm",
    "enc-algo-aes-chacha20-poly1305",
    "auth-algo-sha1", "auth-algo-sha256", "auth-algo-sha384",
)
UNMEASURED_ALGORITHM_KEYS = ("enc-algo-camellia128", "enc-algo-camellia256", "enc-algo-seed")

def decode_certificate(pem: str) -> dict[str, Any]:
    """Key algorithm, key size and signature algorithm - none of which PAN-OS exposes.

    They exist only inside the X.509 blob stored under `public-key`, which despite its name
    holds the whole certificate. Decoding is the only way to answer PAN-CRT-002 and
    PAN-CRT-003.

    A failure is RECORDED, not raised. One unreadable certificate must not stop the other
    fifty from normalizing, and a control seeing a blank algorithm with a parse_error reports
    it - an unreadable certificate is not a compliant one.
    """
    if not pem or not pem.strip():
        return {"parse_error": "no certificate data"}
    try:
        certificate = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - any decode failure is the same outcome here
        return {"parse_error": f"{type(exc).__name__}: {exc}"[:255]}

    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        algorithm, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        # The curve name travels with the size, because 256-bit EC and 256-bit RSA are not
        # comparable and a reader seeing "256" alone would draw the wrong conclusion.
        algorithm, bits = f"EC ({key.curve.name})", key.curve.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        algorithm, bits = "DSA", key.key_size
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        # Fixed-strength curves with no size parameter. Left as None rather than invented.
        algorithm, bits = type(key).__name__.replace("PublicKey", ""), None
    else:
        algorithm, bits = type(key).__name__.replace("PublicKey", ""), None

    try:
        signature = certificate.signature_algorithm_oid._name
    except AttributeError:
        signature = ""

    return {
        "key_algorithm": algorithm,
        "key_size_bits": bits,
        "signature_algorithm": signature,
        "not_valid_before": certificate.not_valid_before_utc,
        "not_valid_after": certificate.not_valid_after_utc,
        "parse_error": "",
    }


CERTIFICATE_PROFILE_BOOLEANS = (
    ("use_crl", "use-crl"),
    ("use_ocsp", "use-ocsp"),
    ("block_expired_cert", "block-expired-cert"),
    ("block_unknown_cert", "block-unknown-cert"),
    ("block_timeout_cert", "block-timeout-cert"),
    ("block_unauthenticated_cert", "block-unauthenticated-cert"),
)
CERTIFICATE_PROFILE_TIMEOUTS = (
    ("crl_receive_timeout", "crl-receive-timeout", 5),
    ("ocsp_receive_timeout", "ocsp-receive-timeout", 5),
    ("cert_status_timeout", "cert-status-timeout", 5),
)


@dataclass(slots=True)
class ScopedEntry:
    scope: str
    vsys_name: str
    entry: dict[str, Any]


def _entries(node: Any) -> list[dict[str, Any]]:
    if not isinstance(node, dict):
        return []
    return [e for e in ensure_list(node.get("entry")) if isinstance(e, dict) and e.get("@name")]


def scoped_entries(snapshot: Snapshot, object_key: str,
                   predefined: Snapshot | None = None) -> list[ScopedEntry]:
    """Every definition of `object_key`, from every scope it can occupy.

    Object-type agnostic, as are `ScopedEntry` and `write_scoped_objects` below. They live in a
    certificate-named module because certificates needed them first; authentication profiles
    import them from here. Worth moving to their own module the next time this file is opened
    for another reason - not worth a risky move on its own.
    """
    found: list[ScopedEntry] = []
    payload = snapshot.payload or {}
    config = payload.get("config") if isinstance(payload, dict) else None
    if isinstance(config, dict):
        shared = config.get("shared")
        if isinstance(shared, dict):
            found += [ScopedEntry(CertificateProfile.SCOPE_SHARED, "", e)
                      for e in _entries(shared.get(object_key))]

    # Every vsys, not just vsys1. A multi-vsys device can define an object in one vsys and not
    # another, and that difference is the whole point of recording the scope.
    device_entry = device_entry_from_snapshot(snapshot)
    vsys_node = device_entry.get("vsys") if isinstance(device_entry, dict) else None
    for vsys in ensure_list((vsys_node or {}).get("entry")) if isinstance(vsys_node, dict) else []:
        if not isinstance(vsys, dict):
            continue
        name = str(vsys.get("@name") or "").strip()
        if not name:
            continue
        found += [ScopedEntry(CertificateProfile.SCOPE_VSYS, name, e)
                  for e in _entries(vsys.get(object_key))]

    if predefined is not None:
        pre = predefined.payload or {}
        if isinstance(pre, dict):
            found += [ScopedEntry(CertificateProfile.SCOPE_PREDEFINED, "", e)
                      for e in _entries(pre.get(object_key))]
    return found


def _algorithms(protocol_settings: dict[str, Any]) -> tuple[dict[str, bool], list[str]]:
    """Effective algorithm settings, and which keys the configuration actually wrote.

    ABSENT MEANS ENABLED - measured 2026-09-02 from a profile that writes a version range and
    no algorithm key, whose every checkbox renders ticked. So an omitted key is expanded to
    True rather than dropped, or the most permissive profile on the device would look like the
    most restrictive one.
    """
    effective: dict[str, bool] = {}
    explicit: list[str] = []
    for key in ALGORITHM_KEYS:
        raw = protocol_settings.get(key, ABSENT)
        if raw is ABSENT:
            effective[key] = True
            continue
        explicit.append(key)
        value, _, _ = parse_yes_no_field(raw, default_effective=True)
        effective[key] = value
    for key in UNMEASURED_ALGORITHM_KEYS:
        if protocol_settings.get(key, ABSENT) is not ABSENT:
            explicit.append(key)
            value, _, _ = parse_yes_no_field(protocol_settings.get(key), default_effective=True)
            effective[key] = value
    return effective, sorted(explicit)


def write_scoped_objects(model, appliance: Appliance, snapshot: Snapshot,
           rows: list[tuple[ScopedEntry, dict[str, Any]]]):
    content_type = ContentType.objects.get_for_model(model)
    with transaction.atomic():
        seen = []
        for scoped, defaults in rows:
            obj, _ = model.objects.update_or_create(
                appliance=appliance,
                scope=scoped.scope,
                vsys_name=scoped.vsys_name,
                name=scoped.entry["@name"],
                defaults={
                    "management_station": appliance.management_station,
                    "appliance_group": appliance.appliance_group,
                    "source_snapshot": snapshot,
                    **defaults,
                },
            )
            seen.append(obj.pk)
            raw_key, raw_value = entry_provenance(scoped.entry)
            FieldProvenance.objects.filter(
                content_type=content_type, object_id=obj.pk).delete()
            if raw_key is not ABSENT:
                FieldProvenance.objects.create(
                    content_type=content_type, object_id=obj.pk,
                    field_name="__entry__",
                    provenance_type=classify_prov_type(raw_key),
                    raw_key=raw_key or "", raw_value=raw_value or "")
        # Anything not seen this pass is gone from the device. Deleting rather than leaving it
        # matters for the hygiene controls: a stale profile row is a false finding.
        model.objects.filter(appliance=appliance).exclude(pk__in=seen).delete()
        return len(seen)


def normalize_certificate_objects(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"ssl_tls_service_profiles": 0, "certificate_profiles": 0}

    tls_rows = []
    for scoped in scoped_entries(snapshot, "ssl-tls-service-profile",
                                 latest_predefined_ssl_tls_snapshot(appliance)):
        settings = scoped.entry.get("protocol-settings")
        if not isinstance(settings, dict):
            settings = {}
        effective, explicit = _algorithms(settings)
        certificate, _, _ = scalar_value(scoped.entry.get("certificate"))
        min_version, _, _ = scalar_value(settings.get("min-version"))
        max_version, _, _ = scalar_value(settings.get("max-version"))
        tls_rows.append((scoped, {
            "certificate_name": certificate,
            "min_version": min_version,
            "max_version": max_version,
            "protocol_algorithms": effective,
            "explicit_algorithms": explicit,
            # Promoted to a column so a control can rest on it. Derived here, in the one place
            # that already knows absent means enabled.
            "allows_sha1": effective.get("auth-algo-sha1", True),
        }))

    cert_rows = []
    for scoped in scoped_entries(snapshot, "certificate-profile"):
        defaults: dict[str, Any] = {}
        for field, key in CERTIFICATE_PROFILE_BOOLEANS:
            value, _, _ = parse_yes_no_field(scoped.entry.get(key), default_effective=False)
            defaults[field] = value
        for field, key, fallback in CERTIFICATE_PROFILE_TIMEOUTS:
            value, _, _ = parse_integer_field(scoped.entry.get(key),
                                              default_effective=fallback)
            defaults[field] = value
        ca = scoped.entry.get("CA")
        defaults["ca_certificate_names"] = [e["@name"] for e in _entries(ca)]
        cert_rows.append((scoped, defaults))

    certificate_rows = []
    for scoped in scoped_entries(snapshot, "certificate",
                                 latest_predefined_certificate_snapshot(appliance)):
        entry = scoped.entry
        subject_hash, _, _ = scalar_value(entry.get("subject-hash"))
        issuer_hash, _, _ = scalar_value(entry.get("issuer-hash"))
        common_name, _, _ = scalar_value(entry.get("common-name"))
        subject, _, _ = scalar_value(entry.get("subject"))
        issuer, _, _ = scalar_value(entry.get("issuer"))
        is_ca, _, _ = parse_yes_no_field(entry.get("ca"), default_effective=False)
        public_key, _, _ = scalar_value(entry.get("public-key"))
        decoded = decode_certificate(public_key)
        certificate_rows.append((scoped, {
            "common_name": common_name,
            "subject": subject,
            "issuer": issuer,
            "subject_hash": subject_hash,
            "issuer_hash": issuer_hash,
            # Only claim self-signed when BOTH hashes are present. Two blanks compare equal
            # and would mark every unhashed certificate self-signed.
            "is_self_signed": bool(subject_hash and issuer_hash
                                   and subject_hash == issuer_hash),
            "is_ca": is_ca,
            "key_algorithm": decoded.get("key_algorithm", ""),
            "key_size_bits": decoded.get("key_size_bits"),
            "signature_algorithm": decoded.get("signature_algorithm", ""),
            "parse_error": decoded.get("parse_error", ""),
            # Prefer the DECODED validity dates. PAN-OS reports its own, but the certificate
            # is the authority on itself, and `request certificate show` was already caught
            # returning today's date as every certificate's expiry.
            "not_valid_before": decoded.get("not_valid_before"),
            "not_valid_after": decoded.get("not_valid_after"),
        }))

    return {
        "certificates": write_scoped_objects(Certificate, appliance, snapshot, certificate_rows),
        "ssl_tls_service_profiles": write_scoped_objects(SslTlsServiceProfile, appliance, snapshot, tls_rows),
        "certificate_profiles": write_scoped_objects(CertificateProfile, appliance, snapshot, cert_rows),
    }
