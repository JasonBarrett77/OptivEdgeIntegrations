"""Normalize certificates, SSL/TLS service, certificate and SCEP profiles as OBJECTS.

Every type is read from every scope it can occupy - shared, each vsys, and (for certificates
and SSL/TLS profiles) predefined - because PAN-CRT-004 and PAN-CRT-005 ask about every profile
on the device rather than the one some surface has bound. The vsys scope is the half a
shared-only walk gets wrong: pan-fw-111's shared scope holds a certificate profile that
enforces nothing while its vsys1 holds the one that enforces something.

The predefined scope needs its own snapshot: `show config merged` does not carry
/config/predefined, measured 2026-09-02. Its absence is treated as "not collected" rather
than "none exist", which are different facts and only one of them is a finding.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.utils import timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.utils import CryptographyDeprecationWarning

from optivedge_integrations.integrations.models import (
    Appliance,
    Certificate,
    CertificateProfile,
    FieldProvenance,
    ScepProfile,
    Snapshot,
    SslTlsServiceProfile,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ABSENT,
    PREDEFINED,
    classify_prov_type,
    provenance_raw_key,
    provenance_value,
    choice_child,
    ensure_list,
    entry_provenance,
    parse_integer_field,
    parse_text_field,
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

#: Measured 2026-09-02 on oep-mgmt-tls-hardened: a profile writing only min/max version renders
#: EVERY algorithm checkbox ticked. The consequence is why this is stated rather than assumed -
#: a profile carrying only a version range permits SHA-1 and CBC.
ALGORITHM_IMPLICIT = Implicit.measured(
    True,
    "payload contract, ssl-tls-service-profile.protocol-settings/*: ABSENT = ENABLED for every "
    "algorithm key the UI exposes, measured 2026-09-02")


def decode_certificate(pem: str) -> dict[str, Any]:
    """Key algorithm, key size and signature algorithm - none of which PAN-OS exposes.

    They exist only inside the X.509 blob stored under `public-key`, which despite its name
    holds the whole certificate. Decoding is the only way to answer PAN-CRT-002 and
    PAN-CRT-003.

    A failure is RECORDED, not raised. One unreadable certificate must not stop the other
    fifty from normalizing, and a control seeing a blank algorithm with a parse_error reports
    it - an unreadable certificate is not a compliant one.

    NON-CONFORMANCE IS NOT A PARSE FAILURE, and the two must not be conflated: `parse_error`
    means the certificate could not be read, and a control reports it as "could not be
    decoded". A certificate that reads perfectly well but breaks a rule of RFC 5280 is a
    different fact, and it is a fact about the ESTATE rather than about our decoder, so it is
    returned separately in `nonconformance`.

    The one seen in the wild so far is a serial number of zero or below, which RFC 5280
    4.1.2.2 disallows. cryptography 50 warns and still parses it; a future release says it
    will raise, and if it does, the except below turns it into a parse_error and the
    certificate's key data is lost - so that is worth knowing about before it happens.

    The warning is CAPTURED rather than left to print. It is a CryptographyDeprecationWarning,
    which subclasses UserWarning rather than DeprecationWarning, so Python shows it by default
    and one bad certificate prints on every normalization - twice, because loading it and
    reading its serial each warn. The condition itself is then re-established by testing the
    serial directly, so what gets recorded does not depend on matching the text of a warning
    message that upstream is free to reword.

    catch_warnings manipulates a process-global filter, so a thread normalizing concurrently
    could briefly see the altered state. That is accepted here: the window is one function
    call, and the alternative is unbounded log noise on every refresh.
    """
    if not pem or not pem.strip():
        return {"parse_error": "no certificate data"}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            certificate = x509.load_pem_x509_certificate(pem.encode("utf-8"))
            serial_number = certificate.serial_number
    except Exception as exc:  # noqa: BLE001 - any decode failure is the same outcome here
        return {"parse_error": f"{type(exc).__name__}: {exc}"[:255]}

    nonconformance = ""
    if serial_number <= 0:
        nonconformance = (
            f"serial number is {serial_number}; RFC 5280 4.1.2.2 requires a positive integer"
        )

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

    # THE IDENTIFIER IS NOT THE HASH, and the gap is not theoretical. Measured against this
    # library: an RSASSA-PSS certificate's `signature_algorithm_oid._name` is `rsassaPss`,
    # which names NO hash - for PSS the hash lives in the signature PARAMETERS - while
    # `signature_hash_algorithm` reads those parameters and answers `sha256`. So a PSS
    # certificate signed with SHA-1 matches neither `contains md5` nor `contains sha1` on the
    # identifier, carries an empty parse error, and passes every query written over it. Every
    # SHA-3 variant has the same shape, harmless today only because SHA-3 is strong.
    #
    # It answers None for Ed25519 and Ed448, where the signature carries its own hash and
    # there is no separate one to name, and raises UnsupportedAlgorithm for an OID this
    # library does not know. Both land on the empty string, which `weak_signature_hash` reads
    # as weak - so an Ed25519 certificate REPORTS. That is stage 5's declared direction (its
    # value set places the empty string as a finding) and it is the one placement in this
    # domain where the firing side is also a false positive.
    try:
        hash_algorithm = certificate.signature_hash_algorithm
    except Exception:  # noqa: BLE001 - an unknown signature OID is the same outcome here
        hash_algorithm = None
    signature_hash = getattr(hash_algorithm, "name", "") or ""

    return {
        "key_algorithm": algorithm,
        "key_size_bits": bits,
        "signature_algorithm": signature,
        "signature_hash": signature_hash,
        "not_valid_before": certificate.not_valid_before_utc,
        "not_valid_after": certificate.not_valid_after_utc,
        "parse_error": "",
        "serial_number": serial_number,
        "nonconformance": nonconformance,
    }


#: The key-strength floor this assessment carries, PER ALGORITHM FAMILY, in bits. The whole
#: reason `key_strength_band` exists rather than a numeric threshold: 256-bit EC is strong and
#: 256-bit RSA is broken, and the vendor's own predefined certificate is EC P-256 - so a single
#: threshold flags the shipped certificate and passes a hypothetical RSA-512.
#:
#: An algorithm absent from this mapping lands on `algorithm_has_no_floor`, which FIRES. That
#: is the member stage 3 explicitly refuses to RANK while refusing to let it read as acceptable,
#: and it is reachable: the decoder returns Ed25519 and Ed448 with a null size.
KEY_STRENGTH_FLOORS = {"RSA": 2048, "DSA": 2048, "EC": 256}

#: The resolved hashes a signature may use and still be sound. `weak_signature_hash` is TRUE
#: for md5, for sha1 and for the EMPTY string, and that list is stage 5's declared derivation
#: rather than this module's judgement - which is why it is written as the two weak names plus
#: the unresolved case and NOT as "anything not in a sound set". The difference shows on a
#: SHA-3 certificate: a resolved `sha3-256` is not weak here, and would be under the other
#: reading. The SCEP profile's own digest column uses the OTHER rule deliberately - see
#: `csr_digest_weak` - because its value is a configured literal from a set the device's
#: completion does not bound, and this one is decoded from a bounded set.
WEAK_SIGNATURE_HASHES = frozenset({"md5", "sha1"})


def key_algorithm_family(algorithm: str) -> str:
    """`EC (secp256r1)` -> `EC`. The curve travels with the name and is not part of the family.

    The curve name is kept in the stored column on purpose - a reader seeing a bare "256" would
    draw the wrong conclusion - so the family has to be recovered here rather than stored twice.
    """
    return str(algorithm or "").split(" (", 1)[0].strip()


def key_strength_band(algorithm: str, bits: int | None, parse_error: str) -> str:
    """Where this key sits against the floor for ITS OWN algorithm, as one of five bands.

    THE TWO BOUNDARIES ARE THIS STAGE'S AND STAGE 5 LEFT THEM OPEN. Stage 5 names the five
    members and stage 3 grades two concrete cases - RSA 1024 as `below_floor` at high and RSA
    512 as `far_below_floor` at critical - and nothing states the rule between them. The rule
    implemented is HALF THE FLOOR: at or above the floor passes, at or above half of it is
    `below_floor`, anything less is `far_below_floor`. It reproduces both graded cases exactly
    (1024 >= 2048/2; 512 < 2048/2) and it carries to EC without a second constant. A floor set
    that ever gains an algorithm whose graded cases do not follow that rule needs the rule
    stated per algorithm, which is stage 5's to say.

    NONCONFORMANCE IS NOT A PARSE FAILURE and does not reach this: a certificate with a serial
    of zero decodes perfectly and its key is as strong as its bits say.
    """
    if parse_error or not algorithm:
        return Certificate.BAND_UNDECODABLE
    floor = KEY_STRENGTH_FLOORS.get(key_algorithm_family(algorithm))
    if floor is None or bits is None:
        return Certificate.BAND_NO_FLOOR
    if bits >= floor:
        return Certificate.BAND_AT_OR_ABOVE
    if bits >= floor // 2:
        return Certificate.BAND_BELOW
    return Certificate.BAND_FAR_BELOW


def signature_hash_is_weak(signature_hash: str) -> bool:
    """md5, sha1, or a hash that could not be resolved at all."""
    resolved = str(signature_hash or "").lower()
    return resolved in WEAK_SIGNATURE_HASHES or not resolved


#: `private-key-on-hsm` absent. ASSUMED AND NOT MEASURED, and the citation says so rather than
#: dressing the guess up: the only certificate on the lab appliance carries this key's absence
#: ALONGSIDE `private-key`, which is the on-device form, so an absent key most plausibly asserts
#: that custody is local. Nothing was written to settle it - the one write that would is a
#: `private-key-on-hsm` yes on a throwaway certificate, and the only certificate present is
#: another run's standing object. `assumed` keeps the report saying "assumed, not measured", and
#: FALSE is the direction that RAISES PAN-DCP-006 rather than passing it.
PRIVATE_KEY_ON_HSM_ABSENT = Implicit.assumed(
    False,
    "stage 4 recorded `private-key-on-hsm` as unmeasured with consumer_disposition `assumed`: "
    "the one lab certificate lacks the key and carries `private-key`, the on-device form")


def min_version_rank(min_version: str) -> int:
    """The floor's ORDINAL position, with an out-of-set token below the lowest real version.

    The sentinel runs the opposite way from the usual trap: the magnitude is not the meaning,
    and the meaning is that every "the floor is too low" comparison FIRES on it. Stage 0
    measured the alternative - a query enumerating the forbidden values reads a token it does
    not recognise as compliant.
    """
    order = SslTlsServiceProfile.VERSION_ORDER
    token = str(min_version or "")
    return order.index(token) if token in order else SslTlsServiceProfile.RANK_UNRECOGNISED


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


def scoped_nodes(snapshot: Snapshot, object_key: str,
                 predefined: Snapshot | None = None) -> list[tuple[str, str, Any]]:
    """(scope, vsys name, the raw node) for `object_key` in every scope it occupies.

    `scoped_entries` below is this plus "and pull the `entry` children out", which is what almost
    every object needs. Server profiles are the exception: `server-profile` holds six SIBLING
    CONTAINERS - ldap, radius, tacplus, kerberos, saml-idp, mfa-server-profile - and the entries
    are one level further down, so that caller needs the node itself. Splitting the scope walk
    out means it is written once rather than copied for the exception.
    """
    found: list[tuple[str, str, Any]] = []
    payload = snapshot.payload or {}
    config = payload.get("config") if isinstance(payload, dict) else None
    if isinstance(config, dict):
        shared = config.get("shared")
        if isinstance(shared, dict) and shared.get(object_key) is not None:
            found.append((CertificateProfile.SCOPE_SHARED, "", shared.get(object_key)))

    # Every vsys, not just vsys1. A multi-vsys device can define an object in one vsys and not
    # another, and that difference is the whole point of recording the scope.
    device_entry = device_entry_from_snapshot(snapshot)
    vsys_node = device_entry.get("vsys") if isinstance(device_entry, dict) else None
    for vsys in ensure_list((vsys_node or {}).get("entry")) if isinstance(vsys_node, dict) else []:
        if not isinstance(vsys, dict):
            continue
        name = str(vsys.get("@name") or "").strip()
        if name and vsys.get(object_key) is not None:
            found.append((CertificateProfile.SCOPE_VSYS, name, vsys.get(object_key)))

    if predefined is not None:
        pre = predefined.payload or {}
        if isinstance(pre, dict) and pre.get(object_key) is not None:
            found.append((CertificateProfile.SCOPE_PREDEFINED, "", pre.get(object_key)))
    return found


def scoped_entries(snapshot: Snapshot, object_key: str,
                   predefined: Snapshot | None = None) -> list[ScopedEntry]:
    """Every definition of `object_key`, from every scope it can occupy.

    Object-type agnostic, as are `ScopedEntry` and `write_scoped_objects` below. They live in a
    certificate-named module because certificates needed them first; authentication profiles
    import them from here. Worth moving to their own module the next time this file is opened
    for another reason - not worth a risky move on its own.
    """
    return [ScopedEntry(scope, vsys, entry)
            for scope, vsys, node in scoped_nodes(snapshot, object_key, predefined)
            for entry in _entries(node)]


def _excluded_by_range(min_rank: int, max_rank: int) -> set[str]:
    """Algorithm keys the DEVICE has taken out of the rendered set for this version range.

    Measured 2026-10-25 on pan-fw-201 over four objects, none of which stores a single
    algorithm key: a key-less subject at the implicit tls1-2..tls1-3 range renders ELEVEN
    algorithms, the same-shaped subject storing only max-version=tls1-2 renders TEN, the
    predefined profile at tls1-3..tls1-3 renders SIX, and a committed leftover storing only
    min-version renders eleven. The device agrees the set is derived rather than cosmetic:
    writing an algorithm outside the range is refused with "not supported in tls1-2 to tls1-3
    version".

    Two exclusions are NAMED by those readings. Moving the ceiling to tls1-2 removed
    AES-CHACHA20-POLY1305 from that entry's algorithm cells and from no other, and SHA1 is in
    the rendered set at the implicit range and at tls1-2..tls1-2 and OUT of it at
    tls1-3..tls1-3.

    ONE INFERENCE, AND IT IS LABELLED AS ONE: the chacha exclusion is applied to every ceiling
    BELOW tls1-3 and only the tls1-2 ceiling was measured. The step is monotonicity - a
    narrower range cannot render more algorithms than a wider one that contains it - and the
    alternative would claim chacha ENABLED at a tls1-1 ceiling on no reading at all.
    """
    excluded: set[str] = set()
    if max_rank != 3:
        excluded.add("enc-algo-aes-chacha20-poly1305")
    if min_rank == 3:
        excluded.add("auth-algo-sha1")
    return excluded


def _permits_sha1(protocol_settings: dict[str, Any]) -> bool:
    """Whether the profile's CONFIGURATION leaves SHA-1 enabled, whatever the version range.

    READS THE CONFIGURATION AND NOT THE RENDERED SET, decided 2026-10-29. An earlier version of
    this function read the range-narrowed map, so a tls1-3-only profile reported as not
    permitting SHA-1 - the range takes SHA-1 out of the algorithm dialog, which is measured and
    which `protocol_algorithms` still records. That reading treats cipher negotiation as the
    whole of what an SSL/TLS service profile governs, and it is not: a TLS 1.3 session still
    validates a certificate chain, and certificate signatures and self-signed root CA
    signatures may use SHA-1 whatever the cipher suite does. Without insight into every TLS 1.3
    operation, the safe reading is the one the configuration states.

    So the key written OFF is False, the key written ON is True, and an ABSENT key is True
    because absent means enabled for every algorithm key the dialog exposes
    (`ALGORITHM_IMPLICIT`, measured 2026-09-02). NEVER None: the column is a BooleanField, and
    under this reading there is no range in which the configuration is unestablished - which is
    a second reason to read it here rather than off the rendered set.
    """
    raw = protocol_settings.get("auth-algo-sha1", ABSENT)
    if raw is ABSENT:
        return bool(ALGORITHM_IMPLICIT.value)
    value, _, _ = parse_yes_no_field(raw, implicit=ALGORITHM_IMPLICIT)
    return bool(value)


def _algorithms(protocol_settings: dict[str, Any], min_version: str,
                max_version: str) -> tuple[dict[str, bool], list[str]]:
    """Effective algorithm settings, and which keys the configuration actually wrote.

    ABSENT MEANS ENABLED FOR THE ALGORITHMS VALID IN THE PROFILE'S VERSION RANGE, and the
    second half of that sentence is the correction made on 2026-10-29. This function expanded
    every absent key to True and never read the range, which is right for the eleven-rendering
    case - where PAN-CRT-009 fires, so the headline finding was sound - and WRONG for a profile
    pinned low or pinned high, where it reported algorithms the device has disabled. Stage 4
    records the implicit as `status: conditional` for exactly this: what was measured is a
    RELATION and the value alone is not citable.

    THREE OUTCOMES PER ABSENT KEY, not two, and the third is why a pinned-to-1.3 profile stores
    fewer keys than its neighbours:

      * measured OUT of the range  -> False
      * the range whose rendered set was measured COMPLETE (any floor below tls1-3) -> True
      * a tls1-3-only range, for a key that is not one of the two named exclusions -> None

    Only SIX of the eleven render at tls1-3..tls1-3 and nothing says WHICH six, so materialising
    the other five either way would manufacture a fact - which is precisely what stage 4's
    `merge_as: hold` forbids. The map still carries all eleven keys, so a reader still sees the
    whole dialog; the five it cannot establish read as JSON null, which is "not established"
    rather than "enabled". `protocol_algorithms` is a display column nothing may clause on, so a
    third state there costs no query anything.

    `allows_sha1` NO LONGER READS THIS MAP, as of 2026-10-29. This map is the RENDERED set -
    what the algorithm dialog shows - and `auth-algo-sha1` is correctly False here at a
    tls1-3-only range, because that is the range it was measured OUT of. The graded column
    reports the CONFIGURATION instead, for the reason recorded on `_permits_sha1`: the rendered
    cipher set is not the whole of what the profile governs.

    The three camellia/seed keys stay out of the expansion for the reason they always have:
    stage 4 records their implicit as `unsettable` - the write is refused at BOTH ends of the
    range the device offers, so there is no range in which the key can hold a value.
    """
    min_rank = min_version_rank(min_version)
    max_rank = min_version_rank(max_version)
    excluded = _excluded_by_range(min_rank, max_rank)
    unestablished = min_rank == 3

    effective: dict[str, bool] = {}
    explicit: list[str] = []
    for key in ALGORITHM_KEYS:
        raw = protocol_settings.get(key, ABSENT)
        if raw is ABSENT:
            effective[key] = False if key in excluded else (None if unestablished else True)
            continue
        explicit.append(key)
        # Reached only when the key is PRESENT - absence short-circuits above - so this
        # declaration describes an empty element rather than a missing one.
        value, _, _ = parse_yes_no_field(raw, implicit=ALGORITHM_IMPLICIT)
        # A key written ON that the range excludes is still off on the wire: the device refuses
        # the write inside the range and the grid stops rendering it. Recorded as the device
        # behaves rather than as the configuration reads.
        effective[key] = value and key not in excluded
    for key in UNMEASURED_ALGORITHM_KEYS:
        if protocol_settings.get(key, ABSENT) is not ABSENT:
            explicit.append(key)
            value, _, _ = parse_yes_no_field(
                protocol_settings.get(key), implicit=ALGORITHM_IMPLICIT)
            effective[key] = value
    return effective, sorted(explicit)


def write_scoped_objects(model, appliance: Appliance, snapshot: Snapshot,
           rows: list[tuple], extra_key: str | None = None,
           identity: tuple[str, ...] = ("name",)):
    """Write one row per scoped entry, replacing whatever the appliance held before.

    `extra_key` names a field that is part of the object's identity ALONGSIDE the scope and the
    name. Server profiles need it: six kinds live in six sibling containers, so one appliance can
    hold a `shared` saml-idp and a `shared` radius, and keying on the name alone would make the
    second overwrite the first and the count come out short.

    `identity` names the fields that, with the appliance, scope and vsys, identify the row.
    It defaults to `("name",)` - the base's own column, taken from the entry's `@name` - which
    is every caller but one. A field named here that the row's own `defaults` carries is read
    from there instead, which is how a CHILD row identifies itself: a log server target is one
    server entry inside one NAMED PROFILE, so its identity needs the parent's name as well as
    its own, and `name` alone would make the second server of a profile overwrite the first.
    """
    content_type = ContentType.objects.get_for_model(model)
    with transaction.atomic():
        seen = []
        for row in rows:
            # A third element is the per-field provenance. Optional so the callers that have
            # nothing to say about their fields yet keep working unchanged.
            scoped, defaults = row[0], row[1]
            field_rows = row[2] if len(row) > 2 else ()
            lookup = {"appliance": appliance, "scope": scoped.scope,
                      "vsys_name": scoped.vsys_name}
            for field in identity:
                lookup[field] = (defaults[field] if field in defaults
                                 else scoped.entry["@name"])
            if extra_key:
                lookup[extra_key] = defaults[extra_key]
            obj, _ = model.objects.update_or_create(
                **lookup,
                defaults={
                    "management_station": appliance.management_station,
                    "appliance_group": appliance.appliance_group,
                    "source_snapshot": snapshot,
                    **defaults,
                },
            )
            seen.append(obj.pk)
            raw_key, raw_value = entry_provenance(scoped.entry)
            if raw_key is None and scoped.scope == CertificateProfile.SCOPE_PREDEFINED:
                # A predefined entry carries no @ptpl and no @loc, and an unmarked entry
                # records LOCAL - "defined on this device", about an object that ships with
                # the release and cannot be edited. Only the scope says otherwise, and this
                # is where it is known. A marker, if one were ever present, is still the
                # better fact and is left alone.
                raw_key, raw_value = PREDEFINED, None
            FieldProvenance.objects.filter(
                content_type=content_type, object_id=obj.pk).delete()
            if raw_key is not ABSENT:
                FieldProvenance.objects.create(
                    content_type=content_type, object_id=obj.pk,
                    field_name="__entry__",
                    provenance_type=classify_prov_type(raw_key),
                    raw_key=provenance_raw_key(raw_key), raw_value=provenance_value(raw_key, raw_value))
            FieldProvenance.objects.bulk_create([
                FieldProvenance(
                    content_type=content_type, object_id=obj.pk, field_name=field_name,
                    provenance_type=classify_prov_type(rk),
                    raw_key=provenance_raw_key(rk), raw_value=provenance_value(rk, rv)[:128])
                for field_name, rk, rv in field_rows if rk is not ABSENT])
        # Anything not seen this pass is gone from the device. Deleting rather than leaving it
        # matters for the hygiene controls: a stale profile row is a false finding.
        model.objects.filter(appliance=appliance).exclude(pk__in=seen).delete()
        return len(seen)


#: Measured 2026-10-25 on pan-fw-201 (PA-VM 11.2.5), and it TURNS A FALSE FINDING OFF. Both
#: bounds were declared `Implicit.not_assumed('payload contract ... implicit_unmeasured')`, so
#: a profile that omits min-version stored the EMPTY STRING - and the shipped baseline query for
#: PAN-CRT-005 lists `min_version is_empty` as a FIRING clause. The measured truth is that such
#: a profile enforces a TLS 1.2 floor and therefore MEETS the assertion, so every profile in the
#: estate that omits the key was being reported as a finding it does not deserve.
#:
#: The strongest half of the reading rests on an object nobody built for it: the committed
#: leftover `oep-p1-tls` carries min-version and NO max-version, and its grid cell renders
#: `Max Version: TLSv1.3` - so one of the two absences is observed on a running device by
#: natural experiment. The positive control moved the floor cell tls1-2 -> tls1-0 and back, and
#: the ceiling has a second, INDEPENDENT oracle: moving it to tls1-2 removed
#: AES-CHACHA20-POLY1305 from that entry's algorithm cells and from no other, which is a
#: consequence of the value rather than a second rendering of it.
#:
#: The `protocol-settings` CONTAINER above them is mandatory at commit, so the absence being
#: materialised is the CHILD's and not the container's. Stage 4 contradicts the payload contract
#: on exactly that point and this takes stage 4's reading.
MIN_VERSION_IMPLICIT = Implicit.measured(
    "tls1-2",
    "payload contract, ssl-tls-service-profile.protocol-settings/min-version: implicit "
    "'tls1-2' - an absent floor asserts a TLSv1.2 floor on a profile that EXISTS, measured "
    "2026-10-25 on pan-fw-201 with the positive control paid on the element and the absence "
    "observed on a committed object the run did not build")
MAX_VERSION_IMPLICIT = Implicit.measured(
    "tls1-3",
    "payload contract, ssl-tls-service-profile.protocol-settings/max-version: implicit "
    "'tls1-3' - an absent ceiling asserts a TLSv1.3 ceiling, measured 2026-10-25 on pan-fw-201; "
    "the schema's own @default='yes' sits on tls1-3 and matches")

#: MANDATORY AT COMMIT, so the absent state cannot exist on a running device and there is
#: nothing for an absence to assert. It was declared `Implicit.measured(None, '... a profile
#: with no certificate key has none bound')`, which is wrong in two ways at once: the state it
#: describes is unreachable on a committed profile, and a `measured` Implicit whose value is
#: None has `stores_nothing` true - so it persisted as `not_configured`, the declaration
#: claiming a vendor fact while the row recorded "nobody configured it". The stored value does
#: not change; the declaration stops overstating.
TLS_CERTIFICATE_IMPLICIT = Implicit.not_assumed(
    "mandatory at commit validation - 'Validation Error: ssl-tls-service-profile -> "
    "oep-crt-tls-bare is missing certificate', commit job 141 - so a committed profile never "
    "lacks it and an absence asserts nothing")

#: The six booleans' value was always right and the CITATION was not: it named the blank Add
#: Certificate Profile form of 2026-09-02, and this project's own records twice refuse a rung
#: for a UI-only reading ("NO RUNG FITS: the UI is not a rung"). Replaced 2026-10-29 with the
#: measurement that pays the full bar on the same values.
CERTIFICATE_PROFILE_BOOLEAN_IMPLICIT = Implicit.measured(
    False,
    "payload contract, certificate-profile $implicit_values: all six booleans absent = "
    "DISABLED (unticked) - measured 2026-10-25 on pan-fw-201, the grid cell and the dialog "
    "checkbox both UNTICKED on a profile carrying no child key at all, with the tick read as "
    "the CSS class rather than as innerText; observed absent on a COMMITTED profile on a "
    "second appliance and a second build (pan-fw-111 11.2.3-h3); positive control paid on the "
    "element on its own object with a key-less witness read in the same grid read")

#: A PROMOTION, not a new value. These were declared as ASSUMED with the reasoning "the
#: certificate-profile implicit block measured the six BOOLEANS and says nothing about the
#: timeouts; this fallback predates it", so the report rendered a measured number as an
#: inference.
#:
#: The old declaration is described rather than QUOTED on purpose, and this is the one place in
#: this file where that matters: `test_every_assumed_default_is_accounted_for` counts
#: occurrences of the constructor's name with a regex over the module's TEXT, so a comment
#: quoting a declaration it has just replaced keeps the census at its old number and the gate
#: passes on a promotion it was built to notice. Measured 2026-10-25 on pan-fw-201: the grid cell and the dialog field both read
#: `5` on a profile carrying no child key at all, and the dialog reading is a VALUE and not an
#: emptyText hint - the input carries no `x-form-empty-field` class, unlike four fields on the
#: SCEP dialog read in the same pass that do. Each of the three was moved to its OWN distinct
#: value in a twelve-element control round (5 -> 44, 5 -> 22, 5 -> 33) against a key-less
#: witness in the same read, so the three are attributable separately, and the device states its
#: own range unprompted in a refusal message.
#:
#: 0 IS NOT A SENTINEL ON THESE LEAVES, which is worth stating because the same spelling means
#: UNLIMITED on other nodes in this product: 0 is refused at the write - code=12, "value=0
#: should be equal to or between 1 and 60" - so no stored row can hold it and the implicit 5 is
#: inside the writable range.
CERTIFICATE_PROFILE_TIMEOUT_IMPLICIT = Implicit.measured(
    5,
    "payload contract, certificate-profile crl-receive-timeout / ocsp-receive-timeout / "
    "cert-status-timeout: implicit 5 seconds - measured 2026-10-25 on pan-fw-201, grid cell "
    "and dialog field both '5' on a key-less profile with no emptyText class, positive control "
    "moved each of the three to a distinct value against a key-less witness in the same read")

#: `digest` and the `algorithm` container are both MANDATORY at commit validation on all four
#: appliances, enumerated one commit at a time, so a committed profile carries both and an
#: absence asserts nothing. The dialog renders both inputs EMPTY with the `x-form-empty-field`
#: class on a bare subject, so the UI asserts no default either and the two answers agree there
#: is nothing to materialise - which is why neither is guessed. Guessing 2048 from its position
#: in the completion list would be reading an ORDER as a default.
SCEP_MANDATORY_AT_COMMIT = Implicit.not_assumed(
    "mandatory at commit validation - 'Validation Error: scep -> oep-crt-scep-vsys is missing "
    "digest' - so no committed SCEP profile lacks it and an absence asserts nothing")

#: The floor the enrolment verdict compares against, and it is the SAME 2048 as the stored
#: certificate's RSA floor on purpose: the profile names the key every certificate it mints
#: from now on will carry.
SCEP_RSA_KEY_FLOOR = 2048
#: Digests this assessment recognises as sound for a signing request. The verdict is TRUE for
#: anything else, INCLUDING A LITERAL THIS SET DOES NOT CONTAIN, and that is load-bearing
#: rather than defensive: md5 is absent from the leaf's completion set on all four appliances
#: and IS committable - stage 4 wrote `digest: md5`, committed it in job 149, and `show config
#: running` returns it - so the writable set is wider than the offered set and a rule written
#: against the enum cannot see this control's own forbidden value.
SOUND_CSR_DIGESTS = frozenset({"sha256", "sha384", "sha512"})


def _scep_verdicts(rsa_key_bits: str | None, csr_digest: str) -> tuple[bool, bool]:
    """(the key is below the floor, the digest is weak), computed from the stored LITERALS.

    Neither reads the device's completion set, and both put an UNRECOGNISED literal on the
    FIRING side. That is stage 4's own prescription for these two leaves: the completion set is
    what the device will OFFER and not what it will ACCEPT, measured in both directions on one
    appliance on one day - 512 committed to a key length whose enum has three members, and md5
    committed to a digest whose enum has four and does not include it.
    """
    try:
        below_floor = int(str(rsa_key_bits).strip()) < SCEP_RSA_KEY_FLOOR
    except (TypeError, ValueError):
        # Absent, empty, or a literal that is not a number at all. Not shown to meet the floor.
        below_floor = True
    return below_floor, str(csr_digest or "").strip().lower() not in SOUND_CSR_DIGESTS


def collect_certificate_references(
    certificate_rows: list[tuple], tls_rows: list[tuple], profile_rows: list[tuple],
) -> dict[tuple[str, str, str], list[dict[str, str]]]:
    """Which objects on this appliance rely on each certificate, keyed by (scope, vsys, name).

    FOUR EDGES, three of them name references and one a hash chain, and stage 4 confirmed the
    two name edges machine-readably: the SSL/TLS profile's `certificate` completes with
    @type='key' and the certificate profile's CA container with @type='ca-file' - a DIFFERENT
    @type, which is how the two roles are told apart from the device side.

      1. an SSL/TLS service profile presenting it
      2. a certificate profile naming it as a trust anchor. THE CA CONTAINER HOLDS ENTRY NAMES
         AND NOT LEAF VALUES, which is this control's central case and the trap for a scan
         built the obvious way - a value-only walk misses every trust anchor.
      3. another certificate whose issuer-hash equals this one's subject-hash: how a CA that
         nothing NAMES is found to be in use anyway
      4. (not reachable here) the 65 of 69 known reference locations covered by no model

    THE MAP IS A FLOOR AND NOT A CENSUS, and the whole polarity of `not_relied_on` rests on
    that: a count computed from what the store holds UNDER-REPORTS references, and the finding
    it feeds is "nothing uses this, review it for removal", whose remediation is an irreversible
    delete.

    NAME MATCHING IS ACROSS SCOPES on one appliance, deliberately. Resolution order would make
    this narrower, and narrower is the unsafe direction here: over-counting a reference pushes
    `not_relied_on` to False, which makes PAN-CRT-001 LOUDER and PAN-CRT-008 QUIETER, and both
    of those are the safe side of their own control. Under-counting would do the reverse.

    THE HASH CHAIN IS SURFACE-LOCAL. It is not followed from the firewall's own store into the
    predefined catalogue, because the hashes are only comparable within one surface - and the
    subject and issuer STRINGS cannot be compared instead, because the formats differ between
    scopes: "/CN=x" shared, a bare "x" predefined, "CN = x" in subject-int and from the op
    command.
    """
    referrers: dict[tuple[str, str, str], list[dict[str, str]]] = {}

    def _key(scoped, name: str) -> tuple[str, str, str]:
        return (scoped.scope, scoped.vsys_name, name)

    by_name: dict[str, list[tuple[str, str, str]]] = {}
    for scoped, defaults, *_ in certificate_rows:
        name = scoped.entry["@name"]
        by_name.setdefault(name, []).append(_key(scoped, name))

    def _add(name: str, referrer: dict[str, str]) -> None:
        for key in by_name.get(name, ()):
            referrers.setdefault(key, []).append(referrer)

    for scoped, defaults, *_ in tls_rows:
        name = defaults.get("certificate_name")
        if name:
            _add(name, {"kind": "ssl-tls-service-profile", "name": scoped.entry["@name"],
                        "scope": scoped.scope, "vsys_name": scoped.vsys_name})
    for scoped, defaults, *_ in profile_rows:
        for name in defaults.get("ca_certificate_names") or ():
            _add(name, {"kind": "certificate-profile", "name": scoped.entry["@name"],
                        "scope": scoped.scope, "vsys_name": scoped.vsys_name})

    # The chain, within one surface. `predefined` is the vendor's namespace and the firewall's
    # own store is the other; an entry never chains across the two.
    def _surface(scope: str) -> str:
        return ("predefined" if scope == Certificate.SCOPE_PREDEFINED else "local")

    by_subject_hash: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for scoped, defaults, *_ in certificate_rows:
        subject_hash = defaults.get("subject_hash")
        if subject_hash:
            by_subject_hash.setdefault(
                (_surface(scoped.scope), subject_hash), []).append(
                    _key(scoped, scoped.entry["@name"]))
    for scoped, defaults, *_ in certificate_rows:
        issuer_hash = defaults.get("issuer_hash")
        if not issuer_hash:
            continue
        child = _key(scoped, scoped.entry["@name"])
        for parent in by_subject_hash.get((_surface(scoped.scope), issuer_hash), ()):
            if parent == child:
                continue  # self-signed: its own issuer is not a referrer
            referrers.setdefault(parent, []).append(
                {"kind": "certificate", "name": child[2], "scope": child[0],
                 "vsys_name": child[1]})
    return referrers


def normalize_certificate_objects(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"certificates": 0, "ssl_tls_service_profiles": 0,
                "certificate_profiles": 0, "scep_profiles": 0}

    tls_rows = []
    for scoped in scoped_entries(snapshot, "ssl-tls-service-profile",
                                 latest_predefined_ssl_tls_snapshot(appliance)):
        settings = scoped.entry.get("protocol-settings")
        if not isinstance(settings, dict):
            settings = {}
        certificate, cert_rk, cert_rv = parse_text_field(
            scoped.entry.get("certificate"), implicit=TLS_CERTIFICATE_IMPLICIT)
        min_version, min_rk, min_rv = parse_text_field(
            settings.get("min-version"), implicit=MIN_VERSION_IMPLICIT)
        max_version, max_rk, max_rv = parse_text_field(
            settings.get("max-version"), implicit=MAX_VERSION_IMPLICIT)
        # AFTER the two bounds, and it has to be: the algorithm set is a function of both.
        effective, explicit = _algorithms(settings, min_version, max_version)
        tls_rows.append((scoped, {
            "certificate_name": certificate,
            "min_version": min_version,
            "max_version": max_version,
            "min_version_rank": min_version_rank(min_version),
            "protocol_algorithms": effective,
            "explicit_algorithms": explicit,
            # Promoted to a column so a control can rest on it. Reads `settings` - the
            # CONFIGURATION - rather than `effective`, the rendered set: see `_permits_sha1`.
            "allows_sha1": _permits_sha1(settings),
        }, [
            ("certificate_name", cert_rk, cert_rv),
            ("min_version", min_rk, min_rv),
            ("max_version", max_rk, max_rv),
        ]))

    cert_rows = []
    for scoped in scoped_entries(snapshot, "certificate-profile"):
        defaults: dict[str, Any] = {}
        profile_prov = []
        for field, key in CERTIFICATE_PROFILE_BOOLEANS:
            value, rk, rv = parse_yes_no_field(
                scoped.entry.get(key), implicit=CERTIFICATE_PROFILE_BOOLEAN_IMPLICIT)
            defaults[field] = value
            profile_prov.append((field, rk, rv))
        for field, key, _fallback in CERTIFICATE_PROFILE_TIMEOUTS:
            value, rk, rv = parse_integer_field(
                scoped.entry.get(key), implicit=CERTIFICATE_PROFILE_TIMEOUT_IMPLICIT)
            defaults[field] = value
            profile_prov.append((field, rk, rv))
        ca = scoped.entry.get("CA")
        defaults["ca_certificate_names"] = [e["@name"] for e in _entries(ca)]
        # The disjunction and the fail-open classification, computed once so a clause can name
        # them. THE THREE TIMEOUTS ARE NOT INPUTS, deliberately: which of them governs the
        # blocking decision is not establishable from the grammar - they are siblings with no
        # stated precedence and the vendor gives no default for any of them on this screen - so
        # a derivation reading one would have picked one of three without evidence.
        defaults["checks_revocation"] = defaults["use_crl"] or defaults["use_ocsp"]
        defaults["fail_open_mode"] = {
            (True, True): CertificateProfile.FAIL_OPEN_NONE,
            (False, True): CertificateProfile.FAIL_OPEN_UNKNOWN,
            (True, False): CertificateProfile.FAIL_OPEN_TIMEOUT,
            (False, False): CertificateProfile.FAIL_OPEN_BOTH,
        }[(bool(defaults["block_unknown_cert"]), bool(defaults["block_timeout_cert"]))]
        cert_rows.append((scoped, defaults, profile_prov))

    scep_rows = []
    for scoped in scoped_entries(snapshot, "scep"):
        # `algorithm` is a CHOICE node - which child exists is the setting - so it is read with
        # the shared helper rather than by indexing a key that may not be the one present. An
        # algorithm family this build does not name leaves the key length null, which is the
        # honest answer and not a zero.
        which, algorithm = choice_child(scoped.entry.get("algorithm"), ("rsa",))
        bits, bits_rk, bits_rv = parse_text_field(
            algorithm.get("rsa-nbits") if which == "rsa" else None,
            implicit=SCEP_MANDATORY_AT_COMMIT)
        digest, digest_rk, digest_rv = parse_text_field(
            scoped.entry.get("digest"), implicit=SCEP_MANDATORY_AT_COMMIT)
        # NULL rather than the empty string, which is this model's one nullable column: nothing
        # clauses on it, the clause names the verdict beside it, and the literal is what a
        # finding prints and a grading places.
        stored_bits = bits or None
        below_floor, digest_weak = _scep_verdicts(stored_bits, digest)
        scep_rows.append((scoped, {
            "rsa_key_bits": stored_bits,
            "enrolment_key_below_floor": below_floor,
            "csr_digest": digest,
            "csr_digest_weak": digest_weak,
        }, [
            ("rsa_key_bits", bits_rk, bits_rv),
            ("csr_digest", digest_rk, digest_rv),
        ]))

    certificate_rows = []
    for scoped in scoped_entries(snapshot, "certificate",
                                 latest_predefined_certificate_snapshot(appliance)):
        entry = scoped.entry
        subject_hash, _, _ = scalar_value(entry.get("subject-hash"))
        issuer_hash, _, _ = scalar_value(entry.get("issuer-hash"))
        common_name, _, _ = scalar_value(entry.get("common-name"))
        subject, _, _ = scalar_value(entry.get("subject"))
        issuer, _, _ = scalar_value(entry.get("issuer"))
        is_ca, ca_rk, ca_rv = parse_yes_no_field(
            entry.get("ca"),
            implicit=Implicit.assumed(
                False,
                "a certificate entry carries `ca` only when it IS one in every sample seen, but "
                "nobody has written a certificate without it and re-read the device"))
        on_hsm, hsm_rk, hsm_rv = parse_yes_no_field(
            entry.get("private-key-on-hsm"), implicit=PRIVATE_KEY_ON_HSM_ABSENT)
        public_key, _, _ = scalar_value(entry.get("public-key"))
        decoded = decode_certificate(public_key)
        not_valid_after = decoded.get("not_valid_after")
        signature_hash = decoded.get("signature_hash", "")
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
            #: PAN-DCP-006's third fact. ASSUMED, not measured - see the implicit.
            "private_key_on_hsm": on_hsm,
            "key_algorithm": decoded.get("key_algorithm", ""),
            "key_size_bits": decoded.get("key_size_bits"),
            "signature_algorithm": decoded.get("signature_algorithm", ""),
            "parse_error": decoded.get("parse_error", ""),
            # Prefer the DECODED validity dates. PAN-OS reports its own, but the certificate
            # is the authority on itself, and `request certificate show` was already caught
            # returning today's date as every certificate's expiry.
            "not_valid_before": decoded.get("not_valid_before"),
            "not_valid_after": not_valid_after,
            # The three verdicts the controls clause on. Each is computed here rather than
            # queried, and each defaults to its FIRING value on the model so the window
            # between a migration and this pass reports rather than reassures.
            "key_strength_band": key_strength_band(
                decoded.get("key_algorithm", ""), decoded.get("key_size_bits"),
                decoded.get("parse_error", "")),
            "signature_hash": signature_hash,
            "weak_signature_hash": signature_hash_is_weak(signature_hash),
            # A SNAPSHOT of a comparison against a clock, which goes stale between passes. A
            # null validity end reads as expired: the certificate was not shown to be current.
            "is_expired": (not_valid_after is None
                           or not_valid_after <= timezone.now()),
        }, [("is_ca", ca_rk, ca_rv), ("private_key_on_hsm", hsm_rk, hsm_rv)]))

    # The reference walk runs over the rows about to be written, not over the database, so it
    # cannot be out of step with them and needs no ordering guarantee between normalizers.
    referrers = collect_certificate_references(certificate_rows, tls_rows, cert_rows)
    for scoped, defaults, *_ in certificate_rows:
        found = referrers.get((scoped.scope, scoped.vsys_name, scoped.entry["@name"]), [])
        defaults["relied_on_by"] = sorted(
            found, key=lambda r: (r["kind"], r["scope"], r["vsys_name"], r["name"]))
        # The walk completed - every edge it has is in the rows above - so "found nothing" is
        # the only thing `True` can mean here. What it does NOT mean is "nothing relies on it":
        # see collect_certificate_references on why the map is a floor.
        defaults["not_relied_on"] = not found

    return {
        "certificates": write_scoped_objects(Certificate, appliance, snapshot, certificate_rows),
        "ssl_tls_service_profiles": write_scoped_objects(SslTlsServiceProfile, appliance, snapshot, tls_rows),
        "certificate_profiles": write_scoped_objects(CertificateProfile, appliance, snapshot, cert_rows),
        "scep_profiles": write_scoped_objects(ScepProfile, appliance, snapshot, scep_rows),
    }
