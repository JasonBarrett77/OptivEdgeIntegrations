"""Normalize the IKE crypto profiles and IKE gateways on one appliance.

Both objects are DEVICE-WIDE, read from the merged config's single device entry at
`network/ike/crypto-profiles/ike-crypto-profiles` and `network/ike/gateway`. Neither has a vsys
or a shared scope: stage 4 asked ten candidate paths on two platforms and two vsys postures and
found exactly one firewall-local scope for each.

THE CONTAINER HAS THREE STATES AND NOT TWO, which is the trap this module is written around and
which five earlier passes over this estate each got wrong in the same direction - making a device
look emptier than it is:

    absent              the node does not exist                     -> `None`
    present and empty   the node exists and holds no entry          -> `{"<container>": None}`
    populated           the node holds entries                      -> `{"<container>": {...}}`

A reader testing truthiness reports the first two identically, and they have DIFFERENT
consequences: "no crypto profile is defined" is the state that makes every gateway on the
appliance uncommittable, while "the node does not exist" is an appliance that was never
configured for IKE at all. `_ike_container` returns the three apart, and `ensure_list` is what
makes a SINGLE entry - which arrives as a bare dict and not a list of one - iterate the same way
as fourteen of them.

Measured against the lab 2026-10-28, reading both views on both appliances: pan-fw-111 carries 14
profiles and 9 gateways; pan-fw-201 carries 4 profiles and its gateway container is ABSENT
entirely (`action=get` answers None and `action=show` RAISES "No such node" - the raise is the
reading). Those four profiles are LOCAL: they read identically in the merged and running views
and carry no @ptpl and no @src. Nothing in this lab exercises the template scope at these paths.

THE READ IS CANDIDATE-DERIVED AND THAT IS NOT A DETAIL HERE. `action=get` is the merged view and
includes STAGED edits, so an uncommitted change is reported as configuration. On the gateway's
`authentication` container that is the sharpest trap in the domain: the two branches are
exclusive and the exclusion is enforced by SILENT REPLACEMENT at the write, so with a certificate
branch staged over a committed pre-shared key the merged and running views report DIFFERENT
authentication methods for the same gateway in the same second. This module normalizes the merged
view, which is what a collector issues, so `peer_authentication` reports the staged answer.
"""

from __future__ import annotations

import math
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    FieldProvenance,
    IkeCryptoProfile,
    IkeGateway,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    Implicit,
    classify_prov_type,
    ensure_list,
    iter_member_values,
    parse_integer_field,
    parse_text_field,
    parse_yes_no_field,
    provenance_raw_key,
    provenance_value,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)

#: The entry-level provenance record - the entry's own marker rather than one of its fields.
ENTRY_FIELD = "__entry__"

#: Attributes that say an ENTRY came from somewhere other than this device. Measured as ZERO at
#: both IKE paths on all four lab appliances, by stage 4 and again by stage 7's readback - so
#: every row collected here is `local`, and the template mapping is for an estate that pushes
#: these paths rather than for anything that has been seen.
ENTRY_PROVENANCE_ATTRIBUTES = {
    "@ptpl": FieldProvenance.ProvenanceType.TEMPLATE,
    "@src": FieldProvenance.ProvenanceType.PANORAMA,
}

#: The three entries PAN-OS ships under this node's name. They are ORDINARY WRITABLE, DELETABLE
#: config at the same xpath as a custom entry - there is no predefined IKE crypto profile at all
#: (/config/predefined/network-profile holds `bfd-profile` and nothing else on all four
#: appliances) - so they must NEVER be given the PREDEFINED entry-provenance sentinel, which
#: asserts "shipped in the release and not editable here". That they are deletable is what makes
#: PAN-IKE-009's remedy possible.
FACTORY_PROFILE_NAMES = ("default", "Suite-B-GCM-128", "Suite-B-GCM-256")

# ---------------------------------------------------------------------------
# The orderings. WEAKEST FIRST, because what a control grades is the weakest member a profile
# still OFFERS - the profile offers every member and takes the first a peer accepts, so a weak
# member left in place is a live option and not a lower preference.
# ---------------------------------------------------------------------------

#: PAN-IKE-002's severity order over the nine classical groups and `none`.
#:
#: `none` IS PLACED FIRST AND THE SPEC DOES NOT BREAK THE TIE. It shares the top severity with
#: group1 and group2, and stage 5 gives a severity order rather than a total one, so a profile
#: offering `none` beside group1 is ordered by a decision taken here: `none` is a member that can
#: take the key agreement OUT of the proposal entirely ("Make this round optional", the device's
#: own help string), which stage 5 calls the worst outcome available. Within the classical
#: members the order is bit strength, which is the order the severities follow.
DH_GROUP_ORDER = (
    "none", "group1", "group2", "group5", "group14", "group15", "group16",
    "group19", "group20", "group21",
)

#: The groups that MEET PAN-IKE-002's floor: finite-field at 2048 bits or more, or elliptic
#: curve. `none` and every weaker finite-field group fail, and so does an unranked post-quantum
#: member - not because it is weak, but because no ordering places it.
DH_GROUP_FLOOR_MET = frozenset(
    {"group14", "group15", "group16", "group19", "group20", "group21"})

#: PAN-IKE-003's severity order, which places all six members measured at this leaf. `des` is NOT
#: a member at this path on any appliance - it lives on a manual-key tunnel's ESP leaf, which
#: runs no key exchange - so the real floor here is 3des.
ENCRYPTION_ORDER = (
    "3des", "aes-128-cbc", "aes-192-cbc", "aes-128-gcm", "aes-256-cbc", "aes-256-gcm",
)

#: Authenticated-encryption ciphers. The condition PAN-IKE-004's `non-auth` exception turns on.
AEAD_CIPHERS = frozenset({"aes-128-gcm", "aes-256-gcm"})

#: PAN-IKE-004's severity order. `non-auth` RANKS WITH md5 AND NOT BELOW sha1, because on a
#: profile offering no AEAD cipher it is not a weak hash - it is no integrity algorithm at all.
#: Stage 5 ties it with md5 and does not order the pair; `non-auth` is placed first here for the
#: same reason `none` is placed first above.
HASH_ORDER = ("non-auth", "md5", "sha1", "sha256", "sha384", "sha512")

#: The family PAN-IKE-004 requires.
SHA2_HASHES = frozenset({"sha256", "sha384", "sha512"})

#: PAN-IKE-005's bound on the key lifetime, applied to the re-authentication product for want of
#: any other: stage 3 states no target interval, so the number a customer accepts is an engineer
#: question and this is the control's own floor carried onto the product.
REAUTH_BOUND_HOURS = 24

#: Seconds in one hour, for the lifetime coalescing below.
_HOUR_SECONDS = 3600

#: The four unit branches of the `lifetime` choice container, with their multiplier into hours.
#: THE UNIT IS WHICH CHILD ELEMENT EXISTS and is not a value anywhere on the device.
#:
#: WRITING ONE BRANCH SILENTLY DESTROYS ANOTHER, measured: with lifetime/hours=1 stored, a set of
#: <seconds>300</seconds> at the same container was accepted without comment, the read-back
#: carried only the seconds branch, and the commit returned OK. Nothing reports the discard - not
#: the write, not the commit, not the read. So a payload collected before such a write holds a
#: branch that no longer exists, and only one branch is ever present in one reading.
LIFETIME_BRANCHES = (
    ("seconds", 1),
    ("minutes", 60),
    ("hours", _HOUR_SECONDS),
    ("days", 24 * _HOUR_SECONDS),
)


# ---------------------------------------------------------------------------
# Absent-key declarations. Stage 4 recorded `consumer_disposition: not_assumed` and
# `may_materialise: false` on EVERY ONE of its 31 field records across both objects, so
# `Implicit.not_assumed` is the only declaration permitted here - and it is also the honest one.
# NOT ONE ROW OF EITHER MODEL WILL EVER CARRY A VENDOR FACT, which is a strange property for a
# crypto-defaults domain and is the measured shape of this domain's evidence.
# ---------------------------------------------------------------------------

_MANDATORY_LIST_ABSENT = (
    "stage 4 measured this key MANDATORY at commit validation - 'is missing {key}' / "
    "'ike-crypto-profiles is invalid' - so it is NEVER observed absent on a COMMITTED profile "
    "and an absence asserts nothing about configuration. A collected row missing it is a STAGED, "
    "uncommittable profile and not a profile sitting at a default, which is a different thing")

DH_GROUPS_ABSENT = Implicit.not_assumed(_MANDATORY_LIST_ABSENT.format(key="dh-group"))
ENCRYPTION_ABSENT = Implicit.not_assumed(_MANDATORY_LIST_ABSENT.format(key="encryption"))
HASH_ABSENT = Implicit.not_assumed(_MANDATORY_LIST_ABSENT.format(key="hash"))

AUTHENTICATION_MULTIPLE_ABSENT = Implicit.not_assumed(
    "stage 4 recorded the implicit value UNMEASURED: the key is optional, a profile commits "
    "without it, and the only oracle that could settle it is a rendering no screen was opened "
    "for. The stake is larger than the field: if the implicit value IS the documented 0, every "
    "profile that never set this key already has re-authentication disabled, and the control "
    "fires on the whole estate by default rather than on a misconfiguration. Nothing is stored "
    "rather than the vendor's 0, because assuming any other value would report a "
    "re-authentication bound that may not be there")

PRE_SHARED_KEY_ABSENT = Implicit.not_assumed(
    "the key is mandatory whenever the pre-shared-key branch exists, and that branch is one of "
    "two satisfying a mandatory parent - so an absence here is the CERTIFICATE branch being in "
    "use and not a default. Nothing is stored for the secret in any case: a 31-character "
    "plaintext reads back as a 77-character ciphertext, so a length comparison over it would "
    "measure the encoding and pass a four-character key")

DISABLED_ABSENT = Implicit.not_assumed(
    "stage 4 recorded the implicit value UNMEASURED and nothing was written to this key. THE "
    "POLARITY IS NEGATED, so getting the absent state wrong is dangerous in both directions, and "
    "the key's own name plus the vendor's convention that an explicit disable is something a "
    "reader turns on is a guess rather than a reading")

IKE_VERSION_ABSENT = Implicit.not_assumed(
    "stage 4 recorded this implicit UNMEASURED and called it the strongest lead in the domain "
    "left unpromoted. For `ikev1`: the config is silent in every view, the key CAN be absent on "
    "a committed gateway (proved by deleting it and committing), and the ikemgr phase-1 abort "
    "named the IKEV1 SECTION on a gateway storing no version key. Against: the 11.2 schema "
    "@default says ikev2. Stage 4 named the one write that would settle it and did not pay it")

EXCHANGE_MODE_ABSENT = Implicit.not_assumed(
    "stage 4 recorded the implicit UNMEASURED. The key is optional - a gateway commits without "
    "it - and the stake is the control's own: if the implicit value IS `auto`, every gateway "
    "that never set this key is in the state PAN-IKE-007 fires on. Both the schema @default and "
    "the vendor Help say `auto` and neither is a measurement of what the device does with the "
    "key absent; no refusal in 39 writes named an effective exchange mode")

CERTIFICATE_PROFILE_ABSENT = Implicit.not_assumed(
    "stage 4 recorded the implicit UNMEASURED. The key is optional - a gateway commits with the "
    "certificate branch and no profile named, as long as `local-certificate` is there - so it "
    "has a real absent state, and what that absence asserts is the whole of PAN-IKE-006's second "
    "clause. Stage 4's hypothesis, untested: an absent profile means NO peer-certificate "
    "validation constraints are applied at all, which would make the absence a FINDING rather "
    "than a default")

_DPD_ENABLE_ABSENT = (
    "stage 4 recorded the implicit UNMEASURED. Optional - a gateway commits without it - and the "
    "direction matters: if absent means `no`, every gateway that never set this key has no "
    "detection and the control fires across the estate by default rather than on a "
    "misconfiguration. THERE IS NO DOCUMENTED DEFAULT FOR THE SWITCH ITSELF either: help "
    "p.651-652 documents the INTERVAL's default and not the enable's. The operational reads that "
    "would show a probe on the wire are HTTP 403 to this project's credential")

IKEV1_DPD_ENABLE_ABSENT = Implicit.not_assumed(_DPD_ENABLE_ABSENT)
IKEV2_DPD_ENABLE_ABSENT = Implicit.not_assumed(_DPD_ENABLE_ABSENT)

IKEV2_DPD_INTERVAL_ABSENT = Implicit.not_assumed(
    "stage 4 recorded the implicit UNMEASURED. Optional. The vendor documents 5 seconds (help "
    "p.652) and the device offers no default, so a gateway with the switch on and no interval is "
    "at 5 seconds BY DOCUMENTATION ONLY. Storing the 5 would promote `documented` to a stored "
    "vendor fact, which rules.md forbids")

IKEV1_DPD_RETRY_ABSENT = Implicit.not_assumed(
    "stage 4 recorded `implicit.status: not_reached` - state B was not run for this key and no "
    "value was written to it, so there is not even an unmeasured reading behind it. The key "
    "EXISTS ONLY ON THE IKEV1 BRANCH, measured on all four appliances")

_CRYPTO_POINTER_ABSENT = (
    "stage 4 recorded the implicit UNMEASURED and called the ikev1 one THE MOST IMPORTANT "
    "UNMEASURED VALUE IN THE DOMAIN, because PAN-IKE-009 inverts on it. The hypothesis is that "
    "an absent pointer resolves to the profile NAMED `default`, on three device statements: a "
    "pointerless gateway on an appliance with an empty collection ABORTED commit phase 1 with "
    "'ikev1 section lacks kmp_enc_alg / kmp_hash_alg / kmp_dh_group'; writing the literal "
    "`default` where no such profile exists is refused with 'default crypto profile doesn't "
    "exist'; and where it does exist action=complete marks it @default='yes'. The positive "
    "control was attempted and not paid, so nothing is stored")

IKEV1_CRYPTO_PROFILE_ABSENT = Implicit.not_assumed(_CRYPTO_POINTER_ABSENT)
IKEV2_CRYPTO_PROFILE_ABSENT = Implicit.not_assumed(_CRYPTO_POINTER_ABSENT)


# ---------------------------------------------------------------------------
# Reading the payload
# ---------------------------------------------------------------------------

def _ike_container(device_entry: dict, *path: str) -> tuple[str, list[dict]]:
    """(state, entries) for one IKE collection, telling the container's THREE states apart.

    `state` is "absent", "empty" or "populated". `entries` is always a list, so a single entry -
    which arrives as a BARE DICT and not a list of one - iterates like any other count.

    The distinction is the point rather than a nicety. Testing truthiness reports "absent" and
    "empty" identically, and on this object they mean different things: an empty crypto-profile
    collection is the state in which every gateway on the appliance is uncommittable, while an
    absent gateway collection is an appliance that terminates no site-to-site key exchange at
    all. Both shapes occur in this lab.
    """
    node: Any = device_entry
    for step in path[:-1]:
        if not isinstance(node, dict):
            return "absent", []
        node = node.get(step)
        if node is None:
            return "absent", []
    leaf = path[-1]
    if not isinstance(node, dict) or leaf not in node:
        return "absent", []
    holder = node.get(leaf)
    if holder is None:
        # PRESENT AND EMPTY: the key exists and carries nothing.
        return "empty", []
    if not isinstance(holder, dict):
        return "empty", []
    entries = [e for e in ensure_list(holder.get("entry")) if isinstance(e, dict)]
    return ("populated" if entries else "empty"), entries


def _entry_provenance(entry: dict) -> tuple[str, str, str]:
    """(type, raw key, raw value) for the entry's OWN provenance.

    An unmarked entry is LOCAL, which is a positive statement and not the absence of one: a
    missing row would mean only that nothing tracks the entry. Measured as unmarked on every
    entry at both IKE paths in this lab - including pan-fw-201's three factory-named profiles,
    which are local writable config and NOT predefined.
    """
    for attribute, provenance_type in ENTRY_PROVENANCE_ATTRIBUTES.items():
        value = entry.get(attribute)
        if value:
            return provenance_type, attribute, str(value)
    return FieldProvenance.ProvenanceType.LOCAL, "", ""


def _member_list(node: Any, *, implicit: Implicit) -> tuple[list[str], Any, str | None]:
    """A PAN-OS member list as (values, raw key, raw provenance value).

    The values keep THE DEVICE'S OWN SPELLING AND THE DEVICE'S OWN ORDER, because these lists are
    offer sets: the profile offers every member and takes the first a peer accepts.

    `scalar_value` is used only for the node's provenance marker - it scans the marker keys and
    returns the one present, which is exactly what is needed and is not available otherwise -
    while `iter_member_values` reads the members, including the single-member case that arrives
    as a bare string rather than a list.
    """
    _, raw_key, raw_prov = scalar_value(node)
    if raw_key is ABSENT:
        return [], implicit, None
    return [value for value, _ in iter_member_values(node) if value], raw_key, raw_prov


def _weakest(offered: list[str], order: tuple[str, ...]) -> str | None:
    """The weakest member on offer, by `order`. None where nothing was collected.

    A MEMBER THE ORDER DOES NOT PLACE IS NOT SILENTLY DROPPED. Where the offer set holds only
    members outside `order` - the eighteen post-quantum key-agreement groups are the real case -
    the first as the DEVICE listed it is returned, and the grading places it unranked. Returning
    None there would read as "nobody collected this", which is a different claim.
    """
    if not offered:
        return None
    placed = [m for m in order if m in offered]
    if placed:
        return placed[0]
    return offered[0]


def _lifetime(node: Any) -> tuple[str | None, int | None]:
    """(unit, hours) from the `lifetime` choice container, rounded UP.

    ROUNDING UP is stage 5's settlement of a question stage 2 left open, in the direction stage 3
    asked for: a lifetime written in seconds or minutes that is under an hour stores 1 and never
    0, so it lands in the acceptable band instead of falling outside every band.

    Only one branch is ever present - the container is a choice, and writing one branch silently
    deletes the other.
    """
    if not isinstance(node, dict):
        return None, None
    for unit, multiplier in LIFETIME_BRANCHES:
        text, raw_key, _ = scalar_value(node.get(unit))
        if raw_key is ABSENT or not text:
            continue
        try:
            value = int(text)
        except ValueError:
            # Present and unparseable: the unit is still known - the element exists - and the
            # number is not. Reporting the unit without a number is honest; inventing one is not.
            return unit, None
        if value <= 0:
            return unit, None
        return unit, max(1, math.ceil(value * multiplier / _HOUR_SECONDS))
    return None, None


# ---------------------------------------------------------------------------
# The computations
# ---------------------------------------------------------------------------

def dh_group_floor_met(offered: list[str]) -> bool:
    """Every group offered meets PAN-IKE-002's floor. False is the finding side.

    An unranked post-quantum member counts as NOT meeting the floor because no ordering places
    it, and an empty offer set is False rather than vacuously True: a profile whose list nobody
    collected has not been shown to meet anything.
    """
    return bool(offered) and all(member in DH_GROUP_FLOOR_MET for member in offered)


def encryption_floor_met(offered: list[str]) -> bool:
    """Every cipher offered is AES - that is, `3des` is absent. False is the finding side.

    THE VENDOR'S ONLY ADVICE HERE IS ABOUT ORDER and following it to the letter leaves the weak
    cipher negotiable: help p.658 says "change the order (top to bottom) to the following" while
    p.657 says the list is tried top to bottom "until an attempt is successful". So a profile
    ordered exactly as the vendor recommends still offers 3DES to a peer that offers nothing
    else, which is why this is a floor over the WHOLE SET and not a check on the first member.
    """
    return bool(offered) and all(member != "3des" for member in offered)


def offers_aead_cipher(offered: list[str]) -> bool:
    """The profile offers an authenticated-encryption cipher."""
    return any(member in AEAD_CIPHERS for member in offered)


def hash_floor_met(hashes: list[str], ciphers: list[str]) -> bool:
    """Every integrity algorithm is SHA-2, with `non-auth` permitted ONLY alongside an AEAD
    cipher. False is the finding side.

    TWO LISTS, WHICH IS WHY THIS IS A COLUMN AND NOT A QUERY: a clause has one field slot. The
    exception is not optional generosity - the vendor MANDATES `non-auth` with an AES-GCM cipher
    (help p.658), so a one-list test would fire on exactly the configuration a customer was told
    to make, and would spend their remediation budget on it.

    AND THE DEVICE DOES NOT ENFORCE THE PAIRING IN THE OTHER DIRECTION, measured: a profile
    offering hash {sha256, non-auth} with encryption {aes-256-cbc} and no AEAD cipher anywhere
    was accepted at the write and committed OK. So `non-auth` can stand on a profile that has no
    AEAD cipher to justify it, and that profile has no integrity algorithm a peer must use.

    THE MIXED CASE the grading alone could not cover: a profile offering BOTH an AEAD cipher and
    a non-AEAD one needs `non-auth` for the first AND a SHA-2 member for the second, so an
    AEAD-justified `non-auth` on its own is not enough there.
    """
    if not hashes:
        return False
    aead = offers_aead_cipher(ciphers)
    for member in hashes:
        if member in SHA2_HASHES:
            continue
        if member == "non-auth" and aead:
            continue
        return False
    if aead and any(c not in AEAD_CIPHERS for c in ciphers) and not (set(hashes) & SHA2_HASHES):
        return False
    return True


def reauth_interval(multiple: int | None, lifetime_hours: int | None) -> tuple[int | None, bool]:
    """(interval in hours, bounded) for the IKEv2 re-authentication interval.

    ZERO IS THE SENTINEL AND IT IS SPECIAL-CASED BEFORE ANY COMPARISON. The device's own words:
    "IKEv2 SA reauthentication interval equals authetication-multiple * rekey-lifetime; 0 means
    reauthentication disabled" - the misspelling is the vendor's. It is the UNBOUNDED end of the
    axis while sorting as the smallest number, so every numeric comparison reads it as the
    strictest setting available. The interval is held null there, because 0 is not a short
    interval but the absence of one.

    An unread multiplier and the measured 0 are deliberately treated ALIKE in `bounded`, which is
    the one place in this domain where a measured value and an absence give the same answer.
    """
    if multiple is None or lifetime_hours is None:
        return None, False
    if multiple == 0:
        return None, False
    product = multiple * lifetime_hours
    return product, product <= REAUTH_BOUND_HOURS


def relies_on_factory_named_proposal(ikev1_name: str, ikev2_name: str) -> bool:
    """Either pointer names a factory-shipped proposal, OR NEITHER POINTER IS SET. True is the
    finding side.

    THE BOTH-EMPTY CASE IS THE HALF THAT GOES BEYOND A LIST-MEMBERSHIP TEST, and it rests on a
    measurement: a gateway with neither leaf set still CONSUMES a proposal - the ikemgr phase-1
    abort proves the ikev1 section demands algorithms with no pointer present - and nothing
    stored says which. rules.md's direction-of-error rule decides it: a gateway whose proposal
    nothing records is a gateway secured by something nobody has identified.

    THE THREE NAMES ARE NOT EVIDENCE OF WEAKNESS and this does not claim they are. The assertion
    is about provenance and ownership: a proposal nobody chose is a proposal nobody owns.
    """
    named = [name for name in (ikev1_name, ikev2_name) if name]
    if not named:
        return True
    return any(name in FACTORY_PROFILE_NAMES for name in named)


def _gateway_profile_references(entries: list[dict]) -> dict[str, dict[str, bool]]:
    """Per profile name, what the gateways on this appliance say about it.

    Returns {name: {"referenced": bool, "ikev2": bool}}.

    COMPUTED FROM THE SAME PAYLOAD AS THE PROFILES, in the same pass, rather than read back from
    IkeGateway rows: the two then cannot disagree and neither normalizer depends on the other
    having run first. With no gateway container at all - pan-fw-201 - every profile correctly
    gets both answers False, which is what an absent container means and not a missing read.

    `ikev2` is PAN-IKE-005's cross-object applicability condition: a gateway names this profile
    from its ikev2 pointer, or names it from either pointer while its version is anything other
    than `ikev1`. No query can express it, because the multiplier is on the profile and the
    version is on the gateway.
    """
    out: dict[str, dict[str, bool]] = {}
    for entry in entries:
        protocol = entry.get("protocol")
        protocol = protocol if isinstance(protocol, dict) else {}
        version, _, _ = scalar_value(protocol.get("version"))
        for branch in ("ikev1", "ikev2"):
            body = protocol.get(branch)
            if not isinstance(body, dict):
                continue
            name, _, _ = scalar_value(body.get("ike-crypto-profile"))
            if not name:
                continue
            record = out.setdefault(name, {"referenced": False, "ikev2": False})
            record["referenced"] = True
            if branch == "ikev2" or version != "ikev1":
                record["ikev2"] = True
    return out


# ---------------------------------------------------------------------------
# Persisting
# ---------------------------------------------------------------------------

def _replace(model, appliance: Appliance):
    """Drop this appliance's rows and their provenance. Returns the content type."""
    content_type = ContentType.objects.get_for_model(model)
    FieldProvenance.objects.filter(
        content_type=content_type,
        object_id__in=list(
            model.objects.filter(appliance=appliance).values_list("pk", flat=True)),
    ).delete()
    model.objects.filter(appliance=appliance).delete()
    return content_type


def _write_provenance(content_type, obj, entry: dict,
                      rows: list[tuple[str, Any, str | None]]) -> None:
    """One row per tracked field, plus the entry's own.

    A row is written for a PRESENT key saying where it came from, AND for an ABSENT one saying
    what the absence means - skipping the absent ones is what left "PAN-OS supplied it", "we
    inferred it" and "nobody tracks it" sharing one blank. A missing row now means only that the
    field is not tracked.

    On this domain every absent tracked key records `not_configured`: stage 4 licensed no
    implicit value anywhere on either object, so NOT ONE ROW HERE WILL EVER CARRY A VENDOR FACT.
    """
    provenance_type, raw_key, raw_value = _entry_provenance(entry)
    FieldProvenance.objects.create(
        content_type=content_type, object_id=obj.pk, field_name=ENTRY_FIELD,
        provenance_type=provenance_type, raw_key=raw_key[:32], raw_value=raw_value[:128])
    for field_name, key, value in rows:
        if key is ABSENT:
            continue
        FieldProvenance.objects.create(
            content_type=content_type, object_id=obj.pk, field_name=field_name,
            provenance_type=classify_prov_type(key),
            raw_key=provenance_raw_key(key)[:32],
            raw_value=provenance_value(key, value)[:128])


def _profile_rows(entry: dict) -> tuple[dict, list[tuple[str, Any, str | None]]]:
    """The measured half of one profile: (column values, provenance rows)."""
    dh_groups, dh_key, dh_prov = _member_list(entry.get("dh-group"), implicit=DH_GROUPS_ABSENT)
    ciphers, enc_key, enc_prov = _member_list(
        entry.get("encryption"), implicit=ENCRYPTION_ABSENT)
    hashes, hash_key, hash_prov = _member_list(entry.get("hash"), implicit=HASH_ABSENT)
    multiple, mult_key, mult_prov = parse_integer_field(
        entry.get("authentication-multiple"), implicit=AUTHENTICATION_MULTIPLE_ABSENT)
    return (
        {"dh_groups": dh_groups, "encryption_ciphers": ciphers, "hash_algorithms": hashes,
         "authentication_multiple": multiple},
        [("dh_groups", dh_key, dh_prov),
         ("encryption_ciphers", enc_key, enc_prov),
         ("hash_algorithms", hash_key, hash_prov),
         ("authentication_multiple", mult_key, mult_prov)],
    )


def normalize_ike_crypto_profiles(appliance: Appliance) -> list[IkeCryptoProfile]:
    """Replace every IKE crypto profile for one appliance. Returns what was written.

    An appliance whose collection is ABSENT or EMPTY writes no row and raises nothing: there is
    no profile to describe, which is a reading and not a failure. The entry grain has no row for
    "no crypto profile is defined on this appliance" - a real measured state, and the one that
    makes every gateway on it uncommittable - and no control in this domain asserts on it.
    """
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")
    device_entry = device_entry_from_snapshot(snapshot)

    _, entries = _ike_container(
        device_entry, "network", "ike", "crypto-profiles", "ike-crypto-profiles")
    # The references come from the SAME payload, so the two models cannot disagree and neither
    # depends on the other having been normalized first.
    _, gateway_entries = _ike_container(device_entry, "network", "ike", "gateway")
    references = _gateway_profile_references(gateway_entries)

    written: list[IkeCryptoProfile] = []
    with transaction.atomic():
        content_type = _replace(IkeCryptoProfile, appliance)
        seen: set[str] = set()
        for entry in entries:
            name = str(entry.get("@name") or "").strip()
            if not name or name in seen:
                # An entry with no name is not an entry, and a duplicate name is not expressible
                # in PAN-OS. Neither can be keyed, so neither is written.
                continue
            seen.add(name)
            measured, provenance_rows = _profile_rows(entry)
            dh_groups = measured["dh_groups"]
            ciphers = measured["encryption_ciphers"]
            hashes = measured["hash_algorithms"]
            multiple = measured["authentication_multiple"]
            unit, hours = _lifetime(entry.get("lifetime"))
            interval, bounded = reauth_interval(multiple, hours)
            reference = references.get(name) or {}
            profile = IkeCryptoProfile.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                source_snapshot=snapshot,
                entry_name=name,
                scope=IkeCryptoProfile.SCOPE_DEVICE_LOCAL,
                vsys_name="",
                dh_groups=dh_groups,
                weakest_dh_group=_weakest(dh_groups, DH_GROUP_ORDER),
                dh_group_floor_met=dh_group_floor_met(dh_groups),
                encryption_ciphers=ciphers,
                weakest_encryption_cipher=_weakest(ciphers, ENCRYPTION_ORDER),
                encryption_floor_met=encryption_floor_met(ciphers),
                offers_aead_cipher=offers_aead_cipher(ciphers),
                hash_algorithms=hashes,
                weakest_hash_algorithm=_weakest(hashes, HASH_ORDER),
                hash_floor_met=hash_floor_met(hashes, ciphers),
                key_lifetime_unit=unit,
                key_lifetime_hours=hours,
                key_lifetime_known=hours is not None,
                authentication_multiple=multiple,
                authentication_multiple_known=multiple is not None,
                reauth_interval_hours=interval,
                reauth_interval_bounded=bounded,
                used_by_ikev2_gateway=bool(reference.get("ikev2")),
                referenced_by_gateway_on_this_appliance=bool(reference.get("referenced")),
            )
            _write_provenance(content_type, profile, entry, provenance_rows)
            written.append(profile)
    return written


def _gateway_values(entry: dict) -> tuple[dict, list[tuple[str, Any, str | None]]]:
    """One gateway's columns and provenance rows, read out of its entry.

    EVERY TRACKED LEAF GOES THROUGH A `parse_*` HELPER AND NEVER THROUGH BARE `scalar_value`.
    The bare path receives the ABSENT sentinel and writes NO row, which the consumer records as a
    surviving defect in sixteen fields across eight modules rather than a pattern to copy - and
    on this object, where seven keys have real absent states, it would make all seven read as
    untracked. `scalar_value` is used only where no key is being tracked: the branch-existence
    tests, which have no leaf of their own.
    """
    protocol = entry.get("protocol")
    protocol = protocol if isinstance(protocol, dict) else {}
    ikev1 = protocol.get("ikev1") if isinstance(protocol.get("ikev1"), dict) else {}
    ikev2 = protocol.get("ikev2") if isinstance(protocol.get("ikev2"), dict) else {}
    ikev1_dpd = ikev1.get("dpd") if isinstance(ikev1.get("dpd"), dict) else {}
    ikev2_dpd = ikev2.get("dpd") if isinstance(ikev2.get("dpd"), dict) else {}
    auth = entry.get("authentication")
    auth = auth if isinstance(auth, dict) else {}
    certificate = auth.get("certificate") if isinstance(auth.get("certificate"), dict) else {}

    disabled, dis_key, dis_prov = parse_yes_no_field(
        entry.get("disabled"), implicit=DISABLED_ABSENT)
    version, ver_key, ver_prov = parse_text_field(
        protocol.get("version"), implicit=IKE_VERSION_ABSENT)
    mode, mode_key, mode_prov = parse_text_field(
        ikev1.get("exchange-mode"), implicit=EXCHANGE_MODE_ABSENT)
    cert_profile, cp_key, cp_prov = parse_text_field(
        certificate.get("certificate-profile"), implicit=CERTIFICATE_PROFILE_ABSENT)
    v1_enable, v1e_key, v1e_prov = parse_yes_no_field(
        ikev1_dpd.get("enable"), implicit=IKEV1_DPD_ENABLE_ABSENT)
    v2_enable, v2e_key, v2e_prov = parse_yes_no_field(
        ikev2_dpd.get("enable"), implicit=IKEV2_DPD_ENABLE_ABSENT)
    v2_interval, v2i_key, v2i_prov = parse_integer_field(
        ikev2_dpd.get("interval"), implicit=IKEV2_DPD_INTERVAL_ABSENT)
    v1_retry, v1r_key, v1r_prov = parse_integer_field(
        ikev1_dpd.get("retry"), implicit=IKEV1_DPD_RETRY_ABSENT)
    v1_profile, v1p_key, v1p_prov = parse_text_field(
        ikev1.get("ike-crypto-profile"), implicit=IKEV1_CRYPTO_PROFILE_ABSENT)
    v2_profile, v2p_key, v2p_prov = parse_text_field(
        ikev2.get("ike-crypto-profile"), implicit=IKEV2_CRYPTO_PROFILE_ABSENT)

    # The pre-shared key is a PRESENCE test and nothing else: the secret's value is never stored.
    # The row is the point - it is the only record of WHO set the credential, local or template,
    # which is what an assessor asks about a secret they can read in a backup. That is why the
    # column stays MEASURED rather than becoming a derived one, and it is the shipped
    # `SnmpSettings.community_is_default` reasoning exactly.
    psk_text, psk_key, psk_prov = scalar_value(
        (auth.get("pre-shared-key") or {}).get("key")
        if isinstance(auth.get("pre-shared-key"), dict) else None)
    if psk_key is ABSENT:
        psk_key, psk_prov = PRE_SHARED_KEY_ABSENT, None
        uses_psk = False
    else:
        uses_psk = bool(psk_text)

    # WHICH OF THE TWO SUBTREES EXISTS is the authentication method: there is no method field and
    # no enum anywhere on the device. The two are genuinely exclusive - measured - so this cannot
    # see both, and a gateway holding both is a state the device will never produce.
    if certificate:
        peer_auth = (IkeGateway.PeerAuthentication.CERTIFICATE_WITH_PROFILE if cert_profile
                     else IkeGateway.PeerAuthentication.CERTIFICATE_WITHOUT_PROFILE)
    elif uses_psk:
        peer_auth = IkeGateway.PeerAuthentication.PRE_SHARED_KEY
    else:
        # Neither branch. The parent is mandatory at commit validation, so this is a row nobody
        # computed or a staged entry - never a device that answered "unauthenticated".
        peer_auth = ""

    return (
        {
            "disabled": disabled,
            # An ABSENT or unread `disabled` counts as ACTIVE, so the gateway stays in scope and
            # is assessed rather than excused. False only where the key read `yes`.
            "gateway_is_active": disabled is not True,
            "ike_version": version,
            "ikev1_exchange_mode": mode,
            "peer_authentication": peer_auth,
            "certificate_profile_name": cert_profile,
            # The CONTAINER's existence, not a name: it is conditionally mandatory once the
            # certificate branch exists, which is what lets a finding tell a configured gateway
            # from an uncommittable one.
            "local_certificate_named": isinstance(
                certificate.get("local-certificate"), (dict, str)),
            "uses_pre_shared_key": uses_psk,
            "ikev1_dpd_enabled": v1_enable,
            "ikev1_dpd_enabled_known": v1_enable is not None,
            "ikev2_dpd_enabled": v2_enable,
            "ikev2_dpd_enabled_known": v2_enable is not None,
            "ikev2_dpd_interval": v2_interval,
            "ikev1_dpd_retry": v1_retry,
            "ikev1_crypto_profile_name": v1_profile,
            "ikev2_crypto_profile_name": v2_profile,
            "relies_on_factory_named_proposal": relies_on_factory_named_proposal(
                v1_profile, v2_profile),
        },
        [("disabled", dis_key, dis_prov),
         ("ike_version", ver_key, ver_prov),
         ("ikev1_exchange_mode", mode_key, mode_prov),
         ("certificate_profile_name", cp_key, cp_prov),
         ("uses_pre_shared_key", psk_key, psk_prov),
         ("ikev1_dpd_enabled", v1e_key, v1e_prov),
         ("ikev2_dpd_enabled", v2e_key, v2e_prov),
         ("ikev2_dpd_interval", v2i_key, v2i_prov),
         ("ikev1_dpd_retry", v1r_key, v1r_prov),
         ("ikev1_crypto_profile_name", v1p_key, v1p_prov),
         ("ikev2_crypto_profile_name", v2p_key, v2p_prov)],
    )


def normalize_ike_gateways(appliance: Appliance) -> list[IkeGateway]:
    """Replace every IKE gateway for one appliance. Returns what was written.

    An appliance with no gateway collection writes no row and raises nothing. That is the
    commonest state in this lab - and the shape rules.md warns about twice applies to it: every
    assertion on this object carries `gateway_is_active` or a version clause as APPLICABILITY, so
    an absent object SUPPRESSES all six gateway controls where an assertion clause on the same
    object would have raised them. The suppression is right here, because an appliance that
    terminates no key exchange has no tunnel to be weak - but it is a suppression and not a pass.
    """
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")
    device_entry = device_entry_from_snapshot(snapshot)
    _, entries = _ike_container(device_entry, "network", "ike", "gateway")

    written: list[IkeGateway] = []
    with transaction.atomic():
        content_type = _replace(IkeGateway, appliance)
        seen: set[str] = set()
        for entry in entries:
            name = str(entry.get("@name") or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            values, provenance_rows = _gateway_values(entry)
            gateway = IkeGateway.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                source_snapshot=snapshot,
                entry_name=name,
                scope=IkeGateway.SCOPE_DEVICE_LOCAL,
                vsys_name="",
                **values,
            )
            _write_provenance(content_type, gateway, entry, provenance_rows)
            written.append(gateway)
    return written
