"""Assemble the IPSec tunnel path from the rows the four collection normalizers wrote.

READS NO PAYLOAD. Every value this writes is already stored on an `IpsecTunnel`, an `IkeGateway`,
an `IkeCryptoProfile` or an `IpsecCryptoProfile` row for the same appliance, so this module joins
and copies and never parses - which is why a path can never disagree with the object page beside
it, and why it must run AFTER all four of those normalizers for the same appliance. `flows.py`
orders it last of the IPSec passes.

NO PROVENANCE ROWS ARE WRITTEN. Every column is declared derived on the model, and the authority
for any value lives on the component row this path points at through its four nullable foreign
keys. `_replace` here deletes the paths alone.

THE ROW SET, in Jason's keying order: one row per (tunnel, gateway) pair for every tunnel on the
appliance - with a blank gateway where the tunnel names none - and then one row per IKE gateway
on that appliance that no tunnel named. The second half is why an appliance holding gateways and
no tunnels still produces rows: PA-VM holds four IKE crypto profiles and three IPSec crypto
profiles with no tunnels and no gateways and produces none, which is the vacuous state
PAN-COV-001 and -002 cover and not this model's business.

WHICH IKE CRYPTO PROFILE A PATH RUNS ON. The gateway stores two names, one per IKE version
branch, and the version column decides: `ikev2` takes the v2 name, `ikev1` takes the v1 name, and
`ikev2-preferred` takes the v2 name because that is the branch it negotiates first - with
`ike_version` carried on the row beside it so the reader can see that the v1 branch is still
reachable. A gateway whose selected branch names nothing resolves NOT_NAMED, which is the invalid
configuration Jason named: *"IKE Crypto is a required field on IPSec Tunnel. If the value is
missing, that is an invalid configuration."*

WHICH IPSEC CRYPTO PROFILE. `IpsecTunnel.crypto_profile_name` already holds the stored reference
OR the literal `default` inferred where the tunnel stores none, and `crypto_profile_found` already
says whether it resolves on this appliance. This module distinguishes the inferred `default` from
a stored name, because the remedy differs, and treats both the inferred default and a dangling
name as UNRESOLVED - *"We can't know what the 'default' value means, so we should assume that it
fails if it is default, unspecified, or otherwise unknown."*

A STORED PROFILE NAMED `default` THAT RESOLVES IS STILL UNRESOLVED. A tunnel that explicitly
names `default` and an appliance that holds an entry called `default` would otherwise read as a
chosen, hardened profile; the whole point of the ruling above is that the name says nothing about
the content. So `default` is unresolved WHATEVER its resolution state, and the profile's own
columns are still copied onto the row so the reader sees what that entry offers.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    FieldProvenance,
    IkeCryptoProfile,
    IkeGateway,
    IpsecCryptoProfile,
    IpsecTunnel,
    IpsecTunnelPath,
)

#: The reference PAN-OS renders on a tunnel that stores no IPSec crypto profile at all. Inferred
#: by the tunnel normalizer rather than read, and it fails this path whatever it resolves to.
ASSUMED_DEFAULT_NAME = "default"

_RESOLUTION = IpsecTunnelPath.Resolution
_ORIGIN = IpsecTunnelPath.PathOrigin

#: Copied onto the path from the IKE crypto profile the gateway selects, under the same names the
#: nine controls' clauses already use.
IKE_CRYPTO_COLUMNS = (
    "dh_groups",
    "weakest_dh_group",
    "dh_group_floor_met",
    "encryption_ciphers",
    "weakest_encryption_cipher",
    "encryption_floor_met",
    "hash_algorithms",
    "weakest_hash_algorithm",
    "hash_floor_met",
    "offers_aead_cipher",
    "key_lifetime_hours",
    "key_lifetime_known",
    "key_lifetime_unit",
    "authentication_multiple",
    "authentication_multiple_known",
    "reauth_interval_hours",
    "reauth_interval_bounded",
)

#: Copied onto the path from the IPSec crypto profile the tunnel names.
IPSEC_CRYPTO_COLUMNS = (
    "protocol_branch",
    "esp_encryption",
    "esp_authentication",
    "ah_authentication",
    "weakest_encryption_offered",
    "weakest_integrity_offered",
    "all_offered_ciphers_authenticate",
    "integrity_meets_sha2_floor",
    "dh_group",
    "dh_group_meets_target",
    "lifetime_hours",
    "lifetime_unit",
    "lifetime_within_target",
)

#: Copied onto the path from the tunnel itself.
TUNNEL_COLUMNS = (
    "is_disabled",
    "anti_replay",
    "anti_replay_determined",
    "tunnel_monitor_enable",
    "tunnel_monitor_enable_determined",
    "monitor_action_effective",
)

#: Copied onto the path from the IKE gateway.
GATEWAY_COLUMNS = (
    "gateway_is_active",
    "ike_version",
    "ikev1_exchange_mode",
    "peer_authentication",
    "uses_pre_shared_key",
    "certificate_profile_name",
    "local_certificate_named",
)


def _replace(appliance: Appliance):
    """Drop this appliance's paths. Returns the content type.

    Paths carry no provenance rows of their own, and the delete below proves it rather than
    assuming it: anything that ever did get written against a path is removed with it.
    """
    content_type = ContentType.objects.get_for_model(IpsecTunnelPath)
    FieldProvenance.objects.filter(
        content_type=content_type,
        object_id__in=list(
            IpsecTunnelPath.objects.filter(appliance=appliance).values_list("pk", flat=True)),
    ).delete()
    IpsecTunnelPath.objects.filter(appliance=appliance).delete()
    return content_type


def gateway_names_on(tunnel: IpsecTunnel) -> list[str]:
    """The gateway names one tunnel references, in payload order, de-duplicated.

    `ike_gateway_names` is a JSON list or NULL. A tunnel that names none yields the empty list,
    which still produces ONE path row - with a blank gateway, which is how three of
    pan-fw-111's four tunnels are stored.
    """
    names = tunnel.ike_gateway_names or []
    if not isinstance(names, list):
        return []
    out: list[str] = []
    for name in names:
        if isinstance(name, str) and name and name not in out:
            out.append(name)
    return out


def negotiates_ikev2(gateway: IkeGateway | None) -> bool:
    """PAN-IKE-005's applicability condition, MEASURED off the path's own gateway.

    True where the gateway negotiates IKEv2 at all, which includes `ikev2-preferred` - that
    branch's re-authentication interval is reachable the moment a peer offers v2. True where there
    is no gateway, following the source column's rule that an applicability column includes an
    unread row rather than quietly dropping it.
    """
    if gateway is None:
        return True
    return gateway.ike_version in (
        IkeGateway.IkeVersion.IKEV2, IkeGateway.IkeVersion.IKEV2_PREFERRED)


def ike_crypto_profile_name_for(gateway: IkeGateway) -> str:
    """The IKE crypto profile name the gateway's own version branch selects."""
    if gateway.ike_version == IkeGateway.IkeVersion.IKEV1:
        return gateway.ikev1_crypto_profile_name
    return gateway.ikev2_crypto_profile_name or gateway.ikev1_crypto_profile_name


def _resolution(name: str, found: bool) -> str:
    if not name:
        return _RESOLUTION.NOT_NAMED
    return _RESOLUTION.RESOLVED if found else _RESOLUTION.MISSING


def _gateway_values(gateway: IkeGateway | None, name: str,
                    ike_profiles: dict[str, IkeCryptoProfile]) -> dict:
    """The gateway half of a path: the gateway's own settings and its IKE crypto profile."""
    values: dict = {
        "gateway_name": name,
        "gateway_resolution": _resolution(name, gateway is not None),
        "ike_gateway": gateway,
        "ike_crypto_resolution": _RESOLUTION.NO_GATEWAY,
        "ike_crypto_unresolved": True,
        "used_by_ikev2_gateway": negotiates_ikev2(gateway),
    }
    if gateway is None:
        return values

    values.update({field: getattr(gateway, field) for field in GATEWAY_COLUMNS})
    profile_name = ike_crypto_profile_name_for(gateway)
    profile = ike_profiles.get(profile_name) if profile_name else None
    values["ike_crypto_profile_name"] = profile_name
    values["ike_crypto_resolution"] = _resolution(profile_name, profile is not None)
    values["ike_crypto_unresolved"] = profile is None
    if profile is not None:
        values["ike_crypto_profile"] = profile
        values.update({field: getattr(profile, field) for field in IKE_CRYPTO_COLUMNS})
    return values


def _ipsec_crypto_values(tunnel: IpsecTunnel,
                         ipsec_profiles: dict[str, IpsecCryptoProfile]) -> dict:
    """The IPSec crypto half of a path, with the inferred `default` kept apart from a stored name.

    `effective_crypto_profile_chosen` on the tunnel is the tunnel normalizer's own verdict over
    the same three states and is NOT reused as the unresolved flag: it also turns False on a
    profile that resolves and still carries the shipped algorithm set, which is a WEAK profile
    rather than an unknown one, and the two have different remedies and different columns.
    """
    name = tunnel.crypto_profile_name
    profile = ipsec_profiles.get(name) if name else None
    stored = tunnel.provenance_for("crypto_profile_name")
    inferred = (
        name == ASSUMED_DEFAULT_NAME
        and stored is not None
        and stored.provenance_type == FieldProvenance.ProvenanceType.ASSUMED_DEFAULT
    )
    values: dict = {
        "ipsec_crypto_profile_name": name,
        "ipsec_crypto_profile": profile,
        "ipsec_crypto_resolution": (
            _RESOLUTION.DEFAULT_ASSUMED if inferred else _resolution(name, profile is not None)),
        "ipsec_crypto_unresolved": profile is None or name == ASSUMED_DEFAULT_NAME,
    }
    if profile is not None:
        values.update({field: getattr(profile, field) for field in IPSEC_CRYPTO_COLUMNS})
    return values


def normalize_ipsec_tunnel_paths(appliance: Appliance) -> list[IpsecTunnelPath]:
    """Replace every IPSec tunnel path for one appliance. Returns what was written."""
    tunnels = list(IpsecTunnel.objects.filter(appliance=appliance))
    gateways = {g.entry_name: g for g in IkeGateway.objects.filter(appliance=appliance)}
    ike_profiles = {
        p.entry_name: p for p in IkeCryptoProfile.objects.filter(appliance=appliance)}
    ipsec_profiles = {
        p.profile_name: p for p in IpsecCryptoProfile.objects.filter(appliance=appliance)}

    anchors = {
        "management_station": appliance.management_station,
        "appliance": appliance,
        "appliance_group": appliance.appliance_group,
    }

    rows: list[dict] = []
    named_gateways: set[str] = set()
    for tunnel in tunnels:
        crypto = _ipsec_crypto_values(tunnel, ipsec_profiles)
        tunnel_half = {field: getattr(tunnel, field) for field in TUNNEL_COLUMNS}
        names = gateway_names_on(tunnel) or [""]
        for name in names:
            named_gateways.add(name)
            rows.append({
                **anchors,
                "source_snapshot": tunnel.source_snapshot,
                "tunnel": tunnel,
                "tunnel_name": tunnel.tunnel_name,
                "path_origin": _ORIGIN.TUNNEL,
                **tunnel_half,
                **crypto,
                **_gateway_values(gateways.get(name), name, ike_profiles),
            })

    for name, gateway in gateways.items():
        if name in named_gateways:
            continue
        rows.append({
            **anchors,
            "source_snapshot": gateway.source_snapshot,
            "tunnel_name": "",
            "path_origin": _ORIGIN.ORPHAN_GATEWAY,
            **_gateway_values(gateway, name, ike_profiles),
        })

    with transaction.atomic():
        _replace(appliance)
        written = [IpsecTunnelPath.objects.create(**row) for row in rows]
    return written
