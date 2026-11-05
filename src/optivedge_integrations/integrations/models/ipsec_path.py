"""The IPSec tunnel path: one tunnel and every network profile it actually runs on.

WHY A COMPOSITE EXISTS AT ALL. The four objects of this estate's IPSec configuration are stored
one per collection - `IpsecTunnel`, `IkeGateway`, `IkeCryptoProfile`, `IpsecCryptoProfile` - and
the nine strength controls (PAN-IKE-002 to -005, PAN-IPS-001 to -005) were written over the two
PROFILE collections. A profile is not an enforcement point: it is a named algorithm set that a
tunnel may reference nought, once or a thousand times, and a finding raised on the profile says
the same thing in all three cases. Jason, 2026-11-04: *"A weak profile use on one IPSec tunnel
should not receive the same treatment as a weak profile used on 1000 IPSec tunnels. The best way
to accomplish this is to raise a finding per effected tunnel."* So the subject of those controls
becomes the PATH, one row carries every setting the path's profiles contribute, and the finding
count on the findings page is the number of tunnels in the blast radius.

WHAT A ROW IS. One row per (tunnel, IKE gateway) pair, PLUS one row per IKE gateway on the
appliance that no tunnel on that appliance names - an orphan, which keeps `tunnel_name` blank.
Jason set the keying: *"We key off IPSec Tunnel first. If there are any IKE Gateway objects
present on a firewall that are not named by an IPSec Tunnel object on that firewall, then we add
that to the list with a blank IPSec Tunnel value."* A tunnel naming NO gateway still gets its row,
with `gateway_name` blank - on this lab that is three of pan-fw-111's four tunnels.

THE PAIR RATHER THAN THE TUNNEL, and the reason is one stored shape against one screen.
`IpsecTunnel.ike_gateway_names` is a LIST, because `auto-key/ike-gateway` holds entry members;
Jason's 11.2 dialog offers a dropdown, so one name is what an administrator can produce there.
Keying on the pair agrees with both: it yields exactly one row per tunnel for every tunnel this
estate holds, and if a tunnel ever names two gateways it yields two paths rather than silently
reporting one of them.

THE DISABLED FLAG IS NOT A FILTER AND NOT A COLUMN THE CONTROLS READ. Jason, 2026-11-04: *"The
'disabled' value is ignored. So give a tunnel/gateway the same treatment regardless of the
disabled state."* `is_disabled` and `gateway_is_active` are carried for the reader and no control
of this domain grades on them - PAN-IPS-008 keeps its own subject, the tunnel object itself. All
four of pan-fw-111's tunnels are `disabled=yes`, so filtering on it would empty this model on the
one appliance that has anything to say.

AN UNRESOLVED PROFILE FAILS, AND IT FAILS THROUGH THE COLUMNS THAT WERE ALREADY THERE. Jason:
*"IKE Crypto is a required field on IPSec Tunnel. If the value is missing, that is an invalid
configuration. IPSec Crypto Profile must also be specified, but the default value is 'default'.
We can't know what the 'default' value means, so we should assume that it fails if it is default,
unspecified, or otherwise unknown."* So where a path's profile does not resolve, every verdict
column it would have filled is left at its FALSE default and every value column at blank - which
is the state the nine controls' own clauses already fire on, with two exceptions that need a
clause of their own and get one: `protocol_branch` and `weakest_encryption_offered` are compared
against value lists, and a blank matches no member of either. `ipsec_crypto_unresolved` and
`ike_crypto_unresolved` exist for those two clauses and for the reader.

EVERY VALUE COLUMN HERE IS DERIVED, by this repo's own definition - "a value resolved through
another object" - and the whole set is declared. The authority for any of them lives on the
component object this row points at, which is what the four nullable FKs are for; this model
stores no payload key of its own and carries no `__entry__` row.

THE COMPOSITE IS ASSEMBLED FROM STORED ROWS AND NOT FROM THE SNAPSHOT. Its normalizer runs after
the four collection normalizers and reads what they wrote, so a path can never disagree with the
object pages beside it. Nothing re-reads a payload and nothing here can be fresher than the rows
it joins.

WHAT NO ROW CAN SAY. The gateway's peer address and its local interface are NOT STORED anywhere
in this repository - `IkeGateway` carries the version, the authentication choice, the exchange
mode, DPD and the two crypto-profile names, and no address column at all - so a path cannot say
which peer it reaches or which interface it leaves by. That is a collection gap rather than a
join gap and closing it is a change to the gateway normalizer.
"""

from __future__ import annotations

from django.db import models

from .ike import IkeCryptoProfile, IkeGateway
from .ipsec import IpsecCryptoProfile, IpsecNetworkObject


class IpsecTunnelPath(IpsecNetworkObject):
    """One IPSec tunnel and the network profiles it runs on. PAN-IKE-002 to -005, PAN-IPS-001 to -005.

    Device-wide and keyed `unique(appliance, tunnel_name, gateway_name)`, following the three
    objects of the `ipsec` module rather than `IkeScopedObject`: none of the collections this
    joins has a vsys axis, so neither has the join.
    """

    #: Every value column: each one is read off another object's row rather than off a payload
    #: key of this one. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "path_origin",
        "gateway_resolution",
        "ike_crypto_resolution",
        "ipsec_crypto_resolution",
        "ike_crypto_unresolved",
        "ipsec_crypto_unresolved",
        "is_disabled",
        "gateway_is_active",
        "ike_version",
        "ikev1_exchange_mode",
        "peer_authentication",
        "uses_pre_shared_key",
        "certificate_profile_name",
        "local_certificate_named",
        "ike_crypto_profile_name",
        "dh_groups",
        "weakest_dh_group",
        "dh_group_floor_met",
        "encryption_ciphers",
        "hash_algorithms",
        "offers_aead_cipher",
        "key_lifetime_unit",
        "authentication_multiple",
        "authentication_multiple_known",
        "reauth_interval_hours",
        "weakest_encryption_cipher",
        "encryption_floor_met",
        "weakest_hash_algorithm",
        "hash_floor_met",
        "key_lifetime_hours",
        "key_lifetime_known",
        "reauth_interval_bounded",
        "used_by_ikev2_gateway",
        "ipsec_crypto_profile_name",
        "protocol_branch",
        "esp_encryption",
        "esp_authentication",
        "ah_authentication",
        "lifetime_unit",
        "weakest_encryption_offered",
        "weakest_integrity_offered",
        "all_offered_ciphers_authenticate",
        "integrity_meets_sha2_floor",
        "dh_group",
        "dh_group_meets_target",
        "lifetime_hours",
        "lifetime_within_target",
        "anti_replay",
        "anti_replay_determined",
        "tunnel_monitor_enable",
        "tunnel_monitor_enable_determined",
        "monitor_action_effective",
    )

    class PathOrigin(models.TextChoices):
        TUNNEL = "tunnel", "An IPSec tunnel"
        ORPHAN_GATEWAY = "orphan_gateway", "An IKE gateway no tunnel names"

    class Resolution(models.TextChoices):
        #: The path names a profile or gateway and this appliance holds it.
        RESOLVED = "resolved", "Named and found"
        #: The path names one and this appliance does not hold it - a dangling reference.
        MISSING = "missing", "Named and missing"
        #: The path names none at all. On the IKE crypto side that is an invalid configuration.
        NOT_NAMED = "not_named", "Not named"
        #: The IPSec crypto side only: the tunnel stores no reference and PAN-OS renders
        #: `default`, whose content nobody here can know. Kept apart from NOT_NAMED because the
        #: remedy differs - name a hardened profile, rather than name anything.
        DEFAULT_ASSUMED = "default_assumed", "Left at `default`"
        #: The IKE crypto side only: there is no gateway on this path to carry a profile name.
        NO_GATEWAY = "no_gateway", "No gateway on the path"

    #: The tunnel's own name, BLANK on an orphan-gateway row. Blank rather than null so the
    #: uniqueness key below has a value to compare on every row.
    tunnel_name = models.CharField(max_length=64, blank=True, default="")
    #: Which end this row was keyed from. `tunnel` for every row with a tunnel name.
    path_origin = models.CharField(
        max_length=16, choices=PathOrigin.choices, default=PathOrigin.TUNNEL)

    #: The IKE gateway this path uses, BLANK where the tunnel names none.
    gateway_name = models.CharField(max_length=64, blank=True, default="")
    gateway_resolution = models.CharField(
        max_length=16, choices=Resolution.choices, default=Resolution.NOT_NAMED)

    tunnel = models.ForeignKey(
        "integrations.IpsecTunnel", on_delete=models.CASCADE, related_name="paths",
        null=True, blank=True)
    ike_gateway = models.ForeignKey(
        "integrations.IkeGateway", on_delete=models.CASCADE, related_name="paths",
        null=True, blank=True)
    ike_crypto_profile = models.ForeignKey(
        "integrations.IkeCryptoProfile", on_delete=models.SET_NULL, related_name="paths",
        null=True, blank=True)
    ipsec_crypto_profile = models.ForeignKey(
        "integrations.IpsecCryptoProfile", on_delete=models.SET_NULL, related_name="paths",
        null=True, blank=True)

    # ---- carried for the reader; no control of this domain grades on either ----
    is_disabled = models.BooleanField(default=False)
    gateway_is_active = models.BooleanField(default=True)

    # ---- the gateway's own settings ----
    #: WITH THE SOURCE MODEL'S CHOICES, so the cell can read `IKEv2 preferred` rather than the
    #: stored token. The three values are not three settings: `ikev2-preferred` negotiates v2
    #: first and still accepts v1, which is why the v1 columns beside it stay filled.
    ike_version = models.CharField(
        max_length=16, choices=IkeGateway.IkeVersion.choices, blank=True, default="")
    #: CARRIES THE SOURCE MODEL'S CHOICES: the shipped cell reader calls
    #: `get_ikev1_exchange_mode_display()`, and `auto` has to read as the vendor's own word for it.
    ikev1_exchange_mode = models.CharField(
        max_length=16, choices=IkeGateway.ExchangeMode.choices, blank=True, default="")
    peer_authentication = models.CharField(
        max_length=32, choices=IkeGateway.PeerAuthentication.choices, blank=True, default="")
    uses_pre_shared_key = models.BooleanField(default=False)
    #: The two halves of the certificate branch, carried because the shipped cell reader reads
    #: them: what a reader can act on is WHICH profile validates the peer and whether a local
    #: certificate is named, not the three-state verdict alone. The pre-shared key's value is
    #: never stored anywhere, so neither this nor any other column is a strength reading.
    certificate_profile_name = models.CharField(max_length=64, blank=True, default="")
    local_certificate_named = models.BooleanField(default=False)

    # ---- the IKE crypto profile the gateway's own IKE version selects ----
    #: WHICH of the gateway's two profile names this is: `ikev2_crypto_profile_name` on a gateway
    #: set to IKEv2-only, `ikev1_crypto_profile_name` otherwise. A gateway in `ikev2-preferred`
    #: can negotiate either, and the normalizer records the v2 name with the version column
    #: beside it saying so.
    ike_crypto_profile_name = models.CharField(max_length=64, blank=True, default="")
    ike_crypto_resolution = models.CharField(
        max_length=16, choices=Resolution.choices, default=Resolution.NO_GATEWAY)
    #: True where no IKE crypto profile stands behind this path - no gateway, no name, or a name
    #: this appliance does not hold. The clause column for the two controls whose own columns
    #: compare against value lists.
    ike_crypto_unresolved = models.BooleanField(default=True)

    #: THE OFFER SETS, AND NOT ONLY THE WEAKEST MEMBER OF EACH. A profile offers every member and
    #: takes the first a peer accepts, so the weakest is what a control grades - but a remediation
    #: has to know what to DELETE, and stage 4 measured that `action=set` with one member ADDS to
    #: the stored list rather than replacing it, so an offer set cannot be shrunk by overwriting
    #: it. Jason, 2026-11-04: *"The IPSec Tunnel page should display all of the *relevant*
    #: settings from all related Network Profiles."*
    #:
    #: JSON AND DELIBERATELY UNREACHABLE FROM A QUERY, as on the two profile models: the
    #: consumer's convention is that values are reachable and lists are not, and
    #: `test_findings_rest_on_columns` refuses a registered JSONField outright.
    dh_groups = models.JSONField(default=list, blank=True)
    weakest_dh_group = models.CharField(max_length=32, null=True, blank=True)
    dh_group_floor_met = models.BooleanField(default=False)
    encryption_ciphers = models.JSONField(default=list, blank=True)
    weakest_encryption_cipher = models.CharField(max_length=32, null=True, blank=True)
    encryption_floor_met = models.BooleanField(default=False)
    hash_algorithms = models.JSONField(default=list, blank=True)
    weakest_hash_algorithm = models.CharField(max_length=32, null=True, blank=True)
    #: PAN-IKE-004's exception condition rather than an assertion: the vendor MANDATES `non-auth`
    #: alongside AES-GCM, so without this on the row a profile offering it and passing reads as
    #: one that was never checked.
    offers_aead_cipher = models.BooleanField(default=False)
    hash_floor_met = models.BooleanField(default=False)
    key_lifetime_hours = models.PositiveIntegerField(null=True, blank=True)
    key_lifetime_known = models.BooleanField(default=False)
    #: WHICH CHILD ELEMENT HOLDS THE LIFETIME, which is not a value anywhere on the device and is
    #: what a remediation needs: writing one branch silently destroys another, with no gate
    #: reporting the discard. The choices are the source model's, so the shipped cell reader -
    #: which calls `get_key_lifetime_unit_display()` - works on a path unchanged.
    #: NULLABLE, mirroring the source column exactly: a copy that stored a blank where the source
    #: holds NULL would make a profile with no lifetime branch read like one written in an
    #: unmapped unit.
    key_lifetime_unit = models.CharField(
        max_length=8, choices=IkeCryptoProfile.LifetimeUnit.choices, null=True, blank=True)
    authentication_multiple = models.PositiveSmallIntegerField(null=True, blank=True)
    authentication_multiple_known = models.BooleanField(default=False)
    reauth_interval_hours = models.PositiveIntegerField(null=True, blank=True)
    reauth_interval_bounded = models.BooleanField(default=False)
    #: PAN-IKE-005's applicability condition, and ON THE PATH IT IS MEASURED RATHER THAN ASSUMED.
    #: The same column on `IkeCryptoProfile` defaults to True and stays there, because the
    #: multiplier is on the profile and the version is on the GATEWAY - a cross-object question no
    #: query could express, so every profile stayed in the population whether an IKEv2 gateway
    #: used it or not. A path HAS its gateway, so this reads the gateway's own version: true where
    #: it negotiates IKEv2 at all, which includes `ikev2-preferred`. True where there is no
    #: gateway, following the source column's rule that an applicability column INCLUDES an
    #: unread row.
    used_by_ikev2_gateway = models.BooleanField(default=True)

    # ---- the IPSec crypto profile the tunnel's auto-key branch names ----
    ipsec_crypto_profile_name = models.CharField(max_length=64, blank=True, default="")
    ipsec_crypto_resolution = models.CharField(
        max_length=16, choices=Resolution.choices, default=Resolution.NOT_NAMED)
    ipsec_crypto_unresolved = models.BooleanField(default=True)

    #: CARRIES THE SOURCE MODEL'S CHOICES, which is load-bearing rather than tidiness: the shipped
    #: cell reader calls `get_protocol_branch_display()`, because the raw token for the third state
    #: is `none` and `display_value`'s word for a NULL is `(none)` - a reader meeting `none` in
    #: this column could not tell "carries neither branch" from "this cell is empty".
    protocol_branch = models.CharField(
        max_length=8, choices=IpsecCryptoProfile.ProtocolBranch.choices, blank=True, default="")
    #: The two branches' lists, kept APART rather than merged: they differ structurally - the ESP
    #: integrity list may carry the literal `none` and the AH list may not, measured both ways -
    #: so a cell that merged them could not say which branch its members came from. NULL, not
    #: `[]`, where the key is absent: stage 4 measured that to mean nothing is offered.
    esp_encryption = models.JSONField(null=True, blank=True)
    esp_authentication = models.JSONField(null=True, blank=True)
    ah_authentication = models.JSONField(null=True, blank=True)
    weakest_encryption_offered = models.CharField(max_length=16, blank=True, default="")
    weakest_integrity_offered = models.CharField(max_length=16, blank=True, default="")
    #: PAN-IPS-003's applicability condition: where every cipher on offer authenticates as well as
    #: encrypts, the vendor MANDATES the `none` integrity member and the control excludes the row
    #: rather than scoring it. Default False, as on the source column - an unresolved path stays
    #: in the population and is reported.
    all_offered_ciphers_authenticate = models.BooleanField(default=False)
    integrity_meets_sha2_floor = models.BooleanField(default=False)
    dh_group = models.CharField(max_length=32, blank=True, default="")
    dh_group_meets_target = models.BooleanField(default=False)
    lifetime_hours = models.PositiveIntegerField(null=True, blank=True)
    #: As on the IKE side: the unit is which child element exists, and stage 4 measured that an
    #: element naming several units is ACCEPTED with only the LAST one landing.
    lifetime_unit = models.CharField(
        max_length=8, choices=IpsecCryptoProfile.LifetimeUnit.choices, blank=True, default="")
    lifetime_within_target = models.BooleanField(default=False)

    # ---- the tunnel's own settings, carried so one page answers the whole path ----
    anti_replay = models.BooleanField(null=True, blank=True)
    anti_replay_determined = models.BooleanField(default=False)
    tunnel_monitor_enable = models.BooleanField(null=True, blank=True)
    tunnel_monitor_enable_determined = models.BooleanField(default=False)
    monitor_action_effective = models.CharField(max_length=16, blank=True, default="")

    class Meta:
        ordering = ["appliance__hostname", "tunnel_name", "gateway_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "tunnel_name", "gateway_name"],
                name="integrations_unique_ipsec_path_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance", "tunnel_name"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["appliance", "ike_crypto_unresolved"]),
            models.Index(fields=["appliance", "ipsec_crypto_unresolved"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.tunnel_name or '(no tunnel)'} / {self.gateway_name or '(no gateway)'}"
