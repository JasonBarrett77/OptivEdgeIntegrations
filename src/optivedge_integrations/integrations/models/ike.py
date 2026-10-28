"""IKE crypto profiles and IKE gateways, as they exist on one appliance.

Both objects are DEVICE-WIDE. Stage 4 of the `ike-crypto` pipeline domain asked ten candidate
paths on two platforms and two vsys postures and found exactly ONE firewall-local scope for each -
neither shared nor under a vsys:

    /config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name='...']
    /config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name='...']

WHY THESE DO NOT INHERIT `ApplianceScopedObject`, which is the shape every other named PAN-OS
object here uses. That base offers `shared` / `vsys` / `predefined` and DEFAULTS TO SHARED, and
its `clean()` enforces the vsys rule over those three members. Neither object has any of those
scopes: the pair (device-local, local) is not a member of it, and defaulting a device-wide network
object to `shared` would assert a scope the object does not have. `InterfaceManagementProfile` is
the precedent and reaches the same conclusion for the same reason - it is also a `network/`
object, and it also declares its own anchors rather than inheriting that base.

`scope` and `vsys_name` are carried anyway, and `vsys_name` is STRUCTURALLY EMPTY on every row.
They are here so the uniqueness constraint is the same four columns the shipped appliance-scoped
models key on, which is what lets a consumer treat these rows like any other named entry.

ON AN HA PAIR each of these subjects yields TWO ROWS FOR ONE REAL CONFIGURATION and nothing
deduplicates them. On the lab's PA-5220 pair, config sync is ENABLED and `running-sync` reads
`not synchronized` off each member, so a difference between the two rows is not by itself a
configuration finding.

WHAT NO ROW CAN SAY, recorded because it is a real measured state: "no IKE crypto profile is
defined on this appliance" is the state that makes every gateway on it uncommittable, and the
entry grain has no row for it. Nothing in this domain asserts on it.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class IkeScopedObject(ProvenancedMixin, SyncTrackedModel):
    """The anchors and the identity both IKE objects share.

    Abstract, so the two concrete models cannot drift apart on the four identity columns the
    uniqueness constraint is written over.
    """

    #: The one firewall-local scope either object has. `template` is declared because an entry
    #: supplied only by a pushed Panorama template has nowhere else to go - it is NOT exercised
    #: anywhere in this lab (zero @ptpl and zero @src at these paths on all four appliances,
    #: measured by stage 4 and re-measured by stage 7's readback 2026-10-28), so it is here for
    #: an estate that pushes these paths rather than for anything that has been seen.
    SCOPE_DEVICE_LOCAL = "device-local"
    SCOPE_TEMPLATE = "template"
    SCOPE_CHOICES = [
        (SCOPE_DEVICE_LOCAL, "Device-local"),
        (SCOPE_TEMPLATE, "Template"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="%(class)ss")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="%(class)ss")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="%(class)ss", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="%(class)ss")

    #: The entry's own name on the device. What a finding prints as its subject, and what a
    #: reference from the sibling object resolves against.
    entry_name = models.CharField(max_length=64)
    scope = models.CharField(
        max_length=16, choices=SCOPE_CHOICES, default=SCOPE_DEVICE_LOCAL)
    #: Empty on every row of both models: neither object has a vsys scope. Carried so the
    #: uniqueness constraint matches the shipped appliance-scoped models'.
    vsys_name = models.CharField(max_length=64, blank=True)

    class Meta:
        abstract = True

    def __str__(self) -> str:
        return f"{self.appliance} / {self.scope} / {self.entry_name}"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError("Object appliance must belong to the same station.")
        if self.vsys_name:
            raise ValidationError(
                "Neither IKE object has a vsys scope, so no row of either may name a vsys.")


class IkeCryptoProfile(IkeScopedObject):
    """One named IKE crypto profile on one appliance. PAN-IKE-002 to 005 and 009.

    THE THREE ALGORITHM LISTS ARE OFFER SETS AND NOT CHOICES: the profile offers every member and
    takes the first one a peer accepts, so what a control grades is the WEAKEST member on offer -
    the one an exchange can be driven down to. That is why each list has a `weakest_*` column
    beside it and a `*_floor_met` verdict over the whole set, rather than a single value column.

    The lists are JSON and are deliberately NOT reachable from a query. The convention the
    consumer enforces is that values are reachable and lists are not, so each finding rests on
    the derived columns beside its list. The lists are here for a reader comparing the report
    against the screen, and for the remediation, which has to know the whole set.

    THE THREE FACTORY-NAMED ENTRIES - `default`, `Suite-B-GCM-128`, `Suite-B-GCM-256` - ARE
    ORDINARY WRITABLE, DELETABLE CONFIG at the same xpath as a custom entry. They carry no @ptpl,
    no @src and no /config/predefined counterpart (there is no predefined IKE crypto profile at
    all: /config/predefined/network-profile holds `bfd-profile` and nothing else on all four lab
    appliances). So a normalizer must NOT give them the PREDEFINED entry-provenance sentinel,
    which asserts "shipped in the release and not editable here" - false for a deletable entry,
    and it is what makes PAN-IKE-009's deletion remedy possible at all. Re-measured on
    pan-fw-201, 2026-10-28: all four of its profiles, the three factory-named ones included, read
    identically in the merged and running views and carry no provenance marker.

    NO COLUMN ENCODES THE ENTRY'S NAME AS A PROXY FOR STRENGTH, in either direction. `default` on
    pan-fw-201 offers 3DES, SHA-1 and Group 2 - measured - but an estate may equally have hardened
    it in place or named a weak profile after itself, so PAN-IKE-002 to 005 assert over EVERY
    profile. The only column that reads those names is on the gateway, where the assertion is
    about provenance and ownership rather than about algorithms.
    """

    #: Computed here: the weakest member of each offer set, the floor verdicts over them, the
    #: lifetime coalesced across four unit branches, and the two cross-object reference verdicts.
    #: The three member lists and `authentication_multiple` are NOT here - they are payload keys
    #: and carry provenance rows. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "weakest_dh_group",
        "dh_group_floor_met",
        "weakest_encryption_cipher",
        "encryption_floor_met",
        "offers_aead_cipher",
        "weakest_hash_algorithm",
        "hash_floor_met",
        "key_lifetime_unit",
        "key_lifetime_hours",
        "key_lifetime_known",
        "authentication_multiple_known",
        "reauth_interval_hours",
        "reauth_interval_bounded",
        "used_by_ikev2_gateway",
        "referenced_by_gateway_on_this_appliance",
    )

    class LifetimeUnit(models.TextChoices):
        SECONDS = "seconds", "Seconds"
        MINUTES = "minutes", "Minutes"
        HOURS = "hours", "Hours"
        DAYS = "days", "Days"

    #: Every key-agreement group still OFFERED, as the device spells them and in its own order.
    dh_groups = models.JSONField(default=list, blank=True)
    #: The weakest group on offer, by PAN-IKE-002's severity order over the nine classical
    #: members and `none`. That order does NOT place the eighteen post-quantum members: where the
    #: offer set holds one of those and no classical member, this holds that member and the
    #: grading places it unranked. Null where no offer list was collected - a guessed value here
    #: would be GRADED, and a wrong severity on a real finding is worse than no severity.
    weakest_dh_group = models.CharField(max_length=32, null=True, blank=True)
    #: PAN-IKE-002's assertion. False is the finding side and is also the migration default, so a
    #: profile nobody has recomputed is reported rather than passing.
    dh_group_floor_met = models.BooleanField(default=False)

    encryption_ciphers = models.JSONField(default=list, blank=True)
    weakest_encryption_cipher = models.CharField(max_length=32, null=True, blank=True)
    #: PAN-IKE-003's assertion: every cipher offered is AES, i.e. `3des` is absent from the set.
    encryption_floor_met = models.BooleanField(default=False)
    #: Not an assertion of its own: the condition PAN-IKE-004's `non-auth` exception turns on.
    offers_aead_cipher = models.BooleanField(default=False)

    hash_algorithms = models.JSONField(default=list, blank=True)
    weakest_hash_algorithm = models.CharField(max_length=32, null=True, blank=True)
    #: PAN-IKE-004's assertion, over TWO lists: every integrity algorithm is SHA-2, with
    #: `non-auth` permitted ONLY where an AEAD cipher is also offered. The vendor MANDATES
    #: `non-auth` alongside AES-GCM (help p.658), so a one-list test would fire on exactly the
    #: configuration the vendor tells a customer to make.
    hash_floor_met = models.BooleanField(default=False)

    #: Which of the four unit branches the profile expresses its lifetime in. The unit is WHICH
    #: CHILD ELEMENT EXISTS and is not a value anywhere on the device.
    #:
    #: WRITING ONE BRANCH SILENTLY DESTROYS ANOTHER, measured by stage 4: with lifetime/hours=1
    #: stored, a set of <seconds>300</seconds> at the same container was accepted without
    #: comment, the read-back carried only the seconds branch, and the commit returned OK. No
    #: gate anywhere reports that the other branch was discarded. That is the OPPOSITE of what
    #: the same verb does to the member lists above, which it MERGES into.
    key_lifetime_unit = models.CharField(
        max_length=8, choices=LifetimeUnit.choices, null=True, blank=True)
    #: The lifetime in HOURS, coalesced from whichever one of the four branches is present and
    #: rounded UP, so a sub-hour lifetime stores 1 and never 0.
    key_lifetime_hours = models.PositiveIntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(65535)])
    #: Whether a lifetime was read at all, as against the key being absent or the row never
    #: collected. The companion a control clauses on, because a threshold over a NULL integer
    #: passes a bound it was never compared against.
    key_lifetime_known = models.BooleanField(default=False)

    #: The multiplier a gateway applies to this profile's lifetime to get the IKEv2
    #: re-authentication interval.
    #:
    #: ZERO IS NOT A SMALL BOUND - it disables re-authentication entirely, in the device's own
    #: words: "0 means reauthentication disabled". It is the UNBOUNDED end of the axis while
    #: sorting as the smallest number, so every numeric comparison reads it as the strictest
    #: setting available, and a threshold predicate must special-case it before it compares.
    #:
    #: THE VALIDATOR PERMITS 0 THOUGH THE DEVICE'S STATED RANGE EXCLUDES IT. Stage 4 measured
    #: that writing 51 is refused with "should be equal to or between 1 and 50", writing 50 is
    #: accepted, and writing 0 is ALSO ACCEPTED and read back as 0 - and the lab holds such a
    #: profile. A MinValueValidator(1) would make a measured device value unstorable, so the
    #: floor is the storable one and not the documented one.
    authentication_multiple = models.PositiveSmallIntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(50)])
    authentication_multiple_known = models.BooleanField(default=False)
    #: The multiplier times the coalesced lifetime, in hours. Null where the multiplier is 0,
    #: because 0 is not a short interval but the absence of one.
    reauth_interval_hours = models.PositiveIntegerField(null=True, blank=True)
    #: PAN-IKE-005's second half. False where the multiplier is 0, where the product exceeds the
    #: bound, or where either factor was not read - the one place in this domain where a measured
    #: value and an absence are deliberately treated alike.
    reauth_interval_bounded = models.BooleanField(default=False)

    #: PAN-IKE-005's applicability condition, and it is CROSS-OBJECT: the multiplier is on the
    #: profile and the version is on the gateway, so no query can express it. True keeps the row
    #: in the population, which is why that is the default - an applicability column defaults to
    #: INCLUDING an unread row, the reverse of what a verdict column does.
    used_by_ikev2_gateway = models.BooleanField(default=True)
    #: PAN-IKE-009's hygiene half. The name is deliberately narrow: it says nothing about whether
    #: anything ELSEWHERE uses the profile, which is the part a firewall-side read cannot answer.
    #:
    #: AND IT INVERTS ON AN UNMEASURED RESOLUTION RULE. Stage 4 measured that a gateway with
    #: NEITHER pointer set still consumes a profile, with three device statements behind the lead
    #: that it lands on the entry named `default`. So computed over the two explicit leaves this
    #: reports `default` as unreferenced on exactly the estates where it is the profile every
    #: unpointed gateway uses. The column computes what the configuration can see.
    referenced_by_gateway_on_this_appliance = models.BooleanField(default=False)

    class Meta:
        ordering = ["appliance__hostname", "entry_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "entry_name"],
                name="integrations_unique_ike_crypto_profile_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance", "entry_name"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["appliance", "dh_group_floor_met"]),
            models.Index(fields=["appliance", "encryption_floor_met"]),
            models.Index(fields=["appliance", "hash_floor_met"]),
        ]


class IkeGateway(IkeScopedObject):
    """One named IKE gateway on one appliance. PAN-IKE-001 and 006 to 009.

    EVERY CONTROL IN THIS DOMAIN NEEDS `gateway_is_active` AND NONE OF THEM NAMES IT. A disabled
    gateway is configuration that enforces nothing, so reporting a weak exchange mode on one is a
    finding about a negotiation that cannot happen. The clause is on the derived column and never
    on `disabled` itself, because `disabled` is a NULLABLE boolean and an applicability clause
    over a NULL drops the row - which would suppress every gateway nobody read.

    APPLICABILITY IS PER BRANCH AND IS NOT A PROPERTY OF THE GATEWAY. The ikev1 and ikev2
    branches each carry their own exchange mode and dead-peer-detection subtree, and the two
    differ STRUCTURALLY: ikev1/dpd has three children (enable, interval, retry) and ikev2/dpd has
    two, measured on all four appliances - so a schema written once for both loses `retry`. An
    absent ikev1 key on an ikev2-only gateway asserts NOTHING and must not be reported as a
    setting.

    THE CONFIGURED VERSION IS NOT THE NEGOTIATED ONE, and no column here can hold the difference.
    `ikev2-preferred` resolves to ikev2 with an ikev1 fallback the peer can elect, and the
    operational reads that would say which a tunnel is running - `show vpn ike-sa` - are refused
    to this project with HTTP 403, because `<show>` routes to the READ_ONLY credential and that
    administrator cannot read IKE SA state.

    THE PRE-SHARED KEY'S VALUE IS NEVER STORED. A 31-character plaintext reads back as a
    77-character ciphertext under both the merged and the running view, so a length comparison
    over the stored value would measure the ENCODING and pass a four-character key. No column
    holds the ciphertext. `uses_pre_shared_key` is a presence test, and it is kept a MEASURED
    column rather than a derived one precisely so that its FieldProvenance row exists: the
    secret's value is never stored, so that row is the only record of who set the credential -
    local, or a template - which is what an assessor asks about a secret they can read in a
    backup. `SnmpSettings.community_is_default` is the shipped precedent for the same reasoning.
    """

    #: Computed here: the active verdict, the authentication state resolved across two exclusive
    #: subtrees, the two did-we-read-it companions, and the factory-proposal verdict. The payload
    #: keys beside them carry provenance rows. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "gateway_is_active",
        "peer_authentication",
        "local_certificate_named",
        "ikev1_dpd_enabled_known",
        "ikev2_dpd_enabled_known",
        "relies_on_factory_named_proposal",
    )

    class IkeVersion(models.TextChoices):
        IKEV1 = "ikev1", "IKEv1"
        IKEV2 = "ikev2", "IKEv2"
        IKEV2_PREFERRED = "ikev2-preferred", "IKEv2 preferred"

    class ExchangeMode(models.TextChoices):
        AUTO = "auto", "Auto"
        MAIN = "main", "Main"
        AGGRESSIVE = "aggressive", "Aggressive"

    class PeerAuthentication(models.TextChoices):
        PRE_SHARED_KEY = "pre-shared-key", "Pre-shared key"
        CERTIFICATE_WITHOUT_PROFILE = (
            "certificate-without-profile", "Certificate, no validation profile")
        CERTIFICATE_WITH_PROFILE = (
            "certificate-with-profile", "Certificate with validation profile")

    #: The device's own key and the device's own POLARITY: `yes` means the gateway is switched
    #: OFF. A reader filling in the opposite would invert every control in this domain. Nullable,
    #: because the absent state is unmeasured and the polarity is negated, so a wrong guess is
    #: dangerous in both directions. Nothing clauses on this column - `gateway_is_active` does.
    disabled = models.BooleanField(null=True, blank=True)
    #: Whether the gateway is in force - false ONLY where `disabled` read as `yes`. An absent or
    #: unread key counts as ACTIVE, so the gateway stays in scope and is assessed rather than
    #: excused.
    gateway_is_active = models.BooleanField(default=True)

    #: The `protocol/version` leaf. Also the applicability axis for every other control here.
    #:
    #: NON-NULLABLE AND DEFAULTING TO THE EMPTY STRING, and that is load-bearing rather than a
    #: style choice. The assertion clause is a NEGATED EQUALITY against `ikev2`. On a text column
    #: an unread or absent key holds "" (common.py `parse_text_field` returns "" for a
    #: not_assumed declaration), so NOT(version = 'ikev2') is TRUE and the gateway is REPORTED.
    #: A nullable spelling would make SQL answer NOT(NULL = x) with NULL and silently DROP every
    #: gateway nobody read, inverting the behaviour of every clause below it.
    ike_version = models.CharField(
        max_length=16, choices=IkeVersion.choices, blank=True, default="")
    #: The ikev1 branch's exchange mode. `auto` is NOT a middle setting: the vendor's p.651 says
    #: "In auto mode (default), the device can accept both main mode and aggressive mode
    #: negotiation requests", so it behaves like the forbidden value whenever the peer initiates.
    #: Non-nullable for the same reason as `ike_version`.
    ikev1_exchange_mode = models.CharField(
        max_length=16, choices=ExchangeMode.choices, blank=True, default="")

    #: How the peer is authenticated, as one of three states. A DERIVED state and not a value
    #: anywhere on the device: the choice is expressed by WHICH OF TWO SUBTREES EXISTS.
    #:
    #: THE TWO BRANCHES ARE EXCLUSIVE AND THE EXCLUSION IS ENFORCED BY SILENT REPLACEMENT at the
    #: write - staging a certificate-profile over a committed pre-shared key DELETES the PSK
    #: branch from the candidate without comment, while the running view still shows the PSK. So
    #: for the duration of a staging the two views disagree about how the gateway authenticates,
    #: and this domain's read is candidate-derived: this column reports the STAGED answer.
    peer_authentication = models.CharField(
        max_length=32, choices=PeerAuthentication.choices, blank=True, default="")
    #: The certificate profile named to validate the peer's certificate, as the bare name. A
    #: pointer into `CertificateProfile`, which the certificates domain owns. Whether the named
    #: profile actually CHECKS anything - CRL or OCSP - is PAN-CRT-004's assertion and not this
    #: column's: this says a profile is ATTACHED and defers what the profile DOES.
    certificate_profile_name = models.CharField(max_length=64, blank=True, default="")
    #: Whether a LOCAL certificate is named to present to the peer. CONDITIONALLY MANDATORY -
    #: required only once the certificate branch exists - which is why it exists as a column: a
    #: control that checks only `certificate_profile_name` cannot tell a configured gateway from
    #: an uncommittable one.
    local_certificate_named = models.BooleanField(default=False)
    #: Whether a shared secret is in use. The PRESENCE and never the value - see the class
    #: docstring for why nothing else is possible, and why this stays a measured column.
    uses_pre_shared_key = models.BooleanField(default=False)

    #: The ikev1 branch's dead-peer-detection switch, in the vendor's polarity: `true` is the
    #: hardened state. Nullable under an unmeasured absent state, so `*_known` is the companion a
    #: control clauses on - SQL answers `= false` over NULL with no match, so a gateway nobody
    #: read would otherwise PASS a test it was never subjected to.
    ikev1_dpd_enabled = models.BooleanField(null=True, blank=True)
    ikev1_dpd_enabled_known = models.BooleanField(default=False)
    #: The ikev2 branch's liveness-check switch. THE CLAIM A FINDING MAY MAKE HERE IS NARROWER
    #: than on the ikev1 branch: the vendor's p.652 says "The IKEv2 Liveness Check is always on;
    #: all IKEv2 packets serve the purpose of a liveness check", so a finding saying an IKEv2
    #: gateway CANNOT detect a dead peer would be false. What is true is that it sends no IDLE
    #: probe.
    ikev2_dpd_enabled = models.BooleanField(null=True, blank=True)
    ikev2_dpd_enabled_known = models.BooleanField(default=False)
    #: Idle seconds before a liveness probe, on the ikev2 branch. THE INTERVAL AND THE ENABLE ARE
    #: TWO KEYS: a gateway can carry an interval with NO enable, in which case the interval
    #: describes a probe that may not be being sent, and a finding quoting it without the switch
    #: is describing a configuration that does nothing.
    ikev2_dpd_interval = models.PositiveSmallIntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(2), MaxValueValidator(100)])
    #: Probe retries before the peer is declared gone. EXISTS ONLY ON THE IKEV1 BRANCH, measured
    #: on all four appliances - the structural difference that stops PAN-IKE-008's two records
    #: sharing one reading.
    #:
    #: There is deliberately NO column for the ikev1 dpd INTERVAL: that key is in stage 4's key
    #: set with no field record behind it, so a measured column on it could not be reconciled
    #: against any measurement, and the ikev2 sibling's range is not evidence for a branch
    #: measured to differ structurally.
    ikev1_dpd_retry = models.PositiveSmallIntegerField(null=True, blank=True)

    #: The crypto profile named from the ikev1 branch, as the bare name the device stores.
    #: A GATEWAY HAS TWO OF THESE AND THEY CAN NAME DIFFERENT PROFILES - help p.652: "The
    #: profiles selected for IKEv1 and IKEv2 can differ." A model carrying one pointer per
    #: gateway would answer PAN-IKE-009 for half the references in an estate and report the other
    #: half as absent.
    #:
    #: AN UNRESOLVABLE NAME IS NOT REACHABLE BY CONFIGURATION: the reference is checked AT THE
    #: WRITE, synchronously, so a bad name never reaches a commit and a collected gateway can
    #: never carry a dangling one. What CAN happen is the profile being deleted afterwards.
    ikev1_crypto_profile_name = models.CharField(max_length=64, blank=True, default="")
    #: The crypto profile named from the ikev2 branch. THE TWO SECTIONS ARE NOT SYMMETRIC ABOUT
    #: THEIR POINTER: a gateway with version=ikev2, this leaf absent and only the ikev1 pointer
    #: present COMMITTED OK, where the ikev1 section in the same position aborted the commit. So
    #: an empty ikev2 pointer means LESS than an empty ikev1 one, and the verdict below treats
    #: them alike because nothing says it may not.
    ikev2_crypto_profile_name = models.CharField(max_length=64, blank=True, default="")

    #: PAN-IKE-009's assertion. True where either pointer names one of the three factory-shipped
    #: names, AND true where NEITHER pointer is set, because a gateway with no pointer still
    #: consumes a proposal and nothing stored says which. True is the finding side and the
    #: migration default.
    #:
    #: THE THREE NAMES ARE NOT EVIDENCE OF WEAKNESS AND THIS COLUMN DOES NOT CLAIM THEY ARE. The
    #: assertion is about PROVENANCE AND OWNERSHIP - a proposal nobody chose is a proposal nobody
    #: owns - and the strength claim lives with PAN-IKE-002 to 005, which assert over every
    #: profile.
    relies_on_factory_named_proposal = models.BooleanField(default=True)

    class Meta:
        ordering = ["appliance__hostname", "entry_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "entry_name"],
                name="integrations_unique_ike_gateway_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance", "entry_name"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["appliance", "gateway_is_active"]),
            models.Index(fields=["appliance", "ike_version"]),
        ]
