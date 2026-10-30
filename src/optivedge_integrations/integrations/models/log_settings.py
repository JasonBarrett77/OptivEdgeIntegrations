"""Device > Log Settings and the log-settings server profiles - the logging domain.

PAN-LOG-001 to 010. Two models here; the third the domain needs is `LoggingSettings`, which
already existed for PAN-MGT-011 and gained this domain's columns in `services_settings.py`.

WHY A SERVER ENTRY AND NOT A PROFILE IS THE ROW. Transport is per SERVER: one syslog profile can
hold a TLS server and a UDP one, measured on the lab PA-5220, and the remediation is to change
that server's transport. The same is true of an email relay's protocol, TLS version and
authentication. A profile-keyed row would have to fold several servers into one verdict and could
not say which one sends in the clear.

WHY ONE TABLE FOR TWO KINDS. `log-settings` holds `syslog` and `email` as sibling containers and
the shape is the same on both - a named profile holding named server entries, resolved by a
forwarding rule's member list. One table, discriminated by `kind`, exactly as `ServerProfile`
holds six AAA kinds. EVERY CONTROL ON THIS MODEL MUST CLAUSE ON THE KIND: `transport` means
nothing on the email kind and holds its default there, and `protocol`/`tls_version`/`auth_method`
mean nothing on the syslog kind.

`http` and `snmptrap` live in the same container and are NOT modelled: no logging control asserts
them, and a row nothing asserts is a row nobody needs. They become a third and fourth kind when
something asserts them. That is why the normalizer reads two NAMED containers rather than
iterating the container's children the way the AAA one does - an unfamiliar child here is not an
unrecognised kind of the same thing, it is a different object.

NOT A SUBCLASS OF `ApplianceScopedObject`, AND THAT IS THE ONE DEPARTURE FROM THE CONVENTION.
That base carries a single `name`, because every object it was built for is a named entry in a
scope. A row here is a CHILD: its identity is the parent profile's name AND its own, because a
match list's `send-syslog` member resolves against the PROFILE while a finding has to print the
SERVER. Subclassing would leave `name` holding one of the two and the other beside it, with
nothing saying which a reader should trust. The scope choices are imported from that base rather
than restated, so the three tokens still have one home.
"""

from __future__ import annotations

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from .base import ApplianceScopedObject, SyncTrackedModel
from .provenance import ProvenancedMixin


#: The System-log severities, most severe first. NOT a measured device enum: the Log Settings
#: filter is free text whose candidate list completes empty, so no key holds a severity set -
#: these are the five the log viewer grades by, and `system_log_severity_gaps` is a verdict over
#: a parse of that free text rather than a reading of a key.
SYSTEM_LOG_SEVERITIES = ("critical", "high", "medium", "low", "informational")

#: The log types a firewall CAN forward to Panorama: the six Device > Log Settings kinds that
#: carry `send-to-panorama` plus the ten Log Forwarding profile log types. `correlation` is
#: excluded - it has no `send-to-panorama` key at all, measured on the one platform that has the
#: kind, and the vendor says correlation logs cannot be forwarded from a firewall.
PANORAMA_FORWARDABLE_LOG_TYPES = (
    "system", "config", "userid", "hipmatch", "globalprotect", "iptag",
    "traffic", "threat", "wildfire", "url", "data", "gtp", "sctp", "tunnel", "auth",
    "decryption",
)

#: The Log Forwarding profile's own `log-type` enum, measured by `action=complete` on the
#: PA-5220 with @default='yes' on traffic. `system` and `correlation` are REFUSED at the write -
#: "log-type system is not an allowed keyword" - which is why the device log settings are a
#: different subject. The device offers `decryption`, which the vendor Help's own list omits.
FORWARDING_PROFILE_LOG_TYPES = (
    "traffic", "threat", "wildfire", "url", "data", "gtp", "sctp", "tunnel", "auth",
    "decryption",
)

#: What a row that nobody has recomputed holds, and each one FIRES. A gap column lists what is
#: MISSING, so the full set is the firing side and an empty string is the reassuring one: the
#: window between a migration and the normalization pass announces itself instead of reporting
#: that every firewall in the estate forwards everything.
ALL_SYSTEM_SEVERITIES_MISSING = ",".join(SYSTEM_LOG_SEVERITIES)
ALL_PANORAMA_LOG_TYPES_MISSING = ",".join(PANORAMA_FORWARDABLE_LOG_TYPES)
ALL_FORWARDING_LOG_TYPES_MISSING = ",".join(FORWARDING_PROFILE_LOG_TYPES)


class LogServerTarget(ProvenancedMixin, SyncTrackedModel):
    """One server entry inside one log-settings server profile, in one scope of one appliance.

    PAN-LOG-002 (a syslog destination reached in the clear) and PAN-LOG-008's second half (email
    over authenticated TLS). `profile_referrer_count` is what makes either answerable: a profile
    is only an address book, and nothing is sent until a Log Settings or Log Forwarding match
    list names it.
    """

    #: Computed here: the referrer walk, and the two verdicts over the email keys. The positional
    #: columns - scope, vsys_name, kind, profile_name, server_name - are deliberately NOT here,
    #: matching `ServerProfile`: they come from the subtree or an entry's own attribute, which is
    #: the same thing the base's `scope` and `name` are, and those are not declared either.
    #: See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "meets_authenticated_tls",
        "transport_grade",
        "profile_referrer_count",
    )

    class Kind(models.TextChoices):
        SYSLOG = "syslog", "Syslog"
        EMAIL = "email", "Email"

    class Transport(models.TextChoices):
        UDP = "UDP", "UDP"
        TCP = "TCP", "TCP"
        #: The device's own name for the TLS transport, and the only one that encrypts. Writing
        #: `TLS` is refused - "transport TLS is not an allowed keyword".
        SSL = "SSL", "SSL (TLS)"

    class Protocol(models.TextChoices):
        SMTP = "SMTP", "SMTP"
        TLS = "TLS", "SMTP over TLS"

    #: The grades `transport_grade` can hold. Four members for two measured enums: the fourth is
    #: protocol TLS with no `tls-version` key, which stage 4 measured as a RELATION rather than a
    #: constant - the dialog renders 1.2 under protocol TLS and nothing under SMTP - so it may
    #: not be materialised as 1.2 and is its own state.
    GRADE_SMTP = "SMTP"
    GRADE_TLS_11 = "TLS 1.1"
    GRADE_TLS_12 = "TLS 1.2"
    GRADE_TLS_VERSION_UNSET = "TLS version not configured"

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="log_server_targets")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="log_server_targets")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="log_server_targets", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="log_server_targets")

    #: Scope follows the config subtree the profile was read at, never which read returned it.
    #: The tokens are the base's three and are imported rather than restated. A profile that
    #: exists only in a pushed TEMPLATE is stored here as though the appliance defined it -
    #: there is no fourth token - and the per-field `template` provenance row beside it is the
    #: only thing that says otherwise. Two of the lab PA-5220's shared syslog profiles arrive
    #: that way, so this is the common case on a managed estate rather than an edge.
    scope = models.CharField(
        max_length=16, choices=ApplianceScopedObject.SCOPE_CHOICES,
        default=ApplianceScopedObject.SCOPE_SHARED)
    #: Blank unless scope is vsys. Not a foreign key, for the same reason as the base's: the row
    #: is anchored to the appliance and the vsys is a property of where the definition sits.
    #: A SHARED GATEWAY lands here holding the gateway's name, which is not a vsys, so a reader
    #: comparing this against the device's vsys list will not always find it.
    vsys_name = models.CharField(max_length=64, blank=True)
    #: Which log-settings child the profile sits in. A path element, not a key.
    kind = models.CharField(max_length=24, choices=Kind.choices)

    #: The parent profile's name - what a match list's `send-syslog`/`send-email` member
    #: resolves against, which is why it has to be stored and reachable and not only displayed.
    profile_name = models.CharField(max_length=64)
    #: The server entry's own name, which is what a finding prints to say which of a profile's
    #: servers it is about.
    server_name = models.CharField(max_length=64)

    #: TWO KEY NAMES, ONE COLUMN: `server` on the syslog kind, `gateway` on the email kind. The
    #: precedent is `ServerProfile.server_addresses`, which folds three names for the same
    #: reason - a normalizer reading one name loses the other kind silently.
    #:
    #: Empty means the key was absent. On the email kind that cannot happen on a committed
    #: device - `gateway` is mandatory at commit validation, measured - and on the syslog kind
    #: the absence was never observed, so nothing is assumed either way.
    server_address = models.CharField(max_length=255, blank=True)
    #: THE IMPLICIT IS MATERIALISED PER KIND - 514 on syslog, 25 on email - AND IT WAS NULL
    #: UNTIL 2026-10-30. The earlier reading declined to store anything, because the grid renders
    #: 514 under transport SSL where the vendor's own completion help names 6514, and every email
    #: wire test wrote a high port since 25 is privileged on the test host, so no oracle could
    #: separate a real implicit value from a renderer constant.
    #:
    #: WHAT SUPERSEDED IT IS A MEASUREMENT: the 2026-10-26 re-run named the discriminator that
    #: pass lacked - the write path refuses 0 and 70000 with "should be equal to or between 1 and
    #: 65535", so 514 sits inside the range and is not a sentinel - and read the cell rendering
    #: 514 on an entry whose transport is the secure value, so it is a constant rather than a
    #: function of the transport. The stored defaults are the CLEARTEXT ports, which is the side a
    #: reader should worry about: an entry nobody could read reports as reaching a cleartext port.
    #:
    #: WHAT IS STILL OPEN: no oracle has watched an absent-port entry's datagrams on the wire.
    #: Nothing clauses on this column - a secure session on another agreed port still satisfies
    #: the assertion - so the open part is about what a finding PRINTS. The normalizer's implicit
    #: block carries both readings and says a person should settle it.
    port = models.PositiveIntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(65535)])

    # --- syslog ---------------------------------------------------------------------------
    #: IMPLICIT UDP, MEASURED ON TWO ORACLES: a committed server entry holding only its address
    #: renders UDP in the grid AND sends UDP datagrams on the wire; writing TCP moved delivery
    #: to tcp/5514 in octet-counted frames, SSL produced a TLS ClientHello, and deleting the key
    #: returned both oracles to UDP. 2026-10-19, fw-core-tpa-a, PA-5220 11.1.13-h3.
    #:
    #: The default is on the FIRING side of PAN-LOG-002 and that is the whole point of
    #: materialising it: a null here would make every unconfigured syslog server in the estate
    #: pass a control about cleartext.
    transport = models.CharField(
        max_length=8, choices=Transport.choices, default=Transport.UDP, blank=True)

    # --- email ----------------------------------------------------------------------------
    #: MANDATORY AT COMMIT VALIDATION on both platforms, so no committed relay lacks it and an
    #: absence asserts nothing. The empty string is "the key was not there", which on this node
    #: can only be an uncommitted candidate state.
    protocol = models.CharField(max_length=8, choices=Protocol.choices, blank=True)
    #: EMPTY RATHER THAN 1.2, and the reason is the one open question this column carries. The
    #: 1.2 implicit value was measured as a RELATION, not a constant: the dialog's inner grid
    #: renders 1.2 with the key absent UNDER PROTOCOL TLS and renders nothing under SMTP. A
    #: constant 1.2 expanded over every row would claim a hardened setting for relays that have
    #: none, so `transport_grade` carries that state as a member of its own instead.
    tls_version = models.CharField(max_length=8, blank=True)
    #: EMPTY RATHER THAN `Auto`. `action=complete` offers Auto, Login and Plain and marks NONE of
    #: them default on either platform, while the vendor Help documents "Auto (default)" - a
    #: disagreement recorded rather than resolved. The one available oracle does not move with
    #: the key: over cleartext SMTP with a username and password set, the client sent no AUTH
    #: command for auth absent, Auto and Login alike. So a stored `Auto` would not be evidence
    #: that anything authenticates.
    auth_method = models.CharField(max_length=16, blank=True)

    #: PAN-LOG-008's verdict: protocol TLS AND tls-version 1.2 AND an authentication method.
    #: One column rather than three clauses because the failure is a DISJUNCTION over three
    #: columns and the clause grammar is a flat conjunction - written as three queries it would
    #: report one relay three times.
    #:
    #: A relay with protocol TLS and no tls-version key is FALSE here: the device may well
    #: negotiate 1.2 and nothing stored establishes it.
    meets_authenticated_tls = models.BooleanField(default=False)
    #: The protocol-and-version pair as one graded value, because a severity grading places
    #: values of ONE column and the vendor keeps the pair in two. Empty when the row has not
    #: been graded, which matches no severity query and reports at the control's own severity.
    transport_grade = models.CharField(max_length=32, blank=True)

    #: How many forwarding rules on this appliance name this server's PARENT profile - a Device >
    #: Log Settings match list's `send-syslog`/`send-email` for any log type, or a Log Forwarding
    #: profile match list's. Audit-tracking's own `send-syslog` is excluded: it is a different
    #: subject and was ruled out of scope.
    #:
    #: ZERO SILENCES PAN-LOG-002 RATHER THAN FIRING IT, because its applicability clause requires
    #: a non-zero count - the OPPOSITE direction from the shipped control on the same shape
    #: (PAN-AAA-013 fires on `referrer_count eq 0`). So the window between a migration and the
    #: referrer walk is a false negative here and a false positive there.
    profile_referrer_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["appliance__hostname", "kind", "scope", "vsys_name", "profile_name",
                    "server_name"]
        indexes = [
            models.Index(fields=["appliance", "kind"]),
            models.Index(fields=["profile_name"]),
            models.Index(fields=["transport"]),
            models.Index(fields=["profile_referrer_count"]),
        ]
        constraints = [
            # Stage 5's identity, in its order. THE KIND IS INSIDE IT, as it is on
            # `ServerProfile`: one appliance can hold a shared syslog profile and a shared email
            # profile whose server entries have the same names, and keying without the kind would
            # make the second overwrite the first and the count come out short.
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "kind", "profile_name", "server_name"],
                name="unique_log_server_target_per_profile"),
        ]

    def __str__(self) -> str:
        where = f"{self.scope}:{self.vsys_name}" if self.vsys_name else self.scope
        return f"{self.appliance} / {where} / {self.kind} / {self.profile_name}/{self.server_name}"


class VsysLogForwarding(ProvenancedMixin, SyncTrackedModel):
    """The Log Forwarding available to one virtual system of one appliance. PAN-LOG-005.

    THE VSYS IS THE ROW AND NOT THE PROFILE, because the gap the control is about is a vsys with
    NO adequate profile, and a profile-keyed row cannot report something that does not exist.

    The profiles it reads live at FOUR scopes - the vsys's own, shared, Panorama-pushed and
    vendor-predefined - and `offbox_log_type_gaps` is a verdict across all of them. Name
    resolution is PER NAMESPACE and the two measured directions DISAGREE: for `default` only the
    Panorama-pushed profile was offered to a vsys3 rule and the local one was shadowed, while for
    `IoT Security Default Profile` only the local one was offered and the predefined was dropped.
    No single precedence ladder is true, so `profile_names` records which source each name came
    from rather than asserting an order, and the gap column takes the union: a log type is covered
    if any profile available to the vsys sends it off the box.

    CARRIES NO PER-FIELD PROVENANCE, and that is a real `false` rather than a lapse. Every column
    is computed, a computed column may never have a provenance row, and three shipped subject
    models carry none either. The limit it leaves is that a control whose finding turned on
    whether a profile was PUSHED could not be written against this subject - the device-group
    scope is held in provenance on the profile rows, which this model does not store.
    """

    #: Everything but the identity. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "profile_names",
        "offbox_log_type_gaps",
        "pushed_profile_sources_collected",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="vsys_log_forwarding")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="vsys_log_forwarding")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="vsys_log_forwarding", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="vsys_log_forwarding")

    #: The vsys's own name on the device, enumerated from the device's own config and never from
    #: Panorama's assignment records. A vsys named vsys1 exists on single-vsys platforms too, so
    #: one row per appliance is the normal case rather than the exception.
    vsys_name = models.CharField(max_length=64)

    #: The profiles available to this vsys as a display structure - name, the source it came from
    #: and the log types it sends off the box. FOR A READER, NOT FOR A FINDING: a finding must
    #: not rest on a stored structure, because an unindexed lookup and a renamed vendor key that
    #: matches nothing both fail silently. The verdict column beside it is what a query reaches.
    profile_names = models.JSONField(default=list, blank=True)

    #: Which log types no profile available to this vsys sends off the box, as the types that are
    #: MISSING. Empty means every type the profile enum offers is sent somewhere off the box.
    #: Email and SNMP-trap destinations do NOT count as off-box: they notify rather than retain.
    offbox_log_type_gaps = models.CharField(
        max_length=255, blank=True, default=ALL_FORWARDING_LOG_TYPES_MISSING)

    #: Whether the two reads that carry the Panorama-pushed and vendor-predefined profiles
    #: returned for this appliance, as against the gap column having been computed from the local
    #: profiles alone. FALSE EXCLUDES THE ROW from PAN-LOG-005 through its applicability clause,
    #: and the direction is deliberate: over-reporting here means telling an engineer that a
    #: correctly configured vsys has no log forwarding.
    pushed_profile_sources_collected = models.BooleanField(default=False)

    class Meta:
        ordering = ["appliance__hostname", "vsys_name"]
        indexes = [models.Index(fields=["appliance", "vsys_name"])]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "vsys_name"],
                name="unique_vsys_log_forwarding_per_vsys"),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.vsys_name} log forwarding"
