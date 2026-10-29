"""The PAN-OS integrated User-ID agent - PAN-UID-002, 003, 004, 005 and 006's subjects.

Three models, three grains, and the grain is the whole design here:

`UserIdCollectorSettings` is ONE ROW PER ENFORCEMENT POINT - the singleton `setting` node at
`vsys/entry/user-id-collector/setting`, which is what Device > User Identification > User
Mapping > Palo Alto Networks User-ID Agent Setup edits. A row exists for every vsys in scope
WHETHER THE NODE EXISTS OR NOT, because the implicit values apply either way: the panel renders
the same values on a vsys whose whole `setting` node has been deleted and committed, measured on
a lab PA-VM 2026-10-26. The node is absent on all four lab appliances and all twenty vsys, so
on this estate every row's content IS the four materialised defaults.

`UserIdDiscoveryBound` is ONE ROW PER ENFORCEMENT POINT and a VERDICT OVER the entries of
`user-id-collector/include-exclude-network`, not one row per entry. The reason is which row
exists in the commonest FAILING state: PAN-UID-002's baseline failure is no entries at all - an
absent list, a committed-and-empty one, or one holding nothing in force - and in every one of
those states a per-entry model has no row, so the control would report nothing and the estate
would read clean. An engineer fixing it ADDS an entry to the grid; they do not open an entry
that is not there.

`UserIdMonitoredServer` is ONE ROW PER NAMED ENTRY of `user-id-collector/server-monitor`, with
the KIND IN THE KEY. Here the commonest failing state is a row that EXISTS and is wrong - a
syslog sender on the connectionless transport - so the entry grain is right, and it discharges
PAN-UID-005's applicability for free: no sender, no row, no finding.

THE KIND IS IN THE IDENTITY and not merely a column. The entry is discriminated by WHICH CHILD
CONTAINER is present - `active-directory`, `e-directory`, `exchange` or `syslog` - and the
device enforces it: an entry with no branch is accepted at the write, refused by the useridd
daemon at commit phase 1 with `Error: server <name> type is unknown`. Without the kind in the
key, two kinds sharing a name collapse into one row and the survivor is whichever was written
last, and the name is also the string the grid shows and the string that error quotes back.

WHAT NO ROW HERE CAN SAY is whether its content was pushed by a Panorama template. The two
provenanced models record a per-FIELD template marker where one arrives, so a pushed VALUE
survives; what has nowhere to go is the ROW's own scope, because the store keys these subjects
by `EnforcementPoint` and has no scope axis for a pushed singleton. Stage 4 measured no pushed
content under `user-id-collector` on any lab appliance, so this is unobserved rather than
impossible - and the consequence is a wrong REMEDIATION, telling an engineer to untick a box on
a screen whose values the firewall does not own.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class UserIdCollectorSettings(ProvenancedMixin, SyncTrackedModel):
    """One vsys's integrated User-ID agent settings. PAN-UID-003, 004, 006 and half of 005.

    EVERY COLUMN HERE IS NON-NULLABLE AND THAT IS LOAD-BEARING rather than tidy. The consumer's
    clause grammar has no is-null operator: a `> 60` over a NULL is silent on every compiler in
    this estate, and a negated equality against a NULL matches neither value. So a nullable
    spelling of any of these would invert its control in silence, with nothing erroring at any
    layer. The four columns whose implicit is MEASURED carry that measured value; the two whose
    implicit is not established store the empty string, which `parse_text_field` produces for an
    absent key whatever the declaration says.

    `enable_mapping_timeout` DEFAULTS TRUE WHERE ITS NEIGHBOURS DEFAULT FALSE, and it is the one
    value in this domain a reader is most likely to invert. Expiry ON is the good state; probing
    ON and session-reading ON are the bad ones. A normalizer or a query author carrying "absent
    means the weak state" across from the other two stores or clauses the opposite of the truth
    here, and nothing errors.
    """

    #: Only the sync flag. The six configuration columns are all read from payload keys, so each
    #: carries a real `FieldProvenance` row - `pan_os_default` for the four measured implicits
    #: and `not_configured` for the two that are not assumed. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = ("is_missing",)

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="user_id_collector_settings")
    enforcement_point = models.ForeignKey(
        "integrations.EnforcementPoint", on_delete=models.CASCADE,
        related_name="user_id_collector_settings")
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="user_id_collector_settings")

    #: Whether this vsys's agent reaches out to endpoints over WMI to confirm who is logged in.
    #: POSITIVE direction, no inversion: true means the firewall PROBES, and true FIRES.
    #:
    #: FALSE IS THE MEASURED IMPLICIT and it is the compliant side. That is what the device does
    #: - a committed bare `setting` node renders Enable Probing unticked - and what makes it a
    #: measurement rather than a convenience is a positive control paid in BOTH directions on
    #: the same panel: written yes and committed, the box rendered ticked; deleted and committed,
    #: unticked again.
    enable_probing = models.BooleanField(default=False)

    #: Whether this vsys's agent polls its monitored servers for user SESSIONS. True requires the
    #: directory account it authenticates as to hold Server Operator rights over those servers,
    #: so true is the direction that fires.
    #:
    #: THIS COLUMN SAYS WHAT THE CONFIGURATION DEMANDS AND NEVER WHAT THE ACCOUNT HAS. An account
    #: which IS a domain administrator with this option off fails PAN-UID-004 while looking clean
    #: here; the other half is `wmi_account` and a directory read nothing on a firewall can take.
    enable_session = models.BooleanField(default=False)

    #: Whether learned user-to-address mappings expire at all on this vsys. FALSE is the direction
    #: that FIRES - see the class docstring on why this one defaults the other way.
    enable_mapping_timeout = models.BooleanField(default=True)

    #: How many minutes a learned mapping may live. A larger number is worse, and it bounds
    #: NOTHING where `enable_mapping_timeout` is false - which is why the two are separate
    #: assertions rather than one.
    #:
    #: THE DEVICE'S SETTABLE RANGE IS 1 TO 1440 AND THE VENDOR DOCUMENTS 3,600. Measured: the
    #: write gate refuses both 1441 and 3600 with code=12 `ip-user-mapping-timeout value=N should
    #: be equal to or between 1 and 1440`, and accepts 1 and 1440, while the Web Interface Help
    #: documents the ceiling as 3,600 identically on three builds. A remediation written from the
    #: Help above 1440 is refused by the firewall. The same Help sentence IS right about the
    #: default of 45, which is measured.
    #:
    #: 45 as the stored default is the most reassuring value in this domain and is still the right
    #: one: it sits inside the acceptable band, so a clean estate reports clean because the device
    #: really does expire mappings at 45 minutes. A 0 here, or a NULL compared with `> 60`, would
    #: give the same clean answer for the wrong reason and stay clean after somebody typed 3600.
    ip_user_mapping_timeout = models.PositiveIntegerField(default=45)

    #: The directory principal this vsys's agent authenticates as when it reads its monitored
    #: servers' security event logs. The firewall stores the NAME and nothing about what the
    #: account may do, so NON-EMPTY is the direction that fires - not because a configured
    #: account is wrong, but because its rights are unestablished from the firewall.
    #:
    #: BLANK AND NON-NULLABLE, which is not a contradiction: nothing is STORED for an absent key
    #: and what lands in the column is ``. `parse_text_field` returns the empty string for an
    #: absent key whatever the declaration says, and it does NOT fall back to the implicit for a
    #: key that is present and empty - so present-and-empty and absent both store ``, which is
    #: correct here because neither names a principal.
    #:
    #: 255 is this store's number and not the device's: no `maxLength` was measured for any field
    #: of this domain. It is chosen to hold a UPN or a DOMAIN\\user without slicing the tail off a
    #: real value.
    wmi_account = models.CharField(max_length=255, blank=True)

    #: The SSL/TLS service profile bound to this vsys's ENCRYPTED syslog listener, by name - the
    #: certificate and protocol floor that listener presents. Empty means nothing is bound, which
    #: is the state in which the encrypted listener cannot be switched on at all.
    #:
    #: A NAME AND NOT A FOREIGN KEY, deliberately: `integrations.SslTlsServiceProfile` is anchored
    #: to the APPLIANCE and may be pushed, and PAN-CRT-005 owns the floor those profiles set. What
    #: this domain owns is only whether one is bound. The boolean a finding rests on is
    #: `UserIdMonitoredServer.tls_service_profile_bound`, computed from this column.
    syslog_service_profile = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["enforcement_point__vsys_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point"],
                name="integrations_unique_user_id_collector_per_point"),
        ]
        indexes = [
            models.Index(fields=["enforcement_point"]),
            models.Index(fields=["management_station"]),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} User-ID collector"

    def clean(self) -> None:
        """The timeout has to be a value the device would accept.

        Measured at the write gate rather than taken from the Help, which documents 3,600: the
        firewall refuses anything outside 1-1440. A stored value outside that range could only
        come from a normalizer bug or a payload nobody has seen, and a remediation quoting it
        back would be refused.
        """
        if not 1 <= self.ip_user_mapping_timeout <= 1440:
            raise ValidationError(
                "ip_user_mapping_timeout must be between 1 and 1440 - the range the device "
                "accepts at the write gate, measured, against the 3,600 the Help documents.")


class UserIdDiscoveryBound(ProvenancedMixin, SyncTrackedModel):
    """One vsys's whole User-ID discovery bound, as a verdict. PAN-UID-002.

    EVERY COLUMN IS DERIVED, and that is the price of the verdict grain rather than an oversight:
    a verdict row holds nothing read directly off the collection it is a verdict over, so stage
    4's one measured implicit on this object - the per-entry `disabled` key, polarity NEGATED
    with implicit `no`, so an entry carrying no `disabled` key is IN FORCE - is honoured INSIDE
    the derivation and carries no provenance row of its own. It was weighed against being unable
    to report the control's baseline failure, and the baseline failure won outright.

    AN ABSENT LIST AND A COMMITTED EMPTY ONE ARE COLLAPSED HERE DELIBERATELY. They read
    differently on the wire - an absent collection answers None and raises `No such node` under
    `show`, while an empty committed one answers a truthy `{'include-exclude-network': null}` in
    all three views, measured on a lab PA-VM - and for this control they mean the same thing: an
    empty list bounds nothing, exactly as no list bounds nothing. The failure to avoid is the
    opposite one, a query testing whether the NODE IS PRESENT rather than whether an in-force
    include entry exists, which answers `bounded` on an appliance that is not.
    """

    #: EVERY column is computed at normalization and no payload key carries any of them, so none
    #: can have a provenance row. Nothing is tracked on this model by design.
    DERIVED_FIELDS = (
        "is_missing",
        "list_shape",
        "include_entry_count",
        "exclude_entry_count",
        "include_networks",
    )

    #: At least one in-force include entry exists and none of them covers publicly routable space.
    SHAPE_INCLUDE_PRESENT = "include_present"
    #: At least one in-force include entry covers address space outside RFC 1918 and RFC 3927.
    SHAPE_INCLUDE_COVERS_PUBLIC = "include_covers_public"
    #: In-force entries exist and every one of them is an exclude. The vendor's implicit
    #: exclude-all rule then stops user mapping entirely - a functional fault rather than an
    #: exposure, which is why it grades below the unbounded state rather than above it.
    SHAPE_EXCLUDE_ONLY = "exclude_only"
    #: The list is absent, or committed and empty, or holds nothing in force.
    SHAPE_NO_ENTRIES = "no_entries"
    #: ORDERED, and the order IS the evaluation order the normalizer walks, so one row has one
    #: answer. Covering public space beats merely having an include; having an include beats
    #: having only excludes; anything beats nothing.
    SHAPE_CHOICES = [
        (SHAPE_INCLUDE_COVERS_PUBLIC, "An include entry covers public address space"),
        (SHAPE_INCLUDE_PRESENT, "An include entry is in force"),
        (SHAPE_EXCLUDE_ONLY, "Excludes only"),
        (SHAPE_NO_ENTRIES, "No entries in force"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="user_id_discovery_bounds")
    enforcement_point = models.ForeignKey(
        "integrations.EnforcementPoint", on_delete=models.CASCADE,
        related_name="user_id_discovery_bounds")
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="user_id_discovery_bounds")

    #: The verdict, in one of the four states above - AND BLANK, which is a fifth state that must
    #: never be rendered as a verdict. Blank means `not computed`: it is what a row holds between
    #: the migration that adds this column and the pass that fills it, and it fires, because the
    #: restatement is written as the passing condition and `` is not `include_present`. The
    #: report should print it as unevaluated and the finding it raises should say the bound could
    #: not be established, not that it is absent.
    #:
    #: A STRING AND NOT A SET OF BOOLEANS for exactly that reason: a boolean false would have been
    #: the compliant side on half of these readings.
    list_shape = models.CharField(max_length=32, choices=SHAPE_CHOICES, blank=True)

    #: How many of this vsys's discovery entries are include entries that are IN FORCE. ZERO is
    #: the value that matters - the vendor's documented unbounded state, where the collector
    #: discovers in all subnetworks, and this control's baseline failure. Zero is therefore the
    #: FIRING side, which is the reverse of the usual direction for a count and is why an
    #: unrecomputed row needs no companion.
    include_entry_count = models.PositiveIntegerField(default=0)

    #: How many in-force exclude entries this vsys holds. ZERO IS THE QUIET SIDE here - no
    #: excludes is not a fault - so no finding may rest on this column alone, and none does: it
    #: exists to let a report say WHICH shape it found and to separate the exclude-only state
    #: from the unbounded one. `list_shape` is the companion that fires, and it is blank on
    #: exactly the rows this column is 0 on.
    exclude_entry_count = models.PositiveIntegerField(default=0)

    #: The in-force include entries' configured CIDRs, in list order, as written. NOT RESOLVED
    #: and not judged - these are the ranges a finding prints, qualified by the engineer's answer
    #: about which of them hold the organisation's own staff.
    #:
    #: DISPLAY DATA, AND NO FINDING MAY REST ON IT. A JSON lookup is unindexed and matches nothing
    #: when the vendor renames a key, so a control resting on one stops finding anything instead
    #: of failing; the verdict beside it is `list_shape`. An empty list on an unrecomputed row
    #: would render as `no ranges configured`, which is wrong on a bounded appliance - another
    #: reason nothing may clause on it.
    include_networks = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["enforcement_point__vsys_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point"],
                name="integrations_unique_user_id_discovery_bound_per_point"),
        ]
        indexes = [
            models.Index(fields=["enforcement_point"]),
            models.Index(fields=["management_station"]),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} User-ID discovery bound"

    def clean(self) -> None:
        """The verdict, the counts and the JSON list have to agree.

        A JSON field paired with the column a control actually reads gets a `clean()` asserting
        the two agree - the convention `InterfaceManagementProfile` and `Certificate` already
        follow. Here it is load-bearing in one direction: a verdict of `include_present` beside
        an include count of zero would tell a reader the bound exists on a vsys that has none,
        and the query reads the string.
        """
        if len(self.include_networks) != self.include_entry_count:
            raise ValidationError(
                "include_networks must hold exactly one range per in-force include entry.")
        if self.list_shape in (self.SHAPE_INCLUDE_PRESENT, self.SHAPE_INCLUDE_COVERS_PUBLIC):
            if not self.include_entry_count:
                raise ValidationError(
                    f"list_shape {self.list_shape} cannot be stored where no include entry is "
                    f"in force.")
        if self.list_shape == self.SHAPE_EXCLUDE_ONLY:
            if self.include_entry_count or not self.exclude_entry_count:
                raise ValidationError(
                    "list_shape exclude_only means in-force excludes and no in-force include.")
        if self.list_shape == self.SHAPE_NO_ENTRIES:
            if self.include_entry_count or self.exclude_entry_count:
                raise ValidationError(
                    "list_shape no_entries cannot be stored where an entry is in force.")


class UserIdMonitoredServer(ProvenancedMixin, SyncTrackedModel):
    """One host a vsys's User-ID collector takes identity from. PAN-UID-005's third half.

    The row is the entry the Server Monitoring grid shows, and the finding names it:
    `pan-fw-201 vsys1 / ad-syslog-01`. A vsys with no sender has no row, which is what
    PAN-UID-005's applicability asks for - where no sender is configured the firewall admits no
    host on this path and there is nothing to judge.

    ALL FOUR KINDS GET A ROW, not only the syslog senders. The control's clause is a scope clause
    on the kind, so storing only the kind it asks about would make this model unusable for the
    first control that asserts anything about an Active Directory server - and the four branches
    are named here so that a later run adding one can see what it is joining.
    """

    #: `monitored_server_kind` is WHICH CHILD CONTAINER was present, and
    #: `tls_service_profile_bound` is a value resolved through another model's row. Neither is a
    #: payload key, so neither may have a provenance row. The entry's own `__entry__` row and
    #: `connection_type`'s row are real. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "monitored_server_kind",
        "tls_service_profile_bound",
    )

    KIND_ACTIVE_DIRECTORY = "active-directory"
    KIND_E_DIRECTORY = "e-directory"
    KIND_EXCHANGE = "exchange"
    KIND_SYSLOG = "syslog"
    #: The device's own spelling of its four type branches, measured with `action=complete` and
    #: enforced at commit rather than merely offered. ORDERED, and the order is what
    #: `choice_child` walks; the schema permits only one branch per entry.
    KIND_CHOICES = [
        (KIND_ACTIVE_DIRECTORY, "Active Directory"),
        (KIND_E_DIRECTORY, "eDirectory"),
        (KIND_EXCHANGE, "Exchange"),
        (KIND_SYSLOG, "Syslog sender"),
    ]

    CONNECTION_UDP = "udp"
    CONNECTION_SSL = "ssl"
    CONNECTION_CHOICES = [
        (CONNECTION_UDP, "UDP"),
        (CONNECTION_SSL, "SSL"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="user_id_monitored_servers")
    enforcement_point = models.ForeignKey(
        "integrations.EnforcementPoint", on_delete=models.CASCADE,
        related_name="user_id_monitored_servers")
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="user_id_monitored_servers")

    #: The entry's own name - what the grid shows, what the useridd error quotes back, and what a
    #: finding prints as its subject. An entry cannot be nameless, and a nameless one is dropped
    #: rather than stored with an empty subject, as the shipped zone normalizer does.
    name = models.CharField(max_length=64)

    #: Which of the four type branches this entry carries. It is what the entry IS, and it decides
    #: which other columns mean anything: a syslog sender's `connection_type` has no counterpart
    #: on an AD server, whose transport is a different question with a different answer.
    #:
    #: BLANK SUPPRESSES RATHER THAN FIRES, and that is worth saying plainly because it is the one
    #: direction in this domain that cannot be arranged away. A row holding `` matches no kind
    #: clause, so every control on this model reports nothing for it - the control is not wrong,
    #: it is absent. No value would be safer: any value this column held would put the row into
    #: some OTHER kind's control. The mitigation is ordering - the pass that fills it must run
    #: before any control on this model is enabled - and on a committed device it should be
    #: impossible, because the useridd daemon refuses an entry with no branch at commit phase 1.
    #: A blank value in the store is therefore a normalization fault and not a device state.
    monitored_server_kind = models.CharField(max_length=32, choices=KIND_CHOICES, blank=True)

    #: Which transport a SYSLOG sender delivers identity mappings over - `ssl` for the encrypted,
    #: certificate-backed listener, `udp` for the connectionless, unauthenticated one. Blank on
    #: the other three kinds, which have no such leaf.
    #:
    #: ANYTHING THAT IS NOT `ssl` FIRES, AND THAT INCLUDES A VALUE NOBODY READ. The clause is a
    #: negated equality against `ssl` rather than an equality against `udp`, on purpose: the
    #: column holds `` for an absent key and for an unread one alike, and `eq udp` would pass an
    #: unread sender silently. Non-nullable for the same reason - a negated equality against a
    #: NULL matches neither value in SQL, so a nullable spelling would stop the unread sender
    #: firing with nothing erroring.
    connection_type = models.CharField(
        max_length=16, choices=CONNECTION_CHOICES, blank=True)

    #: Whether the vsys collector this sender belongs to names an SSL/TLS service profile for its
    #: encrypted syslog listener. True means a profile is bound; false means nothing is, and the
    #: encrypted listener cannot be switched on at all.
    #:
    #: A BOOLEAN AND NOT THE PROFILE NAME, deliberately: the name lives on
    #: `UserIdCollectorSettings`, where it was measured, PAN-CRT-005 owns the floor that profile
    #: sets, and what this control owns is only whether one is bound. Carrying the name here
    #: would duplicate another subject's value across rows and invite a clause that is really a
    #: certificate control's.
    #:
    #: FALSE on an unrecomputed row, which FIRES: false is the unbound state, and here the
    #: prescribed direction costs nothing to arrange because the compliant state is the one that
    #: needs a value present.
    tls_service_profile_bound = models.BooleanField(default=False)

    class Meta:
        ordering = ["enforcement_point__vsys_name", "monitored_server_kind", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "monitored_server_kind", "name"],
                name="integrations_unique_user_id_monitored_server_per_point"),
        ]
        indexes = [
            models.Index(fields=["enforcement_point", "monitored_server_kind"]),
            models.Index(fields=["management_station"]),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} / {self.monitored_server_kind or '?'} / {self.name}"

    def clean(self) -> None:
        """A transport belongs to a syslog sender and to nothing else.

        The other three branches carry no `connection-type` leaf at all, so a stored transport on
        one of them would be a value the device cannot hold - and the control's clause pairs the
        kind with the transport, so it would read as a syslog sender that was never one.
        """
        if self.connection_type and self.monitored_server_kind != self.KIND_SYSLOG:
            raise ValidationError(
                "connection_type belongs to a syslog sender; no other branch carries the leaf.")
