"""Platform lifecycle - PAN-PLT-001 to PAN-PLT-006's subjects.

EIGHT MODELS, SEVEN OF THEM ONE ROW PER APPLIANCE AND ONE A COLLECTION. Every reading behind
them is device-wide rather than vsys-scoped, so nothing here is anchored to an enforcement
point, and on an HA pair each peer yields its own row for what an operator thinks of as one
firewall. That is deliberate and nothing downstream deduplicates it: a license is per serial,
content is installed per serial, and the dataplane load of an active member is not its peer's.
`DataplaneUtilisation` is the one model where the two rows of a pair SHOULD differ.

A ROW EXISTS EVEN WHERE THE READ NEVER ARRIVED, following `MasterKey` and
`DeviceIdentificationState`: every model here is anchored to the MERGED snapshot, which every
appliance has, and each one carries a companion boolean or token saying whether its own read
answered - `content_streams_collected`, `telemetry_switches_known`, `portal_vsys_coverage`,
`licence_inventory_read`, `alarm_generation_enabled_known`, `on_box_snapshot_list_collected`,
`resource_monitor_collected`. "We never asked" must not look like "we asked and it was fine",
and on this domain that separation is load-bearing in four different ways at once:

  - `{"licenses": null}` is what an UNLICENSED appliance answers AND what a read that never
    happened leaves behind, measured on both PA-5220s;
  - a telemetry switch that is null means the node is absent, which is NOT `no`;
  - `cpu-load-average` comes back `0,0,0,...` on all four lab appliances, so an idle appliance
    and one whose counters never populated are the same number;
  - the alarm node is absent on every appliance in the estate, so its master switch holds a
    genuine NULL and a clause `eq false` on it matches no row at all.

NO `scope` COLUMN ON ANY OF THESE MODELS, and stage 5 declared one for every subject. Every
reading here is device-wide, so the column would hold one value on every row for ever; OEI's
own appliance-wide models - `MasterKey`, `DeviceIdentificationState`, `LoggingSettings`,
`CertificateSettings` - carry none either, and `ApplianceScopedObject.SCOPE_CHOICES` offers
only shared/vsys/predefined, none of which is what a runtime reply is. Recorded in the stage 7
artifact's `columns_not_built` and `spec_surplus` rather than built.

PROVENANCE IS STORED FOR TWO MODELS AND DECLARED DERIVED FOR THE REST. `LogAlarmSettings` and
`LicenceEntitlement` write real `FieldProvenance` rows - the first because `not_configured` is
the only thing a row there can ever say and saying it is the point, the second because
`base_license_name`'s absence is a MEASURED discriminator (an absent key means this row IS the
base license) and the provenance row is the only place that separates that from nobody looking.
Everything else is either a computation or a key off an operational reply, which carries no
`@ptpl`, `@loc` or `@src` decoration and never will, so those columns are declared in
`DERIVED_FIELDS` instead.

Measured on 013201001475 (PA-5220, 11.1.13-h3), 013201001085 (PA-5220, 11.1.13-h3),
6A9C0A9904E7D6E (PA-VM, 11.2.3-h3) and 691665AC334B458 (PA-VM, 11.2.5). Appliances are named
by SERIAL throughout: 691665AC334B458 answers to the factory-default hostname `PA-VM` and has
never had one set.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


#: `content_currency_state`'s vocabulary. INVENTED BY STAGE 5 FROM STAGE 3's SEVERITY RANKS -
#: no device read returns any of these - and the empty string is a sixth state this list does
#: not carry on purpose: it is what an unrecomputed row holds, it is not `current`, and the
#: control's clause is a negated equality against `current`, so it FIRES.
CONTENT_CURRENCY_STATES = [
    ("applications_and_threats_behind", "Applications and threats behind"),
    ("malware_stream_behind", "Malware stream behind"),
    ("inside_minimum_outside_preferred", "Inside minimum, outside preferred"),
    ("current", "Current"),
    ("release_date_not_reported", "No release date reported"),
    ("stream_never_installed", "A stream was never installed"),
]

#: `portal_container_state`'s vocabulary, from the FOUR shapes a container read can return plus
#: the not-collected state. Three of the four obvious readings collapse at least two of them:
#: `if result:` reports an empty container as a portal, `result is None` reports a staged one as
#: absent, and an entry walk reports a staged one as empty.
PORTAL_CONTAINER_STATES = [
    ("container_absent", "No portal container"),
    ("container_empty", "Container present and empty"),
    ("entries_present", "Portal entries present"),
    ("container_staged_uncommitted", "Staged, not committed"),
    ("not_collected", "Not collected"),
]

#: `portal_vsys_coverage`'s vocabulary. The column exists because of one measurement: a
#: vsys1-only read answers "not a portal" on an appliance that IS one, and both PA-5220s are in
#: that state.
PORTAL_VSYS_COVERAGE_STATES = [
    ("every_vsys_read", "Every vsys read"),
    ("some_vsys_unread", "Some vsys unread"),
    ("no_vsys_read", "No vsys read"),
]

#: `licence_inventory_read`'s vocabulary, named for the SHAPE of the reply and never for a
#: conclusion: `null_licenses_element` is the only shape an unlicensed appliance produces AND
#: the shape a licensed one would produce with every row stripped, so it means unknown.
LICENCE_INVENTORY_READ_STATES = [
    ("rows_returned", "Rows returned"),
    ("null_licenses_element", "Null licenses element"),
    ("not_collected", "Not collected"),
]

#: `entitlement_state`'s vocabulary, from stage 3's severity ranks plus the two unknown shapes.
ENTITLEMENT_STATES = [
    ("expired_entitlement_present", "An entitlement has expired"),
    ("expiring_within_30_days", "An entitlement expires within 30 days"),
    ("active_inside_90_days", "All active, inside 90 days"),
    ("active_beyond_90_days", "All active, beyond 90 days"),
    ("no_licence_rows_returned", "No license rows returned"),
    ("inventory_not_collected", "Inventory not collected"),
]

#: `support_entitlement_state`'s vocabulary. `absent_from_inventory` is the value every row in
#: this estate holds - not one of the thirteen licence rows measured names a support
#: entitlement - and it is a FINDING rather than a pass: an absent row is the same shape as a
#: subscription nobody bought.
SUPPORT_ENTITLEMENT_STATES = [
    ("absent_from_inventory", "Absent from the inventory"),
    ("expired", "Expired"),
    ("expires_within_90_days", "Expires within 90 days"),
    ("active_beyond_90_days", "Active beyond 90 days"),
    ("inventory_not_collected", "Inventory not collected"),
]

#: `alarm_mechanism_state`'s vocabulary, from stage 3's four ranks plus the state its ranks do
#: not cover. `node_absent` is this estate's own state on three of four appliances.
ALARM_MECHANISM_STATES = [
    ("node_absent", "No alarm node"),
    ("generation_off", "Alarm generation off"),
    ("on_without_thresholds", "On, no threshold"),
    ("on_with_thresholds_no_route", "On, thresholds, no notification route"),
    ("on_with_thresholds_and_route", "On, thresholds and a notification route"),
]


class FirewallContentStreams(ProvenancedMixin, SyncTrackedModel):
    """One appliance's installed content streams. PAN-PLT-002.

    A COLUMN PER STREAM ON ONE ROW, not a row per stream, and the reason is that the device
    offers no stream entity to key on: the streams are KEYS OF ONE REPLY and a per-stream row
    would make a normalizer invent the row names. The cost is that each stream is separately
    clausable, which is what PAN-PLT-002 asserts - stage 3 records that one `show system info`
    returns all three version strings, so a later stage reading the command as one answer would
    report one verdict where the control asserts three.

    EVERY VERSION COLUMN IS TEXT AND `0` IS A VALUE RATHER THAN AN ABSENCE. `0` is TRUTHY as a
    string, so a truthiness test reports an uninstalled stream as installed, and a numeric
    comparison treats it as the lowest version rather than as no version. The URL filtering
    stream spells the same thing `0000.00.00.000`, which is a different literal for the same
    state - measured on both PA-5220s.

    THE RELEASE DATES ARE NOT COMPARABLE ACROSS APPLIANCES AND NOT STABLE ON ONE. They carry a
    timezone ABBREVIATION rather than an offset, and the same content instant read on two PA-VMs
    answers "02:35:51 GMT" and "19:35:51 PDT". The arithmetic that needs them is done at
    normalization against the appliance's OWN clock, in the same frame, and what lands here is
    the string the appliance printed.
    """

    #: Computed here: the two verdicts, the companion, and every version and date string -
    #: which are keys of an OPERATIONAL reply and so carry no marker of any kind. A missing
    #: `FieldProvenance` row means "nothing tracks this field", so declaring them is the only
    #: thing that separates "we worked this out" from "nothing tracks it".
    #: See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "app_version",
        "app_release_date",
        "av_version",
        "av_release_date",
        "threat_version",
        "threat_release_date",
        "wildfire_version",
        "url_filtering_version",
        "device_dictionary_version",
        "device_dictionary_release_date",
        "release_date_reported",
        "content_streams_collected",
        "content_currency_state",
    )

    #: What a version column holds when the stream was NEVER INSTALLED, as the appliance spells
    #: it. Two literals for one state, measured: the four content streams answer `0` and the URL
    #: filtering stream answers `0000.00.00.000`.
    NEVER_INSTALLED_VERSIONS = frozenset({"0", "0000.00.00.000"})

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="firewall_content_streams")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="firewall_content_streams")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="firewall_content_streams", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="firewall_content_streams")

    #: `app-version`. Blank means nobody read it; `0` means the appliance says it was never
    #: installed. Those are different states and the column keeps them apart because blank is
    #: not a value the device ever returns for this key.
    app_version = models.CharField(max_length=64, blank=True)
    #: `app-release-date`, verbatim. BLANK ASSERTS THAT THIS REPLY CARRIES NO RELEASE DATE FOR
    #: THE STREAM and NOT that the stream is uninstalled - the decisive measurement is both
    #: PA-5220s, which report a real `8939-9248` with no `app-release-date` key at all. It must
    #: never be read as a proxy for installation.
    app_release_date = models.CharField(max_length=64, blank=True)
    av_version = models.CharField(max_length=64, blank=True)
    av_release_date = models.CharField(max_length=64, blank=True)
    threat_version = models.CharField(max_length=64, blank=True)
    threat_release_date = models.CharField(max_length=64, blank=True)
    #: `wildfire-version`. There is NO `wildfire-release-date` column: stage 5 declared none,
    #: and the key is absent from the reply wherever the version is `0`. So this stream can
    #: contribute "never installed" to the verdict and never "behind".
    wildfire_version = models.CharField(max_length=64, blank=True)
    #: `url-filtering-version`. Declared and not claused on: stage 3 scopes PAN-PLT-002 to the
    #: applications, antivirus and threats streams.
    url_filtering_version = models.CharField(max_length=64, blank=True)
    #: THE SAME TWO KEYS ALSO LAND ON `DeviceIdentificationState`, which another domain's
    #: PAN-IOT-003 reads. Stage 5 declared them for this subject as well, so both are built;
    #: that they are two columns over one reply is a product decision and not this model's to
    #: reconcile.
    device_dictionary_version = models.CharField(max_length=64, blank=True)
    device_dictionary_release_date = models.CharField(max_length=64, blank=True)

    #: Whether a publication date was reported for every ASSERTED stream that is installed.
    #: It consults the VERSION beside each date, so an uninstalled stream is not reported as a
    #: missing date. False until the normalization pass runs, which FIRES.
    release_date_reported = models.BooleanField(default=False)
    #: Whether `show system info` answered for this appliance at all. The unknown-detector, and
    #: the only column here a control may rely on to tell "we never asked" from "we asked and it
    #: was fine" - the query layer has no is-null operator to ask with.
    content_streams_collected = models.BooleanField(default=False)
    #: The verdict the severity varies with. NON-NULLABLE TEXT ON PURPOSE: the empty string is
    #: not `current`, and the control's clause is a negated equality against `current`, so an
    #: unrecomputed or uncollected row reports rather than passing. A boolean here would be
    #: invisible to both polarities when null.
    content_currency_state = models.CharField(
        max_length=64, blank=True, choices=CONTENT_CURRENCY_STATES)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_content_streams_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} content streams"

    def clean(self) -> None:
        """The verdict must agree with the companion it was computed from.

        The pattern `InterfaceManagementProfile` and `Certificate` already use: a column
        derived from another gets a `clean()` asserting the two agree, because the alternative
        is a verdict that silently outlives the reading it rested on.
        """
        if not self.content_streams_collected and self.content_currency_state:
            raise ValidationError(
                "content_currency_state must be blank where the content read did not answer: "
                "a token here would be a verdict over a reply nobody received.")


# DeviceTelemetrySettings LIVED HERE AND WAS DELETED BY RULING P374a, 2026-10-29. It held this
# appliance's three telemetry sharing switches as NULLABLE, because its own stage 4 run found no
# appliance with the node or any key absent and would not guess. `device_services.py::
# DeviceTelemetry` covers the same node, measured the absent-key behaviour by creating the absent
# instance, and now carries PAN-PLT-003's input as well as PAN-SVC-008's finding - including the
# committed-read source and the `telemetry_switches_known` companion, both of which were invented
# here. Deleted in migration `0115_one_telemetry_model`; the collector `collect_device_telemetry`
# in this domain's collectors module is kept and is now called by the device-services collection.


class GlobalProtectPortalPresence(ProvenancedMixin, SyncTrackedModel):
    """Whether one appliance is a GlobalProtect portal, ACROSS EVERY VSYS. PAN-PLT-003's input.

    A VERDICT GRAIN CHOSEN AGAINST THE DEFAULT, and the test stage 5 applied: which row exists
    in the commonest failing state? For "is this appliance a portal" the commonest answer in
    this estate is NO ROW AT ALL - three of four appliances answer `No such node` at vsys1 - so
    an entry-grained row cannot report it. And an engineer triaging an advisory asks whether the
    feature is on, not which portal is misconfigured.

    THE VSYS SWEEP IS THE POINT. A vsys1-only read answers "not a portal" on an appliance that
    IS one: both PA-5220s hold portals in vsys3 and vsys4 while vsys1 has no `global-protect`
    subtree at all. `portal_vsys_coverage` is what says whether a zero count is a measurement or
    a gap, and it is the only column here the unknown can fire from - the count cannot, because
    zero portals is the compliant reading for this control.

    NOT THE SAME MODEL AS `GlobalProtectEnforcementPoint`, which is one row per VSYS and carries
    its own `portal_count` for the globalprotect-portal domain. This row is one per APPLIANCE
    and spans every vsys, which is why it cannot name one. The overlap is real and reconciling
    the two is a product decision rather than this model's.
    """

    #: Every column of this model is computed - stage 5 declares the whole subject derived,
    #: because a verdict grain forbids any column read directly from a collection.
    #: See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "portal_entry_count",
        "portal_container_state",
        "portal_vsys_coverage",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="globalprotect_portal_presences")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="globalprotect_portal_presences")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="globalprotect_portal_presences", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="globalprotect_portal_presences")

    #: Portal entries across EVERY vsys read. Zero where the container is absent and zero where
    #: it exists and is empty - different device states, told apart by the column beside this
    #: one. NOTHING SHOULD CLAUSE ON THIS ALONE: zero reads as "not a portal", which for
    #: PAN-PLT-003 is a pass, so an unrecomputed row looks like a compliant appliance.
    portal_entry_count = models.PositiveIntegerField(default=0)
    #: Which of the four read shapes the container came back in, across every vsys, taking the
    #: strongest shape found. Text rather than a boolean so the unknown reports itself for free.
    portal_container_state = models.CharField(
        max_length=32, blank=True, choices=PORTAL_CONTAINER_STATES)
    #: Whether every vsys of the appliance was read for a portal. The companion that says
    #: whether a zero count is a measurement or a gap.
    portal_vsys_coverage = models.CharField(
        max_length=32, blank=True, choices=PORTAL_VSYS_COVERAGE_STATES)
    #: How many vsys were read and how many the appliance has, kept beside the token because a
    #: reader of `some_vsys_unread` immediately asks how many.
    vsys_read_count = models.PositiveIntegerField(default=0)
    vsys_total_count = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_gp_portal_presence_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} GlobalProtect portal presence"


class LicenceInventory(ProvenancedMixin, SyncTrackedModel):
    """A verdict over one appliance's whole entitlement set. PAN-PLT-004, and PAN-PLT-001's half.

    THE GRAIN IS THE SET AND THE READING IS PER ROW, which is stage 3's own finding rather than
    a preference: the assertion is over every subscription together, so a check answering per
    row cannot answer the control. `LicenceEntitlement` beside this keeps the per-row reading,
    and both grains exist because the commonest failing state in this estate is NO ROW AT ALL.

    `licence_inventory_read` IS THE COLUMN THIS MODEL EXISTS FOR. `request license info`
    answers `{"licenses": null}` on both PA-5220s: the outer dict is TRUTHY, the inner value is
    None, and `result["licenses"]["entry"]` raises TypeError - three readings of one reply and
    only the middle one is right. Nothing in the payload separates "nothing is licensed" from
    "nobody asked", so the token is named for the SHAPE and `no_licence_rows_returned` is placed
    as a FINDING rather than a pass.

    NO APPLIANCE IN THIS ESTATE CARRIES A SUPPORT ENTITLEMENT ROW - none of the thirteen rows
    measured across two appliances names one - so `support_entitlement_state` holds
    `absent_from_inventory` everywhere, which is a finding at the baseline severity and NOT the
    same value as the unknown.
    """

    #: Every column is a computation over the licence rows. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "licence_inventory_read",
        "licence_row_count",
        "expired_entitlement_count",
        "expiring_within_30_days_count",
        "entitlement_state",
        "support_entitlement_state",
        "entitlement_features_held",
    )

    #: The horizons. Thirty days is the vendor's own - a warning appears in the system log daily
    #: once a licence is within thirty days of expiry - and ninety is stage 3's, the point at
    #: which a renewal still fits in a normal purchasing cycle.
    EXPIRY_WARNING_DAYS = 30
    RENEWAL_HORIZON_DAYS = 90

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="licence_inventories")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="licence_inventories")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="licence_inventories", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="licence_inventories")

    #: Which SHAPE the licence read came back in. Text, non-nullable: the empty string is none
    #: of the three tokens, so a negated equality against `rows_returned` fires.
    licence_inventory_read = models.CharField(
        max_length=32, blank=True, choices=LICENCE_INVENTORY_READ_STATES)
    #: How many entitlement rows the appliance returned. Zero for a null licences element AND
    #: zero for a read that never ran - told apart by the column above, never by this one.
    licence_row_count = models.PositiveIntegerField(default=0)
    #: Counted off the vendor's own `expired` FLAG and never off a date comparison: `expires`
    #: holds the literal `Never` on every licence in this estate, which no date parser accepts.
    expired_entitlement_count = models.PositiveIntegerField(default=0)
    #: Counted at NORMALIZATION time against the date the collection ran, so a stored row ages
    #: into being wrong without changing. There is no mechanism for recomputing at query time.
    expiring_within_30_days_count = models.PositiveIntegerField(default=0)
    #: The verdict the subscription half's severity varies with.
    entitlement_state = models.CharField(
        max_length=48, blank=True, choices=ENTITLEMENT_STATES)
    #: Separate from the verdict beside it because a lapsed SUPPORT licence removes the ability
    #: to obtain software at all, which is a different consequence and a different remediation.
    #: This is the half PAN-PLT-001 depends on.
    support_entitlement_state = models.CharField(
        max_length=48, blank=True, choices=SUPPORT_ENTITLEMENT_STATES)
    #: The feature names held, for a control in ANOTHER domain that needs to know whether the
    #: subscription its protection depends on exists at all. A JSONField is for display and
    #: inspection: nothing may clause on it, and an empty list must be read as "nobody looked"
    #: rather than as "no entitlements held".
    entitlement_features_held = models.JSONField(default=list, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_licence_inventory_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} license inventory"

    def clean(self) -> None:
        """The count must agree with the list it was gathered beside.

        `Certificate` and `InterfaceManagementProfile` already carry this shape: a column
        derived from a JSON field gets a `clean()` asserting the two agree, so a stale count
        cannot outlive the rows it counted.
        """
        features = self.entitlement_features_held
        if isinstance(features, list) and len(features) > self.licence_row_count:
            raise ValidationError(
                "entitlement_features_held names more features than licence_row_count counts "
                "rows; the count and the list come from one reply and must agree.")


class LicenceEntitlement(ProvenancedMixin, SyncTrackedModel):
    """One entitlement row of one appliance, keyed by the feature name it reports. PAN-PLT-004.

    THE ENTRY GRAIN BESIDE THE VERDICT GRAIN, and both exist because each keeps what the other
    throws away. The verdict reports "no row at all", which this cannot; this keeps
    `base_license_name`'s MEASURED implicit, which a verdict subject may not carry.

    `expired` IS THE VENDOR'S KEY WITH THE VENDOR'S POLARITY, UN-INVERTED - TRUE means the
    entitlement HAS EXPIRED and is the finding side. Stage 4 measured this key's polarity as
    `negated`, the only negated polarity in the whole domain, and warned that a normalizer
    storing it without knowing stores the opposite of "licensed". Getting it wrong would be a
    wrong finding in both directions at once and in silence.

    `expires` IS TEXT AND NOT A DATE, deliberately. Every license in this estate reports the
    literal `Never`, which no date parser accepts; a date column would have to reject it or
    coerce it, and either choice loses the only thing these licenses actually say. The date
    arithmetic lives in `LicenceInventory`'s derived counts.

    `authcode` IS DELIBERATELY NOT STORED. Stage 4 measured it None on every one of the thirteen
    rows, nothing asserts it, and an authorization code is a liability no control asked for.
    """

    #: Only the two columns that are not keys of the reply. The five measured columns are read
    #: off `request license info` and WRITE REAL PROVENANCE ROWS - `base_license_name` carries a
    #: materialised measured default, and the provenance row is the only place that says its
    #: empty string came from a vendor fact (the row IS the base licence) rather than from
    #: nobody looking. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="licence_entitlements")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="licence_entitlements")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="licence_entitlements", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="licence_entitlements")

    #: `feature`, verbatim - the name a finding prints as its subject and the only thing that
    #: tells two rows apart. A row with no feature name could not be keyed and is not written.
    feature = models.CharField(max_length=128)
    #: `expires`, verbatim, INCLUDING the literal `Never`.
    expires = models.CharField(max_length=64, blank=True)
    #: `expired`, un-inverted: TRUE means expired. Nullable because stage 4 measured no absent
    #: state for it and storing nothing is the truth - though a null here is invisible to both
    #: polarities, which is why the counts on `LicenceInventory` are what a finding reads.
    expired = models.BooleanField(null=True, blank=True)
    #: `base-license-name`. THE EMPTY STRING ASSERTS THAT THIS ROW IS THE BASE LICENCE ITSELF
    #: rather than a subscription on one - measured off a natural experiment with the positive
    #: control inside one reply, eleven rows carrying it and the two that lack it being exactly
    #: the two whose `feature` is the platform name. It must NOT be used to tell the unknown
    #: from the base licence: both are blank here and only the provenance row separates them.
    base_license_name = models.CharField(max_length=64, blank=True)
    #: `description`, vendor prose. Kept because stage 4 used it as the SECOND ORACLE that
    #: agreed with `base-license-name`'s partition - the rows lacking a base licence describe
    #: themselves as capacity tiers - and a reader checking that measurement needs it here.
    #: Nothing may clause on it: a finding resting on vendor prose stops finding anything the
    #: day the vendor rewords it.
    description = models.TextField(blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "feature"],
                name="unique_licence_entitlement_per_feature"),
        ]
        indexes = [models.Index(fields=["appliance", "feature"])]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.feature}"


class LogAlarmSettings(ProvenancedMixin, SyncTrackedModel):
    """One appliance's log-database alarm mechanism. PAN-PLT-006's first half.

    THE ALARM NODE IS ABSENT ON THREE OF THE FOUR LAB APPLIANCES AND WAS ABSENT ON ALL FOUR
    BEFORE THE LAB WAS BUILT, which makes this the model where the unknown is the normal state
    rather than the edge case. Three things follow and all three are load-bearing:

    `alarm_generation_enabled` IS NULLABLE AND NULL IS NOT `no`. Stage 4 took its ladder end to
    end on this node and still yields no implicit value: `show system state filter` answers
    NO_MATCHES for *alarm*, `show log alarm` answers `invalid client cli` through the API on all
    four appliances, and the Device > Log Settings screen has no route - so there is no oracle,
    and what the device does with the master switch absent is UNKNOWN. The vendor's documented
    default is a LEAD this code may not promote: the Help documents one and its own field table
    on the same page states none, and the Help has measured wrong before.

    SO A CLAUSE `alarm_generation_enabled eq false` MATCHES NO ROW ON ANY APPLIANCE IN THIS
    ESTATE. A plain scalar-boolean compiler emits `filter(field=value)`, which is `NOT col` for
    `eq false` with no IS NULL branch, and SQL evaluates `NOT NULL` as NULL. The answer is
    `alarm_generation_enabled_known`, not a different operator: the polarity is per MODEL, and
    both behaviors already live on one shipped model.

    AND `alarm_settings_node_present` IS NOT THE SAME CLAIM AS THE ALARM BEING OFF. Stage 3's
    second rank is "nothing recorded at all, which cannot be told apart from a device sitting at
    the vendor's documented default", and this column is how the three states stay distinct.

    THE THRESHOLD'S REFERENT IS NOT SETTLED. `reference/known-vendor-contradictions.md` records
    the log-database alarm threshold as a percentage of "available disk space" on one page of
    its section and of "the maximum size" on the next, and the two denominators measure 11 GB
    and 0.341 GB on one lab appliance - a factor of thirty. So the same stored number means two
    different occupancies, and `log_db_alarm_threshold_lowest` carries a sentinel note saying
    which comparison may be exactly inverted.
    """

    #: The verdicts and the companion. The five columns read off the node are NOT here: they
    #: write real `FieldProvenance` rows, and on this subject a row can only ever say
    #: `not_configured` - "normalization declined to guess" - which is precisely the thing a
    #: reader of this model must not get wrong. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "alarm_settings_node_present",
        "alarm_generation_enabled_known",
        "log_db_alarm_threshold_count",
        "log_db_alarm_threshold_lowest",
        "alarm_notification_route_present",
        "alarm_mechanism_state",
    )

    #: The node's own ceiling, and NOT the number of log databases. Thirteen children under
    #: `log-databases-alarm-threshold` against about twenty-five log types in `show system
    #: logdb-quota`, measured - so twelve or more quota'd databases have no alarm threshold
    #: available at ANY value and "every log database is thresholded" is false by construction.
    LOG_DB_ALARM_THRESHOLD_CEILING = 13

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="log_alarm_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="log_alarm_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="log_alarm_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="log_alarm_settings")

    #: Whether the committed read returned the alarm container rather than `No such node`.
    #: FALSE is the state of this estate on three of four appliances and is NOT the same claim
    #: as the alarm being switched off.
    alarm_settings_node_present = models.BooleanField(default=False)
    #: `enable-alarm-generation`, the vendor's key un-inverted: TRUE means alarms are armed.
    #: NULL means the key is not in the committed configuration and what the device does in that
    #: state is UNMEASURED - deliberately not made non-nullable-defaulting-false, because false
    #: would mean "an administrator switched alarms off".
    alarm_generation_enabled = models.BooleanField(null=True, blank=True)
    #: Whether the committed read answered AND carried the master switch. ONE COMPANION FOR
    #: EVERY BOOLEAN ON THIS MODEL, not one each: all three measured booleans come from the same
    #: node by the same read, so the node either answered or it did not.
    alarm_generation_enabled_known = models.BooleanField(default=False)
    #: The per-log-type occupancy thresholds as the appliance holds them, keyed by log type.
    #: Display and inspection only - nothing may clause on a JSONField - and the two derived
    #: columns beside it are what a finding reads.
    log_db_alarm_thresholds = models.JSONField(default=dict, blank=True)
    #: How many log types carry a threshold, out of the thirteen the node offers.
    log_db_alarm_threshold_count = models.PositiveIntegerField(default=0)
    #: The strictest threshold recorded, or NULL where no log type carries one. SENTINEL: zero
    #: is inside the grammar's range and the device accepts it, and whether it means "alarm
    #: always" or "alarm never" is UNMEASURED - so a query ranking "lower is stricter" may be
    #: exactly inverted at the one value an unconfigured-looking appliance would hold.
    log_db_alarm_threshold_lowest = models.PositiveIntegerField(null=True, blank=True)
    #: `enable-cli-alarm-notification`, un-inverted.
    cli_alarm_notification_enabled = models.BooleanField(null=True, blank=True)
    #: `enable-web-alarm-notification`, un-inverted.
    web_alarm_notification_enabled = models.BooleanField(null=True, blank=True)
    #: Whether EITHER notification route is on. A disjunction over two nullable booleans, which
    #: is not expressible as a clause list at all.
    alarm_notification_route_present = models.BooleanField(default=False)
    #: The verdict the severity varies with. Text, non-nullable: every boolean on this model is
    #: invisible to both polarities when null and this estate holds nothing but nulls, so the
    #: verdict has to be the one type where the unknown reports itself for free.
    alarm_mechanism_state = models.CharField(
        max_length=48, blank=True, choices=ALARM_MECHANISM_STATES)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_log_alarm_settings_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} log alarm settings"

    def clean(self) -> None:
        """The threshold count must agree with the map it was counted over."""
        thresholds = self.log_db_alarm_thresholds
        if isinstance(thresholds, dict) and len(thresholds) != self.log_db_alarm_threshold_count:
            raise ValidationError(
                "log_db_alarm_threshold_count must equal the number of entries in "
                "log_db_alarm_thresholds; the count is derived from that map.")


class ConfigurationBackupEvidence(ProvenancedMixin, SyncTrackedModel):
    """What the firewall records about its own configuration backups. PAN-PLT-005.

    THE FIREWALL RECORDS NOTHING THIS CONTROL CAN BE PAID WITH, and this model exists to say so
    rather than to answer it. The assertion is about a copy held somewhere OTHER than the
    firewall, and the appliance holds no record that an export happened, where it went, or
    whether anything is still there.

    AND THE ON-BOX SNAPSHOT LIST IS NOT READABLE EITHER. `show config saved` takes a MANDATORY
    argument - the bare form answers `code=17` on all four lab appliances and a name that does
    not exist answers "is missing/malformed" - and nothing in the 70,462-command CLI index lists
    the names. Missing and malformed are ONE message, so a collector could not tell a snapshot
    that was never taken from a corrupt one even if it had a name to pass.

    SO `on_box_saved_configuration_count` IS A TRAP MARKER RATHER THAN EVIDENCE, and it is the
    one column here whose purpose is to stop a later stage using it. A positive comparison on it
    would read "this appliance has snapshots, therefore it is backed up", which INVERTS the
    control: stage 3 is explicit that the on-box list is what the control's own first sentence
    says is insufficient. It is kept rather than dropped so the next stage does not rediscover
    the command and the trap separately.
    """

    #: Both columns are computations, and both are honest at their firing values today.
    #: See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "on_box_saved_configuration_count",
        "on_box_snapshot_list_collected",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="configuration_backup_evidence")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="configuration_backup_evidence")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="configuration_backup_evidence", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="configuration_backup_evidence")

    #: Named on-box snapshots. NOT EVIDENCE FOR THIS CONTROL and must never be read as it - an
    #: on-box snapshot does not survive the loss of the appliance.
    on_box_saved_configuration_count = models.PositiveIntegerField(default=0)
    #: Whether anything was able to ENUMERATE the on-box snapshots. False on every appliance in
    #: every estate until an enumeration instrument exists, which is why the count beside it can
    #: never be read as a measurement. The one column in this domain whose until-renormalized
    #: value and its steady-state value are the same.
    on_box_snapshot_list_collected = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_backup_evidence_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} configuration backup evidence"

    def clean(self) -> None:
        """A count with no enumeration behind it is not a count.

        The only guard that stops the trap column above being read as evidence: while nothing
        can enumerate, the count must be zero, so a non-zero value cannot appear beside a false
        collection flag and look like a measurement.
        """
        if not self.on_box_snapshot_list_collected and self.on_box_saved_configuration_count:
            raise ValidationError(
                "on_box_saved_configuration_count must be zero where nothing enumerated the "
                "snapshots: a count with no enumeration behind it reads as evidence and is not.")


class DataplaneUtilisation(ProvenancedMixin, SyncTrackedModel):
    """One appliance's dataplane load, for the collected window. PAN-PLT-006's second half.

    THE SUBJECT EXISTS AND THE ASSERTION STILL CANNOT REST ON IT. There is no configuration node
    anywhere on the firewall holding a dataplane CPU or session-utilization threshold, so
    "sustained" has no stored definition - and the vendor's own monitoring procedure instructs
    the reader to configure the SNMP MANAGER to watch these identifiers and never uses the word
    threshold. The comparison is off-box by the vendor's design.

    A WALL OF ZEROES IS NOT AN ABSENCE, which is the trap this model is most prone to.
    `cpu-load-average` comes back `0,0,0,...` on all four lab appliances - populated, truthy and
    all zero - so a threshold over it cannot tell an idle appliance from one whose counters
    never populated. The honest zero and the unknown are the same number and both pass a
    headroom test, which is why `resource_monitor_collected` is the only column here that
    separates them and why no clause rests on the maximum.

    THE PROCESSOR NAME IS STORED VERBATIM BECAUSE IT IS PLATFORM-SHAPED - `dp0` on a PA-VM and
    `s1dp0` on a PA-5220. A consumer that normalizes the names away loses which processor a
    reading came from; one that hard-codes either returns nothing on half the estate. That is
    also why the row is per APPLIANCE and not per processor: the key would be the row name.

    THE VALUES ARE A COMMA-SEPARATED STRING PER CORE and must be split, not parsed as a number.
    """

    #: Every column is a computation over the reply's shape. There is no stage 4 field record
    #: for the load values themselves - that object carries two field records and neither is the
    #: CPU load - so the evidence is a shape measurement rather than a keyed field.
    #: See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "dataplane_cpu_load_samples",
        "dataplane_cpu_load_max_percent",
        "dataplane_count",
        "resource_monitor_collected",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="dataplane_utilisations")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="dataplane_utilisations")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="dataplane_utilisations", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="dataplane_utilisations")

    #: Per-processor, per-core samples for the collected window, keyed by processor name and core
    #: id, with the processor names verbatim. Display and inspection only.
    dataplane_cpu_load_samples = models.JSONField(default=dict, blank=True)
    #: The highest per-core load average in the window across every data processor. The single
    #: number a headroom comparison WOULD be written against if a threshold existed to compare
    #: it to. Nullable, and nothing clauses on it: see the wall of zeroes above.
    dataplane_cpu_load_max_percent = models.PositiveIntegerField(null=True, blank=True)
    #: How many data processors the appliance reported - a platform fact, and the denominator a
    #: reader needs before comparing a maximum from a single-processor PA-VM against one from a
    #: multi-processor PA-5220.
    dataplane_count = models.PositiveIntegerField(default=0)
    #: Which window the samples came from, so a reader of a maximum knows what it averages over.
    #: Stage 3 records that the window decides whether "sustained" can be expressed at all, and
    #: the choice belongs to whoever issues the command - so the row says which was issued.
    collected_window = models.CharField(max_length=32, blank=True)
    #: Whether the read answered AND carried at least one load series. The only column that can
    #: tell "we never asked" from "we asked and the appliance was idle".
    resource_monitor_collected = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_dataplane_utilisation_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} dataplane utilization"
