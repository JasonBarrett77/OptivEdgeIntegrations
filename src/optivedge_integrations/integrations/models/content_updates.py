"""Dynamic content update scheduling - PAN-UPD-001 to PAN-UPD-006's subjects.

TWO MODELS AT TWO DIFFERENT GRAINS OVER TWO DIFFERENT NODES, and neither node was covered
before. `ContentUpdateSchedule` is one row per APPLIANCE over the firewall-local
`deviceconfig/system/update-schedule`; `ContentDeploymentSchedule` is one row per MANAGEMENT
STATION and is a verdict over every `deviceconfig/system/deployment-update-schedule` entry on it.

NEITHER IS `FirewallContentStreams` AND NEITHER IS `LicenceInventory`, which was checked before
either class was written because a node already covered under another name is the failure ruling
P374a was about. `platform_lifecycle.py::FirewallContentStreams` holds the content a firewall HAS
INSTALLED, read from `show system info` - versions and release dates, no cadence and no action.
`platform_lifecycle.py::LicenceInventory` holds the entitlement verdict from `request license
info`. This domain holds what the appliance has ARRANGED TO FETCH, which is a configuration node
neither of those reads touches: `grep -rn 'update-schedule' src/` returned nothing at all.

ONE MODEL FOR FIVE CONTENT TYPES ON THE FIREWALL SIDE, which is the stretch `LoggingSettings`
already accepts in its own words at `services_settings.py:69`. The five content types are five
PARALLEL CHILDREN of one node, read by one call, and four of the five are remediated on one
screen - `Device > Dynamic Updates`. The alternative stage 5 weighed and rejected was a
kind-discriminated row per (appliance, content type), which fails on the value sets: the five
content types have five DIFFERENT measured recurrence branch sets - antivirus four, Applications
and Threats five, WildFire a disjoint six, the two GlobalProtect types four each - so one shared
`recurrence` column could not declare a measured vocabulary for any of them.

ON AN HA PAIR EACH PEER YIELDS ITS OWN ROW AND NOTHING DEDUPLICATES IT. threat p.35 STEP 3 item 5
says `the update schedule does not sync across peers; you must manually configure the schedule on
both peers`, so the two peers genuinely hold two independent values. Measured in this lab: the
active PA-5220 013201001475 carries four content types and no `threats` node, and the passive peer
013201001085 carries a `threats` schedule and nothing else.

THE RECURRENCE IS NOT A KEY. It is expressed by WHICH BRANCH ELEMENT EXISTS under `recurring`, and
the device enforces the choice by SILENT REPLACEMENT at the write - writing a second branch
element is accepted, returns no message, and deletes the first branch and everything under it. So
at most one branch exists at a time, which is what makes a single-valued text column lossless
rather than a summary.

EVERY RECURRENCE AND ACTION COLUMN IS NON-NULLABLE TEXT, AND THE EMPTY STRING IS LOAD-BEARING.
`""` means this appliance was never read; `none` means it was read and nothing is scheduled (or,
for an action, that the in-force branch carries no `action` key). Both FIRE, because every clause
in this domain is a negated equality and `"" != "daily"` holds - so an appliance nobody read
reports rather than passing, with no companion column needed. A nullable column would have been
invisible to both polarities, which is why `parse_text_field`'s coercion of `None` to `""`
(`normalization/common.py:225-238`) is the behavior these columns are built on rather than one
they work around.

THE TWO INTEGER COLUMNS ARE THE EXCEPTION AND THEY ARE NULLABLE ON PURPOSE. What an absent
`threshold` or `new-app-threshold` does is UNMEASURED - four vendor wordings disagree about what
the threshold even gates, and with the key deleted the dialog renders ` [1 - 336]` as an
emptyText hint rather than a value - so nothing is stored and the column holds NULL. A NULL is
unreachable by every operator the query grammar has (`is_empty` compiles to an exact match
against the empty string and there is no `is_null`), so both columns read as COMPLIANT when
nobody looked. `update_schedule_collected` is the declared companion that carries that unknown,
and stage 5 requires it be claused as an ASSERTION and never as an applicability clause - the
consumer has already paid for that mistake once, at `services_settings.py:226-237`.

Measured on 013201001475 (PA-5220, 11.1.13-h3), 013201001085 (PA-5220, 11.1.13-h3),
691665AC334B458 (PA-VM, 11.2.5) and 6A9C0A9904E7D6E (PA-VM, 11.2.3-h3). Appliances are named by
SERIAL throughout: 691665AC334B458 answers to the factory-default hostname `PA-VM` because its
running config holds no `hostname` leaf, and that is not a finding of this domain.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


#: `scope`'s only member on the firewall subject. Stage 4 measured three scopes for these objects
#: - `device-local`, `template` and `template-stack` - and this column can hold exactly the
#: first: the store holds one row per appliance for the schedule IN FORCE, and a template's own
#: copy has no row. The token is a constant for that reason and not because the question is
#: small; `ApplianceScopedObject.SCOPE_CHOICES` has no member for it, which is why it is spelled
#: here rather than reused.
SCOPE_DEVICE_LOCAL = "device-local"

#: `scope`'s only member on the station subject. Stage 4 measured `name_resolution.order` as the
#: single member `panorama-own`, and `config_complete` at the station's path answers
#: `code=6 Invalid sequence` on both lab firewalls - a name here cannot be shadowed from anywhere.
SCOPE_PANORAMA_OWN = "panorama-own"

#: The token every recurrence and action column holds for an absence that was READ. Distinct from
#: `""`, which is an absence that was never read. NOT a value any device returns for an action:
#: the device's action set is {download-only, download-and-install} and `none` is what the screen
#: renders for a branch carrying no `action` key - measured, with the dialog's OK button writing
#: nothing, which is what rules out "the rendered None is a value the form holds".
NOT_SCHEDULED = "none"

#: The recurrence branch element names, per content type, exactly as the device spells them.
#: MEASURED by `config_complete` at each `recurring` container on 691665AC334B458 and again on
#: 013201001475, which answered IDENTICALLY at every path - same children, same counts, same enum
#: members - across two platforms, two major versions and both vsys modes at once.
#:
#: FIVE DIFFERENT SETS, WHICH IS THE WHOLE REASON THIS IS A COLUMN PER CONTENT TYPE. WildFire's
#: six are disjoint from everything else's, and `hourly` is the CEILING for antivirus - so
#: PAN-UPD-001's preferred posture is already the fastest the grammar offers for that content and
#: nothing better can be asked for.
AV_RECURRENCES = ("daily", "hourly", "weekly", NOT_SCHEDULED)
THREATS_RECURRENCES = ("daily", "every-30-mins", "hourly", "weekly", NOT_SCHEDULED)
WILDFIRE_RECURRENCES = (
    "every-15-mins", "every-30-mins", "every-hour", "every-min", NOT_SCHEDULED, "real-time")
GP_DATAFILE_RECURRENCES = ("daily", "hourly", "weekly", NOT_SCHEDULED)
GP_CLIENTLESS_VPN_RECURRENCES = ("daily", "hourly", "weekly", NOT_SCHEDULED)

#: The `action` leaf's two members, measured by `config_complete` with `with_body=True` at the
#: leaf and corroborated as an inline enum in the CLI index, identical on both lab platforms. The
#: vendor documents the pair in words at help p.950. `none` and `""` are NOT members: the device
#: cannot store either, and every clause in this domain compares against `download-and-install`
#: and reaches the other states by negation.
ACTION_DOWNLOAD_ONLY = "download-only"
ACTION_DOWNLOAD_AND_INSTALL = "download-and-install"

#: `central_schedule_state`'s vocabulary. INVENTED BY STAGE 5 rather than read off a device - the
#: station returns no such token - and declared `unmeasured` there for that reason. The empty
#: string is a fourth state this list does not carry on purpose: it is what an unread station
#: holds, it is not `enabled`, and PAN-UPD-006's clause is a negated equality against `enabled`,
#: so it FIRES.
#:
#: `all_disabled` exists because DISABLED IS A THIRD STATE AND A COUNT PASSES IT. Stage 4 measured
#: that `disabled` is the ONLY way to switch a deployment schedule off - there is no `none` branch
#: on this object's recurrence, `<none/>` is refused `recurring -> none unexpected here` - and
#: that the operational oracle omits everything about a disabled schedule except that it is
#: disabled. An estate whose single schedule is disabled has no central governance at all and a
#: count of entries reports one.
CENTRAL_SCHEDULE_STATES = [
    ("enabled", "At least one schedule entry is enabled"),
    ("all_disabled", "Entries exist and every one is disabled"),
    (NOT_SCHEDULED, "No schedule entry exists at all"),
]

#: `rollout_staging_shape`'s vocabulary, also stage 5's own and also `unmeasured`. THE PRODUCT HAS
#: NO RING, CANARY OR TEST-GROUP CONSTRUCT, which stage 1 established and help p.1224-1225
#: confirms, so staging IS two schedules over two disjoint device lists and nothing marks either
#: as intended. This column carries the computable half and PAN-UPD-006's second record is
#: discharged onto an engineer for the rest.
ROLLOUT_NONE = "none"
ROLLOUT_SINGLE = "single"
ROLLOUT_MULTIPLE_DISJOINT = "multiple_disjoint"
ROLLOUT_MULTIPLE_OVERLAPPING = "multiple_overlapping"
ROLLOUT_STAGING_SHAPES = [
    (ROLLOUT_NONE, "No installing schedule"),
    (ROLLOUT_SINGLE, "One installing schedule"),
    (ROLLOUT_MULTIPLE_DISJOINT, "Several, over disjoint device lists"),
    (ROLLOUT_MULTIPLE_OVERLAPPING, "Several, and not demonstrably disjoint"),
]


class ContentUpdateSchedule(ProvenancedMixin, SyncTrackedModel):
    """One firewall's dynamic content update schedule. PAN-UPD-001 to PAN-UPD-005.

    All five content types on one row, keyed by the appliance alone. The node is per APPLIANCE
    under `deviceconfig/system` - stage 4 measured that there is no vsys and no shared spelling of
    any of the five objects, and that on the multi-vsys PA-5220 the path is the same one - so the
    firewall-versus-vsys question does not arise here and there is no `vsys_name` column.

    A ROW EXISTS WHEREVER A MERGED SNAPSHOT DOES, following `FirewallContentStreams` and
    `UpdateServerSettings`. An appliance with NO merged snapshot gets no row at all, because
    `write_node_row`'s caller short-circuits on a missing snapshot, and that residual case is the
    one hole `update_schedule_collected` cannot plug: such an appliance is absent from every query
    rather than present and false. Stage 5 records it and it is not this model's to fix.
    """

    #: Everything but the two integer columns, which are the only keys this model reads off the
    #: payload. The recurrence and action columns are computed from WHICH ELEMENT EXISTS, so they
    #: have no payload key and can never carry a `FieldProvenance` row; without being declared
    #: here they would be indistinguishable from a field nothing tracks.
    #:
    #: `scope` is declared too. It is computed from the subtree the node was read at, which is not
    #: a value on the node - nothing in `update-schedule` names a scope.
    DERIVED_FIELDS = (
        "is_missing",
        "scope",
        "update_schedule_collected",
        "av_recurrence",
        "av_action",
        "threats_recurrence",
        "threats_action",
        "wildfire_recurrence",
        "wildfire_action",
        "gp_datafile_recurrence",
        "gp_datafile_action",
        "gp_clientless_vpn_recurrence",
        "gp_clientless_vpn_action",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="content_update_schedules")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="content_update_schedules")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="content_update_schedules", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="content_update_schedules")

    #: One value only, and declared though it is a constant: a finding carries its subject's scope
    #: as well as its name, because a name is not unique on a device. It would stop being a
    #: constant the day a template-scoped row is added, and that is the day the subject's
    #: `scope.not_representable` has to be revisited rather than this column extended in place.
    scope = models.CharField(max_length=32, default=SCOPE_DEVICE_LOCAL)

    #: Whether this appliance's management-plane configuration was actually read for this
    #: snapshot. The unknown-detector, and the only column here a control may rely on to tell "we
    #: never asked" from "we asked and it was fine" - the query layer has no is-null operator.
    #:
    #: THE DERIVATION IS ONE LEVEL UP FROM WHAT STAGE 4 MEASURED, and stage 5 flags it as
    #: reasoning rather than a measurement. Stage 4 measured non-distinguishability at
    #: `update-schedule/<type>/recurring`; the PARENT `deviceconfig/system` node carries hostname,
    #: timezone, the update server and much else on every firewall, so its emptiness is a sound
    #: proxy for "not read" where the child's absence is not.
    #:
    #: FALSE until the normalization pass runs, which FIRES. The alternative default would assert
    #: that every pre-existing row was read when nobody checked.
    update_schedule_collected = models.BooleanField(default=False)

    #: `threats/recurring/threshold` - how many hours old a published Applications-and-Threats
    #: release must be before the firewall acts on it. NULL where the key is absent, because what
    #: an absent threshold does is UNMEASURED: nothing is stored rather than assert a wait nobody
    #: measured. The range is measured twice over and from two directions - write-time refusals of
    #: `0`, `337` and `-1` all returned `recurring -> threshold value=N should be equal to or
    #: between 1 and 336`, and both `1` and `336` were accepted with `336` COMMITTED.
    #:
    #: A SIBLING OF THE BRANCHES AND NOT A CHILD OF ONE: it sits beside the branch elements under
    #: `recurring`, so ONE threshold governs whichever branch is in force and SURVIVES a change of
    #: branch - measured, since writing a second branch element deletes the first and left
    #: `threshold` untouched.
    threats_threshold_hours = models.PositiveIntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(336)])
    #: `threats/recurring/new-app-threshold` - how many hours newly identified applications are
    #: held back before they begin affecting policy. Also a sibling of the branches, also NULL on
    #: an absent key, and it exists on the Applications-and-Threats content type alone, which is
    #: correct: no other content type delivers application identifications.
    #:
    #: THE VENDOR HAS TWO NAMES FOR THIS FIELD and each document carries only its own; the
    #: disagreement is already filed in the project's vendor-contradictions register.
    threats_new_app_threshold_hours = models.PositiveIntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(336)])

    #: ANTIVIRUS. `hourly` is this content type's ceiling, measured on three builds.
    av_recurrence = models.CharField(max_length=32, blank=True, default="")
    av_action = models.CharField(max_length=32, blank=True, default="")
    #: APPLICATIONS AND THREATS. The only content type with `every-30-mins`, and the only one
    #: carrying the two threshold siblings above.
    threats_recurrence = models.CharField(max_length=32, blank=True, default="")
    threats_action = models.CharField(max_length=32, blank=True, default="")
    #: WILDFIRE. Six branch members, disjoint from every other content type's, and `real-time` is
    #: the one PAN-UPD-004 asserts. The cadence ceiling depends on which WildFire service feeds
    #: the firewall, which no column here holds - stage 3 instructed grading against the
    #: public-service ceiling by default.
    wildfire_recurrence = models.CharField(max_length=32, blank=True, default="")
    wildfire_action = models.CharField(max_length=32, blank=True, default="")
    #: GLOBALPROTECT DATA FILE.
    gp_datafile_recurrence = models.CharField(max_length=32, blank=True, default="")
    gp_datafile_action = models.CharField(max_length=32, blank=True, default="")
    #: GLOBALPROTECT CLIENTLESS VPN. The one content type with no screen of its own.
    gp_clientless_vpn_recurrence = models.CharField(max_length=32, blank=True, default="")
    gp_clientless_vpn_action = models.CharField(max_length=32, blank=True, default="")

    class Meta:
        ordering = ["appliance__hostname", "pk"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_content_update_schedule_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance"]),
            models.Index(fields=["management_station"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} content update schedule"

    def clean(self) -> None:
        """A cadence cannot be reported for an appliance whose configuration did not answer.

        The pattern `FirewallContentStreams` already uses: a column derived from a companion gets
        a `clean()` asserting the two agree, because the alternative is a verdict that silently
        outlives the reading it rested on. Here it is the empty string that must survive - an
        uncollected appliance holds `""` on all ten columns, and a token on any of them would be a
        cadence read off a reply nobody received.
        """
        if self.update_schedule_collected:
            return
        populated = [name for name in (
            "av_recurrence", "av_action",
            "threats_recurrence", "threats_action",
            "wildfire_recurrence", "wildfire_action",
            "gp_datafile_recurrence", "gp_datafile_action",
            "gp_clientless_vpn_recurrence", "gp_clientless_vpn_action",
        ) if getattr(self, name)]
        if populated:
            raise ValidationError(
                "a recurrence or action must be blank where the appliance's configuration did "
                f"not answer: {', '.join(populated)} would be a cadence read off a reply nobody "
                f"received, and the empty string is what makes an unread appliance report")


class ContentDeploymentSchedule(ProvenancedMixin, SyncTrackedModel):
    """A verdict over one management station's content deployment schedules. PAN-UPD-006.

    ONE ROW PER MANAGEMENT STATION, AND THE GRAIN CUTS AGAINST THE OBJECT'S OWN SHAPE. Stage 4
    measured `deployment-update-schedule` as a collection of named entries, so the entry grain is
    the shape the object has - but the commonest failing state is NO ENTRY AT ALL, measured twice
    in this lab (the station held none before stage 4's fixtures and holds none after them), and
    an entry-grained row cannot report that it does not exist. An engineer fixing either half of
    PAN-UPD-006 opens `Panorama > Device Deployment > Dynamic Updates > Schedules`, which is one
    screen per station and is what this row is. The per-entry detail survives in `schedules`.

    NO FINDING IN THIS DOMAIN RESTS ON ANY COLUMN HERE, AND THAT IS A RULING RATHER THAN AN
    OVERSIGHT. Jason, 2026-10-27: "own panorama is still out of scope (values that effect the
    panorama appliance only)". PAN-UPD-006's first record is discharged `not_in_configuration` on
    that ruling and its clause is left in the artifact as the record of what WAS derived; its
    second record is discharged `engineer_answers`, and the three columns that record names -
    `rollout_staging_shape`, `installing_schedule_count` and `schedules` - are what the estate
    hands the engineer rather than what a query reads.

    NO PROVENANCE ROW FOR ANY COLUMN, and nothing is lost by it. Provenance answers "was this
    value defined locally or pushed", and this object exists at exactly ONE scope with nothing
    above it to push from. Every column is computed, so none has a payload key to carry a marker.
    """

    #: Every column. See the class docstring: all eight are computed, because a row that is a
    #: verdict over entries reads no key off any one of them.
    DERIVED_FIELDS = (
        "is_missing",
        "scope",
        "deployment_schedule_read",
        "central_schedule_state",
        "enabled_schedule_count",
        "installing_schedule_count",
        "rollout_staging_shape",
        "schedules",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="content_deployment_schedules")
    #: NULLABLE, unlike every appliance-anchored model's, and the difference is the point: there
    #: is no station-scoped snapshot an estate is guaranteed to have. A station nobody collected
    #: still gets a row - at its firing values, with `deployment_schedule_read` false - because
    #: otherwise an uncollected station and a standalone estate with no station at all would both
    #: be absent from every query and indistinguishable. `SET_NULL` follows `DeviceGroup`:
    #: losing a snapshot must not delete the verdict that was computed from it.
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.SET_NULL,
        related_name="content_deployment_schedules", null=True, blank=True)

    #: One value only, `panorama-own`. Declared for the same reason the firewall subject's is: a
    #: finding carries its subject's scope, and here the token is also the record of WHY no
    #: finding is raised from this row.
    scope = models.CharField(max_length=32, default=SCOPE_PANORAMA_OWN)

    #: Whether a read addressed at the station's OWN configuration - no `target=` - answered for
    #: this snapshot. FALSE until the collection runs, which fires.
    deployment_schedule_read = models.BooleanField(default=False)

    #: Whether content delivery to the estate is actually governed from one place, as one of three
    #: tokens plus the empty string for a station nobody read. See CENTRAL_SCHEDULE_STATES.
    central_schedule_state = models.CharField(
        max_length=32, blank=True, default="", choices=CENTRAL_SCHEDULE_STATES)

    #: How many entries are not switched off. `disabled` is the only way to switch one off.
    enabled_schedule_count = models.PositiveIntegerField(default=0)
    #: How many entries carry a `download-and-install` action under their content type's
    #: `recurring` branch - which is strictly fewer than the entry count, and the gap matters: a
    #: `download-only` schedule names NO DEVICES AT ALL by construction, because `devices` is a
    #: child of `download-and-install` and not of the action container. So an estate could hold
    #: two schedules, look staged by count, and have one of them pushing to nobody.
    installing_schedule_count = models.PositiveIntegerField(default=0)

    #: The computable shape of the estate's content rollout. See ROLLOUT_STAGING_SHAPES.
    rollout_staging_shape = models.CharField(
        max_length=32, blank=True, default="", choices=ROLLOUT_STAGING_SHAPES)

    #: The per-entry detail this row is a verdict over, flattened for presentation: one object per
    #: entry carrying its name, whether it is enabled, its one content type, its cadence, its
    #: action and the serials its installing action names. NOT a second copy of the verdict - the
    #: columns above are what anything reads programmatically - and not searchable.
    schedules = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["management_station__hostname", "pk"]
        constraints = [
            models.UniqueConstraint(
                fields=["management_station"],
                name="unique_content_deployment_schedule_per_station"),
        ]
        indexes = [models.Index(fields=["management_station"])]

    def __str__(self) -> str:
        return f"{self.management_station} content deployment schedule"

    def clean(self) -> None:
        """A verdict must not outlive the read it rested on, and a count must not either.

        Same pattern as its sibling above. A station whose own configuration did not answer holds
        the empty string on both token columns and zero on both counts; a token or a count there
        would be a statement about an estate nobody asked.
        """
        if self.deployment_schedule_read:
            return
        if self.central_schedule_state or self.rollout_staging_shape:
            raise ValidationError(
                "central_schedule_state and rollout_staging_shape must be blank where the "
                "station's own configuration did not answer: a token here would be a verdict "
                "over a reply nobody received, and the empty string is what makes an unread "
                "station report")
        if self.enabled_schedule_count or self.installing_schedule_count or self.schedules:
            raise ValidationError(
                "a schedule count must be zero and `schedules` empty where the station's own "
                "configuration did not answer: a non-zero count would assert entries nobody read")
