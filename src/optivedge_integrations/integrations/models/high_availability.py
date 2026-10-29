"""Device > High Availability - the redundant relationship one firewall is configured for.

PAN-HAP-001 to 004's subject, from `stage5-ha-panorama.json`'s `firewall-ha-relationship`.

ONE ROW PER APPLIANCE, like `ManagementSshSettings` and `LoggingSettings`: HA configuration is
device-wide `deviceconfig/high-availability`, so there is one row per appliance however many
vsys it carries, and vsys-scoped content does not arise here at all.

ON AN HA PAIR THIS SUBJECT YIELDS TWO ROWS FOR ONE REAL RELATIONSHIP and nothing downstream
deduplicates them. Unlike the device-wide settings models that warning was written for, THESE
TWO ROWS ARE NOT EXPECTED TO AGREE, and this estate measures that directly: on 2026-10-29
fw-core-tpa-a holds `group/mode/active-passive` and fw-core-tpa-b holds no `mode` key at all,
while `running-sync` reads `synchronized` on both. The same pair's `local-panorama` IS equalised
by the same config sync. Synchronisation is per PATH, not one fact about one pair.

TWO READS FILL THIS ROW AND ONLY ONE OF THEM IS CONFIGURATION:

  - `show config merged` carries every configuration column. `ha_config_collected` says whether
    that read happened for this appliance.
  - `show high-availability all` carries the runtime half - whether a peer is answering, whether
    state is being exchanged, whether the control link is actually encrypted, and
    `ha1-encrypt-imported`, which has no configuration node anywhere.
    `ha_runtime_state_collected` says whether THAT read happened, and it is the column that
    tells "no live peer" apart from "nobody asked".

THE TWO MONITORING ENABLES ARE TRUE WHEN THE KEYS ARE ABSENT, and that is a vendor fact rather
than a bug: `show high-availability state` really does answer `enabled: yes` with `groups: null`
on an appliance holding no `group/monitoring` node at all. So a clause written on either of them
passes every unconfigured appliance in the estate. NO CONTROL CLAUSES ON THEM. PAN-HAP-004
clauses on `ha_monitors_nothing`, which is derived and whose default fires. Moving a clause onto
`link_monitoring_enabled` or `path_monitoring_enabled` reinstates exactly the defect stage 4
called the reading most likely to be got backwards.

NULLABLE BOOLEANS HERE ARE DISPLAY AND DERIVATION INPUTS, NEVER CLAUSE TARGETS. The search layer
has no is-null operator, so a positive comparison over a NULL matches nothing and the control
goes quiet - `LoggingSettings.central_store_delivery_healthy` carries the incident that
established this. Every column a control compares on this model is non-nullable and defaults to
its firing value; the five nullable switches below are the ones stage 5 declared `not_assumed`
because no oracle on the firewall can move them, and they feed the derived verdicts instead.

THE TEXT COLUMNS ARE BLANK RATHER THAN NULL, DELIBERATELY, AND STAGE 5 ASKED FOR NULL. Its
reasoning was that blank cannot tell "nobody looked" from "nothing configured"; its own
`when_unknown` for the same columns says the clause shape is `is empty` and that a null matches
it. MEASURED 2026-10-29 against the consumer: `is_empty` compiles to `filter(field="")` in every
per-model compiler in `OptivEdgeAssessments/src/assessments/search/*/compiler.py`, so a NULL
matches nothing and the control would never fire. The two requirements cannot both hold, the
firing direction wins, and "nobody looked" is carried by `ha_config_collected` - the companion
column stage 5 created for precisely that job.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class HighAvailabilityConfig(ProvenancedMixin, SyncTrackedModel):
    """One appliance's high-availability configuration and the runtime state of its pair."""

    #: `group/mode` is a CHOICE NODE: the device stores an empty child element and a normalizer
    #: reads WHICH CHILD is present. Measured by `action=complete` at `group/mode`, 2026-10-26:
    #: two children on both PA-5220s and ONE on both PA-VMs (`active-passive` alone), so
    #: `active-active` is not valid on every platform in this estate.
    MODE_ACTIVE_PASSIVE = "active-passive"
    MODE_ACTIVE_ACTIVE = "active-active"
    MODE_CHOICES = (MODE_ACTIVE_PASSIVE, MODE_ACTIVE_ACTIVE)

    #: What `interface/ha1-backup/port` completes to on both PA-5220s. The same position answers
    #: `code=6 Invalid sequence` on both PA-VMs, where `ha1-backup` is not a child of `interface`
    #: at all - so on a PA-VM this is not an empty value set, it is a position the schema does
    #: not have, and a finding about an absent backup port there names a node that cannot exist.
    HA_PORT_MANAGEMENT = "management"
    DEDICATED_HA_PORTS = ("ha1-a", "ha1-b", "aux-1", "aux-2")

    #: How much of PAN-HAP-004's monitoring is in place. A VOCABULARY THIS LAYER INVENTS: the
    #: device offers no such set, so stage 5 could not record it as `measured` and its
    #: completeness gate does not run on it. `unknown` is a PLACED member that reports at the
    #: baseline severity, not a hole in the grading.
    MONITORING_UNKNOWN = "unknown"
    MONITORING_NEITHER_ENABLED = "neither-enabled"
    MONITORING_ENABLED_NO_GROUP = "enabled-with-no-group"
    MONITORING_LINK_ONLY = "link-only-with-group"
    MONITORING_LINK_AND_PATH = "link-and-path-with-groups"

    #: How far this appliance is from a second independent keepalive path. Same kind of invented
    #: vocabulary as above, and `backup-link-without-peer-address` is the measured state of both
    #: PA-5220s in this estate.
    KEEPALIVE_UNKNOWN = "unknown"
    KEEPALIVE_NEITHER = "neither-mechanism"
    KEEPALIVE_BACKUP_WITHOUT_PEER = "backup-link-without-peer-address"
    KEEPALIVE_ONE_COMPLETE = "one-mechanism-complete"
    KEEPALIVE_BOTH = "both-independent-mechanisms"

    #: How exposed the peer control conversation is. Five bands over the encryption verdict and
    #: how far the port the link rides can travel.
    EXPOSURE_ENCRYPTED = "encrypted"
    EXPOSURE_MANAGEMENT_PORT = "unencrypted-management-port"
    EXPOSURE_IN_BAND = "unencrypted-in-band-interface"
    EXPOSURE_DEDICATED_HA_PORT = "unencrypted-dedicated-ha-port"
    EXPOSURE_PORT_UNKNOWN = "unencrypted-port-unknown"

    #: Computed here: the two collection flags, the count over the link-group collection, and
    #: the four verdict/classification columns. Every configuration column below reads a real
    #: key and carries a provenance row. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "ha_config_collected",
        "ha_runtime_state_collected",
        # NOT A COMPUTATION, AND DECLARED HERE ANYWAY - the one honest answer the provenance
        # vocabulary leaves. `ha1_encryption_key_imported` is lifted straight from
        # `show high-availability all`'s `ha1-encrypt-imported`, so it reads a real key; but
        # `ProvenanceType` is about where a CONFIGURATION value came from, and the key is a
        # key of an OPERATIONAL REPLY, which has no commit, no absence and no marker. The
        # fallthrough in `classify_prov_type` is `local`, which would assert an administrator
        # configured it on this device, and there is no configuration node for it anywhere.
        # `LoggingSettings` sets the precedent and takes the same answer for its two runtime
        # columns. The gap is filed as `archive/requests/open/provenance-for-a-runtime-reply.md`.
        "ha1_encryption_key_imported",
        "monitored_link_group_count",
        "no_live_redundant_peer",
        "ha_monitors_nothing",
        "ha_monitoring_state",
        "no_independent_second_keepalive_path",
        "second_keepalive_path_state",
        "ha1_control_link_not_encrypted",
        "ha1_control_link_exposure",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="high_availability_configs")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="high_availability_configs")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="high_availability_configs", null=True, blank=True)
    #: The MERGED CONFIG snapshot. The runtime read is a second snapshot and is not referenced
    #: here: `ha_runtime_state_collected` is what records whether it existed, which is what any
    #: reader of this row needs and what stage 5 declared.
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="high_availability_configs")

    # --- did anyone look ------------------------------------------------------------------
    #: FALSE MEANS NOBODY LOOKED, which is a different state from a value being absent. True
    #: where the merged-config read returned a device entry for this appliance - including on an
    #: appliance that holds no HA node at all, because that absence IS a reading and the
    #: operational read confirms it as `enabled: no`.
    ha_config_collected = models.BooleanField(default=False)
    #: Whether `show high-availability all` was collected for this appliance at all. FALSE ON
    #: EVERY APPLIANCE UNTIL THE COLLECTOR RUNS, which is what tells the four runtime-dependent
    #: verdicts below apart from four findings.
    ha_runtime_state_collected = models.BooleanField(default=False)

    # --- the configuration, as the vendor spells it ----------------------------------------
    #: `enabled`. IMPLICIT NO, measured: `show high-availability state` answers `enabled: no`
    #: where the key is absent and `enabled: yes` where it is present and yes, on all four lab
    #: appliances in one pass, 2026-10-26. FIRES for PAN-HAP-001, which asserts a live redundant
    #: peer; REASSURES for PAN-HAP-002, -003 and -004, where it is an applicability clause and
    #: false correctly suppresses a control about a control link that does not exist.
    ha_enabled = models.BooleanField(default=False)
    #: `cluster/enabled`. NULL AND NOT FALSE: `show high-availability cluster` was never asked,
    #: so nothing distinguishes "not a cluster member" from "this read does not report clusters",
    #: and a stored guess would decide PAN-HAP-001's second branch on nothing.
    cluster_participation_enabled = models.BooleanField(null=True, blank=True, default=None)
    #: `group/mode`, read as WHICH CHILD is present. Blank where no branch is - which on
    #: fw-core-tpa-b is the measured state beside a partner that holds `active-passive`.
    ha_mode = models.CharField(max_length=32, blank=True, default="")
    #: `group/configuration-synchronization/enabled`. Configured to exchange configuration is
    #: NOT the same as doing so: with this `yes` and `running-sync-enabled: yes` on both members,
    #: stage 4 measured four successful commits on one member producing no change on the other.
    config_sync_enabled = models.BooleanField(null=True, blank=True, default=None)
    #: `group/state-synchronization/enabled`. The configured half of PAN-HAP-001's "exchanging
    #: state": both lab members hold `no` explicitly and the runtime read answers
    #: `state-sync: User-disabled`, so the pair satisfies the switch and fails the assertion.
    state_sync_enabled = models.BooleanField(null=True, blank=True, default=None)
    #: `interface/ha1/encryption/enabled`. IT DOES NOT MEAN THE LINK IS ENCRYPTED: the key
    #: cannot take effect without an imported HA key, and `validate full` refuses the commit
    #: without one ("High-availability ha1 encryption requires an import of the
    #: high-availability-key"), which is why no positive control for it is payable at any price.
    ha1_encryption_enabled = models.BooleanField(null=True, blank=True, default=None)
    #: `ha1-encrypt-imported` from the RUNTIME read. The prerequisite the switch above cannot
    #: take effect without, and a fact with no configuration node anywhere. `no` on all four lab
    #: appliances, including the two where HA is off entirely.
    #:
    #: NULL MEANS THE RUNTIME READ WAS NOT COLLECTED, never "the key was absent": the key is
    #: never absent from that reply. `ha_runtime_state_collected` is the column that says which.
    #: It carries NO provenance row - see the note in DERIVED_FIELDS above for why, which is the
    #: only thing about this model the provenance vocabulary cannot express.
    ha1_encryption_key_imported = models.BooleanField(null=True, blank=True, default=None)
    #: `interface/ha1-backup/port`. BLANK IS THE LAB'S COMMITTED STATE and the container above it
    #: is PRESENT AND EMPTY on both PA-5220s, so `if node:` at the container reports a backup
    #: control link that does not exist. The normalizer reads the container's presence
    #: separately; no column holds it.
    ha1_backup_port = models.CharField(max_length=32, blank=True, default="")
    #: `group/peer-ip-backup` - the far end of the second keepalive path. Blank means the backup
    #: link has no far end, which is the half-configured state the vendor's own Help names.
    peer_ip_backup = models.CharField(max_length=64, blank=True, default="")
    #: `group/election-option/heartbeat-backup` - the management port as a backup path for
    #: heartbeat and hello messages. A DIFFERENT SUBTREE from the backup control link and on a
    #: different tab: the catalogue's asserted path reaches only the container, so a stage
    #: retrieving that path alone reports a firewall with management-path keepalives as failing
    #: a control it satisfies. Not valid on a PA-VM at all (`code=6` at the position).
    heartbeat_backup_enabled = models.BooleanField(null=True, blank=True, default=None)
    #: `group/monitoring/link-monitoring/enabled`. IMPLICIT YES, measured in both directions on
    #: fw-core-tpa-a across commit jobs 538 and 539, 2026-10-26. SEE THE MODEL DOCSTRING: this
    #: default reassures on the control that asserts the thing it is the default for, and no
    #: clause may be written on it.
    link_monitoring_enabled = models.BooleanField(default=True)
    #: `group/monitoring/path-monitoring/enabled`. Same implicit, same experiment, same
    #: prohibition. And do NOT read it off `show high-availability path-monitoring`, which
    #: answers from the DATAPLANE: its `active` tracked dataplane activity rather than this key.
    path_monitoring_enabled = models.BooleanField(default=True)
    #: `group/monitoring/link-monitoring/failure-condition` - `any` or `all`. Carried for
    #: display: stage 3 leaves it deliberately unranked on both branches of PAN-HAP-004, so no
    #: clause and no grading touches it, and setting it to `all` would largely defeat the control.
    link_monitoring_failure_condition = models.CharField(max_length=16, blank=True, default="")
    #: `group/monitoring/path-monitoring/failure-condition`. Same shape and same decision.
    path_monitoring_failure_condition = models.CharField(max_length=16, blank=True, default="")
    #: The monitored link groups' names. DISPLAY ONLY - a JSON column cannot be registered in the
    #: search layer (`test_findings_rest_on_columns` walks every compiled field for JSONField
    #: references and fails on one), so the reachable value beside it is the count.
    monitored_link_groups = models.JSONField(default=list, blank=True)
    #: How many monitored link groups are configured. ZERO IS BOTH THE TRUE COUNT AND THE FIRING
    #: SIDE for an appliance with no link-group collection. It is not sufficient on its own:
    #: stage 4 measured that `<entry name='...'/>` carrying NO interface passes `validate full`,
    #: so a count of one can still monitor nothing - which is why the verdict below exists.
    monitored_link_group_count = models.PositiveIntegerField(default=0)

    # --- the verdicts a control reads -------------------------------------------------------
    #: NO LIVE REDUNDANT PEER - true is the finding side. True unless the runtime read shows a
    #: peer answering AND state being exchanged, by either mechanism the control accepts. The
    #: configuration switch alone is not enough and this estate is why: both members hold
    #: `enabled: yes` and `configuration-synchronization/enabled: yes` while the runtime read
    #: answers `state-sync: User-disabled`.
    #:
    #: DEFAULTS TO THE FIRING VALUE. A row nobody recomputed, and an appliance whose runtime
    #: state nobody collected, report themselves rather than passing - which is the only safe
    #: answer for a control whose premise is that nobody notices a redundancy never formed.
    no_live_redundant_peer = models.BooleanField(default=True)
    #: HA MONITORING WATCHES NOTHING - true is the finding side. True when no POPULATED link
    #: group and no POPULATED path group exists, regardless of what the two enables report. This
    #: is the column PAN-HAP-004 clauses on instead of the enables, and the whole point of the
    #: control: the naive expression reads the enables, and the enables pass every unconfigured
    #: appliance in the estate.
    ha_monitors_nothing = models.BooleanField(default=True)
    #: Which of stage 3's four monitoring ranks this appliance sits in, plus an explicit unknown.
    #: The column PAN-HAP-004's severity varies with.
    ha_monitoring_state = models.CharField(max_length=32, default=MONITORING_UNKNOWN)
    #: NO SECOND INDEPENDENT KEEPALIVE PATH - true is the finding side. True unless a backup
    #: control link with a far end, or management-path heartbeat backup, is configured AND
    #: independent of the primary link by the vendor's own tests. An unread appliance must not
    #: satisfy the disjunction on the branch nobody looked at, which is the specific way a
    #: single-keepalive pair would pass this control.
    no_independent_second_keepalive_path = models.BooleanField(default=True)
    #: Which of stage 3's four keepalive ranks this appliance sits in. PAN-HAP-003's severity
    #: varies with it.
    second_keepalive_path_state = models.CharField(max_length=48, default=KEEPALIVE_UNKNOWN)
    #: HA1 CONTROL LINK IS NOT ENCRYPTED - true is the finding side. True unless the switch is
    #: on AND the runtime read confirms encryption in force AND a key is imported.
    #:
    #: THIS ANSWERS ONLY THE PER-APPLIANCE HALF. Whether the link is encrypted is a property of
    #: the PAIR, and no column of a one-row-per-appliance model can hold that: a pair with the
    #: key imported on one member only reports as two independent findings rather than as one
    #: broken link.
    ha1_control_link_not_encrypted = models.BooleanField(default=True)
    #: The exposure band: encrypted, or unencrypted classified by what the primary control
    #: link's port can reach. PAN-HAP-002's severity varies with it.
    ha1_control_link_exposure = models.CharField(
        max_length=48, default=EXPOSURE_PORT_UNKNOWN)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_high_availability_config_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance"]),
            models.Index(fields=["ha_config_collected"]),
            models.Index(fields=["no_live_redundant_peer"]),
            models.Index(fields=["ha_monitors_nothing"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} high availability"
