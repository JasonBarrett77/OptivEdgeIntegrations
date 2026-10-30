"""Device > Setup > Services and Device > Setup > Management > Logging and Reporting Settings.

Two single-control clusters, cut out of `DeviceConfigurationProfile` together because each is
one field on a screen of its own. They are small, and that is the point: PAN-MGT-009 lives on
Setup > SERVICES and PAN-MGT-011 on Setup > Management > Logging and Reporting, two different
screens, and the aggregate had them on one row beside thirty other values. A model per cluster
makes the address right even when the cluster is one field wide.

The two implicit values are OPPOSITE and were measured together for that reason: an absent
`server-verification` is ENABLED, an absent `enable-log-high-dp-load` is DISABLED. One shared
assumption would have flagged every device for one control and no device for the other - wrong
in both directions at once.

Neither model carries the rest of its screen. Setup > Services also holds the update server
hostname, the DNS servers, the proxy and the NTP pair; Logging and Reporting holds a dozen quota
and report settings. None of it is read by a completed control, so none of it is here - Jason's
rule, 2026-09-10: an object no completed control relates to comes out, and comes back when a
control defines it.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .log_settings import (
    ALL_PANORAMA_LOG_TYPES_MISSING,
    ALL_SYSTEM_SEVERITIES_MISSING,
)
from .provenance import ProvenancedMixin


class UpdateServerSettings(ProvenancedMixin, SyncTrackedModel):
    """Whether the firewall verifies the update server's TLS identity. PAN-MGT-009."""

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="update_server_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="update_server_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="update_server_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="update_server_settings")

    #: Implicit YES - the checkbox reads ticked with the key absent, measured 2026-09-01. So an
    #: untouched device SATISFIES PAN-MGT-009, and only an explicit `no` fires it.
    verify_identity = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_update_server_settings_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} update server settings"


class LoggingSettings(ProvenancedMixin, SyncTrackedModel):
    """Logging and Reporting Settings, and this appliance's device-wide logging posture.

    PAN-MGT-011 named it and PAN-LOG-001, 003, 004, 006, 007, 008, 009 and 010 now live on it.

    THE NAME IS NARROWER THAN THE MODEL AND THAT IS THE ACCEPTED STRETCH. It was cut out for one
    checkbox on Setup > Management > Logging and Reporting; the columns added for the logging
    domain are drawn from `deviceconfig/setting/management` AND from
    `/config/shared/log-settings`, which is a different screen. The alternative was a second
    per-appliance model, which costs about fifteen times as much and splits one appliance's
    logging posture across two sheets. One row per appliance is the right grain for both.

    ON AN HA PAIR THIS IS TWO ROWS FOR ONE REAL CONFIGURATION, one per peer, and nothing
    deduplicates them. That is not cosmetic here: the two peers' management containers have been
    measured DIFFERING while config sync reported synchronized, so an asymmetric reading between
    peers is DATA rather than a normalization fault.

    EVERY GAP COLUMN LISTS WHAT IS MISSING, so the full set is the firing side and an empty
    string is the reassuring one. Their defaults are the full set deliberately: a row nobody has
    recomputed has demonstrated no coverage, and the opposite reading would report every
    firewall in the estate as fully covered the day a migration lands.
    """

    #: Computed here: verdicts and gap sets over `/config/shared/log-settings`, the collection
    #: path, and the `show logging-status` reading. `require_audit_comment` and
    #: `log_on_high_dp_load` are deliberately NOT here - both read a real key and have a
    #: provenance row. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "log_retention_configured",
        "offbox_destination_count",
        "syslog_destination_in_use",
        "log_settings_match_lists",
        "system_log_severity_gaps",
        "config_log_fully_offbox",
        "config_log_offbox_destination",
        "config_log_filter_narrows",
        "panorama_managed",
        "panorama_log_type_gaps",
        "email_alerting_for_critical_system_events",
        "central_store_delivery_healthy",
        "central_store_status_collected",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="logging_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="logging_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="logging_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="logging_settings")

    #: Implicit NO - unticked with the key absent AND with the whole deviceconfig/setting/
    #: management node absent, which is the state on both PA-5220s. So an untouched device FIRES
    #: PAN-MGT-011, the opposite direction from its neighbour above.
    log_on_high_dp_load = models.BooleanField(default=False)

    # --- PAN-LOG-007 ---------------------------------------------------------------------
    #: IMPLICIT NO, measured in BOTH directions against the commit gate on fw-core-tpa-a
    #: (PA-5220 11.1.13-h3), 2026-10-19: with the key absent a policy change committed with no
    #: audit comment; with it set to yes the same commit was refused at submission with code=13
    #: naming the rule's xpath; deleting the key let the rule commit again (job 438). So an
    #: untouched device FIRES PAN-LOG-007.
    #:
    #: WHAT THE MEASUREMENT ADDED IS NOT IN THE COLUMN: the gate is the commit SUBMISSION. No
    #: job is created, so a remediation that tells an engineer to watch for a failed commit job
    #: is describing something that will not happen.
    require_audit_comment = models.BooleanField(default=False)

    # --- PAN-LOG-009 ---------------------------------------------------------------------
    #: Whether ANY per-log-type disk quota or log expiration key is set on this appliance, as
    #: against every log type keeping the platform's shipped quota and never expiring. A
    #: presence test over about 170 keys in two platform-dependent shapes: chassis-quota and
    #: chassis-log-expiration-period split mgmt-card/log-card on the PA-5220, disk-quota and
    #: log-expiration-period carry 43 log types on the PA-VM.
    #:
    #: THE NUMBERS THEMSELVES CANNOT BE STORED. They exist only in `show system logdb-quota`,
    #: which no configuration read carries, and the never-expire sentinel cannot be written at
    #: all - the device reports "Expiration-period: 0 days" for a key-less log type and refuses
    #: a written 0, "value=0 should be equal to or between 1 and 2000". PAN-LOG-009's assertion
    #: is discharged onto the engineer; this column is so the answer can be applied to a stored
    #: reading rather than needing another measurement.
    log_retention_configured = models.BooleanField(default=False)

    # --- PAN-LOG-001 ---------------------------------------------------------------------
    #: HOW MANY DISTINCT OFF-BOX LOG DESTINATIONS THIS APPLIANCE *DEFINES*, which is the half of
    #: PAN-LOG-001 the boolean below cannot carry. The two are deliberately separate columns:
    #: `a destination nothing forwards to` and `no destination at all` have the same outcome and
    #: DIFFERENT REMEDIATIONS, and stage 3's grading over this control has three rungs that are a
    #: COUNT - none at all, one path, two or more - which no boolean can hold.
    #:
    #: Counted over three sources, which are stage 5's own `derived_from` for this column:
    #: the distinct addresses of every syslog server entry at BOTH scopes, the Panorama /
    #: log-collector path where a Device > Log Settings match list sends to it, and each HTTP
    #: collector profile such a match list names. Distinct by ADDRESS and not by entry, because
    #: two profiles naming one host are one destination; email and SNMP-trap are not counted at
    #: all, on the settlement that they notify rather than retain.
    #:
    #: BOTH SCOPES, AND THAT IS MEASURED RATHER THAN TIDY: every appliance in this lab holds a
    #: vsys-scoped syslog profile and two of them hold a collector address the shared scope does
    #: not carry, so a count taken at the shared scope alone reports `no destination` on all four.
    #:
    #: A TEMPLATE-SUPPLIED PROFILE COUNTS. The assertion is about whether the audit trail leaves
    #: the box; that it cannot be remediated on the firewall is a different finding, and the only
    #: thing that records it is the per-field provenance row - which this column, being derived,
    #: does not have.
    #:
    #: ZERO IS BOTH THE DEFAULT AND THE FIRING SIDE, which is the whole reason it is safe: the
    #: clause is `fewer than two`, so a row nobody has recomputed reports rather than passing.
    offbox_destination_count = models.PositiveIntegerField(default=0)

    #: Whether at least one syslog server profile on this appliance is named by a forwarding
    #: rule that is actually in place. Existence is NOT enough and that is the measured point:
    #: the profile is only an address book, and nothing is sent until a Device > Log Settings
    #: match list's `send-syslog` or a Log Forwarding profile match list's names it.
    #: Audit-tracking's own `send-syslog` does not count - it was ruled out of scope.
    syslog_destination_in_use = models.BooleanField(default=False)

    #: The Device > Log Settings match lists, flattened per log type, FOR A READER. This is the
    #: ONLY place that object's content is stored: no subject is keyed on a match-list entry,
    #: because every assertion about them is a verdict ACROSS entries. The cost is that
    #: description, send-snmptrap, actions and quarantine are reachable by nothing.
    log_settings_match_lists = models.JSONField(default=list, blank=True)

    # --- PAN-LOG-003 ---------------------------------------------------------------------
    #: Which System-log severities no off-box destination on this appliance covers, as the
    #: severities that are MISSING. Email and SNMP-trap destinations are deliberately not
    #: counted as off-box: they notify rather than retain. An HTTP collector is counted.
    #:
    #: A PARSE RATHER THAN A COMPARISON: the filter is free text the device evaluates, whose
    #: candidate list completes empty, so turning it into covered severities is parsing and the
    #: answer is a set across entries rather than a value on one row.
    system_log_severity_gaps = models.CharField(
        max_length=64, blank=True, default=ALL_SYSTEM_SEVERITIES_MISSING)

    # --- PAN-LOG-004 ---------------------------------------------------------------------
    #: Whether every Configuration log leaves this appliance: an off-box Configuration
    #: destination AND no filter on that path holding any configuration change back. One verdict
    #: column rather than two clauses, because the failure is a disjunction and the clause
    #: grammar is a flat conjunction - the two halves are stored beside it so a finding can say
    #: which one failed.
    config_log_fully_offbox = models.BooleanField(default=False)
    #: The first half: any Configuration match list naming a syslog profile, an HTTP profile or
    #: Panorama. No match list at all means no destination - that object is the only forwarding
    #: path for this log type, measured.
    config_log_offbox_destination = models.BooleanField(default=False)
    #: The second half, and TRUE IS THE FIRING SIDE: true means something is held back.
    #: `filter` is mandatory at commit validation on this node (measured, job 434), so every
    #: committed entry carries one and none can be assumed unrestricted until it is parsed.
    config_log_filter_narrows = models.BooleanField(default=True)

    # --- PAN-LOG-006 and 010 -------------------------------------------------------------
    #: Whether this appliance has a central log store to reach at all - PAN-LOG-006's and 010's
    #: applicability. RESTS ON THE COLLECTION PATH AND NOT ON A DEVICE READING: the station the
    #: appliance was reached through and its appliance group. The firewall-side fact is
    #: `deviceconfig/system/panorama-server`, which belongs to another domain's control and was
    #: not measured here. Defaulted TRUE so the assertion fires rather than silently excluding
    #: every unrecomputed row.
    panorama_managed = models.BooleanField(default=True)
    #: Which forwardable log types this appliance does not forward to Panorama or Strata Logging
    #: Service, as the types that are MISSING, taken across BOTH node families - the Device >
    #: Log Settings match lists and the Log Forwarding profile match lists.
    #:
    #: `send-to-panorama`'s implicit `no` was measured on the SYSTEM kind only, against the
    #: device's own forwarding counters. The same leaf on config, userid, hipmatch,
    #: globalprotect and iptag is the same key by completion and was not exercised, and the Log
    #: Forwarding profile's copy renders differently for absence and was never settled
    #: behaviourally. That measurement is carried to all of them, which is the FIRING direction:
    #: a log type nobody can show to be forwarded counts as not forwarded.
    panorama_log_type_gaps = models.CharField(
        max_length=255, blank=True, default=ALL_PANORAMA_LOG_TYPES_MISSING)

    # --- PAN-LOG-008 ---------------------------------------------------------------------
    #: Whether a System-log match list whose filter includes critical severity names an email
    #: server profile - the configuration half of "critical events alert by email". No query
    #: rests on it: the control is discharged onto the engineer, because its own floor is "not
    #: required where SIEM alerting already covers critical events". The column exists so that
    #: answer can be applied to a stored reading.
    email_alerting_for_critical_system_events = models.BooleanField(default=False)

    # --- PAN-LOG-010 ---------------------------------------------------------------------
    #: Whether the firewall reports itself connected to its Panorama, Log Collector or Strata
    #: Logging Service destination AND forwarding with no backlog building up. A RUNTIME reading
    #: on a configuration model, which is where it goes because the store has no runtime-state
    #: model at all and the grain is the same.
    #:
    #: FALSE WHEN NOBODY LOOKED, AND IT FIRES. Jason's rule, 2026-10-23: an unknown fires, and a
    #: `passes` has to be argued in writing - "in a production environment, the outcome I would
    #: expect is a finding raised if there's no evidence of healthy delivery state. That's the
    #: only safe assumption." A missing reading reported as compliant is a customer told they are
    #: safe on the strength of nothing; a finding raised where the estate is fine is checkable in
    #: a minute and arrives with its evidence attached.
    #:
    #: NOT NULLABLE, AND IT WAS UNTIL THAT RULE LANDED. A null matched no positive comparison, so
    #: an appliance nobody had read came out of the query as healthy - and the companion column
    #: meant to catch that was wired as an APPLICABILITY clause, which SUPPRESSED the control
    #: rather than raising it. Same field, opposite outcome, and the suppressing form read as the
    #: careful one.
    central_store_delivery_healthy = models.BooleanField(default=False)
    #: Whether that reading exists for this appliance at all. NO LONGER A CLAUSE: PAN-LOG-010's
    #: applicability clause on it was removed 2026-10-23 for the reason above. What it is for now
    #: is letting a finding say WHICH case a false neighbour is - a reading that says unhealthy,
    #: or no reading at all - because the boolean beside it cannot tell those apart.
    central_store_status_collected = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_logging_settings_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance"]),
            models.Index(fields=["syslog_destination_in_use"]),
            models.Index(fields=["central_store_status_collected"]),
            # PAN-LOG-001 clauses on this column twice - a threshold at two and an equality on
            # one - which is the same reason `LogServerTarget.profile_referrer_count` carries one.
            models.Index(fields=["offbox_destination_count"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} logging settings"
