"""Objects > Security Profiles (Anti-Spyware, Vulnerability Protection, Antivirus) and Groups.

Subjects of PAN-SPY-001 and PAN-VLN-001. Both are policy objects in the PAN-OS sense - they live
under `vsys/entry/profiles` or `shared/profiles`, arrive from Panorama through the pushed reads,
and a rule names them - so they scope exactly like address objects: vsys scope on the
enforcement point, shared scope on the appliance group, vendor scope synthesized per point. See
`ScopedPolicyObject`.

ONE MODEL FOR EVERY PROFILE KIND, with `kind`. This used to hold two kinds and said so, on the
grounds that they are one shape - an ordered rule list whose entries match on severity. The
vulnerability rule adds `host`, `cve` and `vendor-id`, which only change which rules can match,
and that is decided in normalization rather than stored as columns.

ANTIVIRUS IS NOT THAT SHAPE, and it is here anyway. It has per-protocol decoders - ftp, http,
http2, imap, pop3, smb, smtp - not severity rules. What made room for it was moving the severity
verdict off this model onto `SecurityProfileSeverityVerdict`: what remains here is what every
kind genuinely shares, which is a name, a scope, a precedence, whether it is predefined, and who
references it. A kind that answers no severity question simply writes no verdict rows.

That is the line to hold as the remaining kinds arrive - URL filtering, file blocking, WildFire
analysis, decryption, SCTP, SD-WAN path quality, all of which the predefined collector already
downloads. Shared identity belongs here; anything true of only one kind belongs beside it.

THE VERDICT IS ORDER-INDEPENDENT (Jason, 2026-09-11). A severity is blocked only when a
catch-all rule covers it - client AND server, for vulnerability - and every rule that can match
it takes a blocking action. No document says whether profile rules are first-match, and this
reading does not need to know: it cannot pass a weak profile. Its cost is that a non-blocking rule
sitting BELOW a broad blocking one still fails the severity, where first-match would never reach
it. `blocking` is drop, reset-client, reset-server, reset-both and block-ip - a deviation from the
corpus minimum, which names reset-both alone.

PREDEFINED PROFILES ARE ROWS TOO. `default` and `strict` ship with the device, live under
`/config/predefined/profiles` rather than in the merged config, and are what a rule uses when
nobody built a custom profile. They are assessed only when something USES them - a rule or a
profile group names them - which is what `is_used` records. An unused `default` is not a finding
about the estate; a rule protected by it is.
"""

from __future__ import annotations

from django.db import models

from ..collected import ApplianceGroup, EnforcementPoint, ManagementStation
from .objects import ScopedPolicyObject


class SecurityProfile(ScopedPolicyObject):

    #: Computed here: severity verdicts over the rule list, and the referrer walk. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "is_predefined",
        "rule_count",
        "threat_exception_count",
        "referrer_count",
        "is_used",
    )
    KIND_SPYWARE = "spyware"
    KIND_VULNERABILITY = "vulnerability"
    KIND_VIRUS = "virus"
    KIND_WILDFIRE_ANALYSIS = "wildfire-analysis"
    KIND_CHOICES = [
        (KIND_SPYWARE, "Anti-Spyware"),
        (KIND_VULNERABILITY, "Vulnerability Protection"),
        (KIND_VIRUS, "Antivirus"),
        (KIND_WILDFIRE_ANALYSIS, "WildFire Analysis"),
    ]
    #: Kinds built from an ordered rule list matching on SEVERITY, and so the only kinds for
    #: which a severity verdict means anything. Antivirus is deliberately not here: it has
    #: per-protocol decoders instead, and writes no verdict rows.
    THREAT_RULE_KINDS = (KIND_SPYWARE, KIND_VULNERABILITY)

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE, related_name="security_profiles")
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE, related_name="security_profiles",
        null=True, blank=True)
    appliance_group = models.ForeignKey(
        ApplianceGroup, on_delete=models.CASCADE, related_name="security_profiles",
        null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="security_profiles")

    kind = models.CharField(max_length=32, choices=KIND_CHOICES)
    description = models.TextField(blank=True)
    is_predefined = models.BooleanField(default=False)
    rule_count = models.PositiveIntegerField(default=0)
    threat_exception_count = models.PositiveIntegerField(default=0)

    #: Rules and profile groups that name this definition, resolved within their own scope
    #: first (vsys, then shared, then predefined). A count and a flag rather than the list,
    #: because a finding rests on a column; `referrers` is for the tab.
    referrer_count = models.PositiveIntegerField(default=0)
    is_used = models.BooleanField(default=False)
    referrers = models.JSONField(default=list, blank=True)

    raw_profile = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["kind", "name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "kind", "name", "precedence_rank"]),
            models.Index(fields=["appliance_group", "kind", "name", "precedence_rank"]),
            models.Index(fields=["enforcement_point", "namespace_type", "namespace_value"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "kind", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_per_point_namespace",
            ),
            models.UniqueConstraint(
                fields=["appliance_group", "kind", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_per_group_namespace",
            ),
        ]

    @property
    def disabled_ml_models(self) -> list[str]:
        """Models this profile does not run at all. Absent counts as disabled."""
        return sorted(m.name for m in self.ml_models.all() if not m.enabled)

    @property
    def non_blocking_ml_models(self) -> list[str]:
        """Models that do not STOP a file - off, or running in alert-only.

        What PAN-AVW-002 reports. A model set to `enable(alert-only)` is not a model doing
        nothing, but it is a model that lets the file through, which is the same outcome for
        the control's purpose and a different remediation for the engineer - hence both lists.
        """
        return sorted(m.name for m in self.ml_models.all() if not m.blocks)

    @property
    def has_disabled_ml_model(self) -> bool:
        return bool(self.disabled_ml_models)

    @property
    def has_non_blocking_ml_model(self) -> bool:
        return bool(self.non_blocking_ml_models)

    @property
    def inline_detectors_not_blocking(self) -> list[str]:
        """Inline cloud-analysis detectors that do not stop the traffic.

        PAN-SPY-004 and PAN-VLN-003. Covers both ways of not blocking - a detector the
        profile never mentions, which does not run at all, and one set to `alert`, which runs
        and lets the traffic through. The second is the `enable(alert-only)` case from
        PAN-AVW-002 wearing a different name, and reading it as "enabled" would pass a
        profile that only watches.
        """
        return sorted(d.name for d in self.inline_detectors.all() if not d.blocks)

    @property
    def has_inline_detector_not_blocking(self) -> bool:
        return bool(self.inline_detectors_not_blocking)

    @property
    def non_blocking_decoders(self) -> list[str]:
        """Protocols this antivirus profile detects malware on without stopping it.

        Reads the resolved action, not the configured one: every decoder of an unedited profile
        says `default`, and on smtp, imap and pop3 that means alert.
        """
        return sorted(d.protocol for d in self.decoders.all() if not d.blocks)

    @property
    def has_non_blocking_decoder(self) -> bool:
        return bool(self.non_blocking_decoders)

    @property
    def non_blocking_wildfire_decoders(self) -> list[str]:
        """Protocols whose WILDFIRE SIGNATURE ACTION does not stop the transfer.

        A separate question from `non_blocking_decoders`: the two columns are independent
        verdict sources and a profile can be hard on one and open on the other.
        """
        return sorted(d.protocol for d in self.decoders.all() if not d.wildfire_blocks)

    @property
    def has_non_blocking_wildfire_decoder(self) -> bool:
        return bool(self.non_blocking_wildfire_decoders)

    @property
    def non_blocking_mlav_decoders(self) -> list[str]:
        """Protocols whose WILDFIRE INLINE ML ACTION does not stop the transfer.

        `blocks is not True` rather than `not blocks`, so a row predating the column - a null,
        meaning not computed - is reported rather than passed. The label says which it is.
        """
        return sorted(f"{d.protocol} (not yet computed)" if d.mlav_blocks is None
                      else d.protocol
                      for d in self.decoders.all() if d.mlav_blocks is not True)

    @property
    def has_non_blocking_mlav_decoder(self) -> bool:
        return bool(self.non_blocking_mlav_decoders)

    @property
    def wildfire_submits_all_file_types(self) -> bool:
        """Does this WildFire analysis profile send EVERY file type for analysis?

        True only when some rule covers `any` file type. A profile with no rules submits
        nothing and is False - not None: that is a measured state, not an unknown.
        """
        return any(r.covers_all_file_types for r in self.wildfire_rules.all())

    @property
    def wildfire_coverage_gaps(self) -> list[str]:
        """Why this profile does not submit everything, in the UI's column order.

        Empty when a rule covers `any` file type, `any` application and both directions.
        """
        rules = list(self.wildfire_rules.all())
        if not rules:
            return ["no rules at all, so nothing is sent for analysis"]
        gaps = []
        if not any(r.covers_all_file_types for r in rules):
            gaps.append("no rule covers every file type")
        if not any(r.covers_all_applications for r in rules):
            gaps.append("no rule covers every application")
        if not any(r.covers_both_directions for r in rules):
            unset = [r.name for r in rules if r.covers_both_directions is None]
            gaps.append(f"no rule covers both directions (direction not set on: "
                        f"{', '.join(unset)})" if unset
                        else "no rule covers both directions")
        return gaps

    @property
    def non_blocking_application_overrides(self) -> list[str]:
        """Per-application overrides that do not stop the transfer, as labelled strings.

        `blocks is not True` rather than `not blocks`, so the unestablished `default` case is
        reported rather than passed - see SecurityProfileApplicationOverride.blocks.
        """
        return sorted(o.label for o in self.application_overrides.all() if o.blocks is not True)

    @property
    def has_non_blocking_application_override(self) -> bool:
        return bool(self.non_blocking_application_overrides)

    def verdict(self, severity: str) -> tuple[bool | None, str]:
        """(blocked, detail) for one severity, or (None, "") where the profile makes no such
        claim. Reads a prefetched `severity_verdicts` list without a query when one is loaded."""
        for row in self.severity_verdicts.all():
            if row.severity == severity:
                return row.blocked, row.detail
        return None, ""

    @property
    def critical_blocked(self) -> bool | None:
        return self.verdict(SecurityProfileSeverityVerdict.CRITICAL)[0]

    @property
    def critical_detail(self) -> str:
        return self.verdict(SecurityProfileSeverityVerdict.CRITICAL)[1]

    @property
    def high_blocked(self) -> bool | None:
        return self.verdict(SecurityProfileSeverityVerdict.HIGH)[0]

    @property
    def high_detail(self) -> str:
        return self.verdict(SecurityProfileSeverityVerdict.HIGH)[1]

    @property
    def medium_blocked(self) -> bool | None:
        return self.verdict(SecurityProfileSeverityVerdict.MEDIUM)[0]

    @property
    def medium_detail(self) -> str:
        return self.verdict(SecurityProfileSeverityVerdict.MEDIUM)[1]

    def __str__(self) -> str:
        return f"{self.owner} / {self.kind} / {self.namespace_key} / {self.name}"


class SecurityProfileDecoder(models.Model):
    """One protocol decoder of an antivirus profile, and what it ACTUALLY does.

    PAN-AVW-001's subject, and the reason it cannot be answered from the configuration alone:
    every decoder of every unedited profile stores the literal `default`, including the shipped
    one. Measured 2026-10-07 on the lab - `/config/predefined/profiles/virus/entry[@name='default']`
    returns `action=default` on all seven decoders, and so does a profile created through the UI
    without touching a setting.

    What `default` RESOLVES to is per protocol, and the UI is the only thing that states it.
    Jason captured both profiles side by side on 2026-10-07: the predefined `default` and a
    UI-created one render identically -

        http, http2, ftp, smb   ->  reset-both
        smtp, imap, pop3        ->  alert

    Three decoders alert, which is independently what controls.json says about the shipped
    profile: "The shipped 'default' profile only alerts on several decoders - detection without
    prevention." Two sources that agree, neither of them the device's own words, which is why
    the resolution is a named table in this module rather than an assumption spread through it.

    `configured_action` keeps what the config says and `effective_action` what it means. A
    control reads the second; an engineer looking for the line to change needs the first.
    """

    #: Every decoder PAN-OS evaluates, in the order its UI lists them. The CONFIG may name
    #: fewer - or none - and the device still inspects all seven. Measured 2026-10-07.
    PROTOCOLS = ("http", "http2", "smtp", "imap", "pop3", "ftp", "smb")

    #: What the literal `default` means, per protocol. The UI's rendering, confirmed on the
    #: predefined profile, a UI-created one, and a profile written with an explicit `default`.
    #: If a PAN-OS release changes this, every antivirus finding changes with it - so it is one
    #: table, cited, and not a conditional somewhere in the normalizer.
    DEFAULT_RESOLUTION = {
        "http": "reset-both", "http2": "reset-both", "ftp": "reset-both", "smb": "reset-both",
        "smtp": "alert", "imap": "alert", "pop3": "alert",
    }

    #: WHAT AN ABSENT ACTION MEANS, and it is NOT `default`.
    #:
    #: Measured 2026-10-07 by writing three profiles and exporting the UI's own view of them:
    #: one with no decoder node at all, one with a decoder entry carrying no `action`, and one
    #: naming `default` on http alone. All three render `allow` on every protocol the config
    #: does not give a value for - including the six the third profile never mentions.
    #:
    #: So absence is the PERMISSIVE end, not the vendor default. A profile that names nothing
    #: inspects nothing. Reading absence as `default` would report such a profile as blocking
    #: malware on http when the device allows it, which is the one direction an inspection
    #: control must never fail in.
    ABSENT_ACTION = "allow"
    #: Actions that stop the transfer. Wider than the corpus's `reset-both`, the same deviation
    #: PAN-SPY-001 makes and for the same reason: a profile that drops malware has not failed to
    #: block it. Recorded in control-changes.json.
    BLOCKING_ACTIONS = frozenset({"drop", "reset-client", "reset-server", "reset-both"})

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="decoders")
    protocol = models.CharField(max_length=32)
    #: What the config holds - usually the literal `default`.
    configured_action = models.CharField(max_length=32)
    #: What that means on this protocol, after DEFAULT_RESOLUTION.
    effective_action = models.CharField(max_length=32)
    blocks = models.BooleanField()
    #: THREE ACTION COLUMNS, NOT ONE. The UI's decoder table has SIGNATURE ACTION, WILDFIRE
    #: SIGNATURE ACTION and WILDFIRE INLINE ML ACTION per protocol, and `default` resolves by
    #: the SAME per-protocol table in all three - measured 2026-10-07, the create-form capture
    #: in OptivEdgeProbe scratch/jason/ showing every row rendering identically across the
    #: three columns.
    #:
    #: They are three VERDICT SOURCES on one protocol: a signature hit, a WildFire-derived
    #: signature hit, and an inline ML verdict. A profile can reset-both on the first and allow
    #: the other two, and malware caught by WildFire is then delivered. PAN-AVW-001 read only
    #: the first until 2026-10-08.
    configured_wildfire_action = models.CharField(max_length=32, blank=True)
    effective_wildfire_action = models.CharField(max_length=32, blank=True)
    wildfire_blocks = models.BooleanField(default=False)
    configured_mlav_action = models.CharField(max_length=32, blank=True)
    effective_mlav_action = models.CharField(max_length=32, blank=True)
    #: NULLABLE, and a null means NOT COMPUTED - a row written before this column existed.
    #:
    #: The checklist's rule is that a new derived column on an already-populated model must not
    #: default to the compliant side, because the gap between migrating and re-normalizing then
    #: reads as a hardened estate. `False` here already means "does not block", which fires -
    #: but it is indistinguishable from a measured `allow`. A null fires AND says why, so
    #: "nobody has computed this yet" cannot be read as "we checked and it allows". Same
    #: obligation MasterKey's `undetermined` carries.
    mlav_blocks = models.BooleanField(null=True)

    class Meta:
        ordering = ["security_profile", "protocol"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "protocol"],
                name="integrations_unique_decoder_per_profile_protocol"),
        ]

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.protocol}: {self.effective_action}"


class SecurityProfileApplicationOverride(models.Model):
    """One per-application action override on an antivirus profile.

    WHY THIS EXISTS. PAN-AVW-001 asserts that every decoder stops the transfer, and a decoder
    action is NOT the last word: this node overrides it for a named application. A profile can
    read `reset-both` on all seven decoders and still allow malware over a named application,
    and a control that walked only `decoder` reported such a profile as hardened. Found
    2026-10-08 by enumerating the profile's key set with `action=complete` rather than reading
    a sample - the node was in the config all along and nothing looked at it.

    Measured 2026-10-08 on pan-fw-111 by writing each candidate shape:

    **The key is a REFERENCE to an application, and eligibility is ENFORCED at the write.**
    The completion offers 1454 of the device's 5552 predefined applications, and an entry
    naming one outside that set is refused - `ping 'ping' is not a valid reference`, code=12 -
    as is an application that does not exist. So the offered set is the real set and not a UI
    convenience, which is a stronger result than confirming a dropdown by clicking it.

    **An entry with NO action is accepted and stores an absent action.** An entry with an
    EMPTY action element is refused, `action is invalid`. So absent and empty are different
    here, and only one of them is reachable.

    **The literal `default` is accepted**, as it is on a decoder - but it does NOT mean the
    same thing. A decoder's `default` resolves to one action per protocol; an exception's
    resolves per SIGNATURE. Measured 2026-10-09 - see `blocks`.
    """

    #: The same seven values as a decoder's action, enumerated 2026-10-08, and enforced at the
    #: write: `action 'wibble' is not an allowed keyword`, code=12.
    ACTIONS = ("default", "allow", "alert", "drop", "reset-client", "reset-server",
               "reset-both")

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="application_overrides")
    #: As the config names it, which is a predefined application name.
    application = models.CharField(max_length=128)
    #: What the config holds. BLANK where the entry carries no action at all, which the device
    #: accepts and which is read as `allow` - the same rule as an absent decoder action.
    configured_action = models.CharField(max_length=32, blank=True)
    #: Does this override stop the transfer?
    #:
    #: NULL means NO SINGLE BOOLEAN IS TRUE OF IT, and it is reserved for the literal
    #: `default`, whose meaning here was MEASURED 2026-10-09.
    #:
    #: An exception's `default` resolves PER SIGNATURE. Two profiles carrying the same eleven
    #: `default` exceptions and differing only in their decoders - one at `default`, one
    #: explicitly INVERTED - render the bare word on all 22 rows and agree with each other.
    #: That rules out inheriting the decoder (they would disagree), the per-protocol table and
    #: a single fixed value (either would bracket). The same export brackets the decoder
    #: column in the same row, so the absence is real and not a rendering limit. Help p.272
    #: says the same: a signature's default action is the one it ships with.
    #:
    #: NOT the same mechanism as a DECODER's `default`, which does resolve to one action per
    #: protocol. Same word, same screen, two behaviours - carrying the decoder's resolution
    #: across would have been wrong.
    #:
    #: It stays null and the control REPORTS it, for a better reason than not knowing: a
    #: signature's own default is typically alert or reset-both, so an exception left at
    #: `default` lets whatever the alerting signatures catch through.
    blocks = models.BooleanField(null=True)

    class Meta:
        ordering = ["security_profile", "application"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "application"],
                name="integrations_unique_app_override_per_profile_application"),
        ]

    @property
    def label(self) -> str:
        """`app (action)` for a finding row, naming the absent and unresolved cases."""
        if not self.configured_action:
            return f"{self.application} (no action set, which allows)"
        if self.blocks is None:
            return f"{self.application} (default - each signature's own action)"
        return f"{self.application} ({self.configured_action})"

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.application}: {self.configured_action}"


class SecurityProfileWildfireRule(models.Model):
    """One match rule of a WildFire analysis profile - what gets sent for sandbox analysis.

    PAN-AVW-003's content. Measured 2026-10-09 on pan-fw-111 (PA-VM 11.2.3).

    **The kind has NO ACTION ANYWHERE.** A rule has exactly four keys - `application`,
    `file-type`, `direction`, `analysis` - enumerated against a profile that does not exist, so
    the answer is schema rather than local membership. Nothing decides what HAPPENS to a file;
    the rules decide only whether it is sent and where. So the allow/alert/reset-both vocabulary
    every antivirus question is phrased in does not apply here at all, and a control that
    assumed a shared shape across profile kinds would be asking a question this node cannot
    answer.

    **A profile that analyses NOTHING is valid configuration.** Measured by writing each shape:
    a profile with no `rules` node, one with an empty `rules` node, and a rule carrying only a
    name are all accepted. So no rows is a real state and it means nothing is submitted - the
    same trap as an antivirus profile with no decoder node, and the reason the control asks
    about the rule rather than only about the rules it finds.

    **`direction` and `analysis` stay ABSENT when not written.** The UI fills `both` and
    `public-cloud` when a rule is added through the form, so an operator-created rule always
    carries them, but the API accepts a rule with neither and stores neither. What the device
    DOES with an absent direction is NOT established - no instance exists to read and the UI
    cannot show a value that is not there - so `covers_both_directions` is null in that case
    rather than guessed.
    """

    #: Measured 2026-10-09 by writing each one: 12 real types plus `any`. The device refuses
    #: anything else - `file-type 'x' is not a valid reference`, code=12 - so this is the whole
    #: set on 11.2.3. It comes from the content release, so a consumer reads what is stored
    #: rather than validating against this tuple.
    FILE_TYPES = ("apk", "archive", "email-link", "eml", "flash", "jar", "linux", "MacOSX",
                  "ms-office", "pdf", "pe", "script")
    ANY = "any"
    DIRECTIONS = ("upload", "download", "both")
    ANALYSIS = ("public-cloud", "private-cloud")

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="wildfire_rules")
    name = models.CharField(max_length=64)
    #: Member lists, stored as given. `["any"]` is the passing case and is NOT normalized away
    #: - an engineer looking at a finding needs to see what the rule actually says.
    applications = models.JSONField(default=list, blank=True)
    file_types = models.JSONField(default=list, blank=True)
    direction = models.CharField(max_length=16, blank=True)
    analysis = models.CharField(max_length=16, blank=True)

    #: Derived at normalization because the search layer cannot look inside a JSON list.
    covers_all_file_types = models.BooleanField(default=False)
    covers_all_applications = models.BooleanField(default=False)
    #: NULL where `direction` is absent: the device stores nothing and nothing establishes what
    #: it then does, so this is unestablished rather than false.
    covers_both_directions = models.BooleanField(null=True)

    class Meta:
        ordering = ["security_profile", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "name"],
                name="integrations_unique_wildfire_rule_per_profile"),
        ]

    @property
    def label(self) -> str:
        """What a finding says about this rule, in the UI's own column order."""
        types = ", ".join(self.file_types) or "(none)"
        apps = ", ".join(self.applications) or "(none)"
        where = self.direction or "(direction not set)"
        return f"{self.name}: {types} / {apps} / {where}"

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.name}"


class SecurityProfileInlineDetector(models.Model):
    """One inline cloud-analysis detector on an anti-spyware or vulnerability profile.

    PAN-SPY-004 and PAN-VLN-003. Advanced Threat Prevention's deep-learning engines, which
    judge live traffic rather than waiting for a signature.

    **controls.json POINTS BOTH CONTROLS AT THE WRONG NODE.** It names
    `cloud-inline-analysis/enabled`; writing that is refused with `cloud-inline-analysis is
    invalid` (code=12) on 11.2.3-h3 with ATP licensed - measured 2026-10-10. The real node is
    `mica-engine-spyware-enabled` / `mica-engine-vulnerability-enabled`, entry-keyed by
    detector. That is what the corpus DESCRIBES - "unknown C2 (Cobalt Strike, Empire-style
    beacons)" and "SQLi, command injection" - just not where it points. Deviation recorded in
    control-changes.json; Jason approved building against the real node 2026-10-10.

    **THE TWO KINDS ARE NOT ONE SHAPE**, which is why `action_values` is per kind rather than
    a single constant:

        spyware         5 detectors   action has SIX values, including `drop`
        vulnerability   2 detectors   action has FIVE, no `drop`

    Spyware entries also carry `local-deep-learning`, which vulnerability entries do not.

    **The detector names come from the CONTENT release**, the same rule as the antivirus ML
    models, so nothing here hardcodes them - the catalogue is read from the profiles in the
    build.
    """

    #: Measured 2026-10-10 by completing the container on a profile that does not exist, so
    #: these are the key SPACE rather than one device's membership.
    SPYWARE_DETECTORS = (
        "HTTP Command and Control detector", "HTTP2 Command and Control detector",
        "SSL Command and Control detector", "Unknown-TCP Command and Control detector",
        "Unknown-UDP Command and Control detector",
    )
    VULNERABILITY_DETECTORS = ("SQL Injection", "Command Injection")
    #: `drop` is spyware-only.
    SPYWARE_ACTIONS = ("alert", "allow", "drop", "reset-both", "reset-client", "reset-server")
    VULNERABILITY_ACTIONS = ("alert", "allow", "reset-both", "reset-client", "reset-server")
    #: Actions that stop the traffic rather than logging it. Same set the decoders use, minus
    #: `block-ip` which this node does not offer.
    BLOCKING_ACTIONS = frozenset({"drop", "reset-client", "reset-server", "reset-both"})

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="inline_detectors")
    #: As the content release names it.
    name = models.CharField(max_length=128)
    #: What the config holds. BLANK where the profile does not mention this detector, which
    #: is itself the finding - the same rule as an unmentioned antivirus ML model.
    configured_action = models.CharField(max_length=32, blank=True)
    #: Does the detector run at all? An unmentioned detector does not.
    enabled = models.BooleanField(default=False)
    #: Does it STOP the traffic, or only log it? `alert` runs and does not block, exactly as
    #: `enable(alert-only)` does on an antivirus ML model - and that distinction is why these
    #: are two booleans rather than one.
    blocks = models.BooleanField(default=False)

    class Meta:
        ordering = ["security_profile", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "name"],
                name="integrations_unique_inline_detector_per_profile"),
        ]

    @classmethod
    def detectors_for(cls, kind: str) -> tuple[str, ...]:
        return {SecurityProfile.KIND_SPYWARE: cls.SPYWARE_DETECTORS,
                SecurityProfile.KIND_VULNERABILITY: cls.VULNERABILITY_DETECTORS}.get(kind, ())

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.name}: {self.configured_action or '(unset)'}"


class SecurityProfileMlModel(models.Model):
    """One WildFire Inline ML model of an antivirus profile, and whether it is on.

    PAN-AVW-002's subject. Three things make it awkward, and all three are measured:

    **The model names come from the CONTENT release, not from PAN-OS.** controls.json says so
    and says to enumerate them on the target version before automating. So nothing here hardcodes
    them: the catalogue is read from the PREDEFINED profile, which carries every model the
    device knows about. On the lab that is eight - Windows Executables, PowerShell Script 1,
    PowerShell Script 2, Executable Linked Format, MSOffice, Shell, OOXML, MachO - and a
    content update that adds a ninth adds it here with no code change.

    **An absent model means DISABLED**, the same way an absent decoder action means `allow`.
    Measured 2026-10-07: a profile written with no `mlav-engine-filebased-enabled` node at all
    renders every model as `disable (for all protocols)` in the UI. So a profile that says
    nothing about ML does no ML, and a row is synthesized for every model in the catalogue
    rather than only for the ones the config names.

    **The shipped profile is STRONGER than a hand-made one here**, which is the reverse of the
    usual direction: the predefined `default` enables every model, and a profile created through
    the UI without touching anything writes `disable` for every one. An admin who builds their
    own profile to be careful ends up with less inline ML than if they had left the shipped one
    alone.
    """

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="ml_models")
    #: THREE values, enumerated from the device with action=complete on 2026-10-08:
    #: `enable`, `enable(alert-only)` and `disable`. The middle one is why this model carries
    #: two booleans rather than one - a model set to alert-only RUNS, and does not BLOCK, and a
    #: single `enabled` flag has to misreport one of those.
    ACTIONS = ("enable", "enable(alert-only)", "disable")
    RUNS = ("enable", "enable(alert-only)")
    BLOCKS = "enable"

    #: As the content release names it. Not an enum - see the class docstring.
    name = models.CharField(max_length=128)
    #: The engine runs at all: `enable` or `enable(alert-only)`.
    enabled = models.BooleanField()
    #: It stops the file rather than logging it: `enable` alone. What PAN-AVW-002 asserts, and
    #: what the corpus names for both its minimum and its preferred value.
    blocks = models.BooleanField(default=False)
    #: What the config held, for an engineer looking for the line to change. Blank where the
    #: profile does not mention this model at all, which is itself the finding.
    configured_action = models.CharField(max_length=32, blank=True)

    class Meta:
        ordering = ["security_profile", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "name"],
                name="integrations_unique_ml_model_per_profile"),
        ]

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.name}: {'on' if self.enabled else 'off'}"


class SecurityProfileSeverityVerdict(models.Model):
    """Whether one profile blocks one threat severity, and why not when it does not.

    A SATELLITE rather than columns on the profile, because the verdict is the one part of a
    security profile that is KIND-SPECIFIC. Anti-spyware and vulnerability profiles are an
    ordered list of rules matching on severity, so "does this block critical" is a question they
    answer. An antivirus profile has no such rules - it has per-protocol decoders - and a column
    that can only say yes or no would have to say NO about it, which reads as "critical threats
    are not blocked" when the truth is that the profile makes no claim in those terms.

    With the verdict here, a profile that does not answer simply has no row, and
    `SecurityProfile` is left holding only what every profile kind shares: a name, a scope, a
    precedence, whether it is predefined, and who references it. That is what lets the other
    seven profile kinds under /config/predefined/profiles - antivirus, URL filtering, file
    blocking, WildFire analysis, decryption, SCTP and SD-WAN path quality - become rows without
    a model each.

    The verdict itself is unchanged and still order-independent: see SecurityProfile's docstring.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    SEVERITY_CHOICES = [(CRITICAL, "Critical"), (HIGH, "High"), (MEDIUM, "Medium")]

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="severity_verdicts")
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES)
    blocked = models.BooleanField()
    #: WHY it is not blocked - the tab has to say so, because two profiles failing one severity
    #: can fail it for different reasons (an alert rule, or no catch-all rule at all).
    detail = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["security_profile", "severity"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "severity"],
                name="integrations_unique_verdict_per_profile_severity"),
        ]

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.severity}: {'blocked' if self.blocked else 'not blocked'}"


class SecurityProfileGroup(ScopedPolicyObject):
    """Objects > Security Profile Groups. Modelled because it is how profiles reach rules: on the
    lab every Panorama-shared rule protection arrives through a group, and a predefined profile
    counts as used when a group names it. Not assessed itself."""

    #: Computed here: referenced but never defined. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE, related_name="security_profile_groups")
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE, related_name="security_profile_groups",
        null=True, blank=True)
    appliance_group = models.ForeignKey(
        ApplianceGroup, on_delete=models.CASCADE, related_name="security_profile_groups",
        null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="security_profile_groups")

    spyware_profile = models.CharField(max_length=255, blank=True)
    vulnerability_profile = models.CharField(max_length=255, blank=True)
    #: Every profile type the group names, `{type: [names]}` - antivirus, URL filtering and the
    #: rest are read here so their controls do not need a second walk. Not searchable.
    members = models.JSONField(default=dict, blank=True)
    raw_group = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "name", "precedence_rank"]),
            models.Index(fields=["appliance_group", "name", "precedence_rank"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_group_per_point_namespace",
            ),
            models.UniqueConstraint(
                fields=["appliance_group", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_group_per_group_namespace",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.owner} / {self.namespace_key} / {self.name}"
