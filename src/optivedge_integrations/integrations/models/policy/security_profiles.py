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
    KIND_CHOICES = [
        (KIND_SPYWARE, "Anti-Spyware"),
        (KIND_VULNERABILITY, "Vulnerability Protection"),
        (KIND_VIRUS, "Antivirus"),
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

    kind = models.CharField(max_length=16, choices=KIND_CHOICES)
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
    def non_blocking_decoders(self) -> list[str]:
        """Protocols this antivirus profile detects malware on without stopping it.

        Reads the resolved action, not the configured one: every decoder of an unedited profile
        says `default`, and on smtp, imap and pop3 that means alert.
        """
        return sorted(d.protocol for d in self.decoders.all() if not d.blocks)

    @property
    def has_non_blocking_decoder(self) -> bool:
        return bool(self.non_blocking_decoders)

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
    configured_wildfire_action = models.CharField(max_length=32, blank=True)
    effective_wildfire_action = models.CharField(max_length=32, blank=True)
    wildfire_blocks = models.BooleanField(default=False)

    class Meta:
        ordering = ["security_profile", "protocol"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "protocol"],
                name="integrations_unique_decoder_per_profile_protocol"),
        ]

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.protocol}: {self.effective_action}"


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
