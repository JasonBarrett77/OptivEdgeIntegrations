"""Two security-policy models whose subject is not a rule.

`PolicyRuleSettings` is ONE ROW PER APPLIANCE, read from `deviceconfig/setting/management` -
the two device-wide switches PAN-POL-011 and PAN-POL-013 rest on.

`VsysRulePosture` is ONE ROW PER ENFORCEMENT POINT, and every column on it is a verdict taken
over the `SecurityRule` rows of that point rather than over a payload. It follows
`RulebaseDeviceMatchVerdict` in shape and diverges from it in one way that matters: that model
writes NO ROW for a point with no merged snapshot, and this one writes a row with
`rules_collected` false. The reason is the subject itself - three of nine vsys on
013201001475 have no `rulebase/security/rules` node at all and each one still ENFORCES the two
rules PAN-OS ships, so "this vsys has no policy" is the answer these controls exist to give and
a missing row cannot give it.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from ..base import SyncTrackedModel
from ..provenance import ProvenancedMixin


class PolicyRuleSettings(ProvenancedMixin, SyncTrackedModel):
    """The device-wide policy-rule switches at `deviceconfig/setting/management`.

    ONE ROW PER APPLIANCE, which on an HA pair is TWO ROWS FOR ONE REAL CONFIGURATION with
    nothing downstream deduplicating them. That is the same stretch `LoggingSettings` carries
    and it is not cosmetic: the node has no vsys axis, the two peers' management containers have
    been measured differing while config sync reported synchronized, and a difference between
    peers is therefore DATA rather than a normalization fault.

    BOTH COLUMNS ARE NULLABLE AND NULL IS THE FIRING SIDE. Neither key's absence has been
    measured, and the two controls are written so that NULL MATCHES: PAN-POL-013 asserts the
    counter is READ as on rather than assumed on, and PAN-POL-011 asserts the shadow check is
    read as running. Storing `False` for an absent key would be inventing a vendor default from
    the key's name, and for `disable-shadow-rule-check` the name is a NEGATIVE - so the guess
    would land on the reassuring side of a control whose evidence the key suppresses.
    """

    #: Nothing here is derived: both columns read a real key and carry a provenance row saying
    #: whether it was present, template-supplied or absent. `is_missing` is the mixin's own.
    DERIVED_FIELDS = ("is_missing",)

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="policy_rule_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="policy_rule_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="policy_rule_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="policy_rule_settings")

    #: The device's own `rule-hit-count` key. TRUE means the firewall is counting how often each
    #: rule is matched, which is the only thing that makes a rule reading as unused mean
    #: anything. MEASURED 2026-10-29: `yes` on 013201001475 (supplied by template
    #: `ptpl_fw-core-tpa`, so the container carries `@ptpl`/`@src`) and `no` on
    #: 691665AC334B458, with no marker. NULL where the key is absent, which stage 4 found on all
    #: four lab appliances before stage 6 wrote these two leaves.
    rule_hit_count_enabled = models.BooleanField(null=True, blank=True)

    #: The device's own `disable-shadow-rule-check` key, WITH THE DEVICE'S OWN POLARITY KEPT:
    #: TRUE means the check has been SUPPRESSED. The polarity is recorded here explicitly
    #: because silence is what lets a normalizer store the opposite of the truth in a column a
    #: control then grades. A device with this set reports zero shadow warnings for exactly the
    #: same reason a clean device does, which is why the control reads it as `is not false`.
    disable_shadow_rule_check = models.BooleanField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="integrations_unique_policy_rule_settings_per_appliance",
            ),
        ]
        indexes = [models.Index(fields=["management_station", "appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} policy rule settings"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError(
                "Policy rule settings must belong to the same management station as the "
                "appliance.")


class VsysRulePosture(ProvenancedMixin, SyncTrackedModel):
    """One enforcement point's verdicts about what its whole policy does and does not do.

    Every column is a statement about the ABSENCE of a rule somebody should have written, which
    is why they are verdicts over the point's stored `SecurityRule` rows rather than values on
    any one rule. A rule set is THREE reads and not one - the firewall-local vsys rulebase, the
    Panorama pre- and post-rulebases pushed to it, and the vendor's two predefined default rules
    - so the verdict is taken over the stored rows, which carry all three with `config_source`
    telling them apart, rather than over a payload this model would have to re-read.

    `rules_collected` IS THE LOAD-BEARING COLUMN. Without it a vsys nobody collected would
    answer false to every existence verdict below it and report as missing every rule it was
    supposed to have - a full set of findings raised on an empty set of rows. It is false until
    a rulebase read has answered, and it fires.

    NO SCOPE COLUMN, and the consequence is a remediation one, the same as
    `RulebaseDeviceMatchVerdict`'s: the row cannot say which of the three rulebases an absence
    spans, so an estate whose policy is pushed from Panorama would be told to edit a vsys
    rulebase the firewall will not accept rules into. The distinction IS stored, on
    `SecurityRule.config_source`; joining back to it is a presentation question.
    """

    #: EVERY column is computed at normalization and no payload key carries any of them, so none
    #: can have a provenance row. Nothing is tracked on this model by design.
    DERIVED_FIELDS = (
        "is_missing",
        "rules_collected",
        "has_logged_catch_all_deny",
        "default_rules_log_session_end",
        "has_application_block_rule_above_permits",
        "vendor_hostile_list_block_directions_missing",
        "expresses_geographic_boundary",
        "has_prestaged_blocklist_rule",
        "has_port_matched_block_rule",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="vsys_rule_postures")
    enforcement_point = models.ForeignKey(
        "integrations.EnforcementPoint", on_delete=models.CASCADE,
        related_name="vsys_rule_postures")
    #: NULLABLE, unlike every other `source_snapshot` in this package, and the null is the
    #: point: a vsys with no merged snapshot has had no rulebase read at all, which is exactly
    #: the state `rules_collected` false records. Requiring the FK would mean no row, and no row
    #: is the one answer this subject may not give.
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="vsys_rule_postures", null=True, blank=True)

    #: Whether a rulebase read answered for this vsys at all. FALSE IS THE REPORTABLE STATE and
    #: it is what keeps every verdict below from reading as a clean vsys. An absent rulebase node
    #: is REAL and not rare: on both PA-5220s, vsys7, vsys8 and vsys10 had no
    #: `rulebase/security/rules` node, and such a vsys still enforces the two predefined rules.
    rules_collected = models.BooleanField(default=False)

    #: Whether some rule with a blocking action, an open match tuple and `log-end` true is
    #: evaluated after every permitting rule in this vsys - PAN-POL-010. FALSE until the pass has
    #: run, and false is also the real answer for a vsys nobody wrote a catch-all into.
    has_logged_catch_all_deny = models.BooleanField(default=False)

    #: Whether the two rules PAN-OS ships record the sessions they refuse in this vsys.
    #:
    #: THIS IS WHERE A VENDOR SELF-CONTRADICTION LANDS and the device settled it ASYMMETRICALLY.
    #: The Help says both things about the same two fields: p.134 "enabled by default" and p.142
    #: "cleared by default". MEASURED on 013201001475 vsys6: both default rules' Actions tabs
    #: render Log at Session End UNTICKED while an ordinary rule in the same grid storing no log
    #: key renders it TICKED - so p.142 is right about `log-end` on these two rules and WRONG
    #: about `log-start`, which it calls "selected by default" and which renders unticked.
    #:
    #: FALSE on an unrecomputed row, which fires, and false is also the measured truth for a
    #: vsys whose override node is absent - which is every vsys in this lab.
    default_rules_log_session_end = models.BooleanField(default=False)

    #: Whether some rule with a blocking action and a non-`any` application list sits above
    #: every permitting rule whose application set it intersects - PAN-POL-007.
    #:
    #: ANY BLOCKING ACTION SATISFIES IT. The action field has six members of which four block
    #: and differ only in what the sender is told, so a rulebase that blocks with a silent
    #: `drop` satisfies the intent even though it does not match the literal `deny`.
    has_application_block_rule_above_permits = models.BooleanField(default=False)

    #: How many of the two directions - traffic TO those addresses and traffic FROM them - have
    #: no standing rule blocking the vendor's own hostile-address lists in this vsys. 0, 1 or 2.
    #:
    #: A COUNT rather than two booleans because the control asserts both directions and the
    #: severity turns on how many are missing. TWO on an unrecomputed row, which is the worst
    #: band; a zero would report every vsys as fully protected before anything looked.
    #:
    #: THE LIST NAMES ARE NOT A VALUE SET HERE, deliberately: the ten the lab offered came from
    #: ONE appliance of three, the Help prints no slug for any of them, and the configurable
    #: list object has five type branches of which none is the predefined kind - so there is no
    #: path to create one and the remediation is to reference a list the device already has.
    vendor_hostile_list_block_directions_missing = models.PositiveSmallIntegerField(default=2)

    #: Whether this vsys's policy says anything about geography at all - a rule naming a region
    #: on either address side, with either polarity of action - PAN-POL-018.
    #:
    #: FALSE FIRES, and the direction is the whole argument: nothing in the configuration
    #: distinguishes a deliberate decision not to geo-block from nobody having considered it,
    #: and a missing reading reported as compliant is a customer told they are safe on nothing.
    expresses_geographic_boundary = models.BooleanField(default=False)

    #: Whether a standing address-blocklist rule a responder could edit under pressure is
    #: already in place - a blocking rule naming an address group or external list on a side and
    #: evaluated above the permitting rules. Without one, the first thing a responder does in an
    #: incident is write a new rule and get it approved and committed.
    has_prestaged_blocklist_rule = models.BooleanField(default=False)

    #: Whether this vsys carries any rule that refuses traffic by matching on the PORT - a
    #: blocking rule whose service list names a service object or group rather than `any` or
    #: `application-default`. WHICH services must be blocked is the estate's decision; this
    #: answers only whether the mechanism exists at all. The device ships service objects for
    #: HTTP and HTTPS and for nothing else, so every other port needs an object the customer
    #: builds.
    has_port_matched_block_rule = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point"],
                name="integrations_unique_vsys_rule_posture_per_point",
            ),
        ]
        indexes = [models.Index(fields=["management_station", "enforcement_point"])]

    def __str__(self) -> str:
        return f"{self.enforcement_point} rule posture"

    def clean(self) -> None:
        if self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError(
                "Vsys rule posture must belong to the same management station as the "
                "enforcement point.")
