"""Network hardening - PAN-NET-002 to PAN-NET-007's subjects.

FIVE MODELS, FOUR GRAINS, and the grains are the decisions in this file:

`PanOsSessionSettings` and `PanOsLldpGlobalSettings` are ONE ROW PER APPLIANCE. Both sit
on device-wide singleton nodes - `deviceconfig/setting/config`, `deviceconfig/setting/session`
and `network/lldp` - so a finding about either names the appliance and not a vsys, an
interface or a rule. They are two models and not one because they are two screens and two
findings: "LLDP is on firewall-wide" is not something a reader would look for on the
Session panel.

`PanOsDhcpInterfaceConfig` is ONE ROW PER INTERFACE PER APPLIANCE, and a row exists ONLY
where `network/dhcp/interface` carries an entry for that interface. The passing state for
PAN-NET-004 therefore needs no row at all: the finding names the configuration that should
not be there, not the port.

`PanOsTunnelInspectionCoverage` is ONE ROW PER APPLIANCE PER SCOPE PER VSYS and is a
VERDICT over a rulebase rather than a row per rule. The commonest failing state is that NO
RULE EXISTS - measured as the state of every vsys in the lab bar three - and a per-rule row
cannot report it, because there is no row.

`PanOsRoutingAdjacency` is ONE ROW PER ADJACENCY within one router within one appliance.
The protocol is part of the identity because a BGP peer and an OSPF attachment can carry
the same name and are different things.

ALL FIVE PRODUCE A ROW PER HA NODE, not per pair. The merged configuration is read per
appliance and the pair is synchronised, so two rows describe one real configuration and
nothing downstream deduplicates them - the same convention `Interface` and
`ManagementInterface` already follow, and for the reason `models/interfaces.py:17-24`
gives: these models have no appliance-group bridge, so "this peer holds nothing" would be
indistinguishable from "this peer was never normalized".

WHICH COLUMNS CARRY A `FieldProvenance` ROW. Only the ones that read a payload key:
`session_rematch`, `ipv6_firewalling`, `lldp_global_enable`, `dhcp_server_mode`,
`dhcp_relay_ipv4_enabled`, `tunnel_acceleration`, `bgp_authentication_profile`,
`ospf_authentication_profile` and `max_prefixes`. Everything else is computed and is
DECLARED in `DERIVED_FIELDS`, which is what `provenance_for()` answers from; declaring
them is the only thing that separates "we worked this out" from "nothing tracks this
field".

NULLABILITY IS NOT UNIFORM HERE AND THE RULE IS NOT COSMETIC. A text or integer column
whose absence a control compares is non-nullable, because the search layer has no is-null
operator and SQL answers every positive comparison over a NULL with no match - a reading
that must FIRE would silently pass. `null=True` is used only where stage 5 declared that
nothing is to be stored AND its own `when_unknown` records that no clause rests on the
column: `link_state`, `dhcp_server_mode` and `max_prefixes` are display-and-input columns
read by the verdict beside them, never by a clause. The three nullable BOOLEANS
(`session_rematch`, `dhcp_relay_ipv4_enabled`, `lldp_global_enable`) are the cases where
stage 5 measured no implicit value and storing a guess would decide a control off nothing;
see each one's own comment for what that costs a query.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class PanOsSessionSettings(ProvenancedMixin, SyncTrackedModel):
    """One appliance's Device > Setup > Session settings.

    TWO SIBLING CONFIG NODES, ONE ROW. `rematch` lives under
    `deviceconfig/setting/config` and `ipv6-firewalling` under
    `deviceconfig/setting/session`; both are device-wide and both appear on the one screen
    an engineer opens, so splitting them would give a reader two rows for one panel.

    The two columns carry OPPOSITE provenance on purpose and that is the point of tracking
    it here: `ipv6_firewalling` holds a MEASURED vendor default, so an absent key records
    `pan_os_default`, while `session_rematch` holds nothing at all and records
    `not_configured`. Without the rows a materialised `yes` and an unmeasured null render
    identically.
    """

    #: Only the row's own anchors. Both value columns read a payload key and carry a
    #: provenance row. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = ("is_missing",)

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="pan_os_session_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="pan_os_session_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="pan_os_session_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="pan_os_session_settings")

    #: Whether the firewall re-evaluates running sessions against policy when a policy
    #: change is committed. True means withdrawing a rule withdraws the access it granted;
    #: false means every connection open at the time keeps it until it ends by itself.
    #:
    #: NULL IS THE HONEST VALUE FOR AN ABSENT KEY AND IT IS NOT FREE. The vendor says this
    #: is enabled by default and says so twice, and nobody has measured it: `show session
    #: info` carries about sixty dataplane settings and no rematch field, `show system
    #: state filter *rematch*` answers NO_MATCHES on all four lab appliances, and `show
    #: session rematch` reports whether a rematch has EXECUTED rather than the setting. So
    #: nothing is stored. What that costs: a clause testing `session_rematch is not true`
    #: matches no NULL row, so an appliance whose key is absent reads as compliant, and
    #: the control's second query is what has to catch it.
    session_rematch = models.BooleanField(null=True, blank=True)

    #: Whether session-level inspection of IPv6 traffic is on. False means the firewall
    #: ignores every IPv6 rule it holds wherever it routes.
    #:
    #: NON-NULLABLE WITH A MEASURED DEFAULT OF TRUE, which is the reassuring side, and the
    #: licence is that the device's own dataplane says so: with the key absent `show
    #: session info` reports ipv6-fw True, with `no` committed it reports False, and with
    #: the leaf deleted again it reports True - measured on 6A9C0A9904E7D6E 2026-10-26.
    #: The provenance row beside it is what tells a reader the stored `true` came from an
    #: absent key rather than from a configured `yes`.
    ipv6_firewalling = models.BooleanField(default=True)

    #: `deviceconfig/setting/session/tcp-reject-non-syn`. Whether this appliance rejects TCP
    #: segments that are not the opening of a session, device-wide - THE NODE A ZONE PROTECTION
    #: PROFILE'S `global` POINTER RESOLVES TO, and the half of PAN-ZON-006's answer that no
    #: profile row carries.
    #:
    #: ADDED BY THE `zone-dos-protection` DOMAIN, WHICH DECLARED A `SessionSettings` MODEL OF ITS
    #: OWN. It is a column here instead, by ruling P374a - one model per PAN-OS node - because
    #: this class already owns `deviceconfig/setting/session` for `ipv6_firewalling`, which is
    #: PAN-NET-005's subject in the same container. Stage 5 named that collision itself without
    #: drawing the conclusion: its own note says `ipv6-firewalling` is "PAN-NET-005's subject in
    #: the same container - a shared container and a different subject".
    #:
    #: NON-NULLABLE WITH A MEASURED DEFAULT OF TRUE, and TRUE IS THE COMPLIANT SIDE - the
    #: uncomfortable combination, and the default is correct anyway. Measured, 2026-10-25 on
    #: pan-fw-201 (PA-VM 11.2.5), as a natural experiment needing no writes plus a two-direction
    #: control: the node has never existed on this appliance and `show session info` answers
    #: `tcp-nonsyn-rej: True`; written `no` and committed it moved to False; deleted and
    #: committed it returned to True, with the per-zone dataplane report moving in step both
    #: times. Stage 4's own words are that a collector reporting "not configured" here would be
    #: reporting the OPPOSITE of what the firewall does.
    #:
    #: WHAT MAKES THE REASSURING DEFAULT SAFE IS THAT NO CONTROL CLAUSES ON THIS COLUMN. The
    #: assertion clauses on `ZoneProtectionProfile.non_syn_reject_effective`, which is derived
    #: from this column AND from the profile's own three-valued pointer and whose own default is
    #: `no` - the FIRING side. So a comparison here reading an uncollected appliance as one that
    #: rejects non-SYN TCP is never the last word. IF A LATER CONTROL EVER CLAUSES ON THIS COLUMN
    #: DIRECTLY IT OWES A COMPANION COLUMN AND AN UNDETERMINED GROUP, and this sentence is the
    #: warning stage 5 asked to be carried.
    #:
    #: A REFUSAL STAGE 4 RECORDED BECAUSE IT LOOKS LIKE EVIDENCE AND IS NOT: writing `global`
    #: here - the third keyword the PROFILE's same-named leaf accepts - was ACCEPTED AT THE WRITE
    #: and never committed, because that batch's commit was refused for an unrelated reason. So
    #: whether commit validation rejects `global` on a <yes|no> leaf IS NOT ESTABLISHED, and the
    #: normalizer must not assume this column can only ever come from the two values: anything
    #: that is not `yes` reads false, which is the firing side of the resolution above.
    tcp_reject_non_syn = models.BooleanField(default=True)

    class Meta:
        ordering = ["appliance__hostname"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="integrations_unique_session_settings_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} session settings"


class PanOsLldpGlobalSettings(ProvenancedMixin, SyncTrackedModel):
    """One appliance's device-wide LLDP setting - the Network > LLDP screen.

    One leaf, one row, and the row exists wherever a merged configuration was read, so
    that an appliance whose `network/lldp` node is ABSENT is distinguishable from one that
    was never collected. The node is absent on 6A9C0A9904E7D6E and was absent on all four
    lab appliances before 2026-10-27.
    """

    DERIVED_FIELDS = ("is_missing",)

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="pan_os_lldp_global_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="pan_os_lldp_global_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="pan_os_lldp_global_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="pan_os_lldp_global_settings")

    #: The device-wide LLDP enable. True means the protocol is running firewall-wide and
    #: is one checkbox away from announcing on any port anyone adds later; false means it
    #: is switched off once, globally, which is PAN-NET-003's preferred state.
    #:
    #: NULL FOR AN ABSENT NODE, because what the absence MEANS is unmeasured in both
    #: directions: it could mean the protocol is globally enabled by default, in which
    #: case the preferred value is unmet everywhere, or globally disabled, in which case
    #: the per-interface keys are moot. The one piece of evidence - zero frames
    #: transmitted on three interfaces that also store `enable: no` individually - is
    #: consistent with either reading. Guessing would decide the control for every
    #: appliance in an estate off nothing.
    #:
    #: WHAT THE NULL COSTS A QUERY, named because the obvious reach does not work: `is
    #: empty` is the only operator in the search layer that is about absence and it is a
    #: TEXT operator compiling to `filter(field="")`, so it cannot reach a NULL on a
    #: boolean column. An appliance that has never touched the setting is therefore not
    #: selectable by any single clause over this column.
    lldp_global_enable = models.BooleanField(null=True, blank=True)

    class Meta:
        ordering = ["appliance__hostname"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="integrations_unique_lldp_global_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} LLDP global"


class PanOsDhcpInterfaceConfig(ProvenancedMixin, SyncTrackedModel):
    """One interface's DHCP server and relay configuration on one appliance.

    THE ROW'S EXISTENCE IS THE FINDING'S SUBJECT. `network/dhcp/interface` holds an entry
    only where somebody configured DHCP on that port, so a firewall with no DHCP produces
    no rows - which is PAN-NET-004's passing state and needs no representation. The entry's
    name is an INTERFACE name rather than an operator-chosen label, so two entries of one
    name would mean two DHCP configurations on one interface and the namespace is
    effectively the platform's port list.

    THE ABSENCE OF THE CONTAINER IS NOT DISTINGUISHABLE FROM A PATH NOBODY READ, measured:
    an appliance with no DHCP and a collector that skipped `network/dhcp` both produce
    nothing. For this control that is the direction that produces SILENCE rather than a
    firing default, and no column on this model can carry it - a reading about whether the
    container was fetched has no row to live on when no row exists.
    """

    MODE_ENABLED = "enabled"
    MODE_AUTO = "auto"
    MODE_DISABLED = "disabled"
    MODE_CHOICES = [
        (MODE_ENABLED, "Enabled"),
        (MODE_AUTO, "Auto"),
        (MODE_DISABLED, "Disabled"),
    ]

    RELAY_RELAYING = "relaying"
    RELAY_CONFIGURED_AND_OFF = "configured_and_off"
    RELAY_NOT_CONFIGURED = "not_configured"
    RELAY_STATE_CHOICES = [
        (RELAY_RELAYING, "Relaying"),
        (RELAY_CONFIGURED_AND_OFF, "Configured, every switch off"),
        (RELAY_NOT_CONFIGURED, "Not configured"),
    ]

    #: Computed here: the server branch's EXISTENCE, which is not a value any key holds,
    #: and the relay verdict across both address families. See
    #: ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "dhcp_server_configured",
        "dhcp_relay_state",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="pan_os_dhcp_interface_configs")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="pan_os_dhcp_interface_configs")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="pan_os_dhcp_interface_configs", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="pan_os_dhcp_interface_configs")

    #: The interface this DHCP configuration is attached to - the entry's own name, and
    #: what a finding prints as its subject.
    interface_name = models.CharField(max_length=64)

    #: Whether this interface carries a DHCP SERVER branch at all, in any mode. The
    #: branch's EXISTENCE is what PAN-NET-004's first half asserts against; the mode only
    #: decides how bad it is. `server` and `relay` are independent siblings, so the
    #: absence of one asserts nothing about the other.
    dhcp_server_configured = models.BooleanField(default=False)

    #: `server/mode`, verbatim - enabled, auto or disabled - read as how little has to
    #: change before the server starts handing out addresses. `auto` is an ENABLED server
    #: with a back-off and not a safe middle setting: the vendor says it "enables the
    #: server and disables it if another DHCP server is detected on the network".
    #:
    #: NULL WHERE THE KEY IS ABSENT. Nobody has established whether `mode` is MANDATORY on
    #: a bare server branch, so nothing is assumed: two of the three values ENABLE the
    #: server and a guess would be a guess about whether an unconfigured branch serves
    #: addresses. Nullable is safe here only because no clause compares this column - the
    #: assertion rests on `dhcp_server_configured`, whose answer does not depend on the
    #: mode, and this column grades the severity.
    dhcp_server_mode = models.CharField(
        max_length=8, choices=MODE_CHOICES, null=True, blank=True)

    #: `relay/ip/enabled` - the IPv4 family's switch, and ONE family only. The IPv6 family
    #: is a separate and independent switch.
    #:
    #: NULL WHERE THE KEY IS ABSENT, for the same reason as the mode above: nothing
    #: establishes what an absent `enabled` on a configured relay branch does, and a relay
    #: that is configured and silently assumed off is the reassuring direction on a
    #: control about relays that should not exist. The verdict column beside it is what
    #: the assertion rests on, and it treats a configured-and-unknown relay as configured.
    dhcp_relay_ipv4_enabled = models.BooleanField(null=True, blank=True)

    #: What this interface's relay configuration amounts to ACROSS BOTH address families,
    #: as one token. The two families are independent switches, so a reading that tests
    #: one has answered for neither - which is why this is a verdict and not the
    #: `relay/ip/enabled` key.
    #:
    #: THE DEFAULT IS THE WORST MEMBER, DELIBERATELY. A row written before the recompute
    #: pass reads `relaying` and over-reports; the alternative, `not_configured`, would
    #: pass every pre-existing row in silence.
    dhcp_relay_state = models.CharField(
        max_length=24, choices=RELAY_STATE_CHOICES, default=RELAY_RELAYING)

    class Meta:
        ordering = ["appliance__hostname", "interface_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "interface_name"],
                name="integrations_unique_dhcp_interface_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.interface_name} DHCP"

    def clean(self) -> None:
        """A mode cannot be stored for a branch that does not exist."""
        if self.dhcp_server_mode and not self.dhcp_server_configured:
            raise ValidationError(
                "dhcp_server_mode cannot be set where no DHCP server branch exists.")


class PanOsTunnelInspectionCoverage(ProvenancedMixin, SyncTrackedModel):
    """One enforcement point's tunnel inspection coverage, as a verdict over its rulebase.

    THE GRAIN IS AGAINST THE ENTRY GRAIN DELIBERATELY. An absent tunnel-inspect rulebase
    is PAN-NET-006's FAILING state - the one object in this domain whose absence fires
    rather than passes - and a per-rule row cannot report it, because there is no rule. An
    engineer fixing it does not open a rule either: the rule they need does not exist.

    THREE IDENTITY COLUMNS AND ONE OF THEM IS A SCOPE, because a vsys's coverage can come
    from its own rulebase or from a Panorama device group and the two are different
    answers about the same vsys. `scope` says which config subtree the rules came from and
    NOT who owns it.

    WHAT THIS MODEL CANNOT SAY, and it is the reading most likely to be mistaken for one it
    can: whether any tunnel actually transits this firewall. That is traffic and not
    configuration, so no column holds it and the verdict fires on a vsys with no policy
    whether or not a tunnel has ever crossed it. The counters that LOOK like an answer are
    not one - `num-gtpu-active` and `num-active` read zero on all four lab appliances, so
    zero there is "nothing is happening" rather than "no tunnels traverse this firewall".
    """

    SCOPE_VSYS = "vsys"
    SCOPE_DEVICE_GROUP = "device-group"
    SCOPE_CHOICES = [
        (SCOPE_VSYS, "Vsys"),
        (SCOPE_DEVICE_GROUP, "Device group"),
    ]

    #: Worst first, which is the order the normalizer walks. The last four of stage 3's
    #: ranks are NOT REACHABLE FROM CONFIGURATION - `protocol_subset`, `zone_pair_gap`,
    #: `single_level_only` and `overlay_id_scoped` each need to know what actually
    #: transited, which is a person's answer - and neither is `fully_opened`, which is the
    #: claim that everything transiting IS opened. They are members so that a later stage
    #: handed the traffic answer has somewhere to put it; a configuration-only normalizer
    #: writes only the three it can establish.
    STATE_NO_POLICY = "no_policy"
    STATE_ALL_RULES_DISABLED = "all_rules_disabled"
    STATE_PROTOCOL_SUBSET = "protocol_subset"
    STATE_ZONE_PAIR_GAP = "zone_pair_gap"
    STATE_SINGLE_LEVEL_ONLY = "single_level_only"
    STATE_OVERLAY_ID_SCOPED = "overlay_id_scoped"
    STATE_UNVERIFIED = "coverage_unverified_without_traffic_answer"
    STATE_FULLY_OPENED = "fully_opened"
    COVERAGE_STATE_CHOICES = [
        (STATE_NO_POLICY, "No tunnel inspection policy"),
        (STATE_ALL_RULES_DISABLED, "Every rule disabled"),
        (STATE_PROTOCOL_SUBSET, "Only some tunnel protocols"),
        (STATE_ZONE_PAIR_GAP, "Zone pairs not covered"),
        (STATE_SINGLE_LEVEL_ONLY, "One level of encapsulation only"),
        (STATE_OVERLAY_ID_SCOPED, "Scoped to named overlay identifiers"),
        (STATE_UNVERIFIED, "Coverage unverified without a traffic answer"),
        (STATE_FULLY_OPENED, "Fully opened"),
    ]

    #: Computed here: the row's address, a count over entries, a did-we-collect-it flag and
    #: the coverage verdict. `tunnel_acceleration` is the one column that reads a key, and
    #: it carries a provenance row. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "tunnel_inspect_rule_count",
        "tunnel_inspect_rules_collected",
        "tunnel_inspection_coverage_state",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="pan_os_tunnel_inspection_coverages")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="pan_os_tunnel_inspection_coverages")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="pan_os_tunnel_inspection_coverages", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="pan_os_tunnel_inspection_coverages")

    #: Which config subtree this row's rules came from. It says which copy a reader is
    #: looking at and NOT who owns it: a pushed rulebase is device-group scope with a
    #: Panorama owner, and the two axes are separate.
    scope = models.CharField(max_length=16, choices=SCOPE_CHOICES, default=SCOPE_VSYS)
    #: The vsys this verdict is about - the enforcement point a finding names alongside
    #: the appliance. A vsys name is not unique across devices, so the row carries both.
    vsys_name = models.CharField(max_length=64)

    #: How many tunnel inspection rules this enforcement point holds at this scope. ZERO
    #: is the state PAN-NET-006's worst rank describes and it is also what an uncollected
    #: rulebase reads as, which is why the flag beside it exists.
    tunnel_inspect_rule_count = models.PositiveIntegerField(default=0)

    #: Whether the rulebase was actually READ for this enforcement point, as against read
    #: and found empty. The did-we-collect-it signal, and it is REPORTED rather than
    #: claused on: an applicability clause on a column like this one SUPPRESSES the
    #: control when the answer is no, which reads as careful and is the exact inversion of
    #: what the pipeline requires. The count's firing default already covers the case.
    tunnel_inspect_rules_collected = models.BooleanField(default=False)

    #: Whether the appliance performs tunnel acceleration. Device-wide rather than per
    #: vsys, so every row of one appliance carries the same value.
    #:
    #: IT MATTERS IN THE OPPOSITE DIRECTION FROM MOST SETTINGS: where acceleration is on
    #: the vendor says a GTP-U inspection rule is NOT required, so true is the state that
    #: narrows the assertion. An absent node means ENABLED - measured as a natural
    #: experiment on three appliances across two platforms and two major versions, all of
    #: which hold no node and all of which report `tunnel-accel: True` in `show session
    #: info`, against 6A9C0A9904E7D6E which stores `no` and reports False.
    tunnel_acceleration = models.BooleanField(default=True)

    #: How much of the transiting tunnel traffic this policy opens, as one token. Every
    #: value other than `fully_opened` names traffic crossing the firewall that policy
    #: never sees. The default is the worst member and FIRES, which is both the prescribed
    #: direction and the truth for this estate.
    tunnel_inspection_coverage_state = models.CharField(
        max_length=48, choices=COVERAGE_STATE_CHOICES, default=STATE_NO_POLICY)

    class Meta:
        ordering = ["appliance__hostname", "scope", "vsys_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name"],
                name="integrations_unique_tunnel_coverage_per_scope"),
        ]
        indexes = [models.Index(fields=["appliance", "scope"])]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.scope}:{self.vsys_name} tunnel inspection"

    def clean(self) -> None:
        """A count cannot be claimed for a rulebase nobody read, and a vsys-scoped row has
        to name its vsys - the store's own rule, which nothing enforces at write time."""
        if not self.vsys_name:
            raise ValidationError("A tunnel inspection coverage row must name its vsys.")
        if self.tunnel_inspect_rule_count and not self.tunnel_inspect_rules_collected:
            raise ValidationError(
                "tunnel_inspect_rule_count cannot be non-zero where the rulebase was "
                "never collected.")


class PanOsRoutingAdjacency(ProvenancedMixin, SyncTrackedModel):
    """One dynamic routing adjacency on one appliance - what carries authentication.

    The row is the thing an engineer opens to attach authentication or a prefix ceiling.
    NOT the router and NOT the authentication profile: a profile is reusable, and
    reporting it once would understate how many adjacencies are unauthenticated.

    FOUR PROTOCOLS, ONE MODEL, AND NO `kind` DISCRIMINATOR. A BGP peer and an OSPF
    attachment can carry the same name and are different things, so `protocol` is part of
    the identity; it is a plain column rather than a kind because this model's rows span
    bgp, ospf, ospfv3 and rip and a kind assumes one value per subject.

    WHAT NO READ RETURNS, and it is the thing the control is really about: the key. The
    authentication secret and the OSPF password are encrypted-text and cannot be read back
    from the firewall at all, so whether a key is unique to an adjacency or shared across
    sites is unanswerable from any read. That is an engineer's question and no column here
    pretends to it.

    ONLY THE LEGACY ROUTING ENGINE IS WALKED. `network/logical-router` - the Advanced
    Routing Engine's tree - holds no instance on any of the four lab appliances and the
    engine is off everywhere, so a walk of it would be code measured against nothing. The
    normalizer raises a NormalizationIssue where that tree holds an entry rather than
    reading it wrongly in silence; `routing_engine` is what says which tree a reader
    should have been looking at.
    """

    PROTOCOL_BGP = "bgp"
    PROTOCOL_OSPF = "ospf"
    PROTOCOL_OSPFV3 = "ospfv3"
    PROTOCOL_RIP = "rip"
    PROTOCOL_CHOICES = [
        (PROTOCOL_BGP, "BGP"),
        (PROTOCOL_OSPF, "OSPFv2"),
        (PROTOCOL_OSPFV3, "OSPFv3"),
        (PROTOCOL_RIP, "RIP"),
    ]

    ENGINE_LEGACY = "legacy"
    ENGINE_ADVANCED = "advanced"
    ENGINE_UNKNOWN = "unknown"
    ENGINE_CHOICES = [
        (ENGINE_LEGACY, "Legacy"),
        (ENGINE_ADVANCED, "Advanced Routing Engine"),
        (ENGINE_UNKNOWN, "Unknown"),
    ]

    #: WEAKEST FIRST, which is the order a grading reads. Two members are not reachable on
    #: the legacy engine and the reason is measured: `weaker_inner_attachment` needs an
    #: area-wide profile to be overridden and there is NO per-area authentication node on
    #: this engine, confirmed on four appliances; `authenticated_and_encrypted` is
    #: OSPFv3's ESP branch, which no lab instance exercises. `explicitly_disabled` has no
    #: key behind it either - nothing measured says how authentication is turned off as
    #: against never attached.
    STRENGTH_NONE = "none"
    STRENGTH_EXPLICITLY_DISABLED = "explicitly_disabled"
    STRENGTH_WEAKER_INNER = "weaker_inner_attachment"
    STRENGTH_CLEARTEXT = "cleartext_password"
    STRENGTH_WEAK_DIGEST = "weak_digest"
    STRENGTH_STRONG_DIGEST = "strong_digest"
    STRENGTH_AUTHENTICATED_ENCRYPTED = "authenticated_and_encrypted"
    STRENGTH_CHOICES = [
        (STRENGTH_NONE, "None"),
        (STRENGTH_EXPLICITLY_DISABLED, "Explicitly disabled"),
        (STRENGTH_WEAKER_INNER, "Weaker inner attachment"),
        (STRENGTH_CLEARTEXT, "Cleartext password"),
        (STRENGTH_WEAK_DIGEST, "Weak digest"),
        (STRENGTH_STRONG_DIGEST, "Strong digest"),
        (STRENGTH_AUTHENTICATED_ENCRYPTED, "Authenticated and encrypted"),
    ]

    LIMIT_NO_CEILING = "no_ceiling"
    LIMIT_UNLIMITED = "unlimited"
    LIMIT_WARN_ONLY = "warn_only"
    LIMIT_ENFORCING = "enforcing"
    PREFIX_LIMIT_CHOICES = [
        (LIMIT_NO_CEILING, "No ceiling"),
        (LIMIT_UNLIMITED, "Unlimited"),
        (LIMIT_WARN_ONLY, "Warn only"),
        (LIMIT_ENFORCING, "Enforcing"),
    ]

    #: `unlimited` IS A SENTINEL AND NOT A MAGNITUDE. A present literal that is the
    #: negation of the field's purpose: it means NO PREFIX LIMIT, which for the control is
    #: indistinguishable from not setting one - and it is not the same row state as the key
    #: being absent, because one row has a value and the other has none while both mean
    #: unlimited. It also sorts as a string, so every numeric comparison a query author
    #: reaches for skips it. `prefix_limit_state` is what a clause tests.
    MAX_PREFIXES_UNLIMITED = "unlimited"

    #: Computed here: the row's address, the coalesced authentication reference, the engine
    #: in effect and the two gradings. The three columns that read a key -
    #: `bgp_authentication_profile`, `ospf_authentication_profile` and `max_prefixes` -
    #: carry provenance rows. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "routing_engine",
        "authentication_profile",
        "authentication_strength",
        "prefix_limit_state",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="pan_os_routing_adjacencies")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="pan_os_routing_adjacencies")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="pan_os_routing_adjacencies", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="pan_os_routing_adjacencies")

    #: The routing instance this adjacency belongs to. Part of identity because an
    #: authentication profile resolves WITHIN one router, so the same profile name on
    #: another router is a different object and the same adjacency name on another router
    #: is a different adjacency.
    router_name = models.CharField(max_length=64)
    protocol = models.CharField(max_length=16, choices=PROTOCOL_CHOICES)
    #: The adjacency's own name on the device - a BGP peer's name, or the name of the OSPF
    #: attachment. This is what a finding prints as its subject.
    adjacency_name = models.CharField(max_length=64)

    #: Which routing engine is in effect on this appliance, and therefore which of the two
    #: trees this row's siblings should have come from. Only one engine is in effect at a
    #: time, by the vendor's own statement.
    #:
    #: `unknown` IS THE VALUE FOR AN ABSENT SWITCH AND IT IS NOT DECORATION. The leaf at
    #: `deviceconfig/setting/advance-routing` is absent on all four lab appliances and
    #: `show advanced-routing` is refused on all four with "advanced routing mode is not
    #: enabled", which is consistent with an implicit `no` but is a reading of the
    #: ENGINE's state rather than of the leaf. Nothing clauses on this column; a later
    #: stage using it to pick a tree must read `unknown` as "read both and say so".
    routing_engine = models.CharField(
        max_length=16, choices=ENGINE_CHOICES, default=ENGINE_UNKNOWN)

    #: `protocol/bgp/peer-group/peer/connection-options/authentication`. Empty means the
    #: adjacency is UNAUTHENTICATED: there is no implied profile and no device-wide default
    #: to fall back to, measured as an absence in three config views on four appliances.
    #: Blank and not nullable, so `is empty` - the one operator in the search layer that
    #: is about absence - can reach it.
    bgp_authentication_profile = models.CharField(max_length=64, blank=True)

    #: The OSPFv2 authentication profile this adjacency names, empty where none is
    #: attached. THE ATTACHMENT LEVEL IS THE MEASUREMENT: `action=complete` at an OSPF
    #: area entry returns exactly four children - interface, range, type, virtual-link -
    #: and NO authentication, identically on all four lab appliances, so on this engine
    #: authentication attaches at the area's children and there is no per-area node to
    #: attach it to. Both of those children are read into this column; which one a row
    #: came from is `adjacency_name`.
    ospf_authentication_profile = models.CharField(max_length=64, blank=True)

    #: The authentication profile this adjacency actually uses, whichever protocol it
    #: belongs to - the one column a clause can name without knowing the protocol first,
    #: because the device spells the reference at four different paths and a clause has one
    #: field slot. Empty means unauthenticated.
    #:
    #: THE TWO SOURCE COLUMNS ABOVE KEEP THEIR OWN PROVENANCE and are stored beside this
    #: one, so coalescing throws no measurement away. Declaring only this column would
    #: have demoted both to derived.
    authentication_profile = models.CharField(max_length=64, blank=True)

    #: `protocol/bgp/peer-group/peer/max-prefixes`, as the device stores it - a NUMBER or
    #: the keyword `unlimited`, sharing one leaf, which is why the stored type is text.
    #:
    #: NULL WHERE THE KEY IS ABSENT, which is a configured-ceiling-of-none and is a
    #: different row state from the keyword even though the firewall treats the two the
    #: same. Nothing establishes what an absent `max-prefixes` does - the vendor is
    #: completely silent, `probe.corpus max-prefixes` returning no section across all eight
    #: documents - so nothing is assumed. Nullable is safe only because no clause compares
    #: this column: `prefix_limit_state` is what the grading rests on.
    max_prefixes = models.CharField(max_length=16, null=True, blank=True)

    #: What this adjacency's authentication amounts to, as one token, read from WEAKEST
    #: upward. Where a protocol attaches authentication at more than one level the weakest
    #: attachment in use sets the value, because the vendor documents the narrower
    #: attachment as overriding the wider one. The default is the worst member and fires.
    authentication_strength = models.CharField(
        max_length=48, choices=STRENGTH_CHOICES, default=STRENGTH_NONE)

    #: Whether this BGP peer's ceiling actually REFUSES the routes beyond it. A ceiling
    #: that only raises an alarm and takes the routes anyway is not a ceiling.
    #: `warn_only` IS NOT COMPUTABLE TODAY: the peer's measured key set carries
    #: connection-options and max-prefixes and no key that says whether the limit warns or
    #: stops, so a peer whose ceiling only warns is stored as `enforcing`. The member
    #: exists because the rank does.
    prefix_limit_state = models.CharField(
        max_length=16, choices=PREFIX_LIMIT_CHOICES, default=LIMIT_NO_CEILING)

    class Meta:
        ordering = ["appliance__hostname", "router_name", "protocol", "adjacency_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "router_name", "protocol", "adjacency_name"],
                name="integrations_unique_routing_adjacency_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance", "protocol"]),
            models.Index(fields=["appliance", "router_name"]),
        ]

    def __str__(self) -> str:
        return (f"{self.appliance} / {self.router_name} / {self.protocol} / "
                f"{self.adjacency_name}")

    def clean(self) -> None:
        """The coalesced reference has to agree with whichever per-protocol column fed it.

        A populated `authentication_profile` beside two empty source columns would tell a
        reader an adjacency is authenticated with nothing behind the claim, and the
        grading reads the coalesced one.
        """
        sources = {self.bgp_authentication_profile, self.ospf_authentication_profile}
        if self.authentication_profile and self.authentication_profile not in sources:
            raise ValidationError(
                "authentication_profile must be one of the per-protocol references.")
        if (self.authentication_strength != self.STRENGTH_NONE
                and not self.authentication_profile):
            raise ValidationError(
                "authentication_strength cannot grade an adjacency with no profile.")
