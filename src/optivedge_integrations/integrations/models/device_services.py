"""Device services - PAN-SVC-001, 002, 004, 005, 007 and 009.

Three clusters cut as three models, the same reasoning as `services_settings.py`: each is one
PAN-OS screen, and a model per cluster keeps the address right even when the cluster is small.
`DeviceConfigurationProfile` used to carry NTP, hostname and time zone on one row and was deleted
on 2026-09-11 because no completed control read them - Jason's rule is that such an object comes
back when a control defines it, and these six controls define it.

MEASURED 2026-09-14 against fw-core-tpa-a and fw-core-tpa-b (PA-5220, 11.1.13-h3) and pan-fw-111
(PA-VM, 11.2.3-h3), with `action=complete` for the key sets and the compiled device state for the
effective values. Four facts shaped these models:

  - **`type` is a choice of `static` and `dhcp-client`, and ABSENT MEANS STATIC.** fw-core-tpa-b
    carries no `type` node at all, and its compiled interface state reads `'ip-type': static`
    with `'disable-dhcp': True`, while `show system info` reports `is-dhcp: no`. Absent is
    therefore the safe state rather than an unknown one - the opposite of the usual warning, and
    worth stating because a reader who treats absence as undetermined reports a compliant device.
  - **Addressing mode is MGT-only.** `aux-1` accepts service, mtu, ip-address, netmask,
    default-gateway, speed-duplex and permitted-ip, and completing `aux-1/type` returns
    `code=6 Invalid sequence`. So this is an APPLIANCE fact, not a per-surface one, and it does
    not belong on `ManagementInterface` beside the aux and data-plane rows.
  - **The factory hostname is the MODEL.** Help p.700: "If you don't enter a value, PAN-OS uses
    the firewall model (for example, PA-5220_2) as the default." That makes "left at the factory
    default" decidable against `Appliance.model` rather than a guess at a name pattern.
  - **PAN-OS 11.1/11.2 cannot express SNMP v1.** `snmp-setting/access-setting/version` completes
    to exactly `v2c` and `v3` on both platforms. PAN-SVC-004 is titled "SNMP v3 Only (v1/v2c
    Disabled)"; v1 is not a state this device can be in.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


# ---------------------------------------------------------------------------
# The graded classifications, as TextChoices
#
# EVERY MEMBER NAME AND VALUE BELOW COMES FROM stage5-device-services.json's own `value_set`,
# verbatim. That artifact says of each of them that `value_set.status` has no rung for a
# vocabulary a stage INVENTS - the ladder's members all describe a set the DEVICE offers - and
# records `unmeasured` as the least wrong answer. So none of these is a device vocabulary and
# none should be read as one: they are the stage's restatement of stage 3's severity ranks, and
# the one thing that IS measured about them is which member a device lands on.
#
# THE FIRST MEMBER OF EACH IS THE FIRING ONE and is the Django field default, deliberately: a
# migration creates the column and only normalization fills it, so a migrate-and-reseed without
# a re-normalize must be loud rather than reporting a clean estate - the same reasoning
# `SystemIdentity.hostname_is_factory_default` already carries.
# ---------------------------------------------------------------------------


class TimeSourceInForce(models.TextChoices):
    """Which class of source is actually keeping the clock. PAN-SVC-001's grading."""

    NOT_SYNCHRONISED_OR_NEVER_READ = (
        "not_synchronised_or_never_read", "Not synchronised, or never read")
    #: DELIBERATELY NOT STAGE 3's WORDS. Stage 3 grades "synchronised, but to an address
    #: supplied with the management interface's network lease", and stage 4 measured that NO
    #: instrument on this estate attributes a time server to a lease: `show dhcp client
    #: mgmt-interface-state`'s ntp1/ntp2 members track the CONFIGURATION, not the lease -
    #: re-measured 2026-10-29, where pan-fw-201 (which HAS a configured server) shows `ntp1`
    #: and pan-fw-111 (which has none) shows none, from the same DHCP server. So the readable
    #: distinction is "a source the configuration does not name", which is wider than stage 3's
    #: rank and is the one a column can hold.
    SYNCHRONISED_TO_AN_UNNAMED_SOURCE = (
        "synchronised_to_a_source_the_configuration_does_not_name",
        "Synchronised to a source the configuration does not name")
    SYNCHRONISED_TO_A_CONFIGURED_SERVER = (
        "synchronised_to_a_configured_server", "Synchronised to a configured server")


class ServerAuthenticationMechanism(models.TextChoices):
    """How the configured time servers authenticate. PAN-SVC-002's grading.

    `autokey` IS A DIFFERENT MECHANISM RATHER THAN A WEAKER GRADE of the same one, which is why
    it is its own member: the remediation is not "turn authentication on".
    """

    NONE = "none", "No configured server authenticates"
    SOME_BUT_NOT_ALL = (
        "symmetric_key_on_some_configured_servers_and_not_others",
        "Symmetric key on some configured servers and not others")
    AUTOKEY = "autokey", "Autokey"
    EVERY_SERVER = (
        "symmetric_key_on_every_configured_server", "Symmetric key on every configured server")


class SnmpVersionInForce(models.TextChoices):
    """Which version the agent would answer on. PAN-SVC-004's grading.

    THE FIRST TWO MEMBERS ARE THE TWO STATES `version` CANNOT TELL APART on its own - both read
    `v2c` - and `version_implicit` is the column that separates them.
    """

    V2C = "v2c", "The cleartext version"
    CONFIGURED_WITH_NO_VERSION_RECORDED = (
        "configured_with_no_version_recorded", "Configured with no version recorded")
    V3 = "v3", "The authenticated version"
    NO_AGENT_CONFIGURED = "no_agent_configured", "No agent configured"


class DefaultCommunityExposure(models.TextChoices):
    """Whether a published default credential is live. PAN-SVC-005's grading.

    THE SEVERITY TURNS ON THE DIFFERENCE BETWEEN A MEASURED REFUSAL AND AN ABSENT READING, which
    is why `set_and_reachability_not_established` exists and is the default: an appliance whose
    surfaces have not been walked must not have its credential finding reduced.
    """

    SET_AND_REACHABILITY_NOT_ESTABLISHED = (
        "set_and_reachability_not_established", "Set, and reachability not established")
    SET_AND_A_SURFACE_ACCEPTS_QUERIES = (
        "set_and_a_surface_accepts_queries", "Set, and a surface accepts queries")
    SET_AND_EVERY_SURFACE_REFUSES = (
        "set_and_every_surface_refuses", "Set, and every surface refuses")
    NO_DEFAULT_CREDENTIAL_SET = "no_default_credential_set", "No default credential set"


class HostnamePosture(models.TextChoices):
    """The stored name against the model and against the lease. PAN-SVC-010's grading."""

    NO_NAME_STORED = "no_name_stored", "No name stored"
    STORED_NAME_IS_THE_MODEL = (
        "stored_name_is_the_model_with_a_numeric_suffix",
        "The stored name is the model, with or without a numeric suffix")
    CHOSEN_NAME_THE_LEASE_MAY_REPLACE = (
        "a_chosen_name_on_a_device_that_may_take_its_name_from_the_lease",
        "A chosen name on a device that may take its name from the lease")
    A_CHOSEN_NAME_IN_FORCE = "a_chosen_name_in_force", "A chosen name in force"


class TimezoneOffsetClass(models.TextChoices):
    """The stored zone by what it declares. PAN-SVC-009's grading."""

    NO_ZONE_RECORDED = "no_zone_recorded", "No zone recorded"
    NON_ZERO_OR_SHIFTS = (
        "non_zero_offset_or_shifts_under_a_daylight_rule",
        "Non-zero offset, or shifts under a daylight rule")
    ZERO_TODAY_BUT_NOT_DECLARED = (
        "zero_offset_today_but_not_declared", "Zero offset today, but not declared")
    DECLARES_ZERO_OFFSET = "declares_zero_offset", "Declares zero offset"


class AddressingModePosture(models.TextChoices):
    """The addressing mode by the KIND of platform. PAN-SVC-007's grading.

    `leased_on_a_hardware_appliance` is both the first member and the default because the CLOUD
    member is the one that REDUCES the severity, and nothing in either input says whether a
    virtual appliance is in a public cloud - so an unclassified appliance must not receive the
    reduction.
    """

    LEASED_ON_A_HARDWARE_APPLIANCE = (
        "leased_on_a_hardware_appliance", "Leased, on a hardware appliance")
    LEASED_IN_A_PUBLIC_CLOUD = (
        "leased_on_a_virtual_appliance_in_a_public_cloud",
        "Leased, on a virtual appliance in a public cloud")
    FIXED = "fixed", "Fixed"


class ResolverMechanism(models.TextChoices):
    """Which branch of the dns-setting choice container exists. PAN-SVC-003's input."""

    NONE = "none", "Neither mechanism chosen"
    SERVERS = "servers", "Addresses named directly"
    DNS_PROXY_OBJECT = "dns_proxy_object", "A DNS proxy object this firewall hosts"


class ManagementResolverPosture(models.TextChoices):
    """How the resolvers in force came to be in force. PAN-SVC-003's grading."""

    NONE_ON_A_LEASED_ADDRESS = (
        "no_resolver_chosen_on_a_leased_management_address",
        "No resolver chosen, on a leased management address")
    NONE_ON_A_FIXED_ADDRESS = (
        "no_resolver_chosen_on_a_fixed_management_address",
        "No resolver chosen, on a fixed management address")
    ONE_RESOLVER_ONLY = "one_resolver_only", "One resolver only"
    TWO_OR_MORE = "two_or_more_resolvers_in_force", "Two or more resolvers in force"


class RecordedDecisionReconciliation(models.TextChoices):
    """The organisation's own recorded decision about telemetry, against the device.
    PAN-SVC-008's grading.

    THE ESTATE HAS NO MECHANISM TO INGEST AN ENGINEER'S ANSWER, so this holds its firing default
    on every row until one exists. The three data categories are DELIBERATELY NOT RANKED against
    each other: which of them an organisation accepts IS the decision this control asks to see.
    """

    NO_RECORDED_DECISION_LOCATED = (
        "no_recorded_decision_located", "No recorded decision located")
    DEVICE_CONTRADICTS_IT = (
        "a_recorded_decision_the_device_contradicts", "A recorded decision the device contradicts")
    DEVICE_MATCHES_IT = (
        "a_recorded_decision_the_device_matches", "A recorded decision the device matches")


class ServiceRouteScope(models.TextChoices):
    """Which enforcement point a service-path row is the verdict for.

    SCOPE FOLLOWS THE CONFIG SUBTREE the value came from and never which read returned it.
    """

    DEVICE_LOCAL = "device-local", "The firewall-wide paths"
    VSYS = "vsys", "One virtual system's own set"


class ServicePathPosture(models.TextChoices):
    """PAN-SVC-006's FIRST half: the firewall-wide paths."""

    NO_PATH_SET = (
        "no_path_set_for_a_sensitive_service", "No path set for a sensitive service")
    ONE_FAMILY_ONLY = (
        "a_path_set_for_one_address_family_only", "A path set for one address family only")
    EVERY_SERVICE = (
        "a_path_set_for_every_sensitive_service_naming_interface_and_address",
        "A path set for every sensitive service, naming interface and address")


class PerSystemPathPosture(models.TextChoices):
    """PAN-SVC-006's SECOND half: one virtual system's recorded choice.

    THE DEVICE CANNOT DISTINGUISH A DELIBERATE INHERITANCE FROM AN OMISSION and stage 3 puts
    that in `engineer_supplies`: "the device records the choice and not the reasoning, and on
    this screen the two look identical". The third member therefore covers both, and the column
    beside it records the choice rather than the reasoning.
    """

    NEITHER_RECORDED = (
        "neither_inheritance_nor_a_customised_path_recorded",
        "Neither inheritance nor a customised path recorded")
    SOME_SERVICES_ONLY = (
        "customised_for_only_some_of_the_services_the_system_uses",
        "Customised for only some of the services the system uses")
    DECIDED_EITHER_WAY = (
        "inheriting_deliberately_or_customised_for_every_service_used",
        "Inheriting deliberately, or customised for every service used")



class NtpSettings(ProvenancedMixin, SyncTrackedModel):
    """The two NTP servers and how each is authenticated. PAN-SVC-001 and 002.

    `ntp-servers` holds `primary-ntp-server` and `secondary-ntp-server`, each with an
    `ntp-server-address` and an `authentication-type`. There is no third slot.

    SYNC STATE IS NOT HERE. `show ntp` reports `reachable` and `status: synched` per server, and
    the corpus marks PAN-SVC-001 `live-device-state` for exactly that reason - but it is an
    operational reply, not configuration, and collecting it needs its own snapshot the way
    `MasterKey` has one. What this model asserts is that two servers are CONFIGURED; whether
    they are answering is a separate question this row does not claim to answer.
    """

    #: Computed here: counts and a verdict over the two slots, not keys. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "server_count",
        "all_servers_symmetric_key",
        "unauthenticated_servers",
        # PAN-SVC-001's second half and PAN-SVC-002's grading, added 2026-10-29. The first two
        # rest on `show ntp`, which is OPERATIONAL and not configuration, so neither can carry a
        # FieldProvenance row: there is no payload key for a row to point at.
        "synched_to_a_configured_server",
        "time_source_in_force",
        "server_authentication_mechanism",
    )

    class AuthType(models.TextChoices):
        NONE = "none", "None"
        SYMMETRIC_KEY = "symmetric-key", "Symmetric key"
        AUTOKEY = "autokey", "Autokey"

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="ntp_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="ntp_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="ntp_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="ntp_settings")

    primary_server = models.CharField(max_length=255, blank=True)
    secondary_server = models.CharField(max_length=255, blank=True)
    #: 0, 1 or 2. PAN-SVC-001 grades on this rather than on the two names, because the assertion
    #: is about redundancy and a count is what a threshold compares.
    server_count = models.PositiveSmallIntegerField(default=0)

    primary_auth_type = models.CharField(
        max_length=16, choices=AuthType.choices, default=AuthType.NONE)
    secondary_auth_type = models.CharField(
        max_length=16, choices=AuthType.choices, default=AuthType.NONE, blank=True)
    #: `sha1` or `md5`, the only two PAN-OS offers. Display: no control asserts the algorithm,
    #: because the corpus names the MECHANISM (symmetric-key) as its preferred value and PAN-OS
    #: offers nothing stronger than SHA-1 to choose between.
    primary_algorithm = models.CharField(max_length=8, blank=True)
    secondary_algorithm = models.CharField(max_length=8, blank=True)

    #: PAN-SVC-002's whole assertion: every CONFIGURED server authenticates with a symmetric key.
    #:
    #: False when no server is configured at all, and that is deliberate rather than a default
    #: standing in for missing data - a device with no NTP server has no authenticated time
    #: source, which is what the control is about. PAN-SVC-001 is what reports the absence.
    #:
    #: `autokey` does NOT satisfy it. The corpus preferred value is the literal `symmetric-key`,
    #: and autokey is a different mechanism rather than a stronger grade of the same one.
    all_servers_symmetric_key = models.BooleanField(default=False)
    #: Which configured servers are not on a symmetric key, for the finding sentence.
    unauthenticated_servers = models.JSONField(default=list, blank=True)

    #: PAN-SVC-001's SECOND half: is the clock actually anchored to a server this configuration
    #: names? `show ntp`'s `synched` member against the two slot addresses.
    #:
    #: DEFAULT FALSE FIRES, and that is the point. An appliance whose operational read was never
    #: collected reports "the clock is not anchored to a configured source" rather than passing.
    #: A nullable boolean would read as compliant under SQL and there is no is-null operator to
    #: ask with. Measured 2026-10-29: fw-core-tpa-b has TWO servers, BOTH on a symmetric key,
    #: both `reachable: no, status: rejected`, and `synched: LOCAL` - a configuration that
    #: passes the countable half and is keeping no time at all.
    synched_to_a_configured_server = models.BooleanField(default=False)
    #: PAN-SVC-001's grading, three ranks. The high-severity member is the default, so an
    #: unread appliance sits with the worst case rather than the best.
    #: 64 AND NOT STAGE 5's 48: its own `value_set` member
    #: `synchronised_to_a_source_the_configuration_does_not_name` is 56 characters and
    #: `max_length=48` fails Django's own `fields.E009` before a migration can be written. The
    #: declared length is one of stage 5's PROPOSALS about OEI's schema, so it is checked rather
    #: than adopted; the member list is authoritative and unchanged.
    time_source_in_force = models.CharField(
        max_length=64, choices=TimeSourceInForce.choices,
        default=TimeSourceInForce.NOT_SYNCHRONISED_OR_NEVER_READ)
    #: PAN-SVC-002's grading, four ranks, read PER SERVER and not per device.
    #:
    #: FILLED FROM THE CONFIGURATION'S OWN BRANCH AND NEVER FROM `show ntp`, which MISNAMES it:
    #: measured 2026-10-29 through Panorama, fw-core-tpa-a stores `symmetric-key` on its first
    #: slot and `show ntp` answers `symmetric key` (with a space, not the config token), while
    #: pan-fw-201 stores `autokey` and answers `autokey` - so that command's vocabulary is
    #: neither the configuration's nor stable across builds. It can discriminate authenticated
    #: from unauthenticated and nothing finer.
    #: 64 AND NOT STAGE 5's 48, for the same reason as `time_source_in_force` above:
    #: `symmetric_key_on_some_configured_servers_and_not_others` is 55 characters.
    server_authentication_mechanism = models.CharField(
        max_length=64, choices=ServerAuthenticationMechanism.choices,
        default=ServerAuthenticationMechanism.NONE)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_ntp_settings_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} NTP"


class SnmpSettings(ProvenancedMixin, SyncTrackedModel):
    """SNMP monitoring access. PAN-SVC-004 and 005.

    THE COMMUNITY STRING IS NOT STORED. It is a live credential that grants read access to the
    device's statistics, and both controls answer without its value: 004 asks which version is
    selected, 005 asks whether the string is one of the defaults. So the row carries
    `community_is_default` and `community_set` and the string stays in the snapshot it came from.

    AN UNCONFIGURED DEVICE IS NOT A FINDING. controls.json says it outright - "If SNMP is unused,
    leave snmp-setting unconfigured entirely" - so `is_configured` false is the compliant state
    and both controls read past it. That is the state of all three lab devices today.

    `is_exposed` is resolved across `ManagementService` rows rather than from this subtree,
    because the two halves live apart: `snmp-setting` says how SNMP would answer and
    `disable-snmp` on each surface says whether anything is listening. Measured 2026-09-14,
    `disable-snmp` is implicit YES and no compiled ACL on any lab surface carries `snmp` - so a
    device can hold a v2c community string that nothing can reach. The finding says which it is.
    """

    #: Computed here: verdicts over the snmp-setting node, plus the surface walk. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_configured",
        "uses_v2c",
        # `community_is_default` is NOT here, though it is every bit as computed. Normalization
        # writes it a real provenance row on purpose: the community string's VALUE is never
        # stored, so the row is the only place that says who set the credential - local, or a
        # template, which is what an assessor asks about a secret they can read in a backup.
        # Declaring it derived would hide that answer behind the word "Derived".
        "community_set",
        "version_implicit",
        "v3_user_count",
        "v3_view_count",
        "is_exposed",
        "exposed_surfaces",
        # PAN-SVC-004's and PAN-SVC-005's gradings, added 2026-10-29. All three are computed
        # over the columns above, so there is no payload key for a provenance row to point at.
        "answers_on_an_unauthenticated_version",
        "default_community_exposure",
        "snmp_version_in_force",
    )

    class Version(models.TextChoices):
        V2C = "v2c", "SNMPv2c"
        V3 = "v3", "SNMPv3"

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="snmp_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="snmp_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="snmp_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="snmp_settings")

    #: A `snmp-setting` node exists. Both controls are silent when this is false.
    is_configured = models.BooleanField(default=False)
    #: The effective version. Empty when nothing is configured.
    version = models.CharField(max_length=4, choices=Version.choices, blank=True)
    #: The version was INFERRED rather than read: an `access-setting` with no `version` child.
    #: Help p.740 states the dialog's default is V2c, so that is what is recorded - and the flag
    #: is here because a finding resting on a vendor sentence should say so.
    version_implicit = models.BooleanField(default=False)
    #: PAN-SVC-004's assertion, as one column: SNMP is configured and answers v2c.
    uses_v2c = models.BooleanField(default=False)

    community_set = models.BooleanField(default=False)
    #: PAN-SVC-005's assertion. `public` or `private`, case-insensitively - the two strings the
    #: corpus names and Help p.740 warns about ("Don't use the default community string public").
    #: "Guessable" is the rest of that control's minimum and is not decidable from a string.
    community_is_default = models.BooleanField(default=False)

    v3_user_count = models.PositiveSmallIntegerField(default=0)
    v3_view_count = models.PositiveSmallIntegerField(default=0)

    #: The `snmp` service is enabled on at least one management surface of this appliance.
    is_exposed = models.BooleanField(default=False)
    #: Which surfaces, for the sentence: "mgt", "aux-1", "ethernet1/1".
    exposed_surfaces = models.JSONField(default=list, blank=True)

    #: PAN-SVC-004's failing set as ONE column: on the cleartext version, OR configured with the
    #: version unrecorded.
    #:
    #: THE DISJUNCTION IS WHY IT EXISTS, and the limit is stage 5's clause grammar rather than
    #: the query language: stage 5's `clauses` list is one CONJUNCTION with no OR, and this
    #: control's failing set is a two-member disjunction. A derived verdict column is the escape
    #: its contract sanctions, and it keeps the restatement reviewable in one clause.
    #:
    #: DEFAULT FALSE READS AS COMPLIANT, so this column must be recomputed in the same pass that
    #: adds it: the migration that creates it and the renormalize that fills it are one unit of
    #: work and not two.
    answers_on_an_unauthenticated_version = models.BooleanField(default=False)
    #: PAN-SVC-005's grading, four ranks, and the one that keeps "every surface refuses" apart
    #: from "nobody walked the surfaces". Only the first earns a reduced severity.
    default_community_exposure = models.CharField(
        max_length=48, choices=DefaultCommunityExposure.choices,
        default=DefaultCommunityExposure.SET_AND_REACHABILITY_NOT_ESTABLISHED)
    #: PAN-SVC-004's grading, four ranks.
    snmp_version_in_force = models.CharField(
        max_length=48, choices=SnmpVersionInForce.choices, default=SnmpVersionInForce.V2C)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_snmp_settings_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} SNMP"


class SystemIdentity(ProvenancedMixin, SyncTrackedModel):
    """How the device names itself, keeps time, and gets its management address.
    PAN-SVC-007 and 009.

    Three settings from two screens on one row, which the other models here deliberately avoid -
    so the reason has to be better than convenience, and it is the vendor's own coupling. All
    three are leaves of `deviceconfig/system`, and PAN-OS ties them together explicitly: "Accept
    DHCP server-provided Hostname (Applies only when the Management Interface IP Type is DHCP
    Client) ... The hostname from the server (if valid) overwrites any value specified in the
    Hostname field" (Help p.701). A device whose address comes from DHCP can have its NAME come
    from DHCP too, so splitting them would put one half of that sentence on each of two tabs.
    """

    #: Computed here: comparisons against the model name, UTC, and whether a type node was written. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "hostname_is_factory_default",
        "timezone_is_utc",
        "addressing_mode_explicit",
        # PAN-SVC-007's, 009's and 010's gradings, added 2026-10-29. `hostname_in_force` and its
        # companion rest on `show system info`, which is OPERATIONAL - there is no payload key
        # for a provenance row to point at - and the other four are computed over the columns
        # above them.
        "hostname_in_force_known",
        "hostname_in_force",
        "hostname_posture",
        "timezone_declares_zero_offset",
        "timezone_offset_class",
        "addressing_mode_posture",
    )

    class AddressingMode(models.TextChoices):
        STATIC = "static", "Static"
        DHCP_CLIENT = "dhcp-client", "DHCP client"

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="system_identities")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="system_identities")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="system_identities", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="system_identities")

    hostname = models.CharField(max_length=64, blank=True)
    #: PAN-SVC-010. Help p.700: with no value written, PAN-OS uses the firewall MODEL, "for
    #: example, PA-5220_2" - so this compares the stored name with `Appliance.model` plus an
    #: optional numeric suffix, rather than pattern-matching a name. Also true when the key is
    #: absent, which is the same state by a different spelling.
    #:
    #: DEFAULT TRUE, deliberately: the default is the value that FIRES. A migration creates the
    #: column and only normalization fills it, so a migrate-and-reseed without a re-normalize must
    #: be loud rather than reporting a clean estate. Its sibling `timezone_is_utc` defaults False
    #: for the same reason.
    hostname_is_factory_default = models.BooleanField(default=True)

    timezone = models.CharField(max_length=64, blank=True)
    #: PAN-SVC-009, and the corpus preferred value. `timezone` is a 566-value enum
    #: on both platforms; only one of them needs no offset arithmetic during log correlation.
    timezone_is_utc = models.BooleanField(default=False)

    #: PAN-SVC-007. Empty is not a state: an absent `type` node IS static - measured, see the
    #: module docstring - so this resolves to one of the two choices on every device.
    addressing_mode = models.CharField(
        max_length=16, choices=AddressingMode.choices, default=AddressingMode.STATIC)
    #: False when the `type` node was absent and `static` was resolved from the measurement
    #: rather than read. The control's verdict is the same either way; the tab says which.
    addressing_mode_explicit = models.BooleanField(default=False)
    #: Only meaningful under `dhcp-client`, and that is why they are here rather than dropped:
    #: they are how a DHCP server reaches the hostname this row also assesses.
    accept_dhcp_hostname = models.BooleanField(default=False)
    accept_dhcp_domain = models.BooleanField(default=False)

    #: THE COMPANION THAT MAKES `accept_dhcp_hostname`'s REASSURING DEFAULT ASKABLE, and stage 5
    #: names it in exactly those terms. `accept_dhcp_hostname` is never null, so an appliance
    #: whose dhcp-client container was never collected stores False - "the lease may NOT
    #: overwrite the name" - which tells PAN-SVC-010 that the stored name IS the name in force,
    #: reached without anybody looking. This column is what a report grades on instead: False
    #: means the effective name was never established.
    hostname_in_force_known = models.BooleanField(default=False)
    #: The name the appliance is actually answering to, from `show system info`. On this estate
    #: it equals the stored name and need not.
    #:
    #: EMPTY IS NOT ITSELF A FINDING - the firing column beside it is `hostname_in_force_known`.
    #: A consumer must grade on that boolean and not on this string's emptiness.
    hostname_in_force = models.CharField(max_length=64, blank=True)
    #: PAN-SVC-010's grading, four ranks.
    hostname_posture = models.CharField(
        max_length=64, choices=HostnamePosture.choices, default=HostnamePosture.NO_NAME_STORED)

    #: PAN-SVC-009's ACTUAL predicate, which `timezone_is_utc` beside it is not.
    #:
    #: Stage 3 restated the control as whether the zone DECLARES zero offset rather than whether
    #: it matches one spelling of it, and records that many of the 566 members denote zero
    #: offset - so an appliance on any other zero-offset spelling has logs needing no arithmetic
    #: and `timezone_is_utc` reports it as failing. That column ships, is claused on by the
    #: shipped baseline query, and is SUPERSEDED rather than removed.
    #:
    #: Measured 2026-10-29 on pan-fw-111 (`Atlantic/Reykjavik`, built by stage 6 for exactly
    #: this): zero offset all year, no daylight rule, and not a zero-offset SPELLING - so
    #: `timezone_is_utc` is False and this is False too, and the third class below is what
    #: separates them.
    timezone_declares_zero_offset = models.BooleanField(default=False)
    #: PAN-SVC-009's grading, four ranks.
    timezone_offset_class = models.CharField(
        max_length=64, choices=TimezoneOffsetClass.choices,
        default=TimezoneOffsetClass.NO_ZONE_RECORDED)

    #: PAN-SVC-007's grading, three ranks. The default is the HIGHEST-severity member.
    addressing_mode_posture = models.CharField(
        max_length=64, choices=AddressingModePosture.choices,
        default=AddressingModePosture.LEASED_ON_A_HARDWARE_APPLIANCE)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_system_identity_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} system identity"


class DnsSettings(ProvenancedMixin, SyncTrackedModel):
    """How the MANAGEMENT PLANE resolves names. PAN-SVC-003.

    `deviceconfig/system/dns-setting` is a CHOICE CONTAINER with two branches - `servers`,
    naming up to two addresses, or `dns-proxy-object`, naming a proxy object the firewall hosts
    itself - and a device may hold neither.

    THE FINDING IS NOT WRITABLE FROM CONFIGURATION ALONE, which is the whole shape of this
    model. Measured 2026-10-29 on all four lab appliances: both PA-VMs hold NO `dns-setting`
    node at all, both of their management interfaces are DHCP clients, and `show dhcp client
    mgmt-interface-state` reports `dns-server: 168.63.129.16` on both from the same DHCP server.
    A query reading configuration alone reports them IDENTICALLY to an appliance with no DNS at
    all - so `resolution_follows_the_management_lease` and `management_resolvers_in_force` are
    filled from an operational read, and the posture column is what a clause reaches.

    THE RESOLVER NODE WAS FENCED FOR WRITES AND THAT IS WHY TWO DEFAULTS ARE NOT ASSUMED. Stage
    4's dispatch forbade writing it: the resolvers govern whether the firewall can name anything
    and every read of the Azure appliances goes through Panorama's `target=` proxy, so a wrong
    value cuts the path the next read needs. What a `servers` branch that EXISTS with no
    `primary` does is therefore unobserved, and the two address columns store nothing rather
    than guess.
    """

    #: Computed here: the mechanism, the counts and the posture - not keys.
    #: See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "resolver_mechanism",
        "chosen_resolver_count",
        "resolution_follows_the_management_lease",
        "management_resolvers_in_force",
        "management_resolver_posture",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="dns_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="dns_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="dns_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="dns_settings")

    #: `servers/primary`. Empty means none is configured - which on a DHCP-addressed appliance
    #: does NOT mean the appliance resolves nothing.
    primary_resolver_address = models.CharField(max_length=255, blank=True)
    #: `servers/secondary`. Empty means ONE configured resolver and no fallback, which two of
    #: the four lab appliances... are not even in: they have none at all. fw-core-tpa-b has
    #: exactly this state - a `servers` branch with `primary` and no `secondary`, committed.
    secondary_resolver_address = models.CharField(max_length=255, blank=True)
    #: `dns-proxy-object`. Empty means the firewall is not resolving through a proxy object it
    #: hosts: measured as a natural experiment on all four appliances with no write, INCLUDING
    #: the two that hold a populated `servers` branch in the same pass, which is what makes it a
    #: reading about the branch rather than about the node.
    dns_proxy_object_name = models.CharField(max_length=64, blank=True)
    #: `servers/encrypted-dns`, stored for DISPLAY ONLY - no control in the catalogue asserts
    #: the transport the management plane uses to reach its resolvers.
    #:
    #: THE STORE HAS NO WAY TO SAY "THIS FIELD DOES NOT EXIST ON THIS BUILD", and this is the
    #: field that needs it: `action=complete` at this path answers `code=6 Invalid sequence` on
    #: 11.1.13-h3 and returns three children on 11.2.3-h3 and 11.2.5. `code=6` means NOT VALID
    #: ON THE DEVICE YOU ASKED, so on 11.1 there is no key there to BE absent - schema surface
    #: the build does not implement, not an unset optional key. A consumer must not read an
    #: empty string here on an 11.1 appliance the way it reads one on 11.2.
    encrypted_dns_connection_type = models.CharField(max_length=32, blank=True)

    #: Which branch exists. `none` is a FIRING member and the state two of four lab appliances
    #: are genuinely in.
    resolver_mechanism = models.CharField(
        max_length=32, choices=ResolverMechanism.choices, default=ResolverMechanism.NONE)
    #: How many resolvers the ORGANISATION chose - configured addresses, or the resolvers the
    #: named proxy object resolves through. Zero means nobody chose any, and zero FIRES.
    chosen_resolver_count = models.PositiveSmallIntegerField(default=0)
    #: PAN-SVC-003's sharpest finding: resolving through an address that arrived with the lease
    #: rather than one anybody chose. The state the configuration shows NOTHING of.
    #:
    #: FALSE IS REASSURING TAKEN ALONE, which is why no clause should rest on it: it means only
    #: that nothing established a lease, NOT that the resolvers were chosen. The posture column
    #: is what fires.
    resolution_follows_the_management_lease = models.BooleanField(default=False)
    #: The addresses actually in force, whatever their origin - configured, reached through the
    #: proxy object, or supplied by the lease. Display: a finding must not rest on a JSON column.
    management_resolvers_in_force = models.JSONField(default=list, blank=True)
    #: PAN-SVC-003's grading, four ranks. The default is a firing member.
    management_resolver_posture = models.CharField(
        max_length=72, choices=ManagementResolverPosture.choices,
        default=ManagementResolverPosture.NONE_ON_A_LEASED_ADDRESS)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_dns_settings_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} management resolvers"


class DeviceTelemetry(ProvenancedMixin, SyncTrackedModel):
    """What this firewall shares with its vendor, and whether anybody decided to. PAN-SVC-008.

    TRUE IS THE STATE OF A FIREWALL NOBODY HAS CONFIGURED, and that is the opposite of what the
    vendor's own guide says. Stage 4 measured the absent-key behaviour of all three category
    switches on pan-fw-201 by deleting them and committing (job 178 FIN OK) and reading
    `show device-telemetry settings`, which reads RUNNING: it answered `yes` for the two deleted
    keys and `no` for `threat-prevention`, which was set to `no` in the same commit - one
    instrument, one call, three elements, two states, which is what makes each attributable. A
    second instrument in a second view agreed: the web interface's Telemetry panel carried
    `x-grid3-check-col-on` (ticked) with the keys absent.

    Administrator's Guide p.201 says the reverse VERBATIM - "By default, your device does not
    share data with Palo Alto Networks" - and three instruments on a committed device agree with
    each other against it. Already recorded in OptivEdgeProbe
    `reference/known-vendor-contradictions.md` under `Device telemetry's default`.

    A SECOND MODEL OVER THIS SAME NODE ALREADY EXISTS and is deliberately not reused:
    `platform_lifecycle.py::DeviceTelemetrySettings` stores the same three switches and the
    region for PAN-PLT-003, NULLABLE, from a COMMITTED-local read, with its own stage 4 run
    recording every switch's implicit as unmeasured. This model's stage 4 run measured them and
    they materialise `yes`. The two readings of one node disagree and neither side is this run's
    to overrule, so this model is additive and the overlap is reported rather than reconciled.
    The constraint name says `device_services_telemetry` because the other model already holds
    `unique_device_telemetry_per_appliance`.
    """

    #: Computed here: the delivery state and the reconciliation. The four category columns are
    #: MEASURED and are deliberately out of this tuple, so that normalization writes them real
    #: provenance rows - which is the only place "this value is the vendor's default and not a
    #: choice" is ever recorded. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "telemetry_delivery_state",
        "recorded_decision_reconciliation",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="device_services_telemetry")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="device_services_telemetry")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="device_services_telemetry", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="device_services_telemetry")

    #: `device-health-performance`. DEFAULT TRUE FIRES: an appliance whose telemetry node was
    #: never written reports as SHARING, which is the measured state of both lab PA-VMs.
    shares_device_health_performance = models.BooleanField(default=True)
    #: `product-usage`, which the vendor's own in-product dialog describes as including
    #: CONFIGURATION INFORMATION - and whose implicit value is `yes`.
    shares_product_usage = models.BooleanField(default=True)
    #: `threat-prevention`. The element the key-less witness read set to `no` while its two
    #: siblings were absent, which is what proves the other two are attributable.
    shares_threat_prevention = models.BooleanField(default=True)
    #: `region`, STORED CASE-FOLDED. The device stores and renders it capitalised (`Americas`)
    #: where the completion set is lowercase (`americas`), so a normaliser comparing the stored
    #: value against the vocabulary must fold case - and this column holds the folded form.
    telemetry_region = models.CharField(max_length=16, default="americas", blank=True)

    #: The runtime `status` the device reports, which is not configuration at all. Empty means
    #: the delivery state was never established; nothing clauses on it, and PAN-SVC-008's
    #: finding is about the recorded DECISION.
    #:
    #: THE LAB MAKES THE GAP CONCRETE: measured 2026-10-29, all four appliances report `Device
    #: Certificate does not exist` or `Device Certificate is expired`, while both PA-VMs have
    #: all three categories `yes`. The recorded decision is "share" and the delivery state is
    #: "cannot", and a control reading either half alone reports the opposite of the other.
    telemetry_delivery_state = models.CharField(max_length=64, blank=True)
    #: PAN-SVC-008's grading, and the column no configuration read can fill: whether the
    #: organisation's own recorded decision has been LOCATED, and whether the device matches it.
    recorded_decision_reconciliation = models.CharField(
        max_length=64, choices=RecordedDecisionReconciliation.choices,
        default=RecordedDecisionReconciliation.NO_RECORDED_DECISION_LOCATED)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="unique_device_services_telemetry_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} telemetry decision"


class ServiceRoute(ProvenancedMixin, SyncTrackedModel):
    """Which path each management service leaves by. PAN-SVC-006.

    ONE ROW PER ENFORCEMENT POINT: one for the firewall-wide paths and one per vsys for a
    per-system set, with SCOPE FOLLOWING THE CONFIG SUBTREE the value came from rather than
    which read returned it.

    EVERY COLUMN IS DERIVED AND THAT IS NOT AN OVERSIGHT. The node this model is about -
    `deviceconfig/system/route/service`, and `vsys/entry/route/service` - is ABSENT on all four
    lab appliances and at every vsys of all four, measured 2026-10-29 and twice before. So the
    row is a verdict over an absence, and the thing that makes the verdict mean anything is not
    this node at all: it is `services_originated`, computed from the REST of the configuration.

    THAT COLUMN IS THE DIFFERENCE BETWEEN A FINDING AND NOISE, in stage 4's own terms: a column
    reporting "no path chosen" for 31 services on every appliance in an estate is noise, and one
    reporting it for the services the appliance actually originates is a finding.

    THE SERVICE SETS DIFFER BY BUILD AND BY SCOPE and the delta is three rather than one.
    Measured 2026-10-29 by `action=complete` at both nodes: 32 firewall-wide on the PA-5220, 31
    on the PA-VM, 13 per-vsys on both. The PA-5220 adds `adem` and `panorama-log-forwarding` and
    LACKS `gp-ip-mgmt`. And a corpus claim the device refutes: `paloalto-updates` is given as a
    service identifier and no build offers it - the real one is `paloalto-networks-services`.
    """

    #: EVERY column is computed, including the two identity ones, because the node carries no
    #: key any of them comes from. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "services_originated",
        "services_with_a_chosen_path",
        "every_originated_service_has_a_chosen_path",
        "path_covers_both_address_families",
        "service_path_posture",
        "per_system_path_choice_recorded",
        "per_system_path_posture",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="service_routes")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="service_routes")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="service_routes", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="service_routes")

    #: Half the row's key. NO DEFAULT, deliberately: stage 5 declares this column precisely
    #: because a statement that does not decide the scope produces a silently wrong row.
    scope = models.CharField(max_length=32, choices=ServiceRouteScope.choices)
    #: The other half. Legitimately empty on a device-local row, and the store does NOT enforce
    #: that a vsys-scoped row names a vsys - so the write is what has to know which it is.
    vsys_name = models.CharField(max_length=64, blank=True)

    #: Which management services this enforcement point actually ORIGINATES, from the
    #: configuration that creates each flow - not from the service-route node.
    services_originated = models.JSONField(default=list, blank=True)
    #: How many of those have a path somebody chose: an entry naming BOTH a source interface and
    #: a source address.
    services_with_a_chosen_path = models.PositiveSmallIntegerField(default=0)
    #: False is the finding. FALSE ON A DEVICE THAT ORIGINATES NOTHING WOULD BE VACUOUS, so an
    #: empty originated set reads as true here and the posture column carries the firing default.
    every_originated_service_has_a_chosen_path = models.BooleanField(default=False)
    #: Whether every chosen path that needs both address families names a source for both.
    #:
    #: UNOBSERVED IN EVERY STATE: no appliance has an entry, and no appliance in the lab has
    #: IPv6 on its management interface - `show system info` reports MGT IPv6 Address `unknown`
    #: - so even a permitted write would have measured a family nothing uses. Declared because
    #: stage 3 asserts it in terms, and FALSE because the family with no path silently follows
    #: the default route and a reader checking only the older family reports the newer as fine.
    path_covers_both_address_families = models.BooleanField(default=False)
    #: PAN-SVC-006's FIRST half, three ranks. The default is both the safe direction and the
    #: measured state of all four lab appliances at both scopes.
    service_path_posture = models.CharField(
        max_length=72, choices=ServicePathPosture.choices,
        default=ServicePathPosture.NO_PATH_SET)
    #: Whether this virtual system's choice was RECORDED at all - either inheriting deliberately
    #: or setting its own. False means neither, which the vendor documents as what happens by
    #: omission, and is the measured state of every vsys of every lab appliance.
    per_system_path_choice_recorded = models.BooleanField(default=False)
    #: PAN-SVC-006's SECOND half, three ranks.
    per_system_path_posture = models.CharField(
        max_length=72, choices=PerSystemPathPosture.choices,
        default=PerSystemPathPosture.NEITHER_RECORDED)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name"],
                name="unique_service_route_per_enforcement_point"),
        ]
        indexes = [models.Index(fields=["appliance", "scope"])]

    def __str__(self) -> str:
        where = self.vsys_name or self.scope
        return f"{self.appliance} service paths ({where})"
