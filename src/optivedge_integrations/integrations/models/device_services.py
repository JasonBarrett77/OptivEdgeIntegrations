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

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_system_identity_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} system identity"
