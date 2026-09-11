"""Device > Setup > Management > SSH Management Profiles - what the management SSH server offers.

PAN-MCR-001 and 003's subject. One row per appliance, like `ManagementTlsBinding`: the SSH
server is the device's, and a profile only narrows it.

THE ROW STORES THE EFFECTIVE OFFER, not the profile, because the two differ in measured ways
(2026-09-11, fw-core-tpa-a and -b, 11.1.13-h3):

  - With NO profile bound the device offers a built-in default - which includes
    `diffie-hellman-group14-sha1`, `hmac-sha1` and `umac-64`, and algorithms a profile cannot
    even select (chacha20, curve25519, every `-etm` MAC).
  - A bound profile that sets only SOME lists leaves the others at that default: a ciphers-only
    profile narrowed the ciphers and left KEX and MACs exactly as they were. Absent is the
    default, not empty.
  - A bound profile changes NOTHING until the SSH service restarts. Nothing in the configuration
    records the restart, so this row describes the configured offer; the finding says so.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class ManagementSshSettings(ProvenancedMixin, SyncTrackedModel):
    """The management SSH server's configured offer, on one appliance."""

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="management_ssh_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="management_ssh_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="management_ssh_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="management_ssh_settings")

    #: `deviceconfig/system/ssh/mgmt/server-profile`. Empty means nothing is bound, and the
    #: device offers its built-in default - which is not benign on 11.1.
    profile_name = models.CharField(max_length=64, blank=True)
    #: The name matches a `ssh/profiles/mgmt-profiles/server-profiles` entry. False with a name
    #: set is a dangling binding; the device then offers its default, and so does this row.
    profile_found = models.BooleanField(default=False)

    #: The effective offer, per list: the profile's where it sets one, else the device default.
    #: Display - controls read the flags below.
    ciphers = models.JSONField(default=list, blank=True)
    kex = models.JSONField(default=list, blank=True)
    macs = models.JSONField(default=list, blank=True)
    #: Which lists came from the DEVICE DEFAULT - the remediation differs: bind a profile, or
    #: edit the one bound.
    ciphers_default = models.BooleanField(default=True)
    kex_default = models.BooleanField(default=True)
    macs_default = models.BooleanField(default=True)
    #: True when this appliance's PAN-OS release is one whose default offer was MEASURED. The
    #: default is not in the configuration; for an unmeasured release the 11.1 offer stands in.
    defaults_measured = models.BooleanField(default=False)

    #: PAN-MCR-001: a CBC cipher is offered. None is in the 11.1 default; only a profile adds one.
    offers_cbc_cipher = models.BooleanField(default=False)
    #: PAN-MCR-003: a MAC other than HMAC-SHA2 is offered - `hmac-sha1`, and the default's
    #: `umac-*` and `hmac-sha1-etm`. The corpus minimum restricts integrity to SHA-2.
    offers_weak_mac = models.BooleanField(default=False)
    weak_macs = models.JSONField(default=list, blank=True)
    #: `diffie-hellman-group14-sha1` is offered. It is the corpus MINIMUM for PAN-MCR-002, so
    #: recorded, not asserted on.
    offers_sha1_kex = models.BooleanField(default=False)
    #: A KEX BELOW the corpus minimum - group1-sha1 or group-exchange-sha1. Neither is selectable
    #: in a profile nor in the measured 11.1/11.2 default, so this is false everywhere measured;
    #: it exists so a release that offers one reports rather than passing silently.
    offers_weak_kex = models.BooleanField(default=False)
    #: `hmac-sha2-256` (or its -etm form) is offered - the corpus band for PAN-MCR-003 grades a
    #: profile whose weakest MAC is SHA2-256 as a preferred-state gap.
    offers_sha2_256_mac = models.BooleanField(default=False)

    #: Effective host key. Help p.904: default RSA 2048.
    host_key_type = models.CharField(max_length=8, blank=True, default="RSA")
    host_key_bits = models.PositiveIntegerField(default=2048)
    #: Session rekey triggers. 0 is the default for each: no time-based rekey, the cipher's own
    #: data limit, and 2^28 packets (Help p.905).
    rekey_interval_seconds = models.PositiveIntegerField(default=0)
    rekey_data_mb = models.PositiveIntegerField(default=0)
    rekey_packets_exponent = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_management_ssh_settings_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} management SSH"
