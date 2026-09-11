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
    """Logging and Reporting Settings. PAN-MGT-011."""

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

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_logging_settings_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} logging settings"
