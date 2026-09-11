"""Device > Master Key and Diagnostics - PAN-CRT-007's subject.

The fourth cluster cut out of `DeviceConfigurationProfile`, and the only one whose values do not
come from the merged configuration at all: the master key is read from `show masterkey
properties`, its own operational command and its own snapshot.

A ROW EXISTS FOR EVERY APPLIANCE even when that snapshot is missing, and its state is then
UNDETERMINED. The alternative - no row - would make PAN-CRT-007 silently report nothing for a
device nobody asked, and "we never asked" must not look like "we asked and it was fine". The
control fires on anything that is not `set`, so undetermined fires, which is the direction the
uncertainty should push.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class MasterKey(ProvenancedMixin, SyncTrackedModel):
    """The master key state on one appliance."""

    #: Read from the reply, not decided here. DEFAULT means the factory key is still in use,
    #: which is what `expire-at` of 0 says; SET means one was configured.
    STATE_DEFAULT = "default"
    STATE_SET = "set"
    STATE_UNDETERMINED = "undetermined"
    STATE_CHOICES = [
        (STATE_DEFAULT, "Factory default"),
        (STATE_SET, "Configured"),
        (STATE_UNDETERMINED, "Undetermined"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE, related_name="master_keys")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="master_keys")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE, related_name="master_keys",
        null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="master_keys")

    state = models.CharField(max_length=16, choices=STATE_CHOICES, default=STATE_UNDETERMINED)
    #: The raw `expire-at`. "0" is what makes the state DEFAULT, so it is kept as evidence for
    #: a verdict that would otherwise have to be taken on trust.
    expires_at = models.CharField(max_length=64, blank=True)
    auto_renew_hours = models.PositiveIntegerField(default=0)
    on_hsm = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_master_key_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} master key"
