"""Device > Setup > Management > General Settings > Certificate Expiration Check.

PAN-CRT-001's second subject, and the one device-wide certificate-hygiene setting the firewall
holds. One row per appliance, with no name of its own, so a finding names the appliance.

THE ROW HAS TO EXIST WHETHER THE KEY DOES OR NOT, and that is the whole reason this is a model
rather than a column somewhere convenient: the key is ABSENT on all four lab appliances, so the
commonest state in the estate - and the failing one - is the one where there is nothing to read.
Keyed on the key's presence there would be no row at all for it, and `PAN-CRT-001` would report
nothing for a device nobody had set it on. The same shape `MasterKey` is built in.

WHY NOT A COLUMN ON `AuthenticationSettings`, which already walks this exact node. That would
have been about two units of work against fifteen, and it is refused by that model's own stated
cut rule - "the cut follows the control line rather than the PAN-OS screen". That model is the
administrator AUTHENTICATION settings of one appliance; a certificate-hygiene column on it would
be a certificates-domain control reporting against a model named for something else, and the
next certificate device-wide setting - the alarm-delivery switch stage 3 already names as
uncovered - would land in the same wrong place. The model is named for the CLUSTER rather than
for its one column so that the second one does not need this argument again.

WHAT THE SETTING DOES IS CONTESTED AND NOTHING HERE SETTLES IT. The vendor's Help calls it a
WARNING, twice on one page and word for word in a second edition - "create warning messages when
on-box certificates approach their expiration date" - while the DEVICE's own completion
help-string for the same leaf reads "Check for expired certificates and stop using them". Those
are different behaviours and the contradiction is recorded in OptivEdgeProbe's
`reference/known-vendor-contradictions.md`. The consequence falls on whoever remediates: if the
device's string is accurate, enabling this can DROP a service whose certificate has lapsed.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class CertificateSettings(ProvenancedMixin, SyncTrackedModel):
    """The certificate-hygiene settings of one appliance."""

    #: Nothing here is computed - the one column reads a real key and carries a provenance row
    #: whether the key was present or absent. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="certificate_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="certificate_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="certificate_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="certificate_settings")

    #: `deviceconfig/setting/management/enable-certificate-expiration-check`, with the DEVICE's
    #: polarity: yes means the check is ON.
    #:
    #: Default False, and THE DEFAULT FIRES, which is the right side: measured 2026-10-25 on
    #: pan-fw-201 (PA-VM 11.2.5), the General Settings checkbox renders UNTICKED on an appliance
    #: where the key is absent from the configuration in every view, and the positive control
    #: was paid on the element - written to yes and committed in job 149, the same panel re-read
    #: in the same browser session showed the box TICKED, then deleted and committed in job 150
    #: with the path returning to its first reading.
    #:
    #: The shape a collector actually meets is the PARENT present and the child absent: nobody
    #: reads a single boolean leaf, they read the management node, which carries 46 or 47 other
    #: children with no error and no empty structure to notice.
    expiry_check_enabled = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_certificate_settings_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} certificate settings"
