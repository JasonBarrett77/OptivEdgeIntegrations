"""Device > Setup > Management > General Settings, the banner pair - PAN-MGT-007 and 008.

The third cluster cut out of `DeviceConfigurationProfile`. Two fields, and they are one object
rather than two settings: the acknowledgement checkbox is GREYED OUT until a banner exists,
measured 2026-09-01, so `acknowledgement_required` is uninterpretable without `text` and a model
holding one without the other would invite a control that reads it alone.

NOT the "Banners and Messages" section, which is a different part of the same screen and holds
the Message of the Day, the header and footer banners and their colours. None of that is
normalized and no control reads it, so it is absent here rather than nulled.

`text` is the banner itself and can be paragraphs. It is stored whole: PAN-MGT-007 asks whether
there IS one, but an assessor reading the finding needs to see what it says, and a length or a
boolean would answer the control while destroying the evidence.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class LoginBanner(ProvenancedMixin, SyncTrackedModel):
    """The management login banner on one appliance, and whether it must be acknowledged."""

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="login_banners")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="login_banners")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="login_banners", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="login_banners")

    #: PAN-MGT-007. Empty means no banner, which is the finding - not missing data.
    text = models.TextField(blank=True)
    #: PAN-MGT-008. Implicit NO, and unsettable while `text` is empty.
    acknowledgement_required = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_login_banner_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} login banner"
