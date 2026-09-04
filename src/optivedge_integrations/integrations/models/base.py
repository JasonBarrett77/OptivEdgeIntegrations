"""Shared abstract model types for the integrations app."""


from django.core.exceptions import ValidationError
from django.db import models

from .provenance import ProvenancedMixin


class TimestampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class SyncTrackedModel(TimestampedModel):
    last_synced_at = models.DateTimeField(null=True, blank=True)
    last_sync_run = models.ForeignKey(
        "integrations.IntegrationRun",
        on_delete=models.SET_NULL,
        related_name="%(app_label)s_%(class)ss",
        null=True,
        blank=True,
    )
    is_missing = models.BooleanField(default=False)
    missing_since = models.DateTimeField(null=True, blank=True)

    class Meta:
        abstract = True


class ApplianceScopedObject(ProvenancedMixin, SyncTrackedModel):
    """A named PAN-OS object that may be defined in shared, in a vsys, or shipped predefined.

    Anchored to the APPLIANCE, never to the vsys: the vsys is a property of where the
    definition sits, not a second owner. That follows the rule the whole model layer uses -
    scope follows the config subtree - and it is why `vsys_name` is a string rather than a
    foreign key.

    Was `CertificateScopedModel`, and the name was wrong: the shape is not about
    certificates. Authentication profiles, certificates, certificate profiles, SSL/TLS
    service profiles, the local user database, server profiles and log settings are all
    definable in shared AND under a vsys, measured 2026-09-04. `predefined` is inherited by
    object types that have none, which costs an unused choice and keeps one base.
"""

    #: Where the definition was found. `predefined` is vendor-shipped and read-only; it beats
    #: a same-named shared entry, measured 2026-09-02 — the opposite of the assumption encoded
    #: in policy/base.py, which governs a different object type and is left alone.
    SCOPE_SHARED = "shared"
    SCOPE_VSYS = "vsys"
    SCOPE_PREDEFINED = "predefined"
    SCOPE_CHOICES = [
        (SCOPE_SHARED, "Shared"),
        (SCOPE_VSYS, "Vsys"),
        (SCOPE_PREDEFINED, "Predefined"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="%(class)ss")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="%(class)ss")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="%(class)ss", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="%(class)ss")

    name = models.CharField(max_length=64)
    scope = models.CharField(max_length=16, choices=SCOPE_CHOICES, default=SCOPE_SHARED)
    #: Blank unless scope is vsys. Not a foreign key: the object is anchored to the appliance,
    #: and the vsys is a property of where the definition sits rather than a second owner.
    vsys_name = models.CharField(max_length=64, blank=True)

    class Meta:
        abstract = True

    def __str__(self) -> str:
        where = f"{self.scope}:{self.vsys_name}" if self.vsys_name else self.scope
        return f"{self.appliance} / {where} / {self.name}"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError("Object appliance must belong to the same station.")
        if self.scope == self.SCOPE_VSYS and not self.vsys_name:
            raise ValidationError("A vsys-scoped object must name its vsys.")
        if self.scope != self.SCOPE_VSYS and self.vsys_name:
            raise ValidationError("Only a vsys-scoped object may name a vsys.")
