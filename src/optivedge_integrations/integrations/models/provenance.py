"""Field-level provenance tracking for normalized PAN-OS configuration objects."""

from __future__ import annotations

from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.db import models


class ProvenancedMixin(models.Model):
    """Add a GenericRelation to FieldProvenance for any model that tracks provenance."""

    field_provenance = GenericRelation(
        "integrations.FieldProvenance",
        related_query_name="%(app_label)s_%(class)s",
    )

    class Meta:
        abstract = True


class FieldProvenance(models.Model):
    """Provenance record for a single field (or entry) on a normalized configuration object.

    One row per tracked field per object. field_name "__entry__" records the object's
    own entry-level provenance (e.g., the @ptpl on a named PAN-OS entry). Absence of a
    row for a given field_name means the key was absent from the source payload — no
    default value should be inferred.
    """

    class ProvenanceType(models.TextChoices):
        LOCAL        = "local",        "Local"
        TEMPLATE     = "template",     "Template"
        DEVICE_GROUP = "device_group", "Device Group"
        PANORAMA     = "panorama",     "Panorama"
        UNKNOWN      = "unknown",      "Unknown"

    content_type   = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id      = models.PositiveIntegerField()
    content_object = GenericForeignKey("content_type", "object_id")

    field_name       = models.CharField(max_length=64)
    provenance_type  = models.CharField(max_length=32, choices=ProvenanceType.choices)
    raw_key          = models.CharField(max_length=32, blank=True)
    raw_value        = models.CharField(max_length=128, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["content_type", "object_id"]),
            models.Index(fields=["content_type", "object_id", "field_name"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["content_type", "object_id", "field_name"],
                name="integrations_unique_field_provenance_per_field",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.content_type} #{self.object_id} [{self.field_name}] = {self.provenance_type}"
