"""Search-grounding vocabulary models derived from normalized security-rule data."""

from __future__ import annotations

import re

from django.db import models

from ..base import SyncTrackedModel
from ..collected import ManagementStation


class SecurityRuleSearchVocabularyEntry(SyncTrackedModel):
    """Precomputed searchable vocabulary entry for security-rule query grounding."""

    class FieldFamily(models.TextChoices):
        SOURCE_ADDRESS_NAME = "source_address_name", "Source Address Name"
        DESTINATION_ADDRESS_NAME = "destination_address_name", "Destination Address Name"
        APPLICATION = "application", "Application"
        SERVICE = "service", "Service"

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="security_rule_search_vocabulary_entries",
    )
    field_family = models.CharField(max_length=64, choices=FieldFamily.choices)
    canonical_value = models.CharField(max_length=255)
    normalized_value = models.CharField(max_length=255, blank=True)
    compact_value = models.CharField(max_length=255, blank=True)
    rule_count = models.PositiveIntegerField(default=0)
    usage_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["management_station__hostname", "field_family", "-rule_count", "canonical_value", "id"]
        indexes = [
            models.Index(fields=["management_station", "field_family", "normalized_value"]),
            models.Index(fields=["management_station", "field_family", "compact_value"]),
            models.Index(fields=["management_station", "field_family", "rule_count"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["management_station", "field_family", "canonical_value"],
                name="integrations_unique_security_rule_search_vocab_entry",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.management_station} / {self.field_family} / {self.canonical_value}"

    def save(self, *args, **kwargs):
        self.normalized_value = self.normalize_lookup_value(self.canonical_value)
        self.compact_value = self.compact_lookup_value(self.canonical_value)
        super().save(*args, **kwargs)

    @staticmethod
    def normalize_lookup_value(value: str) -> str:
        lowered = value.strip().lower()
        separated = re.sub(r"[^a-z0-9]+", " ", lowered)
        return re.sub(r"\s+", " ", separated).strip()

    @staticmethod
    def compact_lookup_value(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", value.strip().lower())
