"""Application-environment metadata for a single-client deployment."""

from __future__ import annotations

from django.core.validators import RegexValidator
from django.db import models

from .base import TimestampedModel


class ApplicationEnvironment(TimestampedModel):
    """Deployment-scoped metadata for the current client engagement."""

    opportunity_number_validator = RegexValidator(
        regex=r"^OP-\d{7}$",
        message='Opportunity number must be in the format "OP-1234567".',
    )

    client_name = models.CharField(max_length=255)
    client_short_name = models.CharField(max_length=64)
    opportunity_number = models.CharField(
        max_length=10,
        unique=True,
        validators=[opportunity_number_validator],
    )
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["client_name", "opportunity_number", "id"]

    def __str__(self) -> str:
        return f"{self.client_short_name} / {self.opportunity_number}"

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)
