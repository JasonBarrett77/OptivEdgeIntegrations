"""Shared abstract model types for the integrations app."""

from django.db import models


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
