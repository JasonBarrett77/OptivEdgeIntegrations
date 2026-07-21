"""IntegrationRun and IntegrationEvent — run history and event log."""

from django.db import models


class IntegrationRun(models.Model):
    SCOPE_STATION = "station"
    SCOPE_APPLIANCE = "appliance"
    SCOPE_CHOICES = [
        (SCOPE_STATION, "Station"),
        (SCOPE_APPLIANCE, "Appliance"),
    ]

    STATUS_RUNNING = "running"
    STATUS_SUCCEEDED = "succeeded"
    STATUS_PARTIAL = "partial"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCEEDED, "Succeeded"),
        (STATUS_PARTIAL, "Partial"),
        (STATUS_FAILED, "Failed"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation",
        on_delete=models.CASCADE,
        related_name="integration_runs",
    )
    run_scope = models.CharField(max_length=16, choices=SCOPE_CHOICES)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"{self.management_station} / {self.run_scope} / {self.status}"


class IntegrationEvent(models.Model):
    LEVEL_INFO = "info"
    LEVEL_WARNING = "warning"
    LEVEL_ERROR = "error"
    LEVEL_CHOICES = [
        (LEVEL_INFO, "Info"),
        (LEVEL_WARNING, "Warning"),
        (LEVEL_ERROR, "Error"),
    ]

    STAGE_COLLECT = "collect"
    STAGE_NORMALIZE = "normalize"
    STAGE_CHOICES = [
        (STAGE_COLLECT, "Collect"),
        (STAGE_NORMALIZE, "Normalize"),
    ]

    # Namespace anchor — every event belongs to a station, always queryable via single FK.
    management_station = models.ForeignKey(
        "integrations.ManagementStation",
        on_delete=models.CASCADE,
        related_name="integration_events",
    )
    # Optional grouping — most events belong to a run, but not required.
    run = models.ForeignKey(
        IntegrationRun,
        on_delete=models.SET_NULL,
        related_name="events",
        null=True,
        blank=True,
    )
    occurred_at = models.DateTimeField(auto_now_add=True)
    level = models.CharField(max_length=16, choices=LEVEL_CHOICES)
    # blank (not null) — empty string for station-scoped events with no pipeline stage.
    stage = models.CharField(max_length=16, choices=STAGE_CHOICES, blank=True)
    reason = models.CharField(max_length=128)
    message = models.TextField()
    # involvedObject — at most one of these should be set per event.
    appliance = models.ForeignKey(
        "integrations.Appliance",
        on_delete=models.SET_NULL,
        related_name="integration_events",
        null=True,
        blank=True,
    )
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup",
        on_delete=models.SET_NULL,
        related_name="integration_events",
        null=True,
        blank=True,
    )
    enforcement_point = models.ForeignKey(
        "integrations.EnforcementPoint",
        on_delete=models.SET_NULL,
        related_name="integration_events",
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ["-occurred_at"]
        indexes = [
            models.Index(fields=["management_station", "-occurred_at"]),
            models.Index(fields=["run", "-occurred_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.management_station} / {self.reason} @ {self.occurred_at}"
