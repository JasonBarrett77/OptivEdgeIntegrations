"""Current normalization health.

Distinct from `IntegrationEvent`, and deliberately so. The event log records **what
happened** and is append-only; this records **what is currently wrong**, and is replaced
on every run exactly like the objects it describes.

That difference is the whole point. A health indicator has to clear itself when a clean
run happens — with an append-only log it never would, and answering "is anything wrong
right now?" would mean joining to the latest run per point, a query that gets slower as
history accumulates and runs on every page load. Replacing the rows per owner makes the
question an EXISTS.

Both are worth having. The event log answers "what happened during that sync"; this
answers "can I trust the data I am looking at".
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import TimestampedModel
from .collected import ApplianceGroup, EnforcementPoint, ManagementStation


class NormalizationIssue(TimestampedModel):
    """One object that could not be normalized cleanly.

    Owned the same way the objects themselves are — an enforcement point for vsys-scoped
    work, an appliance group for shared-scoped work — so a run can replace an owner's
    issues in the same pass that replaces its objects, and neither can go stale relative
    to the other.
    """

    class Severity(models.TextChoices):
        ERROR = "error", "Error"
        WARNING = "warning", "Warning"

    class Disposition(models.TextChoices):
        SKIPPED = "skipped", "Skipped"
        KEPT = "kept", "Kept"

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="normalization_issues",
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="normalization_issues",
        null=True,
        blank=True,
    )
    appliance_group = models.ForeignKey(
        ApplianceGroup,
        on_delete=models.CASCADE,
        related_name="normalization_issues",
        null=True,
        blank=True,
    )

    #: What kind of object - "address object", "address group", "region".
    kind = models.CharField(max_length=64)
    #: Empty when the entry had no @name; that is itself the problem.
    name = models.CharField(max_length=255, blank=True)

    #: Whether the state should be possible. See PolicyObjectIssue for why this is
    #: independent of disposition: a duplicate is an error that is nonetheless kept.
    severity = models.CharField(max_length=16, choices=Severity.choices)
    #: What was actually done - whether the object exists downstream or not.
    disposition = models.CharField(max_length=16, choices=Disposition.choices)

    reason = models.TextField()
    #: Which payload node and which read it came from, for locating it by hand.
    node = models.CharField(max_length=64, blank=True)
    source = models.CharField(max_length=64, blank=True)
    #: The offending entry, because a name and a reason rarely explain a payload problem.
    raw_entry = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["severity", "kind", "name", "id"]
        indexes = [
            # The health indicator asks only "does a row exist"; these keep that cheap.
            models.Index(fields=["management_station", "severity"]),
            models.Index(fields=["enforcement_point", "severity"]),
            models.Index(fields=["appliance_group", "severity"]),
        ]

    def __str__(self) -> str:
        return f"{self.severity}: {self.kind} {self.name or '(unnamed)'}"

    @property
    def owner(self):
        return self.enforcement_point or self.appliance_group

    def clean(self) -> None:
        owner_count = int(self.enforcement_point_id is not None) + int(self.appliance_group_id is not None)
        if owner_count != 1:
            raise ValidationError(
                "A normalization issue belongs to exactly one owner: the enforcement point "
                "whose vsys-scoped work produced it, or the appliance group whose "
                "shared-scoped work did."
            )
