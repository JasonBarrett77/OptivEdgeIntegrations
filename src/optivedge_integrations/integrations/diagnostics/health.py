"""Normalization health, as the chrome and the report need it.

Two functions with deliberately different costs:

`has_normalization_errors()` is what the shell indicator asks on every page load. It is an
EXISTS - it stops at the first row and never counts. The indicator is binary on purpose: a
count invites a threshold, and there is no number of unnormalized objects that is fine.

`normalization_health()` is what the report asks, once, when someone is looking. It counts,
and it separates ROOT causes from CONSEQUENCES - a rule that failed because an object it
references failed is not a second problem. Reporting 1,301 errors for one bad object is
what made a single fault take several rounds to find.
"""

from __future__ import annotations

from typing import Any

from django.db.models import Count

from optivedge_integrations.integrations.models import ManagementStation, NormalizationIssue


def has_normalization_errors(management_station: ManagementStation | None = None) -> bool:
    """Whether anything is currently unnormalized. Binary, and cheap enough for the shell."""
    queryset = NormalizationIssue.objects.filter(severity=NormalizationIssue.Severity.ERROR)
    if management_station is not None:
        queryset = queryset.filter(management_station=management_station)
    return queryset.exists()


def normalization_health(management_station: ManagementStation | None = None) -> dict[str, Any]:
    """Counts for the report, root causes separated from their consequences."""
    queryset = NormalizationIssue.objects.all()
    if management_station is not None:
        queryset = queryset.filter(management_station=management_station)

    errors = queryset.filter(severity=NormalizationIssue.Severity.ERROR)
    roots = errors.filter(is_consequent=False)

    by_kind = {
        row["kind"]: row["n"]
        for row in roots.values("kind").annotate(n=Count("id")).order_by("kind")
    }

    return {
        "has_errors": errors.exists(),
        "root_errors": roots.count(),
        "consequent_errors": errors.filter(is_consequent=True).count(),
        "warnings": queryset.filter(severity=NormalizationIssue.Severity.WARNING).count(),
        "root_errors_by_kind": by_kind,
        # The points and groups actually affected, so the report can lead with where
        # rather than with how many.
        "affected_enforcement_points": roots.filter(enforcement_point__isnull=False)
        .values_list("enforcement_point_id", flat=True).distinct().count(),
        "affected_appliance_groups": roots.filter(appliance_group__isnull=False)
        .values_list("appliance_group_id", flat=True).distinct().count(),
    }
