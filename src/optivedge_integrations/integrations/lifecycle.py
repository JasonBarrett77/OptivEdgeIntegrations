"""When normalization may start, and what a restart leaves behind.

**`normalization_starting`** is sent before anything normalized is rewritten, by every path
that normalizes: inventory sync, the in-scope collection, the bulk refresh, renormalize and the
EDL/FQDN refresh. Normalization deletes and recreates what it owns, and anything built on top of
the normalized models - an assessment's findings - stops describing the configuration the moment
it does. This package cannot know who those consumers are, so it says it is about to happen and
lets them answer. A receiver that raises `NormalizationRefused` stops it before anything changes;
its message is what the operator is shown. (Jason, 2026-10-15.)

Normalization never deletes a collection. Snapshots are its INPUT, and a snapshot is what a
finding records it was computed from - `test_normalization_keeps_snapshots` holds it to that.

**`server_started`** (OptivEdge) closes the runs a restart killed. Collection and renormalize run
on daemon threads, so a restart left their runs RUNNING, and the buttons trusted a two-hour age
limit to tell a dead run from a live one - which locked them for up to two hours after a crash.
An engagement runs one server process, so at the start of a new one nothing can still be running.
"""

from __future__ import annotations

from django.db import transaction
from django.dispatch import Signal, receiver
from django.utils import timezone

from optivedge.lifecycle import server_started

#: Sent with `management_station=` - the station about to be normalized.
normalization_starting = Signal()

INTERRUPTED_REASON = "InterruptedByRestart"


class NormalizationRefused(Exception):
    """Raised by a `normalization_starting` receiver. The message is shown to the operator."""


def begin_normalization(management_station) -> None:
    """Announce a normalization of `management_station`; raises `NormalizationRefused`.

    `send`, not `send_robust`: a receiver's refusal has to stop the caller.
    """
    normalization_starting.send(sender=type(management_station),
                                management_station=management_station)


def integration_work_in_progress() -> bool:
    """Whether any collection, renormalize or EDL/FQDN refresh is running, on any station.

    Every one of them rewrites normalized rows, so a consumer reading those rows - a findings
    run - must not start beside one.
    """
    from .models import IntegrationRun

    return IntegrationRun.objects.filter(status=IntegrationRun.STATUS_RUNNING).exists()


@receiver(server_started)
def close_interrupted_runs(**kwargs) -> None:
    from .models import IntegrationEvent, IntegrationRun

    with transaction.atomic():
        runs = list(IntegrationRun.objects.filter(status=IntegrationRun.STATUS_RUNNING))
        if not runs:
            return
        IntegrationRun.objects.filter(pk__in=[run.pk for run in runs]).update(
            status=IntegrationRun.STATUS_FAILED, completed_at=timezone.now())
        IntegrationEvent.objects.bulk_create(
            IntegrationEvent(
                management_station_id=run.management_station_id, run=run,
                level=IntegrationEvent.LEVEL_ERROR, stage="", reason=INTERRUPTED_REASON,
                message="Interrupted: the server restarted before this finished. Run it again.")
            for run in runs)
