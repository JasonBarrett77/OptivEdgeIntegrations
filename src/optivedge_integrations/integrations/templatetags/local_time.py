"""Render stored UTC timestamps in the host server's own system timezone.

Storage stays UTC (settings.TIME_ZONE = "UTC", USE_TZ = True) for consistency; this filter
converts only at render time, using the server process's actual system-local timezone rather
than Django's globally-active timezone (which defaults to settings.TIME_ZONE and would still
be UTC), so it works with no settings or middleware changes.
"""

from __future__ import annotations

import datetime

from django import template
from django.utils import timezone

register = template.Library()


@register.filter
def local_time(value):
    if not isinstance(value, datetime.datetime) or timezone.is_naive(value):
        return value
    return value.astimezone()
