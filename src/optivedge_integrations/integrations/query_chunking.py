"""Splitting an `__in` lookup into chunks a database will actually accept.

Every parameter in an `IN (...)` clause is a host parameter, and SQLite caps how many one
statement may carry. The cap is a COMPILE-TIME property of the SQLite build, not of our
schema or of Django, so the same query succeeds on one machine and fails on another with
`OperationalError: too many SQL variables`. Measured 2026-09-23: 250,000 on the Linux build
used for development, and low enough on a Windows Python 3.12 to abort a refresh of a real
estate. That difference is the hazard - the failure cannot be reproduced where the code is
written, so it has to be designed out rather than tested for locally.

CHUNK_SIZE is deliberately far below every limit in play (the historical SQLite default is
999) rather than tuned to any one build, because the cost of a few extra round trips is
nothing beside a refresh that dies partway through.

Only use this where the list grows with the SIZE OF THE ESTATE. A list bounded by something
small - the scopes on a device, the zones on a vsys - is not worth the indirection.
"""

from __future__ import annotations

from typing import Iterable, Iterator, Sequence, TypeVar

T = TypeVar("T")

CHUNK_SIZE = 900


def chunked(values: Iterable[T], size: int = CHUNK_SIZE) -> Iterator[Sequence[T]]:
    """Yield `values` in lists of at most `size`. Yields nothing for an empty input."""
    if size < 1:
        raise ValueError("chunk size must be at least 1")
    batch: list[T] = []
    for value in values:
        batch.append(value)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch
