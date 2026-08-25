"""Read-only diagnostics over normalized data.

Plain functions, no Django views or management commands, so the same logic serves a
developer page, a shell session, or a script. Nothing here writes to the database.
"""

from optivedge_integrations.integrations.diagnostics.address_reference import (
    explain_address_reference,
    unmarked_pushed_entries,
)
from optivedge_integrations.integrations.diagnostics.policy_object_census import (
    CENSUS_VERSION,
    capture_census,
    compare_censuses,
    list_censuses,
    load_census,
    write_census,
)

__all__ = [
    "explain_address_reference",
    "unmarked_pushed_entries",
    "CENSUS_VERSION",
    "capture_census",
    "compare_censuses",
    "list_censuses",
    "load_census",
    "write_census",
]


from optivedge_integrations.integrations.diagnostics.health import (  # noqa: E402
    normalization_health,
    has_normalization_errors,
    normalization_indicator,
)

__all__ += ["normalization_health", "has_normalization_errors", "normalization_indicator"]
