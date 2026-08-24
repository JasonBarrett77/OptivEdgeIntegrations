"""Read-only diagnostics over normalized data.

Plain functions, no Django views or management commands, so the same logic serves a
developer page, a shell session, or a script. Nothing here writes to the database.
"""

from optivedge_integrations.integrations.diagnostics.address_reference import (
    explain_address_reference,
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
    "CENSUS_VERSION",
    "capture_census",
    "compare_censuses",
    "list_censuses",
    "load_census",
    "write_census",
]
