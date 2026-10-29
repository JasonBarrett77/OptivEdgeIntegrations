"""The scoped-administrator-role posture of one appliance - PAN-AUTH-023's subject.

A VERDICT MODEL, and the only one in the administrator-authentication domain. Both columns are
counts over `/config/shared/admin-role` and over the accounts that name an entry in it, so the
row names the APPLIANCE and not any role.

WHY THE APPLIANCE AND NOT THE ROLE. PAN-AUTH-023's commonest failing state is NO ROLE AT ALL -
measured on three of the four lab appliances, where the `admin-role` collection is absent in all
three config views - and an entry-grained row cannot report that, because there is no entry to
put it on. The second half of the same test agrees: an engineer answering this finding does not
open a role, they CREATE one and assign it, so the thing the report is about is the appliance's
posture.

ZERO IS THE FINDING ON BOTH COLUMNS, which is why they are non-nullable with a default of 0: an
appliance nobody has renormalised reports that it has no scoped role in use, which over-reports
rather than reassures. The direction is prescribed - an unknown fires.

ROLE DEFINITIONS LIVE ONLY AT SHARED SCOPE, so there is no scope column and no vsys axis. That
`shared/admin-role` is INVALID under a vsys is the project's own record carried forward and was
not re-measured here; if it turns out to be wrong, a per-vsys role would be invisible to this
model and the finding would tell an engineer to create a role they already have.

ON AN HA PAIR THE TWO PEERS YIELD TWO ROWS for one real posture, the same shape as every other
appliance-anchored model here, and nothing downstream deduplicates them.

NO PROVENANCE ROW IS EVER STORED. Every column is in `DERIVED_FIELDS`, so nothing on this model
can say whether the roles it counted are the appliance's own or a template's - which means no
control about a role definition being PUSHED can rest on this model as it stands.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class AdminRolePosture(ProvenancedMixin, SyncTrackedModel):
    """Whether one appliance defines and uses any scoped administrator role."""

    #: Computed here: two counts over a collection and a reverse traversal. Neither has a
    #: payload key, so neither can carry a provenance row. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "scoped_role_count",
        "scoped_roles_in_use_count",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="admin_role_postures")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="admin_role_postures")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="admin_role_postures", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="admin_role_postures")

    #: How many custom administrator roles this appliance DEFINES at shared scope. Zero means
    #: there is no scoped role for anybody to hold, which is the finding.
    scoped_role_count = models.PositiveIntegerField(default=0)
    #: How many of those roles some account actually NAMES through
    #: `permissions/role-based/custom/profile`. Zero covers both failing states at once: no
    #: role is defined, or one is defined and nobody holds it.
    scoped_roles_in_use_count = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_admin_role_posture_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} administrator role posture"
