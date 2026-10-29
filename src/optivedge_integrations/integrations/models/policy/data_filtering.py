"""Whether one enforcement point's outbound traffic is watched for regulated data.

THE ENFORCEMENT POINT IS THE ROW AND NOT THE PROFILE, for the same reason `VsysLogForwarding`
is keyed on the vsys: the commonest failing state is a vsys with NO data-filtering profile at
all - three of the four lab appliances hold none at any local scope - and a profile-keyed row
cannot report something that does not exist. A finding about a profile row cannot be raised on
a device that has no profile.

ITS SIBLING IS `SecurityProfile` WITH `kind=data-filtering`, and the split is deliberate: where
the row exists and is wrong, an engineer opens that profile, so the per-profile assertions name
the profile. Where nothing is watching at all, the thing the report is about is the enforcement
point. Both grains, one domain.

NO NAMESPACE COLUMN, and that is the point of not inheriting `ScopedPolicyObject`. This row is
not DEFINED at a scope - it is a conclusion over definitions sitting at four of them - and the
scoped base carries a namespace default that would silently make such a row shared-scoped.

EVERY COLUMN IS DERIVED and every one of them is in `DERIVED_FIELDS`, so provenance is
synthesized at read time rather than stored (`provenance_for`). No `FieldProvenance` row is
written for this model. The limit that leaves: a control whose finding turned on whether the
profile behind the verdict was PUSHED could not be written against this subject, because the
device-group scope is held in provenance on the profile rows, which this model does not store.
"""

from __future__ import annotations

from django.db import models

from ..base import SyncTrackedModel
from ..provenance import ProvenancedMixin


class DataFilteringPosture(ProvenancedMixin, SyncTrackedModel):
    """One row per enforcement point: is this vsys's outbound traffic watched for its own data?"""

    #: Everything but the identity and the plumbing. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "outward_data_filtering_effective",
        "data_filtering_in_force",
        "named_patterns_defined",
        "profiles_in_force",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="data_filtering_postures")
    #: WHICH APPLIANCE SPOKE for this enforcement point, which on an HA pair is one of two
    #: members and not both: `choose_local_appliance()` picks the member whose merged config the
    #: point is read from. The column records which, so a verdict can be traced to the box it was
    #: computed from.
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="data_filtering_postures")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="data_filtering_postures", null=True, blank=True)
    enforcement_point = models.ForeignKey(
        "integrations.EnforcementPoint", on_delete=models.CASCADE,
        related_name="data_filtering_postures")
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="data_filtering_postures")

    #: THE VERDICT. Data filtering is in force here AND it names patterns AND the pattern objects
    #: it names actually define patterns. FALSE is the finding. One column and not three clauses
    #: because the assertion is one conjunction with no OR, and the three parts fail
    #: independently - which is what the two columns below are for.
    outward_data_filtering_effective = models.BooleanField(default=False)

    #: Whether at least one data-filtering profile CARRYING AT LEAST ONE RULE reaches traffic at
    #: this enforcement point, by any route - a security rule naming it, or a profile group a rule
    #: names, local or pushed.
    #:
    #: THE RULE-BEARING TEST IS WHY THIS IS NOT A BARE REFERENCE WALK: the only referenced
    #: data-filtering profile in the lab estate is a pushed one with no rules, so a bare "is it
    #: referenced" predicate finds exactly one profile in force across four appliances and it
    #: scans nothing - which would report the estate as watched.
    #:
    #: WHERE THE WALK CANNOT COMPLETE this is FALSE and the verdict fires, which is the opposite
    #: of the per-profile column's answer. There the unresolved case is its own value because the
    #: finding is ABOUT a named profile; here the verdict is about the enforcement point, so
    #: "we could not establish that anything is watching" and "nothing is watching" have the same
    #: consequence for the reader and the same direction of error.
    data_filtering_in_force = models.BooleanField(default=False)

    #: Whether every data pattern object named by a rule of an in-force profile here actually
    #: defines at least one pattern. FALSE means the profile names a pattern object that matches
    #: nothing - valid configuration that filters nothing.
    #:
    #: THE DEVICE ENFORCES HALF OF THIS FOR FREE AND NOT THE HALF THAT MATTERS: a dangling
    #: `data-object` is refused at the write and a referenced object cannot be deleted, so a
    #: committed rule's reference always resolves. What is not guaranteed is that the regex is
    #: meaningful or that the predefined name is the one the organisation needs, and that is
    #: beyond any column.
    named_patterns_defined = models.BooleanField(default=False)

    #: The profiles behind the verdict, for the report to print: name, namespace, whether it
    #: carries rules, the route it is reached by, and the pattern objects its rules name.
    #:
    #: FOR A READER, NOT FOR A FINDING. A finding must not rest on a stored structure: an
    #: unindexed lookup and a renamed vendor key that matches nothing both fail silently, so the
    #: control stops finding anything instead of breaking. The verdict column beside it is what a
    #: query reaches. An empty list beside a firing verdict is the honest pair.
    profiles_in_force = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["appliance__hostname", "enforcement_point__vsys_name"]
        indexes = [models.Index(fields=["appliance", "enforcement_point"])]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "enforcement_point"],
                name="integrations_unique_data_filtering_posture_per_point"),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.enforcement_point} data filtering posture"
