"""The interface management profile as an object, rather than a name on a surface.

Every question asked of a profile so far has been asked of the surface it is bound to:
what is THIS interface exposed to, and to whom. `ManagementInterface.profile_name` answers
those, and deliberately stayed a name.

An unused profile is the first question asked of the profile itself, and it cannot be
answered from surfaces at all - a profile bound to nothing produces no surface, so it
leaves no trace. This model exists because that absence had to become a row.

Scoped to an appliance, like every other model outside `vsys/entry` - profiles live under
`network/profiles`. A profile pushed from a Panorama template appears in each firewall's
merged config separately, so a template profile bound on one device and not another is two
rows saying different things, which is the truth about those two devices.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class InterfaceManagementProfile(ProvenancedMixin, SyncTrackedModel):
    """One interface management profile as it exists on one appliance.

    Provenance is recorded the way every other normalized object records it - a
    FieldProvenance row with field_name "__entry__" carrying the entry's `@ptpl`. Measured
    2026-08-31: a template-pushed profile carries `@ptpl` on the entry AND on each service
    leaf, while a locally-created one carries no attributes at all, so LOCAL is established
    by the absence of a row exactly as FieldProvenance documents.

    Which services the profile enables is NOT stored here. `ManagementService` already
    carries them for every profile that is bound, keyed to the surface where they matter,
    and no control yet asks what an unused profile would have enabled if it were bound.
    Adding them is additive when one does.
    """

    #: Computed here: a reverse lookup: which interfaces name this profile. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "bound_interface_names",
        "bound_interface_count",
        "unbound_exposure_class",
    )

    #: What attaching this profile WOULD permit, as a class rather than a service list.
    #: PAN-MGT-013's severity. Counterfactual on purpose: an unattached profile grants no
    #: access today, which is why `bound_interface_count` is the control's baseline and this is
    #: the grade.
    #:
    #: The precedence is strict - an unencrypted administrative service beats an encrypted one
    #: beats everything else - so this is a three-way classification over eleven keys and not
    #: anything a clause comparing one column to one literal reaches.
    EXPOSURE_UNENCRYPTED = "unencrypted_administrative_login"
    EXPOSURE_ENCRYPTED = "encrypted_administrative_login"
    EXPOSURE_MONITORING = "monitoring_or_nothing"
    EXPOSURE_CLASS_CHOICES = [
        (EXPOSURE_UNENCRYPTED, "Would permit an unencrypted administrative login"),
        (EXPOSURE_ENCRYPTED, "Would permit an encrypted administrative login"),
        (EXPOSURE_MONITORING, "Would permit monitoring or reachability only"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="interface_management_profiles")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="interface_management_profiles")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="interface_management_profiles", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="interface_management_profiles")

    name = models.CharField(max_length=64)

    #: Which interfaces reference this profile, by name, on this appliance. Computed from
    #: the same payload in the same pass rather than read back from ManagementInterface, so
    #: the two cannot disagree and neither depends on the other having run first.
    bound_interface_names = models.JSONField(default=list, blank=True)
    #: Zero is the whole point of this model. Stored rather than derived so that "unused"
    #: is a scalar a control query can filter on without a join.
    bound_interface_count = models.PositiveIntegerField(default=0)

    #: The counterfactual class above. The profile's own service keys ARE read in the same pass
    #: for the bound case, so this is a classification and not a new read - but the keys
    #: themselves are deliberately not stored for this row: `ManagementService` holds a
    #: profile's services keyed to the SURFACE where they matter, and an unattached profile
    #: creates no surface. So nothing anywhere said what an unused profile would have enabled.
    #:
    #: DEFAULT IS THE WORST CLASS, deliberately: a profile nobody has classified has not been
    #: shown to be harmless. The baseline clause fires on `bound_interface_count` regardless, so
    #: the window between the migration and the pass affects the SEVERITY and not whether the
    #: finding is raised - the one place in this domain where a default on the firing side buys
    #: an over-statement rather than a report.
    unbound_exposure_class = models.CharField(
        max_length=32, choices=EXPOSURE_CLASS_CHOICES, default=EXPOSURE_UNENCRYPTED)

    class Meta:
        ordering = ["appliance__hostname", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "name"],
                name="integrations_unique_interface_mgmt_profile_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance", "bound_interface_count"]),
            models.Index(fields=["management_station"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.name}"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError(
                "Interface management profile appliance must belong to the same station.")
        if self.bound_interface_count != len(self.bound_interface_names or []):
            raise ValidationError(
                "bound_interface_count must match bound_interface_names.")
