"""Panorama container models - the device-group hierarchy, and which vsys each group reaches.

`show dg-hierarchy` is the source. Measured against the lab Panorama on 2026-09-22, its
result is `dg-hierarchy` holding `dg` entries that carry exactly `@name` and `@dg_id`, with
nesting expressed by containment and nothing else:

    <dg-hierarchy>
      <dg name="dg_fw-core-tpa_base" dg_id="137">
        <dg name="dg_fw-core-tpa_edge" dg_id="140"/>
      </dg>
    </dg-hierarchy>

THREE THINGS THE COMMAND DOES NOT SAY, each recorded here rather than inferred:

* **Shared is not emitted.** The hierarchy starts at the top-level device groups. Panorama
  presents Shared as a container and an operator looks for it by that name, so one row is
  created per station with `is_shared` set, and every top-level group hangs off it.
  `discovered_from` says SYNTHESIZED so nothing mistakes it for something the device said.

* **`dg_id` is not durable.** A group deleted and recreated takes a new id - a traffic log's
  `dg_hier_level_*` that matches nothing is exactly that case (OptivEdgeProbe
  `probe/investigations/traffic_log_identity.py`). It is stored as an attribute, for joining
  against logs within one collection, and never as a key. The key is
  (management_station, name): names are unique per Panorama, not globally.

* **Membership is not in it.** Which vsys a group pushes to is read from `FieldProvenance`
  (see `DeviceGroupBinding`), so a group that has pushed nothing this collection reached has
  no bindings and is still a real group. The lab has one - `dg_fw-core-tpa-base-01`, parent
  to nothing with no devices assigned - which is why the hierarchy is collected rather than
  derived from provenance alone: derivation cannot see an empty container.

Nothing here holds a certificate reference, so no row of
`OptivEdgeProbe/scratch/certificate-reference-locations.csv` changes: these are Panorama
containers, not a config subtree.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel, TimestampedModel
from .collected import EnforcementPoint, ManagementStation


class DeviceGroup(SyncTrackedModel):
    """One device group as Panorama presents it, including Shared."""

    DISCOVERED_COLLECTED = "collected"
    DISCOVERED_PROVENANCE = "provenance"
    DISCOVERED_SYNTHESIZED = "synthesized"

    DISCOVERED_FROM_CHOICES = [
        (DISCOVERED_COLLECTED, "Collected from the hierarchy"),
        (DISCOVERED_PROVENANCE, "Seen only in provenance"),
        (DISCOVERED_SYNTHESIZED, "Synthesized"),
    ]

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="device_groups",
    )
    #: The collection this row was last built from. Null for a group seen only in
    #: provenance, which by definition arrived without a hierarchy entry of its own.
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.SET_NULL,
        related_name="device_groups",
        null=True,
        blank=True,
    )

    name = models.CharField(max_length=255)

    #: SET_NULL rather than CASCADE: a parent row is never deleted in normal operation - a
    #: group that stops appearing is marked missing - and losing the tree should not delete
    #: the subtree with it.
    parent = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        related_name="children",
        null=True,
        blank=True,
    )

    #: Panorama's numeric id for this group in the CURRENT hierarchy. Not a key: see the
    #: module docstring.
    dg_id = models.CharField(max_length=32, blank=True)

    #: Shared, which Panorama shows as a container and does not return from dg-hierarchy.
    is_shared = models.BooleanField(default=False)

    discovered_from = models.CharField(
        max_length=32,
        choices=DISCOVERED_FROM_CHOICES,
        default=DISCOVERED_COLLECTED,
    )

    class Meta:
        ordering = ["name", "pk"]
        constraints = [
            models.UniqueConstraint(
                fields=["management_station", "name"],
                name="integrations_unique_device_group_per_station",
            ),
        ]
        indexes = [
            models.Index(fields=["management_station"]),
            models.Index(fields=["parent"]),
        ]

    def __str__(self) -> str:
        return self.name

    def ancestors(self):
        """This group's parents, nearest first, ending at Shared.

        Walks the stored tree and stops on a cycle rather than recursing forever: the
        hierarchy comes from a device, and a malformed one must not hang a page.
        """
        seen = {self.pk}
        node = self.parent
        while node is not None and node.pk not in seen:
            seen.add(node.pk)
            yield node
            node = node.parent


class DeviceGroupBinding(TimestampedModel):
    """One vsys that a device group has pushed configuration to.

    Derived from `FieldProvenance` rows whose `provenance_type` is `device_group`, so it
    records what a group HAS PUSHED that this collection reached - not what Panorama has
    assigned. Those differ for an empty group, and the difference is the honest one to
    keep: a group with no bindings has no findings to attribute either.
    """

    device_group = models.ForeignKey(
        DeviceGroup,
        on_delete=models.CASCADE,
        related_name="bindings",
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="device_group_bindings",
    )

    class Meta:
        ordering = ["device_group__name", "enforcement_point__vsys_name", "pk"]
        constraints = [
            models.UniqueConstraint(
                fields=["device_group", "enforcement_point"],
                name="integrations_unique_device_group_binding",
            ),
        ]
        indexes = [
            models.Index(fields=["device_group"]),
            models.Index(fields=["enforcement_point"]),
        ]

    def __str__(self) -> str:
        return f"{self.device_group} -> {self.enforcement_point}"
