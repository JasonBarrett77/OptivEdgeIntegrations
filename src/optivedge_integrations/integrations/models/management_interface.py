"""Management surfaces: the thing a management-access finding attaches to.

`DeviceConfigurationProfile` is one row per appliance, which cannot answer "what is
`ethernet1/1` exposed to" - there is no row for `ethernet1/1`. An appliance has several
administrative surfaces, each with its own address and its own permitted-source list:

    mgt         the dedicated management port
    aux-1/2     auxiliary management ports, each its own subtree under deviceconfig/system
    dataplane   any layer-3 interface carrying an interface-management-profile

They are separate doors, so a control asserting "management access is restricted" produces
one finding per surface rather than one per appliance. On an HA pair that is deliberately
two rows for the two peers' MGT ports: the peers have different management addresses and
are separately reachable, so collapsing them would hide a real difference.

Deliberately NOT modelled here: which services each surface exposes. That is a different
assertion (MGMT-001), and the two planes disagree about both the service set and the
polarity of an absent key - see
`docs/palo-alto/pan-os/network/read-an-interface-management-profile.md`. Adding it here
before a control needs it is how this model over-grows.
"""

from __future__ import annotations

import ipaddress

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel


class ManagementInterface(SyncTrackedModel):
    PLANE_MGT = "mgt"
    PLANE_AUX1 = "aux-1"
    PLANE_AUX2 = "aux-2"
    PLANE_DATAPLANE = "dataplane"
    PLANE_CHOICES = [
        (PLANE_MGT, "Management"),
        (PLANE_AUX1, "Aux-1"),
        (PLANE_AUX2, "Aux-2"),
        (PLANE_DATAPLANE, "Data plane"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="management_interfaces")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="management_interfaces")
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="management_interfaces")

    plane = models.CharField(max_length=16, choices=PLANE_CHOICES)
    #: Empty for the deviceconfig planes, which are not named interfaces. For a data-plane
    #: surface this is the interface, e.g. "ethernet1/1" - and it is what a report names.
    interface_name = models.CharField(max_length=64, blank=True)
    #: The interface-management-profile bound to this interface. Data plane only; a surface
    #: exists on the data plane ONLY because a profile is bound, so this is never empty there.
    #:
    #: Deliberately a NAME rather than a foreign key to a profile model. PAN-OS profiles are
    #: named, reusable objects and one may be bound to many interfaces, so an
    #: InterfaceManagementProfile model would be the faithful shape - it was designed and
    #: then not built, because no control needs to query the profile as a thing. Every
    #: question so far is asked of the surface: what is THIS interface exposed to. Promoting
    #: it later is additive - a model, a FK, and a normalizer that already reads the profile
    #: node to populate PermittedSource. Do that when a control asks "which interfaces does
    #: this profile expose", and not before.
    profile_name = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["appliance__hostname", "plane", "interface_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "plane", "interface_name"],
                name="integrations_unique_management_interface_per_appliance_plane"),
        ]
        indexes = [
            models.Index(fields=["appliance", "plane"]),
            models.Index(fields=["management_station"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.display_name}"

    @property
    def display_name(self) -> str:
        """How a report names this surface. 'MGT', 'Aux-1', or the interface name."""
        if self.plane == self.PLANE_DATAPLANE:
            return self.interface_name or "(unnamed interface)"
        return {self.PLANE_MGT: "MGT", self.PLANE_AUX1: "Aux-1",
                self.PLANE_AUX2: "Aux-2"}.get(self.plane, self.plane)

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError("Management interface appliance must belong to the same station.")
        if self.plane == self.PLANE_DATAPLANE:
            if not self.interface_name:
                raise ValidationError("A data-plane management interface must name its interface.")
            if not self.profile_name:
                raise ValidationError(
                    "A data-plane management surface exists only because a profile is bound; "
                    "profile_name must be set.")
        elif self.interface_name:
            raise ValidationError("Only a data-plane surface carries an interface name.")


class PermittedSource(models.Model):
    """One literal source restriction on a management surface.

    Always a literal. Address objects, groups, hostnames and ranges are all rejected by
    PAN-OS on both planes, so nothing here needs resolving - measured 2026-08-27.
    """

    FAMILY_V4 = 4
    FAMILY_V6 = 6

    management_interface = models.ForeignKey(
        ManagementInterface, on_delete=models.CASCADE, related_name="permitted_sources")
    position = models.PositiveIntegerField(default=0)
    value = models.CharField(max_length=64)
    #: Null when the value did not parse - which is a finding, not a defect. See
    #: ManagementInterface exposure states.
    family = models.PositiveSmallIntegerField(null=True, blank=True)
    ipv4_start_int = models.BigIntegerField(null=True, blank=True)
    ipv4_end_int = models.BigIntegerField(null=True, blank=True)
    #: Accepted under deviceconfig/system, REJECTED under an interface-management-profile.
    #: Nullable because the two planes differ by exactly this one field.
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["management_interface", "position", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["management_interface", "position"],
                name="integrations_unique_permitted_source_position"),
        ]
        indexes = [
            models.Index(fields=["management_interface", "ipv4_start_int", "ipv4_end_int"]),
            models.Index(fields=["family"]),
        ]

    def __str__(self) -> str:
        return f"{self.management_interface} <- {self.value}"


def parse_permitted_source(value: str) -> tuple[int | None, int | None, int | None]:
    """(family, ipv4_start_int, ipv4_end_int) for a permitted-source literal.

    Returns (None, None, None) when the value does not parse, which the caller must treat
    as UNDETERMINED rather than as unrestricted or restricted. IPv6 parses and reports its
    family, but carries no interval - the model has no 128-bit columns and this project is
    not IPv6-enabled, so a v6 entry is known-present and not interval-comparable.
    """
    text = (value or "").strip()
    if not text:
        return (None, None, None)
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return (None, None, None)
    if network.version == 6:
        return (PermittedSource.FAMILY_V6, None, None)
    return (PermittedSource.FAMILY_V4,
            int(network.network_address), int(network.broadcast_address))
