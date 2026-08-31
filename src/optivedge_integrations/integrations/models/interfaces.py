"""The interface as an object, which PAN-OS itself does not provide.

An interface is defined across four subtrees keyed only by its name, and nothing links
them - see `docs/palo-alto/pan-os/network/read-an-interface.md`. Every consumer so far has
done part of that join itself: the zone normalizer walks `network/interface` for addresses,
the management-surface normalizer walks it again for profile bindings, and neither leaves a
row behind. An interface that is in no zone and carries no management profile is invisible,
even though it sits in config we already collect.

So this model IS the join. It exists so that "which interfaces does this appliance have"
has an answer that does not depend on the interface happening to be something else.

Scoped to an appliance, and normalized for EVERY appliance including both members of an HA
pair - the same convention as DeviceConfigurationProfile and ManagementInterface, the two
models this sits beside.

An earlier version populated only the active member. That gave the model appliance-anchored
identity - `unique(appliance, name)` says there is one set per appliance - with group-like
population, and nothing in the schema recorded which appliances a row spoke for. Policy
objects get away with one copy per pair because their identity IS the group
(`EnforcementPoint` is unique on `appliance_group, vsys_name`) and `EnforcementNode` records
the members. Interfaces have no such bridge, so "this peer has no interfaces" would have
been indistinguishable from "this peer was never normalized". Choosing the active member is
a presentation and finding-dedup decision, which is where the policy plane already makes it.

Deliberately NOT modelled yet:

    virtual router, vsys and zone bindings   These are most reliable from RUNTIME
                                             (`show interface all`), which nothing collects.
                                             Config holds them in three more subtrees; doing
                                             half the join would be worse than naming the gap.
    link state, speed, duplex                Runtime only. Same reason.
    provenance (@ptpl)                       Available - interface entries carry it the way
                                             profile entries do - but no consumer asks yet.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel


class Interface(SyncTrackedModel):
    """One interface or subinterface as configured on one appliance."""

    #: How the entry declares what it is. Physical entries carry exactly one type KEY;
    #: logical ones carry none at all and their container path is the type. `AGGREGATE_MEMBER`
    #: is neither - it comes from `aggregate-group`, which is a plain string naming the
    #: parent rather than a subtree, and code that looks for a type subtree misses it
    #: silently. `UNKNOWN` is a real outcome, not a defect: the type set is
    #: platform-dependent, so a type this release does not know is reported rather than
    #: assumed to be corruption.
    TYPE_LAYER3 = "layer3"
    TYPE_LAYER2 = "layer2"
    TYPE_VIRTUAL_WIRE = "virtual-wire"
    TYPE_TAP = "tap"
    TYPE_HA = "ha"
    TYPE_AGGREGATE_MEMBER = "aggregate-member"
    TYPE_LOGICAL = "logical"
    TYPE_UNCONFIGURED = "unconfigured"
    TYPE_UNKNOWN = "unknown"
    TYPE_CHOICES = [
        (TYPE_LAYER3, "Layer 3"),
        (TYPE_LAYER2, "Layer 2"),
        (TYPE_VIRTUAL_WIRE, "Virtual wire"),
        (TYPE_TAP, "Tap"),
        (TYPE_HA, "HA"),
        (TYPE_AGGREGATE_MEMBER, "Aggregate member"),
        (TYPE_LOGICAL, "Logical"),
        (TYPE_UNCONFIGURED, "Unconfigured"),
        (TYPE_UNKNOWN, "Unknown"),
    ]

    #: `ip`, `dhcp-client` and `pppoe` are mutually alternative and only the first states an
    #: address. NONE is therefore an ordinary state, not missing data - a DHCP interface
    #: legitimately has no address in configuration because the lease is runtime state.
    ADDRESSING_STATIC = "static"
    ADDRESSING_DHCP = "dhcp-client"
    ADDRESSING_PPPOE = "pppoe"
    ADDRESSING_NONE = "none"
    ADDRESSING_CHOICES = [
        (ADDRESSING_STATIC, "Static"),
        (ADDRESSING_DHCP, "DHCP client"),
        (ADDRESSING_PPPOE, "PPPoE"),
        (ADDRESSING_NONE, "None"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="interfaces")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE, related_name="interfaces")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="interfaces", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="interfaces")

    name = models.CharField(max_length=64)
    #: The container the entry was found under - ethernet, aggregate-ethernet, vlan,
    #: loopback, tunnel, sdwan. NOT a choice field: the set is platform-dependent (a PA-5220
    #: offers vlan and a PA-VM does not, measured 2026-08-31), so constraining it here would
    #: turn a new platform into a validation error.
    container = models.CharField(max_length=32)
    interface_type = models.CharField(max_length=24, choices=TYPE_CHOICES)

    #: The interface this is a UNIT of - ethernet1/1 for ethernet1/1.10. Null for a
    #: top-level entry.
    parent = models.ForeignKey(
        "self", on_delete=models.CASCADE, related_name="units", null=True, blank=True)
    #: The aggregate this is a MEMBER of, by name. A different relationship from `parent`
    #: and deliberately not the same field: a member is, per the vendor guide, "physically
    #: real, logically not an interface", whereas a unit is an interface in its own right.
    #: Held as a name because PAN-OS holds it as one, and because the aggregate may be
    #: absent from a partial collection.
    aggregate_group = models.CharField(max_length=64, blank=True)

    #: The interface management profile bound to this interface, by name. Empty when none
    #: is bound, which is the ordinary case.
    #:
    #: A name rather than a foreign key for the same reason PAN-OS holds it as one: the
    #: binding names a profile that may not exist. A dangling reference is representable
    #: here - and is itself worth reporting - where a foreign key would force either
    #: dropping the interface or inventing a profile row for one that is not configured.
    management_profile_name = models.CharField(max_length=64, blank=True)

    addressing = models.CharField(
        max_length=16, choices=ADDRESSING_CHOICES, default=ADDRESSING_NONE)
    #: Configured addresses. Empty is ambiguous on its own - read `addressing` first.
    ipv4_addresses = models.JSONField(default=list, blank=True)
    ipv6_addresses = models.JSONField(default=list, blank=True)
    comment = models.TextField(blank=True)

    class Meta:
        ordering = ["appliance__hostname", "container", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "name"],
                name="integrations_unique_interface_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance", "container"]),
            models.Index(fields=["appliance", "interface_type"]),
            models.Index(fields=["management_station"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.name}"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError("Interface appliance must belong to the same station.")
        if self.parent_id is not None and self.parent.appliance_id != self.appliance_id:
            raise ValidationError("An interface unit must belong to the same appliance as its parent.")
