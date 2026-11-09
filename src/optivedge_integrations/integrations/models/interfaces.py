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
pair - the same convention as ManagementInterface and the device-wide settings models, the
models this sits beside.

An earlier version populated only the active member. That gave the model appliance-anchored
identity - `unique(appliance, name)` says there is one set per appliance - with group-like
population, and nothing in the schema recorded which appliances a row spoke for. Policy
objects get away with one copy per pair because their identity IS the group
(`EnforcementPoint` is unique on `appliance_group, vsys_name`) and `EnforcementNode` records
the members. Interfaces have no such bridge, so "this peer has no interfaces" would have
been indistinguishable from "this peer was never normalized". Choosing the active member is
a presentation and finding-dedup decision, which is where the policy plane already makes it.

TWO OF THE THREE DEFERRALS BELOW WERE TAKEN UP ON 2026-10-29 for PAN-NET-001 and
PAN-NET-003, and each deferral's own reason turned out to be true of a DIFFERENT reading
than the one a control needs:

    zone binding      `security_zone_name` now exists. The deferral said the binding is
                      "most reliable from RUNTIME (`show interface all`), which nothing
                      collects", and that is still true - but `models/zones.py` already
                      stores the CONFIGURATION answer as `ZoneInterface` rows out of the
                      same merged payload, so "doing half the join" was already done next
                      door. The runtime read remains the better oracle and remains
                      uncollected; this column says what the configuration says.
    link state        `link_state` now exists. The deferral said "runtime only", which is
                      true of the PHYSICAL link and false of the CONFIGURED administrative
                      state: `show interface all` reports the physical state and conflates
                      the two in one field - measured, a port that is down because no cable
                      is attached is indistinguishable there from one an administrator shut
                      down - while `link-state` is a configuration key in the subtree this
                      collector already dumps.

Still deliberately NOT modeled:

    virtual router and vsys bindings         Same reason as before. `out_of_service_residue`
                                             reads virtual-router membership out of the
                                             payload to RANK a port and stores no binding.
    speed, duplex                            Runtime only, and no control asks. `link-speed`
                                             and `link-duplex` are read for the residue
                                             ranking the same way.
    provenance (@ptpl)                       Available - interface entries carry it the way
                                             profile entries do - but no consumer asks yet,
                                             and THIS MODEL CARRIES NO `ProvenancedMixin`,
                                             so no field of it records provenance and the
                                             eight columns added for PAN-NET-001 and
                                             PAN-NET-003 cannot be DECLARED derived either.
                                             A missing FieldProvenance row here means the
                                             model is not provenance-tracked and nothing
                                             more - which is the reverse of the reading a
                                             normalizer author finds written down elsewhere.
                                             Nothing on this model is read through a
                                             `parse_*_field` for that reason.
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

    # ------------------------------------------------------------------
    # PAN-NET-001 - what an out-of-service port is left holding
    # ------------------------------------------------------------------

    #: Whether the profile bound to this port restricts WHICH SOURCES may use the services
    #: it permits. True only where a permitted-source list exists for this port's
    #: management surface. It says nothing about WHICH services are permitted - that is
    #: `InterfaceManagementProfile`'s and PAN-MGT-006's.
    #:
    #: FALSE IS THE UNRESTRICTED READING AND THEREFORE THE FIRING ONE, which is why the
    #: default is false rather than null: an absent `permitted-ip` container means ANY
    #: source, and the device drops an empty container so absent and empty are one state.
    #: A row nobody has recomputed reads as unrestricted, which over-reports.
    management_profile_restricts_sources = models.BooleanField(default=False)

    #: The security zone this interface is a member of, empty where it is in none.
    #:
    #: READ FROM THE ZONE END, which is the only end that expresses it: the zone names its
    #: members and the interface does not name its zone. Every member list the platform
    #: offers is covered, not only layer3, because a layer-2 or virtual-wire port in a zone
    #: is as much a residue as a layer-3 one.
    #:
    #: Empty means "in no zone", and that is also what a row nobody recomputed holds - so
    #: this column REASSURES until the recompute pass. Nothing should clause on it;
    #: `out_of_service_residue` carries the firing.
    security_zone_name = models.CharField(max_length=128, blank=True)

    #: The CONFIGURED administrative link state - auto, down or up - which is what
    #: "administratively shut down" means. NOT the runtime state; see this module's
    #: docstring for why the two are different questions and why only one is readable here.
    #:
    #: NULL WHERE THE KEY IS ABSENT, which was EVERY port in the lab estate when stage 4
    #: measured it. Nothing is assumed: the only oracle for the administrative state
    #: conflates it with the physical link, so guessing `auto` would assert that every port
    #: with no key is not shut down - the reassuring direction on the one key PAN-NET-001's
    #: fourth clause turns on. Nullable is safe here only because no clause compares this
    #: column; `out_of_service_residue` is where the null lands.
    LINK_STATE_AUTO = "auto"
    LINK_STATE_DOWN = "down"
    LINK_STATE_UP = "up"
    LINK_STATE_CHOICES = [
        (LINK_STATE_AUTO, "Auto"),
        (LINK_STATE_DOWN, "Down"),
        (LINK_STATE_UP, "Up"),
    ]
    link_state = models.CharField(
        max_length=8, choices=LINK_STATE_CHOICES, null=True, blank=True)

    #: What this port is left holding, as one token, taking the WORST of the things someone
    #: who patches a cable into it would gain. This is the column PAN-NET-001 is graded on,
    #: and it is a verdict rather than a reading.
    #:
    #: `administrative_state_unknown` CARRIES TWO STATES AND THE VOCABULARY HAS NO MEMBER
    #: FOR THE SECOND. It is written where a port holds no residue AND its administrative
    #: state is not readable (no `link-state` key), and also where a port holds no residue
    #: and IS readable as `auto` or `up` - stripped, but not shut down, which the control's
    #: second half is about and for which there is no token. Both fire at the baseline,
    #: which is right for both; `link_state` beside this column is what separates them
    #: (NULL against a value).
    RESIDUE_UNRESTRICTED_MANAGEMENT = "unrestricted_management_binding"
    RESIDUE_RESTRICTED_MANAGEMENT = "restricted_management_binding"
    RESIDUE_ZONE_MEMBERSHIP = "security_zone_membership"
    RESIDUE_ADDRESS_ONLY = "address_only"
    RESIDUE_COMMENT_OR_LINK_SETTINGS = "comment_or_link_settings_only"
    RESIDUE_ROUTING_INSTANCE = "routing_instance_without_address"
    RESIDUE_STRIPPED_AND_SHUT_DOWN = "stripped_and_shut_down"
    RESIDUE_ADMIN_STATE_UNKNOWN = "administrative_state_unknown"
    #: Worst first, which is the order the normalizer walks.
    RESIDUE_CHOICES = [
        (RESIDUE_UNRESTRICTED_MANAGEMENT, "Management binding, no source restriction"),
        (RESIDUE_RESTRICTED_MANAGEMENT, "Management binding, sources restricted"),
        (RESIDUE_ZONE_MEMBERSHIP, "Security zone membership"),
        (RESIDUE_ADDRESS_ONLY, "Address only"),
        (RESIDUE_COMMENT_OR_LINK_SETTINGS, "Comment or link settings only"),
        (RESIDUE_ROUTING_INSTANCE, "Routing instance, no address"),
        (RESIDUE_STRIPPED_AND_SHUT_DOWN, "Stripped and shut down"),
        (RESIDUE_ADMIN_STATE_UNKNOWN, "Administrative state unknown"),
    ]
    out_of_service_residue = models.CharField(
        max_length=48, choices=RESIDUE_CHOICES, default=RESIDUE_ADMIN_STATE_UNKNOWN)

    # ------------------------------------------------------------------
    # PAN-NET-003 - what a port announces to whatever is plugged into it
    # ------------------------------------------------------------------

    #: Whether the interface has an LLDP node at all. LOAD-BEARING RATHER THAN COSMETIC:
    #: `show lldp config all` lists an interface IF AND ONLY IF this node exists, measured,
    #: so a port with no node and a port storing `enable: no` are the same thing
    #: behaviourally and NOT the same thing to a collector - the first is absent from the
    #: operational read and the second is in it. A consumer must not read that read's
    #: SILENCE as `enable: no`.
    lldp_node_present = models.BooleanField(default=False)

    #: Whether the interface transmits and receives link-layer discovery. True means the
    #: port runs the protocol, and the MANDATORY items go out whenever it transmits at all,
    #: whatever else has been suppressed.
    #:
    #: FALSE FOR AN ABSENT KEY IS MEASURED AND IT IS THE REASSURING DIRECTION, so it is
    #: worth saying what backs it: an empty `<lldp/>` container committed with no `enable`
    #: child reported `enable: no` in `show lldp config all`; the key then written to `yes`
    #: reached running config and the same oracle moved to YES; and on the appliances where
    #: nothing carries the container the reply is null rather than a list of noes, which
    #: rules out a constant printer. One oracle only.
    lldp_enabled = models.BooleanField(default=False)

    #: The LLDP profile bound to this interface, empty where none is bound. EMPTY DOES NOT
    #: MEAN "NOTHING IS ANNOUNCED": the vendor says None means the firewall uses the GLOBAL
    #: defaults, in four places verbatim, and what those defaults transmit is unmeasured -
    #: which is what the column below defaults to.
    lldp_profile_name = models.CharField(max_length=64, blank=True)

    #: What an announcement from this port actually puts on the wire, as one token, taking
    #: the WORST item the bound profile permits. The mandatory items - chassis identifier
    #: and port name - go out whenever the protocol transmits at all, so every value below
    #: ADDS to that floor rather than replacing it.
    #:
    #: `unknown_global_defaults` IS A MATERIALISED DEFAULT THAT FIRES, deliberately, and it
    #: is also the truth wherever a port runs the protocol with no profile: no document in
    #: the vendor corpus says what the global defaults transmit. It over-reports on a port
    #: that is not running LLDP at all until the recompute pass distinguishes it, which is
    #: the opposite of the clean-estate failure.
    ANNOUNCED_MANAGEMENT_ADDRESS = "management_address"
    ANNOUNCED_SYSTEM_DESCRIPTION = "system_description"
    ANNOUNCED_HOSTNAME_OR_ROLE = "hostname_or_role"
    ANNOUNCED_PORT_AND_CHASSIS_ONLY = "port_and_chassis_only"
    ANNOUNCED_RECEIVE_ONLY_OR_OFF = "receive_only_or_off"
    ANNOUNCED_UNKNOWN_GLOBAL_DEFAULTS = "unknown_global_defaults"
    #: Worst first for the first four; the last two are not ranked against them.
    ANNOUNCED_CONTENT_CHOICES = [
        (ANNOUNCED_MANAGEMENT_ADDRESS, "Management address"),
        (ANNOUNCED_SYSTEM_DESCRIPTION, "System description"),
        (ANNOUNCED_HOSTNAME_OR_ROLE, "Hostname or role"),
        (ANNOUNCED_PORT_AND_CHASSIS_ONLY, "Port and chassis only"),
        (ANNOUNCED_RECEIVE_ONLY_OR_OFF, "Receive only, or off"),
        (ANNOUNCED_UNKNOWN_GLOBAL_DEFAULTS, "Unknown - global defaults"),
    ]
    lldp_announced_content = models.CharField(
        max_length=48, choices=ANNOUNCED_CONTENT_CHOICES,
        default=ANNOUNCED_UNKNOWN_GLOBAL_DEFAULTS)

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
