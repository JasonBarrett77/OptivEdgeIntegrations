"""Normalized security-zone models.

A zone belongs to exactly one vsys, so it is scoped to an `EnforcementPoint` - the same
scoping every policy object uses. Interfaces hang off the zone rather than off the
appliance because PAN-OS lets an interface belong to at most one zone, so the containment
is real rather than a convenience.

Interface addresses are denormalized onto `ZoneInterface.ip_addresses` as a JSON list,
matching `DeviceConfigurationProfile.permitted_ip_values`. They are read-only display
data with no cross-references, so a child table would buy nothing.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel
from .collected import EnforcementPoint, ManagementStation


class Zone(SyncTrackedModel):
    """A security zone on one vsys.

    `zone_type` is which of PAN-OS's mutually exclusive `network` subtrees carried the
    interface list (`layer3`, `layer2`, ...). It is stored rather than inferred later
    because the subtree is the only place the type appears - there is no type field.
    """

    TYPE_LAYER3 = "layer3"
    TYPE_LAYER2 = "layer2"
    TYPE_VIRTUAL_WIRE = "virtual-wire"
    TYPE_TAP = "tap"
    TYPE_TUNNEL = "tunnel"
    TYPE_EXTERNAL = "external"
    TYPE_UNKNOWN = "unknown"

    ZONE_TYPE_CHOICES = [
        (TYPE_LAYER3, "Layer 3"),
        (TYPE_LAYER2, "Layer 2"),
        (TYPE_VIRTUAL_WIRE, "Virtual Wire"),
        (TYPE_TAP, "Tap"),
        (TYPE_TUNNEL, "Tunnel"),
        (TYPE_EXTERNAL, "External"),
        (TYPE_UNKNOWN, "Unknown"),
    ]

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="zones",
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="zones",
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="zones",
    )

    name = models.CharField(max_length=64)
    zone_type = models.CharField(max_length=32, choices=ZONE_TYPE_CHOICES, default=TYPE_UNKNOWN)
    zone_protection_profile = models.CharField(max_length=128, blank=True)
    log_setting = models.CharField(max_length=128, blank=True)

    # ------------------------------------------------------------- PAN-ZON-001's three columns
    #
    # `zone_protection_profile` above is THE NAIVE READING and these are what the measurement
    # bought. Stage 4's own warning on the attachment leaf is that a consumer must not treat it
    # as a plain empty string: the test the control needs is RESOLVING the name against the
    # profile collection rather than checking the column for non-emptiness, because a zone
    # naming a profile that does not exist reads as configured and meters nothing. The
    # configuration expresses NO referential integrity here - the leaf is a free string,
    # measured - and `is_empty` on the column above is the clause a reviewer would write and it
    # misses that case entirely.

    #: How many interfaces this zone's type subtree lists, as a reachable scalar beside the
    #: `ZoneInterface` rows. Stored rather than counted at query time for the reason the shipped
    #: `InterfaceManagementProfile.bound_interface_count` is: there is no count operator and no
    #: aggregation in a predicate, and `ZoneInterface.ip_addresses` is a JSON column no query
    #: can read.
    interface_count = models.PositiveIntegerField(default=0)

    #: Whether this zone can receive traffic at all, and so whether PAN-ZON-001 applies to it:
    #: the zone carries one of the six type subtrees AND either names at least one interface or
    #: is an EXTERNAL zone, which has no interfaces of its own and still offers the attachment.
    #:
    #: TRUE IS THE DEFAULT AND IT INCLUDES THE ROW, chosen deliberately AGAINST the column's own
    #: arithmetic: a zone nobody has recomputed has `zone_type: unknown` and `interface_count:
    #: 0`, which would compute FALSE and silently drop every zone out of the control between the
    #: migration and the recompute pass. This is the applicability gate the control rests on,
    #: and rules.md's direction decides it - a missing reading reported as compliant is a
    #: customer told they are safe on the strength of nothing.
    can_receive_traffic = models.BooleanField(default=True)

    #: Whether NO zone protection profile is actually in force on this zone: the attachment leaf
    #: is empty, OR it names a profile that does not resolve CASE-SENSITIVELY in this
    #: appliance's device-local `ZoneProtectionProfile` collection. True is the finding.
    #:
    #: THE JOIN IS CASE-SENSITIVE AND NOT NORMALISED (help p.663), and the resolution order has
    #: exactly ONE member, measured: `action=complete` answers code=6 Invalid sequence at both
    #: the shared and the vsys spellings of the profile collection, so there is no second scope
    #: to fall through to on a firewall.
    #:
    #: TRUE IS THE DEFAULT AND IT FIRES - a zone whose attachment nobody has resolved reports
    #: itself rather than passing. The alternative reads as a clean estate on exactly the
    #: appliances nobody has looked at.
    zone_protection_unresolved = models.BooleanField(default=True)

    #: Tri-state, unlike every other flag here, because its default is ENABLED. Absent
    #: means on; only an explicit `no` means off. See the normalizer for the measurements.
    packet_buffer_protection = models.BooleanField(null=True, blank=True)

    #: PAN-OS "Enable L3 & L4 Header Inspection" - element `net-inspection`, which is not
    #: derivable from that label and was captured from a device rather than guessed.
    net_inspection = models.BooleanField(default=False)

    # User-ID and Device-ID are structurally identical ACLs and are modelled the same way.
    # Their members mix literal addresses with address-object and address-group NAMES
    # (`ag-agent-desktop-services` is a group), stored as written with no resolution -
    # anything computing the addresses an ACL covers has to resolve them itself.
    enable_user_identification = models.BooleanField(default=False)
    include_acl = models.JSONField(default=list, blank=True)
    exclude_acl = models.JSONField(default=list, blank=True)
    enable_device_identification = models.BooleanField(default=False)
    device_include_acl = models.JSONField(default=list, blank=True)
    device_exclude_acl = models.JSONField(default=list, blank=True)

    #: PAN-IOT-002's second half, as a column because the two lists above are JSON and a
    #: JSON column is reachable from no query - a consumer gate compiles every registered
    #: field and fails on one. There is also no count operator and no way to write an OR
    #: across two columns in one clause, so "either list has at least one member" has to be
    #: computed here or not asked at all.
    #:
    #: True means identification was LIMITED to a named set of addresses rather than applied
    #: to the whole zone. False is the MEASURED meaning of an absent `device-acl` - the grid
    #: renders INCLUDED NETWORKS `any` and EXCLUDED NETWORKS `none` - which is why it cannot
    #: simply be flipped to the firing side: 48 of the 50 zones measured are genuinely in
    #: that state. The unknown is carried by the flag below instead.
    device_identification_is_narrowed = models.BooleanField(default=False)

    #: Whether THIS ROW's Device-ID lists were read and the verdict above computed, as
    #: against the row predating the columns. An empty JSON list is indistinguishable from an
    #: unwritten one and the search layer has no is-null operator, so nothing else can ask.
    #:
    #: It does NOT cover a zone with no row at all: if the per-vsys merged read is missed the
    #: zone is absent rather than unknown, and no column of this model can say so. That is a
    #: collection-coverage question and not a column default.
    device_acl_lists_computed = models.BooleanField(default=False)

    # Pre-NAT Identification. Four independent flags under `network/prenat-identification`,
    # whose element names bear almost no relation to their UI labels - "Source Lookup" is
    # `enable-prenat-source-policy-lookup` and "Enable Original ID Downstream" is
    # `enable-prenat-source-ip-downstream`. Named after the elements, not the labels, so a
    # reader who greps the payload finds them.
    prenat_user_identification = models.BooleanField(default=False)
    prenat_device_identification = models.BooleanField(default=False)
    prenat_source_policy_lookup = models.BooleanField(default=False)
    prenat_source_ip_downstream = models.BooleanField(default=False)

    raw_entry = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name", "pk"]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name"],
                name="integrations_unique_zone_per_enforcement_point",
            ),
        ]
        indexes = [
            models.Index(fields=["management_station"]),
            models.Index(fields=["enforcement_point"]),
        ]

    def __str__(self) -> str:
        return self.name

    def clean(self) -> None:
        """`device_identification_is_narrowed` has to agree with the lists it came from.

        A column derived from a JSON field is checked against that field here, the same way
        `InterfaceManagementProfile` checks its count against its names: the verdict is what
        the control reads, the lists are what a reviewer opens, and a disagreement between
        them would print a zone as narrowed beside two empty lists.
        """
        has_members = bool(self.device_include_acl) or bool(self.device_exclude_acl)
        if self.device_identification_is_narrowed != has_members:
            raise ValidationError(
                "device_identification_is_narrowed must be true exactly when one of the "
                "Device-ID lists holds a member."
            )
        if has_members and not self.device_acl_lists_computed:
            raise ValidationError(
                "device_acl_lists_computed cannot be false on a row whose Device-ID lists "
                "hold members."
            )


class ZoneInterface(models.Model):
    """One interface assigned to a zone, with the addresses configured on it.

    `ip_addresses` is empty for an interface that carries none - a Layer 2 member, an
    unnumbered Layer 3 interface, or one whose addresses this collection did not reach.
    Absence therefore does not mean "no addresses configured"; do not read it that way.
    """

    zone = models.ForeignKey(
        Zone,
        on_delete=models.CASCADE,
        related_name="interfaces",
    )
    name = models.CharField(max_length=64)
    ip_addresses = models.JSONField(default=list, blank=True)
    position = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["position", "name", "pk"]
        constraints = [
            models.UniqueConstraint(
                fields=["zone", "name"],
                name="integrations_unique_zone_interface_per_zone",
            ),
        ]

    def __str__(self) -> str:
        return self.name
