"""Two facts about the management PLANE itself, as against the surfaces on it.

`ManagementInterface` is one row per administrative SURFACE - the MGT port, each aux port,
and every traffic-carrying interface a profile has made administrable - and it holds the
services and the permitted sources of each. It holds no addressing at all, and it could not:
its grain is the surface, the addressing leaves are one per APPLIANCE, and three of the four
surface rows would carry permanently-null addressing columns whose null meant "not applicable
here". That is the same argument that put a surface's services in a child table.

So two appliance-grained models:

    ManagementPlaneAddressing   PAN-MGT-004   deviceconfig/system/{ip-address,netmask,
                                              default-gateway,type}
    ApplianceOperationalMode    PAN-MGT-012   `show system info`'s operational-mode, which
                                              is held in NO configuration node at any scope

On an HA pair each is two rows for two appliances, and in both cases that is a real
difference rather than duplication: the peers have different management addresses and are
separately reachable, and the mode is set per appliance from maintenance mode and is
synchronised by nothing.

NEITHER MODEL IS A REMEDIATION TARGET for its addressing columns. Jason's standing
restriction: no change to a management IP address or to management-plane routing is to be
proposed or implied. These columns exist so a finding can PRINT the value an assessor has to
go and look at; the remediation the control carries is a reachability test, which is a
person's work.
"""

from __future__ import annotations

import ipaddress

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


def address_is_globally_routable(address: str) -> bool:
    """Is this literal an address the public internet can route to?

    True where it falls outside the private, loopback, link-local and other reserved ranges,
    and TRUE FOR ANYTHING THAT DOES NOT PARSE OR IS ABSENT - which is the firing side and is
    the whole reason this is a function rather than an inline test. An address nobody could
    classify has not been shown to be private.

    `ipaddress`'s own `is_global` is what decides it, and it is asked rather than reimplemented
    as a list of CIDR literals: the reserved set has grown (100.64/10, 198.18/15) and a
    hand-written list silently stops covering it.
    """
    text = str(address or "").strip()
    if not text:
        return True
    try:
        return bool(ipaddress.ip_address(text).is_global)
    except ValueError:
        return True


class ManagementPlaneAddressing(ProvenancedMixin, SyncTrackedModel):
    """How one appliance's management plane is addressed and routed. PAN-MGT-004.

    THE GAP THIS MODEL CANNOT CLOSE, and it is the control's own: the firewall holds the
    address, the mask and whether a route leaves the segment, and NOTHING about whether the
    network those reach is one the organisation controls. So `exposure_posture` grades the
    configuration's CONTRIBUTION to exposure and is not a statement that the plane is
    reachable.

    Two of the four lab appliances hold no address, no mask and no gateway in ANY of three
    configuration views while being both addressed and routed, because their address comes
    from a DHCP server. That is why `allocation_mode` is read first and why the fourth posture
    class exists: on such an appliance `default-gateway IS NULL` is true of exactly the
    appliances whose route the configuration cannot see.
    """

    #: Computed here: parsed from the address literal and classified over three columns. See
    #: ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "address_is_globally_routable",
        "exposure_posture",
    )

    class AllocationMode(models.TextChoices):
        STATIC = "static", "Static"
        DHCP_CLIENT = "dhcp-client", "DHCP client"

    #: The four posture classes, worst first, which is also the precedence the classifier
    #: walks. `dynamically_allocated` is deliberately NOT ranked among the other three: on such
    #: an appliance the configuration sees neither the address nor the route, so a grade would
    #: be a claim about values nothing here holds.
    POSTURE_ROUTABLE = "routable_address"
    POSTURE_PRIVATE_WITH_ROUTE = "private_with_default_route"
    POSTURE_PRIVATE_NO_ROUTE = "private_no_default_route"
    POSTURE_DYNAMIC = "dynamically_allocated"
    POSTURE_CHOICES = [
        (POSTURE_ROUTABLE, "On a globally routable address"),
        (POSTURE_PRIVATE_WITH_ROUTE, "Private, with a static default route"),
        (POSTURE_PRIVATE_NO_ROUTE, "Private, with no static default route"),
        (POSTURE_DYNAMIC, "Dynamically allocated - the configuration holds neither"),
    ]

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="management_plane_addressings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="management_plane_addressings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="management_plane_addressings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="management_plane_addressings")

    #: How the address was allocated. Encoded on the device as WHICH CHILD of `type` exists
    #: rather than as a value, and an ABSENT `type` node means static - which is the unusual
    #: direction for this domain, where almost every other leaf has it the other way.
    #:
    #: Measured 2026-10-26 as a natural experiment across one HA pair with no write at all:
    #: one member holds no `type` node in any of three views while holding ip-address
    #: 192.168.250.3, netmask 255.255.255.0 and default-gateway 192.168.250.1, and its peer
    #: holds {'type': {'static': null}} with equivalent addressing - same model, same version,
    #: same template stack.
    #:
    #: DEFAULTS TO THE REASSURING SIDE AND NOTHING CLAUSES ON IT, which is why that is
    #: acceptable: `static` is the mode under which an absent default-gateway is readable as
    #: "no default route", this control's most compliant grade. The column PAN-MGT-004 clauses
    #: on is `exposure_posture`, which defaults to the worst class and fires.
    allocation_mode = models.CharField(
        max_length=16, choices=AllocationMode.choices, default=AllocationMode.STATIC)

    #: The plane's own address AS THE CONFIGURATION HOLDS IT. NULL on a DHCP-addressed
    #: appliance, where the configuration holds no address at all - and that null is a MEASURED
    #: state rather than only an unread one.
    #:
    #: NULLABLE AND NOT BLANK-DEFAULTED, deliberately, because the two states are different
    #: facts and the control prints one of them. The cost is recorded rather than discovered:
    #: `is_empty` compiles to `filter(field="")` in every per-model compiler in
    #: OptivEdgeAssessments, so a null is unreachable by the one operator written for absence.
    #: Both of these columns are `needs_compiler_field` - no compiler exists for either yet -
    #: so whoever writes one must test NULL as well as "", and a plain `is_empty` clause would
    #: match nothing on exactly the appliances this column is null on.
    management_ip_address = models.CharField(max_length=64, null=True, blank=True)
    #: The plane's STATIC default gateway as the configuration holds it. NULL means NO STATIC
    #: DEFAULT ROUTE IS CONFIGURED, which is NOT the same as the plane having no route: on a
    #: DHCP-addressed appliance a default route arrives from the server with nothing in the
    #: configuration. A clause that read this leaf alone and reported "no default route on the
    #: management port" would report this control's PREFERRED STATE on a device that has one.
    #:
    #: Same nullability note as the column above.
    static_default_gateway = models.CharField(max_length=64, null=True, blank=True)

    #: Whether the stored address is one the public internet can route to. True is the firing
    #: side, and the default: an address nobody has classified has not been shown to be
    #: private. A row nobody has recomputed therefore reports at this control's worst grade,
    #: which is louder than the alternative and is the direction the pipeline requires - the
    #: cost is a finding on an appliance that may be fine, checkable in a minute and arriving
    #: with the address attached.
    address_is_globally_routable = models.BooleanField(default=True)
    #: The class above. DEFAULTS TO THE WORST, for the same reason: the alternative default -
    #: the private, routeless class - would report the catalogue's preferred state for every
    #: unrecomputed row.
    exposure_posture = models.CharField(
        max_length=32, choices=POSTURE_CHOICES, default=POSTURE_ROUTABLE)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="unique_management_plane_addressing_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} management plane addressing"


class ApplianceOperationalMode(ProvenancedMixin, SyncTrackedModel):
    """The cryptographic operational mode one appliance reports. PAN-MGT-012.

    THERE IS NO CONFIGURATION NODE FOR THIS AT ANY SCOPE. The mode is set from maintenance
    mode, it is not in the running config, and it is reported at
    `/response/result/system/operational-mode` in the `show system info` reply. `show
    fips-mode` - the command a reader reaches for - answers code=17 "show -> fips-mode is
    unexpected" on all four lab appliances, and the CLI grammar carries no node for it.

    NEITHER COLUMN CARRIES A PROVENANCE ROW, and that is not a lapse. There is no
    configuration key and therefore no marker: `ProvenanceType`'s ten members are all about
    where a CONFIGURATION value came from, and `classify_prov_type`'s fallthrough for an
    unmarked present value is `local` - "defined on this device" - which is the one thing a
    runtime reading is not. Both columns are in `DERIVED_FIELDS` instead, which is the
    convention `LoggingSettings` already set for its two runtime columns: `derived` is not
    accurate about where the value came from, but it is accurate about the only thing a reader
    must not get wrong, which is that it did not come from the configuration.

    WHAT THIS MODEL DOES NOT LICENCE. OptivEdgeAssessments records, and Jason decided
    2026-09-04, that a half-implemented assessment of this mode "would lie - a device in
    FIPS-CC mode would be judged against normal-mode defaults, and would be reported as
    failing controls it satisfies and passing ones it does not". That runs OUTWARDS: implicit
    values differ by mode, so an unanswered mode propagates into every other domain's findings
    wherever a control reasons from an absent key. The stored value here MUST NOT be used to
    reinterpret another domain's default until that question is answered estate-wide, and no
    device in this estate runs the other mode, so it cannot be measured on current hardware
    either.
    """

    #: Computed here: a runtime reply has no configuration marker, and the verdict is a
    #: comparison over it. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "operational_mode",
        "approved_cryptography_mode",
    )

    #: The approved-cryptography mode, as the catalogue and the vendor spell it. ONLY THE OTHER
    #: SPELLING IS MEASURED: the device answered lowercase `normal` on all four lab appliances
    #: through both operational reads, and no appliance in this estate is in this mode, so
    #: whether the device spells it `FIPS-CC`, `fips-cc` or something else is UNMEASURED.
    #: Neither available instrument can enumerate it - action=complete needs an xpath and there
    #: is none. The comparison below is therefore case-insensitive on purpose.
    APPROVED_MODE = "FIPS-CC"
    #: NOT IN THE APPROVED MODE - the non-compliant value for this control where it applies,
    #: and simultaneously the value every appliance in this estate reports.
    NORMAL_MODE = "normal"

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="appliance_operational_modes")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="appliance_operational_modes")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="appliance_operational_modes", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="appliance_operational_modes")

    #: The mode VERBATIM as the appliance answers it. EMPTY MEANS THE READ WAS NOT TAKEN, which
    #: is a different state from any value the field can hold: the field cannot be absent from
    #: a reply that arrived, there being no xpath at which it could be missing, but the READ can
    #: be missing. Storing `normal` on a row nobody read would be the one case in this domain
    #: where an unread row looked WORSE than it is rather than better - `normal` being the
    #: non-compliant value - so the blank is kept and the verdict beside it fires.
    operational_mode = models.CharField(max_length=32, blank=True)
    #: The verdict, compared without regard to case. FALSE IS THE FIRING SIDE and the default:
    #: an appliance nobody has read has not been shown to be in the approved mode.
    #:
    #: It is a finding only where the obligation exists, and NOTHING ON THE DEVICE RECORDS THAT
    #: OBLIGATION - so what a finding on this column says is "the mode is not the approved one
    #: and nobody has confirmed whether it must be", which is an item an assessor is owed
    #: rather than a verdict.
    approved_cryptography_mode = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="unique_appliance_operational_mode_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} operational mode"
