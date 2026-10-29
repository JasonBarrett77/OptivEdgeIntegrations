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

Which services a surface exposes is `ManagementService` below - a child table rather than
columns, because the two planes carry overlapping but unequal service sets and a column per
service would mean permanently-NULL fields whose NULL meant "not applicable here" rather
than "unknown".
"""

from __future__ import annotations

import ipaddress

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class ManagementInterface(ProvenancedMixin, SyncTrackedModel):

    #: Computed here: referenced but never defined, and a verdict over this surface's own
    #: service rows. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "is_management_surface",
    )
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

    #: `plane` and `interface_name` together identify the surface. How it is NAMED in a
    #: report - "MGT", "Aux-1", "ethernet1/1" - is a consumer's choice, not stored here;
    #: OptivEdgeAssessments composes it. This model stores what was collected and stops.
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

    #: Does this surface offer a way to ADMINISTER the device at all? PAN-MGT-003's
    #: applicability.
    #:
    #: True on the three deviceconfig planes unconditionally - their permitted-source list
    #: governs every service on the port, the monitoring ones included - and on a data-plane
    #: surface only where the bound profile enables one of `ADMINISTRATIVE_SERVICE_NAMES`.
    #:
    #: A DISJUNCTION, which is why it is a column: a plane test OR a quantifier over the
    #: related `services` rows, and the consumer's clause grammar is one conjunction with no
    #: OR and no quantifier over related rows.
    #:
    #: DEFAULT TRUE, deliberately, and it is the FIRING side: a row nobody has recomputed is
    #: treated as administrable, so PAN-MGT-003's applicability clause lets it through and the
    #: control reports it. The opposite default would turn that applicability clause into a
    #: SUPPRESSION - the same field read the other way silencing exactly the rows nobody
    #: measured, which reads as the careful choice and is not.
    is_management_surface = models.BooleanField(default=True)


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
        return f"{self.appliance} / {self.plane}{f':{self.interface_name}' if self.interface_name else ''}"

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


class PermittedSource(ProvenancedMixin, models.Model):
    """One literal source restriction on a management surface.

    Always a literal. Address objects, groups, hostnames and ranges are all rejected by
    PAN-OS on both planes, so nothing here needs resolving - measured 2026-08-27.

    Provenance is a FieldProvenance row under `field_name="__entry__"`, the same mechanism
    SecurityRule, DeviceConfigurationProfile, the policy objects and InterfaceManagementProfile
    use. The row IS one value here, so "__entry__" is that value's own provenance.

    Absence of a row means the key was absent from the payload - PAN-OS supplied its own
    default and nobody pushed or configured anything. A key that was written locally gets a
    row typed `local`. That distinction is free from this mechanism and was impossible with
    the bare name column this replaces.
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


#: Every service either management plane can carry, as the POSITIVE name.
#:
#: Measured 2026-08-31 by `action=complete` against a PA-5220 on both nodes: the
#: deviceconfig planes accept ten keys, all spelled `disable-*`; an interface management
#: profile accepts eleven, all positive. Nine names are shared. `icmp` exists only on the
#: deviceconfig planes and `ping`/`response-pages` only on a profile.
#:
#: `icmp` and `ping` are stored as the distinct keys the configuration uses. Whether they
#: denote the same underlying service is UNMEASURED - `action=complete` returned no help
#: strings, and no control needs the answer, since neither is an administrative service.
#: Deciding they are the same would be interpretation, which is not this layer's job.
SERVICE_NAMES = (
    "http",
    "https",
    "ssh",
    "telnet",
    "snmp",
    "icmp",
    "ping",
    "response-pages",
    "http-ocsp",
    "userid-service",
    "userid-syslog-listener-ssl",
    "userid-syslog-listener-udp",
)

#: The five services whose presence makes a surface an ADMINISTRATION surface, as against a
#: reachability or monitoring one. Read by `ManagementInterface.is_management_surface` and by
#: `InterfaceManagementProfile.unbound_exposure_class`, both of which are stored verdicts.
#:
#: THIS SET IS ALSO DECLARED IN OptivEdgeAssessments, as `ADMINISTRATIVE_SERVICES` in
#: `assessments/search/management_interface/fields/services.py`, whose module docstring says
#: it "deliberately does not live in OptivEdgeIntegrations" because "whether a service
#: constitutes administrative access is an assessment question, not a collection one".
#:
#: That boundary is crossed here and the crossing is not this module's choice: stage 5's
#: `management-services` artifact declares two columns computed at NORMALISATION whose
#: definition is this set, because each is a disjunction the consumer's clause grammar cannot
#: express. Implemented as declared and reported, per the pipeline rule that a defect is
#: recorded and not fixed mid-run. The two copies can drift, and the drift would move what a
#: finding counts as administrative without either side failing; whoever reconciles them owns
#: that decision. The members are identical as of 2026-10-29.
ADMINISTRATIVE_SERVICE_NAMES = ("http", "https", "ssh", "telnet", "snmp")


class ManagementService(ProvenancedMixin, models.Model):
    """One service on one management surface, with plane polarity already resolved.

    The polarity difference is the whole reason this is normalized at collection. A
    deviceconfig plane says `disable-telnet: yes` and a profile says nothing at all, and
    both mean telnet is off. Storing the raw key would push that inversion into every
    consumer, and a consumer that forgets it reports the exact opposite of the truth.

    So `enabled` is always the effective answer: True means the service is on. Nothing here
    records WHICH plane spelling produced it, because no question so far is asked of the
    spelling - the surface and the effective value are what a control asserts against.

    Provenance is a FieldProvenance row under `field_name="__entry__"`, the same mechanism
    SecurityRule, DeviceConfigurationProfile, the policy objects and InterfaceManagementProfile
    use. The row IS one value here, so "__entry__" is that value's own provenance.

    Absence of a row means the key was absent from the payload - PAN-OS supplied its own
    default and nobody pushed or configured anything. A key that was written locally gets a
    row typed `local`. That distinction is free from this mechanism and was impossible with
    the bare name column this replaces.
    

    A row exists for every service its plane supports, whether on or off. Absence therefore
    means the service does not exist on that plane at all, which is a different fact from
    "off" and one a consumer would otherwise have to reconstruct from the plane.
    """

    management_interface = models.ForeignKey(
        ManagementInterface, on_delete=models.CASCADE, related_name="services")
    name = models.CharField(max_length=32, choices=[(n, n) for n in SERVICE_NAMES])
    #: The effective state, implicit values already applied. Never null: a service valid on
    #: this plane is either on or off, and one that is not valid has no row.
    enabled = models.BooleanField()


    class Meta:
        ordering = ["management_interface", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["management_interface", "name"],
                name="integrations_unique_management_service_per_surface"),
        ]
        #: (name, enabled) serves the question every services control asks: which surfaces
        #: have any of these services on.
        indexes = [models.Index(fields=["name", "enabled"])]

    def __str__(self) -> str:
        return f"{self.management_interface} {self.name}={'on' if self.enabled else 'off'}"
