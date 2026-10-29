"""The management plane itself - its addressing and the appliance's operational mode.

PAN-MGT-004 and PAN-MGT-012. Two models, two different kinds of source, one pass, because both
are one row per appliance and the operational mode is read out of a snapshot the addressing
walk already has to be able to tolerate being absent.

    ManagementPlaneAddressing   the merged config's deviceconfig/system leaves
    ApplianceOperationalMode    `show system info`, which is NOT configuration

THE ADDRESS THIS MODULE STORES IS THE CONFIGURATION'S AND NOT THE RUNNING ONE, deliberately.
`show system info` reports a running management address on an appliance whose configuration
holds none - both lab PA-VMs answer 10.0.0.4 and 10.0.0.5 while every one of three config
views is silent at ip-address, netmask and default-gateway, because their address comes from a
DHCP server. Stage 5 declares `management_ip_address` as what the CONFIGURATION holds and says
in terms that the null on such an appliance is the measured state, so filling it from the
operational reply would change what the column means. The running address is a column stage 5
has not declared; it is reachable from `latest_system_info_snapshot` the day one is.

WHY A SECOND ADDRESSING-MODE COLUMN EXISTS IN THIS PACKAGE, and it is reported rather than
reconciled: `SystemIdentity.addressing_mode` (models/device_services.py) already stores
`static`/`dhcp-client` for the same appliance from the same `deviceconfig/system/type` node,
for PAN-SVC-007, and `SystemIdentity.addressing_mode_explicit` records whether the node was
written. `ManagementPlaneAddressing.allocation_mode` is stage 5's declaration for PAN-MGT-004
on a model stage 5 argued for on its own grain. The two cannot disagree about the device - they
read one node through one shared helper - but they are two columns one of which could have been
a join, and which of them should survive is a product decision rather than this module's.
"""

from __future__ import annotations

from typing import Any

from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceOperationalMode,
    ManagementPlaneAddressing,
    address_is_globally_routable,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    choice_child,
    entry_provenance,
    parse_text_field,
    was_absent,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_identification import (
    latest_system_info_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    write_node_row,
)

#: The two branches of `deviceconfig/system/type`, in the order `choice_child` tries them. The
#: node is a CHOICE OF CHILD and not a value: a reader looking for text finds a dict.
ALLOCATION_BRANCHES = (
    ManagementPlaneAddressing.AllocationMode.STATIC,
    ManagementPlaneAddressing.AllocationMode.DHCP_CLIENT,
)

#: An absent `type` node means STATIC, which is the unusual direction for this domain - almost
#: every other leaf here has absence on the firing side.
#:
#: Measured 2026-10-26 as a natural experiment across one HA pair with no write at all:
#: fw-core-tpa-b holds no `type` node in any of three views while holding ip-address
#: 192.168.250.3, netmask 255.255.255.0 and default-gateway 192.168.250.1; fw-core-tpa-a holds
#: {'type': {'static': null}} with equivalent addressing - same model, same version, same
#: template stack - and both PA-VMs hold {'dhcp-client': {...}} and are DHCP-addressed.
#: `show system info` is the independent cross-check and reports addresses for the member
#: holding no `type` node at all.
#:
#: The same reading is declared for `SystemIdentity.type` in `device_services.py`, citing the
#: same natural experiment. See this module's docstring for why there are two.
ALLOCATION_IMPLICIT_CITATION = (
    "payload contract, system-identity.type: implicit 'static' - measured 2026-10-26, "
    "fw-core-tpa-b carries no type node while holding a static address, mask and gateway, and "
    "its HA peer carries {'static': null} with equivalent addressing")

#: NOTHING IS ASSUMED for the address and the gateway, and the reasoning is the part that
#: matters rather than the rung. The absence that exists in this estate is NOT an implicit
#: value: both PA-VMs hold no ip-address because their address comes from DHCP, so the absence
#: asserts "not statically configured", which is a fact about the sibling `type` node and not a
#: value this leaf holds when absent. Recording an implicit value here would be the error.
ADDRESS_IMPLICIT = Implicit.not_assumed(
    "deviceconfig/system/ip-address holds the statically configured management address and an "
    "absent key means the address was not statically configured - which is a fact about the "
    "sibling `type` node, not a value this leaf holds. Both lab PA-VMs are addressed and "
    "routed while holding nothing here")
GATEWAY_IMPLICIT = Implicit.not_assumed(
    "deviceconfig/system/default-gateway is MANAGEMENT-PLANE ROUTING and an absent key means "
    "no STATIC default route is configured - it says nothing about whether the plane has one, "
    "because a dhcp-client plane can be given a default route by the server with nothing in "
    "the configuration. That is why `type/dhcp-client` is read first")


def _system_node(snapshot) -> dict[str, Any]:
    entry = device_entry_from_snapshot(snapshot)
    deviceconfig = entry.get("deviceconfig") if isinstance(entry, dict) else None
    system = deviceconfig.get("system") if isinstance(deviceconfig, dict) else None
    return system if isinstance(system, dict) else {}


def classify_exposure_posture(*, allocation_mode: str, globally_routable: bool,
                              static_default_gateway: str | None) -> str:
    """How far the plane's own addressing and routing place it from an uncontrolled network.

    Precedence, and the first two lines are what make this a classification rather than three
    independent tests:

        dhcp-client                          dynamically_allocated
        a globally routable address          routable_address
        private, a static default route      private_with_default_route
        private, no static default route     private_no_default_route

    DHCP IS TESTED FIRST, and that order is the whole point. On such an appliance the
    configuration holds NEITHER an address NOR a route while the plane is both addressed and
    routed, so every other branch would be reading absences: `address_is_globally_routable` is
    true by its own firing-side default and `default-gateway IS NULL` is true of exactly the
    appliances whose route the configuration cannot see. Ranking that case among the other three
    would make the reassuring grade reachable by reading two absences.

    It grades the configuration's CONTRIBUTION to exposure. It is not a statement that the
    plane is reachable - the firewall holds the address, the mask and the fact that a route
    leaves the segment, and nothing at all about whether what those reach is a network the
    organisation controls. Stage 4's open question in its own words, and no field on any
    appliance answers it.
    """
    if allocation_mode == ManagementPlaneAddressing.AllocationMode.DHCP_CLIENT:
        return ManagementPlaneAddressing.POSTURE_DYNAMIC
    if globally_routable:
        return ManagementPlaneAddressing.POSTURE_ROUTABLE
    if (static_default_gateway or "").strip():
        return ManagementPlaneAddressing.POSTURE_PRIVATE_WITH_ROUTE
    return ManagementPlaneAddressing.POSTURE_PRIVATE_NO_ROUTE


def operational_mode_from_payload(payload: Any) -> str:
    """`show system info`'s operational-mode, verbatim, or "" when the read is not there.

    EMPTY MEANS THE READ WAS NOT TAKEN and never that the field was absent from a reply that
    arrived: the field cannot be absent, there being no xpath at which it could be missing, and
    both operational reads returned a value on all four lab appliances. The two states must not
    be conflated, because `normal` is the NON-compliant value - storing it on a row nobody read
    would be the one case in this domain where an unread row looked better than it is.

    Guards `isinstance(payload, str)`: `Snapshot.payload` is a JSONField and
    `extract_result_payload` returns `response.response.result` whatever its type, so a PAN-OS
    op command answering plain text stores a `str` that round-trips. `payload or {}` does not
    save a caller from it - a non-empty string is truthy.
    """
    if not isinstance(payload, dict):
        return ""
    system = payload.get("system")
    if not isinstance(system, dict):
        return ""
    value = system.get("operational-mode")
    if isinstance(value, dict):
        value = value.get("#text")
    return str(value or "").strip()


def normalize_management_plane(appliance: Appliance) -> dict[str, int]:
    """Both rows for one appliance, anchored to the MERGED snapshot.

    Anchored there and not to the operational read, for the reason
    `normalize_device_identification_state` gives for the same choice: an appliance that has
    been collected and never asked for `show system info` still gets an operational-mode row,
    holding the blank that fires, rather than no row at all. A missing row and a row saying "not
    the approved mode, and nobody confirmed whether it must be" are different things for a
    reader, and only the second is the item an assessor is owed.
    """
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"management_plane_addressings": 0, "appliance_operational_modes": 0}
    system = _system_node(snapshot)

    mode, _mode_body = choice_child(system.get("type"), ALLOCATION_BRANCHES)
    if mode:
        type_rk, type_rv = entry_provenance(system.get("type"))
    else:
        # Absent, or holding a branch nobody has seen. `choice_child` returns ("", {}) for both
        # and says the caller must resolve it to a measured default - which is `static`.
        mode = ManagementPlaneAddressing.AllocationMode.STATIC
        type_rk, type_rv = Implicit.measured(mode, ALLOCATION_IMPLICIT_CITATION), None

    address, address_rk, address_rv = parse_text_field(
        system.get("ip-address"), implicit=ADDRESS_IMPLICIT)
    gateway, gateway_rk, gateway_rv = parse_text_field(
        system.get("default-gateway"), implicit=GATEWAY_IMPLICIT)
    # `parse_text_field` renders "store nothing" as the empty string, and this column is
    # nullable because stage 5 declares the absence as a state a finding prints. `was_absent`
    # is the only correct absence test - an absent key arrives as an `Implicit`, not as ABSENT.
    stored_address = None if was_absent(address_rk) else address
    stored_gateway = None if was_absent(gateway_rk) else gateway

    routable = address_is_globally_routable(stored_address or "")
    posture = classify_exposure_posture(
        allocation_mode=mode,
        globally_routable=routable,
        static_default_gateway=stored_gateway)

    operational_mode = operational_mode_from_payload(
        getattr(latest_system_info_snapshot(appliance), "payload", None))
    # Case-insensitively, which is deliberate and is the one thing stage 4's open question
    # about the spelling turned out not to decide: every shipped text compiler maps `eq` to
    # `iexact`, so a case difference does not decide a clause either. What a predicate cannot
    # do is tell "the read was taken and said normal" from "no read was taken", which is why
    # this verdict is computed here and not claused.
    approved = operational_mode.casefold() == ApplianceOperationalMode.APPROVED_MODE.casefold()

    with transaction.atomic():
        write_node_row(
            ManagementPlaneAddressing, appliance, snapshot,
            {
                "allocation_mode": mode,
                "management_ip_address": stored_address,
                "static_default_gateway": stored_gateway,
                "address_is_globally_routable": routable,
                "exposure_posture": posture,
            },
            [
                ("allocation_mode", type_rk, type_rv),
                ("management_ip_address", address_rk, address_rv),
                ("static_default_gateway", gateway_rk, gateway_rv),
            ])
        write_node_row(
            ApplianceOperationalMode, appliance, snapshot,
            {
                "operational_mode": operational_mode,
                "approved_cryptography_mode": approved,
            },
            # NO PROVENANCE ROWS, and `provenance=()` is how that is said: `write_node_row`
            # deletes only the rows for the fields it writes, so an empty list writes none and
            # erases none. `ProvenanceType` has ten members and all ten are about where a
            # CONFIGURATION value came from; `classify_prov_type`'s fallthrough for an unmarked
            # present value is `local`, "defined on this device", which is the one thing a
            # runtime reading is not. Both columns are in `DERIVED_FIELDS` instead - the
            # convention `LoggingSettings` set for its two runtime columns.
            ())
    return {"management_plane_addressings": 1, "appliance_operational_modes": 1}
