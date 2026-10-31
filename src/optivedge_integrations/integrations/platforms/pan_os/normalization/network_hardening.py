"""Network hardening normalization - PAN-NET-001 to PAN-NET-007.

SIX ENTRY POINTS AND ONE SHARED PAYLOAD. Every column of every subject in this domain
arrives in the SAME `show config merged` dump - one call for the whole device - so nothing
here collects anything and nothing here needs a second read. The one exception is the
tunnel-inspect rulebase a Panorama device group pushes, which the merged view does NOT
carry and which `show config pushed-shared-policy` already collects per enforcement point.

    normalize_session_settings(appliance)           one row per appliance
    normalize_lldp_global_settings(appliance)       one row per appliance
    normalize_dhcp_interface_configs(appliance)     one row per DHCP-configured interface
    normalize_tunnel_inspection_coverage(appliance) one row per appliance/scope/vsys
    normalize_routing_adjacencies(appliance)        one row per adjacency

and five pure functions - `restricts_sources`, `zone_membership`, `lldp_reading`,
`announced_content` and `out_of_service_residue` - which `normalization/interfaces.py`
imports to fill the eight columns PAN-NET-001 and PAN-NET-003 added to `Interface`. They
live here rather than there because they are this domain's reasoning and that module is
shared by three other consumers; what it imports is five functions and no state.

MERGED IS CANDIDATE-DERIVED, which is the one caveat covering every column below: a column
reports what an administrator has TYPED rather than what the firewall enforces, so an
uncommitted strip of a port reads as already stripped. For PAN-NET-004 and PAN-NET-006 the
direction is over-reporting and under-reporting respectively, and neither is detectable from
the payload.

Measured against 013201001475 (PA-5220, 11.1.13-h3, multi-vsys), 013201001085 (PA-5220,
11.1.13-h3, multi-vsys), 691665AC334B458 (PA-VM, 11.2.5) and 6A9C0A9904E7D6E (PA-VM,
11.2.3-h3) on 2026-10-29. APPLIANCES ARE NAMED BY SERIAL throughout: 691665AC334B458
answers to the factory-default hostname `PA-VM` and has never had one set, while every
artifact calls it `pan-fw-201`.
"""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    EnforcementPoint,
    FieldProvenance,
    Interface,
    NormalizationIssue,
    PanOsDhcpInterfaceConfig,
    PanOsLldpGlobalSettings,
    PanOsRoutingAdjacency,
    PanOsSessionSettings,
    PanOsTunnelInspectionCoverage,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    Implicit,
    classify_prov_type,
    ensure_list,
    entry_container,
    member_values,
    parse_text_field,
    parse_yes_no_field,
    provenance_raw_key,
    provenance_value,
    pushed_vsys_panorama,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot as latest_appliance_merged_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    write_node_row,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.zones import (
    ZONE_NETWORK_TYPES,
)


# ---------------------------------------------------------------------------
# The implicit declarations, with what each one rests on
# ---------------------------------------------------------------------------

#: `deviceconfig/setting/config/rematch`. THE VENDOR SAYS ENABLED BY DEFAULT AND NOBODY HAS
#: MEASURED IT - Networking Administrator's Guide p.726 "This capability is enabled by
#: default", and again at p.732 - and reading the vendor is not measuring. No oracle moves:
#: `show session info` carries about sixty dataplane settings and no rematch field, `show
#: system state filter *rematch*` answers NO_MATCHES on all four lab appliances, `show
#: session rematch` reports whether a rematch has EXECUTED rather than the setting, and the
#: read-only UI panel renders a boolean as a div whose innerText is empty either way. The
#: Help has been wrong about a default on this estate before - `disable-http` is documented
#: implicit `no` and measures `yes`.
REMATCH_ABSENT = Implicit.not_assumed(
    "the vendor documents `rematch` as enabled by default in two places and nobody has "
    "measured it: `show session info` has no rematch field, `show system state filter "
    "*rematch*` answers NO_MATCHES on all four lab appliances, and `show session rematch` "
    "reports whether a rematch has executed rather than the setting. One screenshot of "
    "Device > Setup > Session read by eye settles it, with no write and no commit.")

#: `deviceconfig/setting/session/ipv6-firewalling`. The strongest measurement in the domain
#: and the only one where the absence REASSURES, so it is worth the citation: the positive
#: control was paid in both directions on a committed state.
IPV6_FIREWALLING_ABSENT = Implicit.measured(
    True,
    "stage4-network-hardening.json, deviceconfig-setting-session.ipv6-firewalling: "
    "measured 2026-10-26 on 6A9C0A9904E7D6E in BOTH directions on a committed state - key "
    "absent, `show session info` reports ipv6-fw True; `no` committed at 19:51:28 and the "
    "same oracle reports False; the leaf deleted and that delete committed, and the oracle "
    "reports True again - and corroborated on four appliances across two platforms, two "
    "major versions and both vsys modes. The vendor is SILENT on this default in both "
    "places it describes the field while giving explicit defaults for several neighbours "
    "on the same screen, so the silence is selective.")

#: `deviceconfig/setting/session/tcp-reject-non-syn`. PAN-ZON-006's device-wide half, added by
#: the `zone-dos-protection` domain. THE SECOND MEASUREMENT IN THIS NODE WHERE THE ABSENCE
#: REASSURES, and like `ipv6-firewalling` above it was paid in both directions on a committed
#: state - which is why it carries a citation rather than an inference.
#:
#: WHAT KEEPS THE REASSURING VALUE OFF A FINDING is that no control clauses on the column: the
#: assertion clauses on `ZoneProtectionProfile.non_syn_reject_effective`, which resolves this
#: value through the profile's own three-valued pointer and whose own default is the firing side.
TCP_REJECT_NON_SYN_ABSENT = Implicit.measured(
    True,
    "stage4-zone-dos-protection.json, session-settings.tcp-reject-non-syn: measured "
    "2026-10-25 on 691665AC334B458 (PA-VM 11.2.5) in BOTH directions on a committed state - "
    "the node has never existed on that appliance and `show session info` answers "
    "`tcp-nonsyn-rej: True`; `no` written and committed and the same oracle reports False; "
    "the leaf deleted and that delete committed, and the oracle reports True again, with the "
    "per-zone `show zone-protection` report moving in step both times. `show system state "
    "filter *non-syn*` answers NO_MATCHES, so the dataplane read is the only oracle and the "
    "CLI command index is the only thing that finds it.")

#: `network/lldp/enable`. SETTLED 2026-10-31 and it was `Implicit.not_assumed` until then,
#: because stage 4 had left the meaning of the absence unsettled in both directions - the
#: write that would have settled it failed with ConnectTimeout when Panorama became
#: unreachable. The absence itself was never in doubt: `action=get` (None), `action=show`
#: (`No such node`) and `show config running` (`No such node`) at network/lldp and at
#: network/lldp/enable, on all four appliances.
#:
#: THE DEVICE'S RULE IS AN AND AND THE REPORT'S IS AN OR, and the two are not in conflict.
#: PAN-OS enables LLDP on an interface only where this switch AND the interface's own
#: `lldp/enable` enable it, so a port configured to announce on a firewall whose global
#: switch is off is NOT announcing. PAN-NET-003 reports it anyway, because it is one
#: checkbox away - standing-rulings section 6, A CONTROL WITH TWO HALVES FIRES IF EITHER
#: HALF FIRES. Nothing here resolves one half against the other: this column keeps storing
#: what the configuration holds, and the clause carries both halves.
LLDP_GLOBAL_ABSENT = Implicit.measured(
    False,
    "stage4-network-hardening.json objects['lldp-global'].fields.enable.implicit: an absent "
    "network/lldp asserts that LLDP is OFF firewall-wide. Settled 2026-10-31 by Jason's "
    "ruling - 'The global LLDP enable setting's implicit value is off' - and the artifact "
    "records the provenance split so it can be argued with: the ABSENCE is measured on all "
    "four appliances by three instruments, the MEANING is the ruling rather than a read "
    "taken on this estate, and `settled_by.positive_control` says NOT PAID because the "
    "write that would pay it was lost to the 20:15:49 Panorama outage")

#: `network/dhcp/interface/entry/server/mode`. No state B was ever reached: the experiment
#: that would have shown whether `mode` is MANDATORY on a bare server branch was scripted
#: and lost to a Panorama outage.
DHCP_SERVER_MODE_ABSENT = Implicit.not_assumed(
    "nothing establishes whether `mode` is mandatory on a bare DHCP server branch, and "
    "two of its three values ENABLE the server - so a guess would be a guess about "
    "whether an unconfigured branch serves addresses. The prior art points at mandatory: "
    "a DHCP interface writes cleanly and fails commit, and the vendor requires the "
    "interface to be in a virtual router and a zone first. One `validate full` against a "
    "bare <server/> would report the whole mandatory set in a single call.")

#: `network/dhcp/interface/entry/relay/ip/enabled`.
DHCP_RELAY_ENABLED_ABSENT = Implicit.not_assumed(
    "nothing establishes what an absent `enabled` on a configured relay branch does - the "
    "write was attempted during the outage that took Panorama unreachable and never "
    "reached a device. A relay that is configured and silently assumed off is the "
    "reassuring direction on a control about relays that should not exist at all, so "
    "nothing is stored and the verdict beside it treats the branch as configured.")

#: `deviceconfig/setting/tunnel-acceleration`. A natural experiment whose positive control
#: the estate had already paid.
TUNNEL_ACCELERATION_ABSENT = Implicit.measured(
    True,
    "stage4-network-hardening.json, deviceconfig-setting-tunnel-acceleration: measured "
    "2026-10-26 as a natural experiment - three appliances across two platforms and two "
    "major versions hold no tunnel-acceleration node in get, show or `show config "
    "running` and all three report `tunnel-accel: True` in `show session info`, while "
    "6A9C0A9904E7D6E stores `no` and reports False. The vendor agrees: 'By default, "
    "supported firewalls perform tunnel acceleration' (Networking guide p.761). Note that "
    "the leaf's value and the feature's availability on the model are two different "
    "questions - the oracle reports True on a PA-5220 and a PA-VM regardless.")

#: `protocol/bgp/peer-group/peer/connection-options/authentication`, and the OSPF sibling.
#: THE DIRECTION IS SAFE: materialising "no profile bound" on an adjacency that has none
#: reports an unauthenticated adjacency as unauthenticated.
ROUTING_AUTH_ABSENT = Implicit.measured(
    "",
    "stage4-network-hardening.json, virtual-router."
    "protocol/bgp/peer-group/peer/connection-options/authentication and "
    "protocol/ospf/area/interface/authentication: an absent reference asserts that the "
    "adjacency is UNAUTHENTICATED - measured as an absence in three config views on four "
    "appliances, with the reference pool scoped to the peer's own virtual router and empty "
    "on all seven routers, and with operational confirmation that no BGP adjacency exists "
    "at all (`show routing protocol bgp summary` null, BGP-Routes 0). The positive control "
    "was NOT paid: the write that would have put a resolvable name in the leaf was in the "
    "batch an outage cut off, so the reading rests on there being no default to fall "
    "back to.")

#: `protocol/bgp/peer-group/peer/max-prefixes`.
MAX_PREFIXES_ABSENT = Implicit.not_assumed(
    "no state B was reached: no BGP peer existed anywhere in the estate when this was "
    "measured, and the one scripted never reached the device. The available inference is "
    "reasoning from the enum rather than a reading - a field whose only keyword is "
    "`unlimited` is most plausibly unlimited when absent - and no oracle reports a peer's "
    "prefix limit. THE VENDOR IS COMPLETELY SILENT: `probe.corpus max-prefixes` at rung 1 "
    "returns no sections across all eight documents, so this is silence that can be cited.")


ISSUE_KIND = "routing_adjacency"


def _text(node: Any) -> str:
    """A leaf that may be a bare string or `{'#text': v, '@ptpl': ...}` when pushed."""
    if isinstance(node, dict):
        return str(node.get("#text") or "").strip()
    return str(node or "").strip()


def _dict(node: Any) -> dict[str, Any]:
    return node if isinstance(node, dict) else {}


def _entries(node: Any) -> list[dict[str, Any]]:
    """The `entry` children of a container that may be absent, null, one or many."""
    return [e for e in ensure_list(_dict(node).get("entry")) if isinstance(e, dict)]


# ---------------------------------------------------------------------------
# The Interface columns - pure functions, imported by normalization/interfaces.py
# ---------------------------------------------------------------------------

def management_profiles_by_name(device_entry: dict) -> dict[str, dict[str, Any]]:
    """`network/profiles/interface-management-profile` entries, keyed by name.

    The pool is DEVICE-WIDE rather than vsys-scoped, measured: `action=complete` at the
    binding leaf answered nine candidate names on each PA-5220 and seven and two on the
    PA-VMs, all from the one device-wide container.
    """
    profiles = _dict(_dict(device_entry.get("network")).get("profiles"))
    return {
        name: entry
        for entry in _entries(profiles.get("interface-management-profile"))
        if (name := str(entry.get("@name") or "").strip())
    }


def restricts_sources(profile_name: str, profiles: dict[str, dict[str, Any]]) -> bool:
    """Does the profile bound to this port restrict WHICH SOURCES may reach its services?

    False where no profile is bound, where the named profile does not resolve, and where
    it resolves and carries no permitted-source list. ALL THREE ARE THE UNRESTRICTED
    READING and the direction is deliberate: an absent `permitted-ip` means ANY source,
    which is the most permissive answer available, and a dangling binding still permits
    whatever the port's own surface permits.

    `permitted-ip` HAS THREE STATES AND TRUTHINESS REPORTS TWO OF THEM THE SAME, which is
    why this goes through `entry_container`: absent, present-and-empty (`{"permitted-ip":
    null}`, which exists on this estate - `oep-mgt6-p02` on 6A9C0A9904E7D6E) and
    populated. The first two are both "no restriction"; only the third restricts.
    """
    if not profile_name:
        return False
    entry = profiles.get(profile_name)
    if entry is None:
        return False
    state, sources = entry_container(entry, "permitted-ip")
    return state == "populated" and bool(sources)


def zone_membership(device_entry: dict) -> dict[str, str]:
    """interface name -> the zone that holds it, across every vsys and every member list.

    READ FROM THE ZONE END, which is the only end that expresses it. Every one of the six
    `network` subtrees a zone can carry is walked, not only `layer3`: PAN-OS refuses to put
    a layer-3 interface in a layer-2 zone, so a port in a layer-2 or virtual-wire zone is
    reachable only through that zone's own member list.

    A zone's `network` child can be `{"@ptpl": "<template>"}` WITH NO `member` KEY - which
    is what both PA-VMs' template-supplied `Private` and `Public` zones look like - so the
    member walk goes through `member_values`, which answers [] for that shape rather than
    raising. A later zone claiming an interface an earlier one already claimed does not
    overwrite it: PAN-OS lets an interface belong to at most one zone, so the first
    claimant is the answer and a second would be a payload the device does not permit.
    """
    membership: dict[str, str] = {}
    for vsys in _entries(device_entry.get("vsys")):
        for zone in _entries(vsys.get("zone")):
            zone_name = str(zone.get("@name") or "").strip()
            if not zone_name:
                continue
            network = _dict(zone.get("network"))
            for kind in ZONE_NETWORK_TYPES:
                if kind not in network:
                    continue
                for value, _prov in member_values(network.get(kind)):
                    if value and value not in membership:
                        membership[value] = zone_name
    return membership


def routing_instance_members(device_entry: dict) -> set[str]:
    """Every interface named by a virtual router's `interface` member list.

    An interface in a routing instance and holding no address is a residue PAN-NET-001's
    source ranks explicitly and declines to grade. Only the LEGACY tree is read, for the
    reason `models/network_hardening.py` gives about the Advanced Routing Engine.
    """
    routers = _dict(_dict(device_entry.get("network")).get("virtual-router"))
    members: set[str] = set()
    for router in _entries(routers):
        for value, _prov in member_values(router.get("interface")):
            if value:
                members.add(value)
    return members


def lldp_profiles_by_name(device_entry: dict) -> dict[str, dict[str, Any]]:
    """`network/profiles/lldp-profile` entries, keyed by name.

    One device-wide namespace by path shape. The container is ABSENT on three of the four
    lab appliances and absence is indistinguishable here from a path nobody read.
    """
    profiles = _dict(_dict(device_entry.get("network")).get("profiles"))
    return {
        name: entry
        for entry in _entries(profiles.get("lldp-profile"))
        if (name := str(entry.get("@name") or "").strip())
    }


def lldp_reading(layer3_node: Any) -> tuple[bool, bool, str]:
    """(node present, enabled, profile name) for one interface's `lldp` child.

    `lldp_node_present` is ELEMENT PRESENCE and not a value: an empty `<lldp/>` container
    serialises as None, so a truthiness test on the child reports a port that HAS a node
    as having none - and that distinction is the whole point of the column, because `show
    lldp config all` lists an interface if and only if the node exists.
    """
    node = _dict(layer3_node)
    present = "lldp" in node
    lldp = _dict(node.get("lldp"))
    enabled, _rk, _rv = parse_yes_no_field(
        lldp.get("enable"), implicit=Implicit.measured(
            False,
            "stage4-network-hardening.json, layer3-interface.lldp/enable: measured "
            "2026-10-26 with the positive control paid in both directions on `show lldp "
            "config all` - an empty <lldp/> container committed with no enable child "
            "reported enable=no, the key then written to yes reached running config and "
            "the oracle moved to YES, and three interfaces storing `no` reported no in "
            "the same reply."))
    profile, _rk, _rv = parse_text_field(
        lldp.get("profile"), implicit=Implicit.measured(
            "",
            "stage4-network-hardening.json, layer3-interface.lldp/profile: an absent "
            "reference asserts that NO profile is bound and the interface uses the global "
            "LLDP defaults - measured on `show lldp config all`, which reported "
            "profile=null with mode=tx-rx for all four interfaces of 6A9C0A9904E7D6E, and "
            "confirmed verbatim by the vendor in four places ('Select None to configure "
            "the firewall to use global defaults')."))
    return present, bool(enabled) if present else False, profile


#: `option-tlvs` children, WORST FIRST, mapped to the token each one justifies. The ranking
#: is this domain's and not the device's: the device offers five independent booleans and
#: states no ordering over them.
#:
#: THE CHILDREN ARE NOT SPELLED CONSISTENTLY AND THAT IS MEASURED, 2026-10-29 on
#: 013201001475: `management-address` arrives as `{"enabled": "yes"}` - a container with its
#: own `enabled` child - while `system-description` and `system-name` arrive as the bare
#: string `"yes"`. A reader of a text value gets nothing from the first and a reader of a
#: container gets nothing from the other two, so `_tlv_set` asks both ways.
_TLV_RANKS = (
    ("management-address", Interface.ANNOUNCED_MANAGEMENT_ADDRESS),
    ("system-description", Interface.ANNOUNCED_SYSTEM_DESCRIPTION),
    ("system-name", Interface.ANNOUNCED_HOSTNAME_OR_ROLE),
    ("system-capabilities", Interface.ANNOUNCED_HOSTNAME_OR_ROLE),
    ("port-description", Interface.ANNOUNCED_HOSTNAME_OR_ROLE),
)

#: `mode` values that TRANSMIT. A profile that only receives announces nothing, whatever
#: its TLV switches say. Measured on this estate: `transmit-receive` and `receive-only` are
#: the two the lab carries; `transmit-only` is the third the vendor documents.
_TRANSMITTING_MODES = frozenset({"transmit-receive", "transmit-only"})


def _tlv_set(tlvs: dict[str, Any], name: str) -> bool:
    """Is this optional TLV switched on, in either of the two shapes the device uses?"""
    if name not in tlvs:
        return False
    child = tlvs.get(name)
    if isinstance(child, dict):
        enabled, _rk, _rv = parse_yes_no_field(
            child.get("enabled"), implicit=Implicit.measured(
                False,
                "an option-tlvs container present with no `enabled` child is the shape a "
                "profile takes when the switch was created and left off - measured "
                "2026-10-29 on 013201001475, where every profile carrying a TLV carries "
                "its value with it."))
        return bool(enabled)
    return _text(child).lower() == "yes"


def announced_content(enabled: bool, profile_name: str,
                      profiles: dict[str, dict[str, Any]]) -> str:
    """The worst optional item an announcement from this port carries, as one token.

    The order of the tests is the ranking and it is worth reading in order:

    1. NOT RUNNING THE PROTOCOL -> `receive_only_or_off`. Nothing goes out.
    2. RUNNING WITH NO PROFILE -> `unknown_global_defaults`, which FIRES. The vendor says
       an empty reference means the firewall's global defaults and no document in the
       corpus says what those defaults transmit, so what the port leaks is unknown rather
       than low - and under this pipeline's rules an unknown fires.
    3. RUNNING WITH A PROFILE THAT DOES NOT RESOLVE -> `unknown_global_defaults` as well.
       Stage 4 did not reach what a DANGLING reference does; treating it as a pass would
       put a null join on the compliant side of a plain comparison.
    4. A RESOLVED PROFILE THAT DOES NOT TRANSMIT -> `receive_only_or_off`.
    5. OTHERWISE the worst `option-tlvs` child that is set, and
       `port_and_chassis_only` where none is - which is not "nothing", because the
       mandatory chassis identifier and port name go out whenever the port transmits.
    """
    if not enabled:
        return Interface.ANNOUNCED_RECEIVE_ONLY_OR_OFF
    if not profile_name:
        return Interface.ANNOUNCED_UNKNOWN_GLOBAL_DEFAULTS
    profile = profiles.get(profile_name)
    if profile is None:
        return Interface.ANNOUNCED_UNKNOWN_GLOBAL_DEFAULTS
    mode = _text(profile.get("mode")).lower()
    if mode and mode not in _TRANSMITTING_MODES:
        return Interface.ANNOUNCED_RECEIVE_ONLY_OR_OFF
    tlvs = _dict(profile.get("option-tlvs"))
    for name, token in _TLV_RANKS:
        if _tlv_set(tlvs, name):
            return token
    return Interface.ANNOUNCED_PORT_AND_CHASSIS_ONLY


def out_of_service_residue(*, profile_name: str, restricted: bool, zone_name: str,
                           addressing: str, ipv4: list, ipv6: list, link_state: str | None,
                           in_routing_instance: bool, has_link_settings: bool) -> str:
    """The worst thing an out-of-service port is left holding, as one token.

    The tests run WORST FIRST and the first one that holds is the answer, which is what
    makes this a precedence rather than a set of flags. A query cannot express it: it is a
    comparison between six columns of one row plus two reaches into other parts of the
    payload, and written as clauses it would need an OR.

    THE LAST THREE BRANCHES ARE WHERE THE VOCABULARY RUNS OUT and the choice is recorded
    on the model's `out_of_service_residue` field: a port holding no residue whose
    administrative state is READABLE and is not `down` is stripped but not shut down, which
    is the second half of what PAN-NET-001 asks for and has no token. It reads
    `administrative_state_unknown`, which fires, because the alternative - the one member
    that reads as fully compliant - would say "shut down" about a port that is not.
    """
    if profile_name:
        return (Interface.RESIDUE_RESTRICTED_MANAGEMENT if restricted
                else Interface.RESIDUE_UNRESTRICTED_MANAGEMENT)
    if zone_name:
        return Interface.RESIDUE_ZONE_MEMBERSHIP
    if ipv4 or ipv6 or addressing in (Interface.ADDRESSING_DHCP, Interface.ADDRESSING_PPPOE):
        return Interface.RESIDUE_ADDRESS_ONLY
    if in_routing_instance:
        return Interface.RESIDUE_ROUTING_INSTANCE
    if has_link_settings:
        return Interface.RESIDUE_COMMENT_OR_LINK_SETTINGS
    if link_state == Interface.LINK_STATE_DOWN:
        return Interface.RESIDUE_STRIPPED_AND_SHUT_DOWN
    return Interface.RESIDUE_ADMIN_STATE_UNKNOWN


# ---------------------------------------------------------------------------
# Session settings and global LLDP - two singleton nodes, one row each
# ---------------------------------------------------------------------------

def normalize_session_settings(appliance: Appliance) -> dict[str, int]:
    """Device > Setup > Session. PAN-NET-002, PAN-NET-005 and PAN-ZON-006's device-wide half.

    The row is anchored to the MERGED snapshot, so an appliance that was collected gets a
    row whatever its `deviceconfig/setting` holds - which is what makes "the key is absent"
    distinguishable from "nobody collected this appliance". No merged snapshot means no
    row: there is nothing to anchor to and nothing either column could say.
    """
    snapshot = latest_appliance_merged_snapshot(appliance)
    if snapshot is None:
        return {"pan_os_session_settings": 0}
    device_entry = device_entry_from_snapshot(snapshot)
    setting = _dict(_dict(device_entry.get("deviceconfig")).get("setting"))

    rematch, rematch_rk, rematch_rv = parse_yes_no_field(
        _dict(setting.get("config")).get("rematch"), implicit=REMATCH_ABSENT)
    ipv6, ipv6_rk, ipv6_rv = parse_yes_no_field(
        _dict(setting.get("session")).get("ipv6-firewalling"),
        implicit=IPV6_FIREWALLING_ABSENT)
    # PAN-ZON-006's device-wide half, out of the SAME node `ipv6-firewalling` comes from. Read
    # here rather than in a model of its own: ruling P374a, one model per PAN-OS node.
    #
    # `parse_yes_no_field` reads anything that is not `yes` as false, which is the firing side
    # of the resolution downstream - and that is the right way round for this leaf, because
    # stage 4 measured a `global` WRITE being accepted here and never committed, so whether a
    # third value can reach a committed configuration is not established.
    non_syn, non_syn_rk, non_syn_rv = parse_yes_no_field(
        _dict(setting.get("session")).get("tcp-reject-non-syn"),
        implicit=TCP_REJECT_NON_SYN_ABSENT)

    write_node_row(
        PanOsSessionSettings, appliance, snapshot,
        {"session_rematch": rematch, "ipv6_firewalling": ipv6,
         "tcp_reject_non_syn": non_syn},
        provenance=(
            ("session_rematch", rematch_rk, rematch_rv),
            ("ipv6_firewalling", ipv6_rk, ipv6_rv),
            ("tcp_reject_non_syn", non_syn_rk, non_syn_rv),
        ),
    )
    return {"pan_os_session_settings": 1}


def normalize_lldp_global_settings(appliance: Appliance) -> dict[str, int]:
    """Network > LLDP, the device-wide enable. PAN-NET-003's preferred value.

    `network/lldp` IS ABSENT ON AN UNTOUCHED APPLIANCE and absence here is not
    distinguishable from a path nobody read - the same shape as the LLDP profile container.
    There is no operational oracle either: all four `show lldp` subcommands are keyed by
    interface and none carries a device-wide line, and `show system state filter` answers
    NO_MATCHES for `*lldp*`. So the row is written anchored to the merged snapshot and the
    column is NULL where the node is absent, with the provenance row saying
    `not_configured` beside it - which is what stops a reader guessing whether the
    collector failed.
    """
    snapshot = latest_appliance_merged_snapshot(appliance)
    if snapshot is None:
        return {"pan_os_lldp_global_settings": 0}
    device_entry = device_entry_from_snapshot(snapshot)
    lldp = _dict(_dict(device_entry.get("network")).get("lldp"))

    enable, raw_key, raw_value = parse_yes_no_field(
        lldp.get("enable"), implicit=LLDP_GLOBAL_ABSENT)

    write_node_row(
        PanOsLldpGlobalSettings, appliance, snapshot,
        {"lldp_global_enable": enable},
        provenance=(("lldp_global_enable", raw_key, raw_value),),
    )
    return {"pan_os_lldp_global_settings": 1}


# ---------------------------------------------------------------------------
# DHCP server and relay - a row only where DHCP is configured
# ---------------------------------------------------------------------------

def relay_state(entry: dict[str, Any], ipv4_enabled: bool | None) -> str:
    """What this interface's relay configuration amounts to across BOTH address families.

    `not_configured` only where there is no `relay` branch at all. Where there is one, the
    verdict is the WORSE of the two families and an UNKNOWN switch counts as relaying:

    - either family's `enabled` reading `yes`                     -> `relaying`
    - a family present whose `enabled` key is absent              -> `relaying`
    - every family present and every switch explicitly off        -> `configured_and_off`

    THE IPv6 FAMILY IS READ HERE AND HAS NO COLUMN. Stage 4's measured key set for this
    node carries `relay`, `relay/ip`, `relay/ip/enabled` and `relay/ip/server` and NO ipv6
    sibling, so no column was declared for it - and a verdict that answered for IPv4 alone
    would report a relay configured for IPv6 only as `not_configured`, which is the one
    place in this domain where a gap produces SILENCE rather than a firing default. The
    family is read for the verdict and not stored, so nothing here claims a measurement of
    a key nobody enumerated.

    THE BRANCH'S ABSENCE IS ASKED AS KEY MEMBERSHIP AND NOT AS TRUTHINESS, because
    `{"relay": null}` - the present-and-empty shape - and no `relay` key at all both read
    None from a `.get()`, and they are the two sides of this verdict's only hard
    distinction.
    """
    if "relay" not in entry:
        return PanOsDhcpInterfaceConfig.RELAY_NOT_CONFIGURED
    relay = _dict(entry.get("relay"))
    families = [key for key in ("ip", "ipv6") if key in relay]
    if not families:
        # A `relay` branch with no address family under it. It is configured and relays
        # nothing, which is not the same as having no branch.
        return PanOsDhcpInterfaceConfig.RELAY_CONFIGURED_AND_OFF
    for family in families:
        if family == "ip":
            if ipv4_enabled is None or ipv4_enabled:
                return PanOsDhcpInterfaceConfig.RELAY_RELAYING
            continue
        enabled, raw_key, _rv = parse_yes_no_field(
            _dict(relay.get(family)).get("enabled"), implicit=DHCP_RELAY_ENABLED_ABSENT)
        if enabled is None or enabled:
            return PanOsDhcpInterfaceConfig.RELAY_RELAYING
    return PanOsDhcpInterfaceConfig.RELAY_CONFIGURED_AND_OFF


def normalize_dhcp_interface_configs(appliance: Appliance) -> dict[str, int]:
    """Network > DHCP, server and relay. PAN-NET-004.

    DELETE AND RECREATE, with the provenance rows for the rows being replaced deleted
    first. The grain is a collection and a row's whole meaning is that it EXISTS, so an
    `update_or_create` per entry would leave behind a row for a DHCP configuration
    somebody removed - which is this control's passing state reported as a finding.
    """
    snapshot = latest_appliance_merged_snapshot(appliance)
    if snapshot is None:
        return {"pan_os_dhcp_interface_configs": 0}
    device_entry = device_entry_from_snapshot(snapshot)
    dhcp = _dict(_dict(device_entry.get("network")).get("dhcp"))

    written = 0
    with transaction.atomic():
        content_type = ContentType.objects.get_for_model(PanOsDhcpInterfaceConfig)
        FieldProvenance.objects.filter(
            content_type=content_type,
            object_id__in=list(
                PanOsDhcpInterfaceConfig.objects.filter(appliance=appliance)
                .values_list("pk", flat=True)),
        ).delete()
        PanOsDhcpInterfaceConfig.objects.filter(appliance=appliance).delete()

        seen: set[str] = set()
        for entry in _entries(dhcp.get("interface")):
            name = str(entry.get("@name") or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)

            server_configured = "server" in entry
            mode, mode_rk, mode_rv = parse_text_field(
                _dict(entry.get("server")).get("mode"), implicit=DHCP_SERVER_MODE_ABSENT)
            ipv4_enabled, relay_rk, relay_rv = parse_yes_no_field(
                _dict(_dict(entry.get("relay")).get("ip")).get("enabled"),
                implicit=DHCP_RELAY_ENABLED_ABSENT)

            row = PanOsDhcpInterfaceConfig.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                source_snapshot=snapshot,
                interface_name=name,
                dhcp_server_configured=server_configured,
                # `parse_text_field` answers "" for an absent key and the column stores
                # NULL, because "the key is absent" and "the mode is the empty string" are
                # not the same reading and the empty string is not a member of the enum.
                dhcp_server_mode=(mode or None) if server_configured else None,
                dhcp_relay_ipv4_enabled=ipv4_enabled,
                dhcp_relay_state=relay_state(entry, ipv4_enabled),
            )
            written += 1
            _write_provenance(content_type, row.pk, (
                ("dhcp_server_mode", mode_rk, mode_rv),
                ("dhcp_relay_ipv4_enabled", relay_rk, relay_rv),
            ))
    return {"pan_os_dhcp_interface_configs": written}


def _write_provenance(content_type, object_id: int,
                      provenance: tuple[tuple[str, Any, str | None], ...]) -> None:
    """One `FieldProvenance` row per field that has one. A field whose raw_key is ABSENT is
    skipped entirely - the caller declared no implicit value, so nothing is tracked."""
    FieldProvenance.objects.bulk_create([
        FieldProvenance(
            content_type=content_type, object_id=object_id, field_name=name,
            provenance_type=classify_prov_type(raw_key),
            raw_key=provenance_raw_key(raw_key),
            raw_value=provenance_value(raw_key, raw_value)[:128])
        for name, raw_key, raw_value in provenance if raw_key is not ABSENT])


# ---------------------------------------------------------------------------
# Tunnel inspection coverage - a verdict per enforcement point
# ---------------------------------------------------------------------------

def coverage_state(rules: list[dict[str, Any]], rulebase_state: str) -> str:
    """How much of the transiting tunnel traffic this policy opens, as one token.

    ONLY THREE OF THE EIGHT MEMBERS ARE REACHABLE FROM CONFIGURATION and that is the
    important thing about this function:

    - `no_policy` where the rulebase is ABSENT or PRESENT AND EMPTY. Both are "this
      enforcement point inspects no tunnel", which is the control's worst rank; the two are
      kept apart by `entry_container` so a torn-down lab fixture is not mistaken for a
      device that never had one.
    - `all_rules_disabled` where the rulebase holds rules and every one of them carries
      `disabled: yes`. Populated, and opening nothing.
    - `coverage_unverified_without_traffic_answer` for everything else, which FIRES at the
      baseline. `protocol_subset`, `zone_pair_gap`, `single_level_only` and
      `overlay_id_scoped` each need to know WHAT ACTUALLY TRANSITED between which zones,
      and so does `fully_opened` - the claim that everything transiting is opened. None of
      those is in any configuration read, so a configuration-only normalizer that wrote one
      would be asserting a traffic answer nobody has.

    The refinement is not turned into a suppression: an enabled rule naming every protocol
    from any zone to any zone still reads `coverage_unverified...` rather than
    `fully_opened`, because nothing here can see whether a tunnel crossed a zone pair the
    rule does not cover.
    """
    if rulebase_state != "populated" or not rules:
        return PanOsTunnelInspectionCoverage.STATE_NO_POLICY
    if all(_text(rule.get("disabled")).lower() == "yes" for rule in rules):
        return PanOsTunnelInspectionCoverage.STATE_ALL_RULES_DISABLED
    return PanOsTunnelInspectionCoverage.STATE_UNVERIFIED


def _tunnel_inspect_rules(vsys_entry: dict) -> tuple[str, list[dict[str, Any]]]:
    return entry_container(vsys_entry, "rulebase", "tunnel-inspect", "rules")


def _pushed_tunnel_inspect(appliance: Appliance,
                           vsys_name: str) -> tuple[str, list[dict[str, Any]]] | None:
    """The device-group tunnel-inspect rulebase pushed to one vsys, or None.

    THE MERGED VIEW DOES NOT CARRY PUSHED POLICY, which is the dangerous omission for this
    control: a vsys whose coverage comes entirely from Panorama reads as having NO POLICY
    AT ALL from the merged read alone, and that is this control's worst rank - a wrong
    finding at medium severity on exactly the estates that are centrally managed. The
    collector already issues `show config pushed-shared-policy` per vsys, so the gap was
    normalization and not collection.

    WHERE THE RULES WOULD BE, measured 2026-10-29 on three vsys across two appliances
    (013201001475 vsys1 and vsys2, 691665AC334B458 vsys1): the reply's root is `policy`,
    whose `panorama` subtree carries `pre-rulebase` and `post-rulebase` - NOT a `rulebase`
    key, which is the merged view's spelling. A walk written for the merged shape finds
    nothing here and finds it silently. Both pushed rulebases are read and their counts
    summed, because a vsys evaluates both.

    AND NEITHER PUSHED RULEBASE CARRIES A `tunnel-inspect` KEY ON THIS ESTATE: each holds
    `security`, and the post-rulebase additionally `default-security-rules`. So this
    returns None on every vsys measured, and NO device-group row is written anywhere.

    RETURNING None RATHER THAN AN EMPTY RULEBASE IS A DECISION, and it is the one worth
    reading twice. A device group that pushes no tunnel-inspect policy at all adds nothing
    a reader does not already have: the vsys-scope row for the same enforcement point
    already reads `no_policy` and already fires, so a second row saying `no_policy` would
    double every finding this control raises - nine vsys on a PA-5220 becoming eighteen -
    while telling nobody anything new. A device-group row is therefore written only where
    the pushed policy actually HAS a tunnel-inspect rulebase, populated or emptied. The
    cost, stated because it is real: "the device group pushes none" and "the pushed read
    was never taken" both produce no row, and nothing here distinguishes them. Nothing is
    silenced by that - the vsys row fires either way - but a reader cannot tell from this
    model whether Panorama was asked.

    THE LOOKUP CROSSES A GRAIN. These snapshots are attached to an `EnforcementPoint`,
    which belongs to an appliance OR to an appliance group, while this normalizer is
    appliance-anchored - so the point is found by vsys name under either owner. On an HA
    pair the group's one pushed rulebase is read once per peer and written as two rows,
    which is this model's declared convention and not a double count.
    """
    points = EnforcementPoint.objects.filter(vsys_name=vsys_name).filter(
        **({"appliance_group": appliance.appliance_group}
           if appliance.appliance_group_id else {"appliance": appliance}))
    for point in points.order_by("pk"):
        snapshot = (
            Snapshot.objects.filter(
                enforcement_point=point,
                source_type="show_pushed_shared_policy_vsys")
            .order_by("-collected_at", "-pk").first())
        if snapshot is None:
            continue
        # `pushed_vsys_panorama` is the shipped reader for this payload root and it
        # already answers {} for the "vsys has no device group" message, which is a
        # legitimate operational state and not an error.
        panorama = pushed_vsys_panorama(snapshot.payload)
        states: list[str] = []
        rules: list[dict[str, Any]] = []
        for rulebase in ("pre-rulebase", "post-rulebase"):
            state, found = entry_container(
                panorama, rulebase, "tunnel-inspect", "rules")
            states.append(state)
            rules.extend(found)
        if all(state == "absent" for state in states):
            return None
        return ("populated" if rules else "empty"), rules
    return None


def normalize_tunnel_inspection_coverage(appliance: Appliance) -> dict[str, int]:
    """Policies > Tunnel Inspection, as a coverage verdict per vsys. PAN-NET-006.

    ONE ROW PER VSYS PER SCOPE, written for every vsys the merged payload names - including
    a vsys a template contributes, which `action=get` reports and `action=show` does not.
    The firewall-local row is always written, because the merged read always carries the
    vsys's own rulebase or its absence; the device-group row is written only where a pushed
    read was actually collected for that vsys.
    """
    snapshot = latest_appliance_merged_snapshot(appliance)
    if snapshot is None:
        return {"pan_os_tunnel_inspection_coverages": 0}
    device_entry = device_entry_from_snapshot(snapshot)
    setting = _dict(_dict(device_entry.get("deviceconfig")).get("setting"))
    acceleration, accel_rk, accel_rv = parse_yes_no_field(
        setting.get("tunnel-acceleration"), implicit=TUNNEL_ACCELERATION_ABSENT)

    written = 0
    with transaction.atomic():
        content_type = ContentType.objects.get_for_model(PanOsTunnelInspectionCoverage)
        FieldProvenance.objects.filter(
            content_type=content_type,
            object_id__in=list(
                PanOsTunnelInspectionCoverage.objects.filter(appliance=appliance)
                .values_list("pk", flat=True)),
        ).delete()
        PanOsTunnelInspectionCoverage.objects.filter(appliance=appliance).delete()

        for vsys in _entries(device_entry.get("vsys")):
            vsys_name = str(vsys.get("@name") or "").strip()
            if not vsys_name:
                continue
            scopes: list[tuple[str, str, list[dict[str, Any]], bool]] = []
            state, rules = _tunnel_inspect_rules(vsys)
            scopes.append((PanOsTunnelInspectionCoverage.SCOPE_VSYS, state, rules, True))
            pushed = _pushed_tunnel_inspect(appliance, vsys_name)
            if pushed is not None:
                scopes.append(
                    (PanOsTunnelInspectionCoverage.SCOPE_DEVICE_GROUP,
                     pushed[0], pushed[1], True))

            for scope, rulebase_state, scope_rules, collected in scopes:
                row = PanOsTunnelInspectionCoverage.objects.create(
                    management_station=appliance.management_station,
                    appliance=appliance,
                    appliance_group=appliance.appliance_group,
                    source_snapshot=snapshot,
                    scope=scope,
                    vsys_name=vsys_name,
                    tunnel_inspect_rule_count=len(scope_rules),
                    tunnel_inspect_rules_collected=collected,
                    tunnel_acceleration=acceleration,
                    tunnel_inspection_coverage_state=coverage_state(
                        scope_rules, rulebase_state),
                )
                written += 1
                _write_provenance(content_type, row.pk, (
                    ("tunnel_acceleration", accel_rk, accel_rv),))
    return {"pan_os_tunnel_inspection_coverages": written}


# ---------------------------------------------------------------------------
# Routing adjacencies - BGP peers and OSPF attachments
# ---------------------------------------------------------------------------

def routing_engine(device_entry: dict) -> str:
    """Which routing engine is in effect, from `deviceconfig/setting/advance-routing`.

    Three answers and the third is not decoration: `yes` means advanced, `no` means
    legacy, and an ABSENT key means UNKNOWN. The leaf is absent on all four lab appliances
    and `show advanced-routing` is refused on all four with code 17 'advanced routing mode
    is not enabled' - which is consistent with an implicit `no` but is a reading of the
    ENGINE's state rather than of the leaf, and no instrument was found that reports the
    leaf itself. Resolving the absence to `legacy` would assert a vendor fact nobody
    measured.
    """
    setting = _dict(_dict(device_entry.get("deviceconfig")).get("setting"))
    raw_value, raw_key, _rv = scalar_value(setting.get("advance-routing"))
    if raw_key is ABSENT or not raw_value:
        return PanOsRoutingAdjacency.ENGINE_UNKNOWN
    return (PanOsRoutingAdjacency.ENGINE_ADVANCED if raw_value.lower() == "yes"
            else PanOsRoutingAdjacency.ENGINE_LEGACY)


def authentication_strength(protocol: str, profile_name: str,
                           profiles: dict[str, dict[str, dict[str, Any]]]) -> str:
    """What this adjacency's authentication amounts to, read from WEAKEST upward.

    Following a reference to read a property of the TARGET, then a precedence over what the
    target holds - which is why this cannot be a clause: there is no second field slot and
    the ordering is not a comparison any operator expresses.

    - no reference, or a reference that does not resolve on THIS router -> `none`. An
      unresolvable name is treated as no authentication rather than as unknown, because a
      null join sits on the compliant side of a plain comparison and would be dropped. The
      reference resolves WITHIN the same virtual router, measured, so a name that exists on
      another router does not satisfy it.
    - BGP `secret`             -> `weak_digest`. PAN-OS's TCP MD5 shared secret, which is
                                  the single digest the legacy engine's BGP offers.
    - OSPF `password`          -> `cleartext_password`.
    - OSPF `md5`               -> `weak_digest`.
    - resolves and holds none of those -> `none`. A profile with no material cannot
      authenticate anything.

    `strong_digest`, `authenticated_and_encrypted`, `weaker_inner_attachment` and
    `explicitly_disabled` ARE NOT REACHABLE HERE and each for its own measured reason -
    see `models/network_hardening.py::PanOsRoutingAdjacency.STRENGTH_CHOICES`. Where BOTH
    an OSPF password and an MD5 digest sit on one profile the weaker wins, which is the
    ordering below and matches the vendor documenting the narrower attachment as
    overriding the wider one.
    """
    if not profile_name:
        return PanOsRoutingAdjacency.STRENGTH_NONE
    profile = profiles.get(protocol, {}).get(profile_name)
    if profile is None:
        return PanOsRoutingAdjacency.STRENGTH_NONE
    if protocol == PanOsRoutingAdjacency.PROTOCOL_BGP:
        # Key membership, not truthiness: `secret` holds an encrypted-text blob the read
        # does return, but a profile created with an empty one would serialise as null.
        if "secret" in profile:
            return PanOsRoutingAdjacency.STRENGTH_WEAK_DIGEST
        return PanOsRoutingAdjacency.STRENGTH_NONE
    if "password" in profile:
        return PanOsRoutingAdjacency.STRENGTH_CLEARTEXT
    if "md5" in profile:
        return PanOsRoutingAdjacency.STRENGTH_WEAK_DIGEST
    return PanOsRoutingAdjacency.STRENGTH_NONE


def prefix_limit_state(max_prefixes: str | None) -> str:
    """Whether a configured prefix ceiling actually REFUSES the routes beyond it.

    A threshold over a column that holds a KEYWORD OR A NUMBER in one string, plus a null
    that means the same thing to the firewall as the keyword. No clause can select the
    three failing states: there is no `between`, no `in` and no is-null operator, and a
    numeric comparison on a string column skips the keyword silently.

    `warn_only` IS NOT COMPUTABLE and is not guessed at: the peer's measured key set
    carries `connection-options` and `max-prefixes` and no key saying whether the limit
    warns or stops, so a ceiling that only warns is stored as `enforcing`. The rank is
    stage 3's and the severity is the same either way, so no finding is lost - the
    remediation text would be wrong.
    """
    if not max_prefixes:
        return PanOsRoutingAdjacency.LIMIT_NO_CEILING
    if max_prefixes.strip().lower() == PanOsRoutingAdjacency.MAX_PREFIXES_UNLIMITED:
        return PanOsRoutingAdjacency.LIMIT_UNLIMITED
    return PanOsRoutingAdjacency.LIMIT_ENFORCING


def _auth_profiles(router: dict) -> dict[str, dict[str, dict[str, Any]]]:
    """protocol -> name -> the authentication profile entry, for ONE router.

    Scoped to the router deliberately: the reference resolves within the same virtual
    router, measured, so a pool built across routers would resolve a name that does not
    satisfy the adjacency.
    """
    protocol = _dict(router.get("protocol"))
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for key in (PanOsRoutingAdjacency.PROTOCOL_BGP, PanOsRoutingAdjacency.PROTOCOL_OSPF,
                PanOsRoutingAdjacency.PROTOCOL_OSPFV3):
        out[key] = {
            name: entry
            for entry in _entries(_dict(protocol.get(key)).get("auth-profile"))
            if (name := str(entry.get("@name") or "").strip())
        }
    out[PanOsRoutingAdjacency.PROTOCOL_RIP] = {}
    return out


def _bgp_adjacencies(protocol_node: dict) -> list[dict[str, Any]]:
    """One record per BGP peer, from `protocol/bgp/peer-group/entry/peer/entry`."""
    out = []
    bgp = _dict(protocol_node.get(PanOsRoutingAdjacency.PROTOCOL_BGP))
    for group in _entries(bgp.get("peer-group")):
        for peer in _entries(group.get("peer")):
            name = str(peer.get("@name") or "").strip()
            if not name:
                continue
            out.append({"protocol": PanOsRoutingAdjacency.PROTOCOL_BGP, "name": name,
                        "entry": peer})
    return out


def _ospf_adjacencies(protocol_node: dict, key: str) -> list[dict[str, Any]]:
    """One record per OSPF attachment that can carry authentication, for OSPFv2 or OSPFv3.

    BOTH of an area's authentication-carrying children are walked - `interface` and
    `virtual-link` - and THE SECOND IS A DEPARTURE FROM THE SPEC THIS WAS BUILT FROM, which
    named area interfaces only. Three reasons, in the order they were found:

    1. `action=complete` at an OSPF area entry returns exactly four children - interface,
       range, type, virtual-link - and NO authentication, identically on all four lab
       appliances. So on this engine authentication attaches at the area's CHILDREN, and
       both of those two children take it.
    2. The lab's only OSPF authentication stands on virtual links: measured 2026-10-29 on
       013201001475, areas 0.0.0.0 and 0.0.0.9 of `oep-nhd6-vr1` carry NO `interface`
       entries at all, and three virtual links carry a cleartext profile, an MD5 profile
       and no profile. Reading area interfaces alone would leave
       `ospf_authentication_profile` empty on every row in the estate and
       `cleartext_password` with no device proof anywhere.
    3. A virtual link IS an adjacency that carries authentication, which is what this
       model's row is for.

    The cost, named because it is real: an area interface and a virtual link of the same
    name in one router would collide on the uniqueness constraint. An area interface name
    is an interface name and a virtual link's is operator-chosen, so the collision is
    possible and has never been seen.
    """
    out = []
    node = _dict(protocol_node.get(key))
    for area in _entries(node.get("area")):
        for child in ("interface", "virtual-link"):
            for entry in _entries(area.get(child)):
                name = str(entry.get("@name") or "").strip()
                if not name:
                    continue
                out.append({"protocol": key, "name": name, "entry": entry})
    return out


def _rip_adjacencies(protocol_node: dict) -> list[dict[str, Any]]:
    """One record per RIP interface, from `protocol/rip/interface/entry`.

    No instance exists anywhere in this estate, so this walk is UNEXERCISED by any device
    read. It is here because `protocol` declares `rip` as a member and because the shape is
    the same one-level `interface` container the other protocols use; what it would store
    is an empty `authentication` reference, which is the firing direction.
    """
    out = []
    rip = _dict(protocol_node.get(PanOsRoutingAdjacency.PROTOCOL_RIP))
    for entry in _entries(rip.get("interface")):
        name = str(entry.get("@name") or "").strip()
        if not name:
            continue
        out.append({"protocol": PanOsRoutingAdjacency.PROTOCOL_RIP, "name": name,
                    "entry": entry})
    return out


def normalize_routing_adjacencies(appliance: Appliance) -> dict[str, int]:
    """Network > Virtual Routers, the adjacencies that carry authentication. PAN-NET-007.

    DELETE AND RECREATE for the same reason the DHCP rows are: an adjacency somebody
    removed must stop being reported, and the only thing that says so is the row's absence.

    An `@ptpl`-decorated router is read exactly like a firewall-local one and NOTHING IN
    THE ROW SAYS WHICH IT IS, which is this model's known limitation rather than an
    oversight: a template-supplied router is stored as the firewall's own, so a remediation
    would tell an engineer to attach a profile at a node the firewall will not accept the
    edit on. Measured on this estate - 6A9C0A9904E7D6E carries `vr_pan-fw-111` entirely
    from template `ptpl-pan-fw-111` alongside a firewall-local `default`.
    """
    snapshot = latest_appliance_merged_snapshot(appliance)
    if snapshot is None:
        return {"pan_os_routing_adjacencies": 0}
    device_entry = device_entry_from_snapshot(snapshot)
    network = _dict(device_entry.get("network"))
    engine = routing_engine(device_entry)

    issues: list[dict[str, str]] = []
    advanced = _dict(network.get("logical-router"))
    if _entries(advanced):
        # NOT READ, AND SAID SO RATHER THAN READ WRONGLY. The Advanced Routing Engine's
        # tree holds no instance on any appliance this was measured against, so a walk of
        # it would be code proved against nothing - and a silent zero here would report an
        # estate running the ARE as having no adjacency at all, which is the reassuring
        # direction on every assertion in this domain.
        issues.append({
            "name": "network/logical-router",
            "reason": ("The Advanced Routing Engine's tree holds entries and nothing "
                       "normalizes it: no routing adjacency row is produced from "
                       "network/logical-router, so this appliance's adjacencies are NOT "
                       "represented. `routing_engine` says which tree is authoritative. "
                       "No instance of this tree existed on any appliance this normalizer "
                       "was measured against, so reading it would be a guess at a shape "
                       "nobody has seen."),
        })

    written = 0
    with transaction.atomic():
        content_type = ContentType.objects.get_for_model(PanOsRoutingAdjacency)
        FieldProvenance.objects.filter(
            content_type=content_type,
            object_id__in=list(
                PanOsRoutingAdjacency.objects.filter(appliance=appliance)
                .values_list("pk", flat=True)),
        ).delete()
        PanOsRoutingAdjacency.objects.filter(appliance=appliance).delete()

        for router in _entries(network.get("virtual-router")):
            router_name = str(router.get("@name") or "").strip()
            if not router_name:
                continue
            protocol_node = _dict(router.get("protocol"))
            profiles = _auth_profiles(router)
            found = (_bgp_adjacencies(protocol_node)
                     + _ospf_adjacencies(protocol_node,
                                         PanOsRoutingAdjacency.PROTOCOL_OSPF)
                     + _ospf_adjacencies(protocol_node,
                                         PanOsRoutingAdjacency.PROTOCOL_OSPFV3)
                     + _rip_adjacencies(protocol_node))
            seen: set[tuple[str, str]] = set()
            for item in found:
                protocol, name, entry = item["protocol"], item["name"], item["entry"]
                if (protocol, name) in seen:
                    continue
                seen.add((protocol, name))

                bgp_ref = ""
                ospf_ref = ""
                prov: list[tuple[str, Any, str | None]] = []
                max_prefixes_value: str | None = None
                if protocol == PanOsRoutingAdjacency.PROTOCOL_BGP:
                    bgp_ref, rk, rv = parse_text_field(
                        _dict(entry.get("connection-options")).get("authentication"),
                        implicit=ROUTING_AUTH_ABSENT)
                    prov.append(("bgp_authentication_profile", rk, rv))
                    raw, raw_key, raw_prov = scalar_value(entry.get("max-prefixes"))
                    # NULL rather than "" for an absent key: null and `unlimited` mean the
                    # same thing to the firewall and are two different row states to a
                    # query, which is the distinction `prefix_limit_state` keeps.
                    max_prefixes_value = None if raw_key is ABSENT else (raw or None)
                    prov.append(("max_prefixes",
                                 MAX_PREFIXES_ABSENT if raw_key is ABSENT else raw_key,
                                 raw_prov))
                else:
                    ospf_ref, rk, rv = parse_text_field(
                        entry.get("authentication"), implicit=ROUTING_AUTH_ABSENT)
                    prov.append(("ospf_authentication_profile", rk, rv))

                reference = bgp_ref or ospf_ref
                row = PanOsRoutingAdjacency.objects.create(
                    management_station=appliance.management_station,
                    appliance=appliance,
                    appliance_group=appliance.appliance_group,
                    source_snapshot=snapshot,
                    router_name=router_name,
                    protocol=protocol,
                    adjacency_name=name,
                    routing_engine=engine,
                    bgp_authentication_profile=bgp_ref,
                    ospf_authentication_profile=ospf_ref,
                    authentication_profile=reference,
                    max_prefixes=max_prefixes_value,
                    authentication_strength=authentication_strength(
                        protocol, reference, profiles),
                    prefix_limit_state=prefix_limit_state(max_prefixes_value),
                )
                written += 1
                _write_provenance(content_type, row.pk, tuple(prov))

        _replace_issues(appliance, issues)
    return {"pan_os_routing_adjacencies": written}


def _replace_issues(appliance: Appliance, issues: list[dict[str, str]]) -> None:
    """Replace THIS APPLIANCE's routing-adjacency issues.

    Owned by the appliance rather than its group, for the reason the interface normalizer
    gives: both members of an HA pair normalize their own routers, and a group-scoped
    replace would have the second peer's run delete the first's issues without a trace.
    """
    NormalizationIssue.objects.filter(appliance=appliance, kind=ISSUE_KIND).delete()
    NormalizationIssue.objects.bulk_create([
        NormalizationIssue(
            management_station=appliance.management_station,
            appliance=appliance,
            kind=ISSUE_KIND,
            name=issue["name"],
            severity=NormalizationIssue.Severity.WARNING,
            disposition=NormalizationIssue.Disposition.SKIPPED,
            reason=issue["reason"],
            node=issue["name"],
            source="show_merged_config",
        )
        for issue in issues
    ])
