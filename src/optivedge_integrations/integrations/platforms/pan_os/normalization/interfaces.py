"""Normalize every interface on one appliance from the merged config.

Containers are whatever the payload holds, not a hard-coded list. Measured 2026-08-31 with
`action=complete`: a PA-5220 offers ethernet, aggregate-ethernet, vlan, loopback, tunnel and
sdwan; a PA-VM offers the same set WITHOUT vlan. A fixed tuple would therefore be wrong on
some platform, and the two normalizers that predate this one both hard-code five containers
and miss `sdwan` entirely - an sdwan interface is invisible to them.

Nothing here is skipped quietly. An entry this code cannot make sense of produces a
NormalizationIssue, because the alternative is an interface list that looks complete and
is not - the same failure mode as a management surface reporting no services because its
rows were never written.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    Interface,
    NormalizationIssue,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import ensure_list
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)

#: Type keys that appear as a SUBTREE on a physical entry. Exactly one is present per
#: entry, and presence is the test - an empty subtree serialises as null, so truthiness
#: reports a tap interface as typeless.
TYPE_SUBTREE_KEYS = {
    "layer3": Interface.TYPE_LAYER3,
    "layer2": Interface.TYPE_LAYER2,
    "virtual-wire": Interface.TYPE_VIRTUAL_WIRE,
    "tap": Interface.TYPE_TAP,
    "ha": Interface.TYPE_HA,
}

#: Containers whose entries are logical interfaces: no type key at all, the path is the
#: type. Anything else is treated as physical and type-discriminated by key.
LOGICAL_CONTAINERS = frozenset({"vlan", "loopback", "tunnel", "sdwan"})

ISSUE_KIND = "interface"


@dataclass
class InterfaceIssue:
    kind: str
    name: str
    severity: str
    disposition: str
    reason: str
    node: str = ""
    source: str = "show_merged_config"
    raw_entry: dict = field(default_factory=dict)


@dataclass
class NormalizedInterfaces:
    interfaces: list[Interface]
    issues: list[InterfaceIssue]


def _text(node: Any) -> str:
    """A leaf may be a bare string or {'#text': v, '@ptpl': ...} when pushed from a template."""
    if isinstance(node, dict):
        return str(node.get("#text") or "").strip()
    return str(node or "").strip()


def _ip_names(node: Any) -> list[str]:
    """Address entries under an `ip` or `ipv6/address` node, which may be one or many."""
    if not isinstance(node, dict):
        return []
    out = []
    for entry in ensure_list(node.get("entry")):
        if isinstance(entry, dict):
            value = str(entry.get("@name") or "").strip()
        else:
            value = str(entry or "").strip()
        if value:
            out.append(value)
    return out


def _addressing(node: dict) -> tuple[str, list[str], list[str]]:
    """(addressing mode, ipv4, ipv6) for a node that may carry addressing.

    `ip`, `dhcp-client` and `pppoe` are mutually alternative and only `ip` states an
    address, so an empty address list means different things depending on which is present.
    `ipv6` is a separate node and an interface can carry both, one, or neither.
    """
    ipv6 = _ip_names((node.get("ipv6") or {}).get("address")) if isinstance(node.get("ipv6"), dict) else []
    if "dhcp-client" in node:
        return Interface.ADDRESSING_DHCP, [], ipv6
    if "pppoe" in node:
        return Interface.ADDRESSING_PPPOE, [], ipv6
    ipv4 = _ip_names(node.get("ip"))
    if ipv4 or "ip" in node:
        return Interface.ADDRESSING_STATIC, ipv4, ipv6
    return (Interface.ADDRESSING_STATIC if ipv6 else Interface.ADDRESSING_NONE), ipv4, ipv6


def _classify(container: str, entry: dict, issues: list[InterfaceIssue],
              name: str, *, parent_type: str | None = None) -> tuple[str, dict, str]:
    """(type, the node carrying addressing, aggregate group name).

    Logical containers have no type key - path is type. Physical entries carry exactly one
    type subtree, or the `aggregate-group` STRING, which is not a subtree and which code
    looking for one misses without error.
    """
    if parent_type is not None:
        # A unit inherits its parent's type: `ethernet1/1.10` is layer3 because
        # `ethernet1/1` is, and the unit entry carries no type key of its own. Running the
        # discriminator over it reports every subinterface on the device as an unknown
        # type, which is how a real config produced eighteen false warnings per firewall.
        return parent_type, entry, ""
    if container in LOGICAL_CONTAINERS:
        return Interface.TYPE_LOGICAL, entry, ""

    aggregate = _text(entry.get("aggregate-group"))
    present = [key for key in TYPE_SUBTREE_KEYS if key in entry]

    if aggregate and not present:
        return Interface.TYPE_AGGREGATE_MEMBER, {}, aggregate
    if len(present) == 1:
        node = entry.get(present[0])
        return TYPE_SUBTREE_KEYS[present[0]], node if isinstance(node, dict) else {}, aggregate
    if not present:
        issues.append(InterfaceIssue(
            kind=ISSUE_KIND, name=name, severity=NormalizationIssue.Severity.WARNING,
            disposition=NormalizationIssue.Disposition.KEPT,
            reason=("No interface type key and no aggregate-group. The type set is "
                    "platform-dependent, so this may be a type this release does not know "
                    "rather than a malformed entry - it is kept and reported, not dropped."),
            node=f"network/interface/{container}", raw_entry=entry))
        return Interface.TYPE_UNKNOWN, {}, aggregate

    issues.append(InterfaceIssue(
        kind=ISSUE_KIND, name=name, severity=NormalizationIssue.Severity.ERROR,
        disposition=NormalizationIssue.Disposition.KEPT,
        reason=(f"Entry carries {len(present)} type keys ({', '.join(sorted(present))}); "
                "PAN-OS permits exactly one. The first in configuration order was used."),
        node=f"network/interface/{container}", raw_entry=entry))
    node = entry.get(present[0])
    return TYPE_SUBTREE_KEYS[present[0]], node if isinstance(node, dict) else {}, aggregate


def bound_management_profiles(device_entry: dict) -> list[tuple[str, str]]:
    """(interface name, profile name) for every interface carrying a management profile.

    Container-agnostic, which is the point: the two normalizers that predate this one each
    hard-code five containers and so cannot see a profile bound to an `sdwan` interface at
    all. Here every container in the payload is walked, so a platform that grows a new one
    is handled without an edit.

    The binding appears at four depths, all of them real:

        <container>/interface-management-profile                 vlan, loopback, tunnel
        <container>/units/entry/interface-management-profile     their units
        <container>/entry/<type>/interface-management-profile    ethernet, aggregate-ethernet
        <container>/entry/<type>/units/entry/...                 their subinterfaces
    """
    interfaces = (device_entry.get("network") or {}).get("interface")
    if not isinstance(interfaces, dict):
        return []
    found: list[tuple[str, str]] = []

    def units_of(node: Any, fallback: str) -> None:
        # `.get("units", {})` is not enough: an empty <units/> parses to None, so the
        # default never applies and the chained .get() raises on real configs.
        container = (node or {}).get("units") or {}
        if not isinstance(container, dict):
            return
        for unit in ensure_list(container.get("entry")):
            if not isinstance(unit, dict):
                continue
            profile = _text(unit.get("interface-management-profile"))
            if profile:
                found.append((str(unit.get("@name") or "").strip() or fallback, profile))

    for container, node in sorted(interfaces.items()):
        if container.startswith("@") or not isinstance(node, dict):
            continue

        # Logical containers carry the binding, and their units, directly.
        profile = _text(node.get("interface-management-profile"))
        if profile:
            found.append((container, profile))
        units_of(node, container)

        for entry in ensure_list(node.get("entry")):
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("@name") or "").strip()
            for type_key in TYPE_SUBTREE_KEYS:
                subtree = entry.get(type_key)
                if not isinstance(subtree, dict):
                    continue
                profile = _text(subtree.get("interface-management-profile"))
                if profile:
                    found.append((name, profile))
                units_of(subtree, name)
    return found


def _container_units(node: dict, container: str,
                     issues: list[InterfaceIssue]) -> list[dict]:
    """Units hanging directly off a container, which is how the logical types are shaped."""
    units = node.get("units")
    if not isinstance(units, dict):
        return []
    out = []
    for unit in ensure_list(units.get("entry")):
        if not isinstance(unit, dict):
            issues.append(InterfaceIssue(
                kind=ISSUE_KIND, name="", severity=NormalizationIssue.Severity.ERROR,
                disposition=NormalizationIssue.Disposition.SKIPPED,
                reason=f"A unit under {container!r} is {type(unit).__name__}, expected a mapping.",
                node=f"network/interface/{container}"))
            continue
        name = str(unit.get("@name") or "").strip()
        if not name:
            issues.append(InterfaceIssue(
                kind=ISSUE_KIND, name="", severity=NormalizationIssue.Severity.ERROR,
                disposition=NormalizationIssue.Disposition.SKIPPED,
                reason=f"A unit under {container!r} has no @name.",
                node=f"network/interface/{container}", raw_entry=unit))
            continue
        out.append({"container": container, "name": name, "entry": unit, "parent": ""})
    return out


def _collect(device_entry: dict) -> tuple[list[dict], list[InterfaceIssue]]:
    """Every interface entry in the payload, flattened, with its container and parent."""
    issues: list[InterfaceIssue] = []
    found: list[dict] = []
    interfaces = (device_entry.get("network") or {}).get("interface")
    if interfaces is None:
        return found, issues
    if not isinstance(interfaces, dict):
        issues.append(InterfaceIssue(
            kind=ISSUE_KIND, name="", severity=NormalizationIssue.Severity.ERROR,
            disposition=NormalizationIssue.Disposition.SKIPPED,
            reason=f"network/interface is {type(interfaces).__name__}, expected a mapping. "
                   "No interface was normalized for this appliance.",
            node="network/interface"))
        return found, issues

    for container, node in sorted(interfaces.items()):
        if container.startswith("@"):
            continue
        if node is None:
            # An empty element - `<aggregate-ethernet/>` - parses to None. That is a
            # container with nothing in it, not a fault; reporting it would put a
            # permanent error on every device that has no aggregates.
            continue
        if not isinstance(node, dict):
            issues.append(InterfaceIssue(
                kind=ISSUE_KIND, name="", severity=NormalizationIssue.Severity.ERROR,
                disposition=NormalizationIssue.Disposition.SKIPPED,
                reason=f"Container {container!r} is {type(node).__name__}, expected a mapping.",
                node=f"network/interface/{container}"))
            continue

        # vlan, loopback, tunnel and sdwan hang their units DIRECTLY off the container -
        # there is no named entry above them, so those units have no parent row. Only
        # ethernet and aggregate-ethernet have a named entry that owns its units.
        for unit in _container_units(node, container, issues):
            found.append(unit)

        for entry in ensure_list(node.get("entry")):
            if not isinstance(entry, dict):
                issues.append(InterfaceIssue(
                    kind=ISSUE_KIND, name="", severity=NormalizationIssue.Severity.ERROR,
                    disposition=NormalizationIssue.Disposition.SKIPPED,
                    reason=f"Entry in {container!r} is {type(entry).__name__}, expected a mapping.",
                    node=f"network/interface/{container}"))
                continue
            name = str(entry.get("@name") or "").strip()
            if not name:
                issues.append(InterfaceIssue(
                    kind=ISSUE_KIND, name="", severity=NormalizationIssue.Severity.ERROR,
                    disposition=NormalizationIssue.Disposition.SKIPPED,
                    reason="Entry has no @name, so it cannot be identified or joined to "
                           "anything that references an interface by name.",
                    node=f"network/interface/{container}", raw_entry=entry))
                continue
            found.append({"container": container, "name": name, "entry": entry, "parent": ""})

            # Units hang under the type subtree for ethernet/aggregate-ethernet and directly
            # off the container entry for the logical ones. Both shapes, one walk.
            for holder in ([entry] + [entry[k] for k in TYPE_SUBTREE_KEYS
                                      if isinstance(entry.get(k), dict)]):
                units = holder.get("units")
                if not isinstance(units, dict):
                    continue
                for unit in ensure_list(units.get("entry")):
                    if not isinstance(unit, dict):
                        issues.append(InterfaceIssue(
                            kind=ISSUE_KIND, name="", severity=NormalizationIssue.Severity.ERROR,
                            disposition=NormalizationIssue.Disposition.SKIPPED,
                            reason=f"Unit of {name!r} is {type(unit).__name__}, expected a mapping.",
                            node=f"network/interface/{container}"))
                        continue
                    unit_name = str(unit.get("@name") or "").strip()
                    if not unit_name:
                        issues.append(InterfaceIssue(
                            kind=ISSUE_KIND, name="", severity=NormalizationIssue.Severity.ERROR,
                            disposition=NormalizationIssue.Disposition.SKIPPED,
                            reason=f"A unit of {name!r} has no @name.",
                            node=f"network/interface/{container}", raw_entry=unit))
                        continue
                    found.append({"container": container, "name": unit_name,
                                  "entry": unit, "parent": name})
    return found, issues


def normalize_interfaces(appliance: Appliance) -> NormalizedInterfaces:
    """Replace every interface for one appliance. Returns what was written and what was wrong."""
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")
    device_entry = device_entry_from_snapshot(snapshot)

    raw, issues = _collect(device_entry)

    seen: set[str] = set()
    rows: list[dict] = []
    #: Parents are emitted before their units by `_collect`, so a unit can look its
    #: parent's resolved type up rather than re-deriving it from an entry that has none.
    type_by_name: dict[str, str] = {}
    for item in raw:
        name = item["name"]
        if name in seen:
            issues.append(InterfaceIssue(
                kind=ISSUE_KIND, name=name, severity=NormalizationIssue.Severity.ERROR,
                disposition=NormalizationIssue.Disposition.SKIPPED,
                reason="A second entry uses this name. Interface names are unique per "
                       "device, so the later one was dropped rather than overwriting.",
                node=f"network/interface/{item['container']}", raw_entry=item["entry"]))
            continue
        seen.add(name)
        entry = item["entry"]
        interface_type, address_node, aggregate = _classify(
            item["container"], entry, issues, name,
            parent_type=type_by_name.get(item["parent"]) if item["parent"] else None)
        type_by_name[name] = interface_type
        # A unit of a physical interface carries its own addressing directly, not under a
        # type key - the type key is on the parent.
        addressing, ipv4, ipv6 = _addressing(address_node if not item["parent"] else entry)
        rows.append({
            "name": name, "container": item["container"], "interface_type": interface_type,
            "parent_name": item["parent"], "aggregate_group": aggregate,
            "addressing": addressing, "ipv4_addresses": ipv4, "ipv6_addresses": ipv6,
            "comment": _text(entry.get("comment")),
        })

    written: list[Interface] = []
    with transaction.atomic():
        Interface.objects.filter(appliance=appliance).delete()
        by_name: dict[str, Interface] = {}
        # Parents before units, so a unit's FK has something to point at.
        for row in sorted(rows, key=lambda r: (bool(r["parent_name"]), r["name"])):
            parent = by_name.get(row.pop("parent_name")) if row["parent_name"] else None
            row.pop("parent_name", None)
            interface = Interface.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                source_snapshot=snapshot,
                parent=parent,
                **row,
            )
            by_name[interface.name] = interface
            written.append(interface)

        _replace_issues(appliance, issues)
    return NormalizedInterfaces(interfaces=written, issues=issues)


def _replace_issues(appliance: Appliance, issues: list[InterfaceIssue]) -> None:
    """Replace this APPLIANCE's interface issues.

    Owned by the appliance, not its group, because both members of an HA pair normalize
    their own interfaces. A group-scoped replace would have the second peer's run delete
    the first's issues without a trace - the one failure mode an issue record cannot have.
    """
    NormalizationIssue.objects.filter(appliance=appliance, kind=ISSUE_KIND).delete()
    NormalizationIssue.objects.bulk_create([
        NormalizationIssue(
            management_station=appliance.management_station,
            appliance=appliance,
            kind=issue.kind, name=issue.name, severity=issue.severity,
            disposition=issue.disposition, reason=issue.reason,
            node=issue.node, source=issue.source, raw_entry=issue.raw_entry,
        )
        for issue in issues
    ])
