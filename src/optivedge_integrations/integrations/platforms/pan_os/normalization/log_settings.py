"""Device > Log Settings, the log-settings server profiles, and Log Forwarding availability.

The logging domain - PAN-LOG-001 to 010 - across three models:

    LogServerTarget      one server entry inside one syslog or email profile, in one scope
    VsysLogForwarding    one row per vsys: which log types no available profile sends off-box
    LoggingSettings      one row per appliance, the device-wide posture (the model already
                         existed for PAN-MGT-011; this adds thirteen columns to that row)

FOUR SHAPES HERE WOULD BITE A NORMALIZER WRITTEN FROM ONE OF THEM:

    the address key has TWO NAMES     `server` on the syslog kind, `gateway` on the email kind -
                                      the same trap `ServerProfile` folds three names for
    the filter is FREE TEXT           not an enum. `action=complete` on it answers with an empty
                                      list, so coverage is PARSED and never compared
    a profile is only an ADDRESS BOOK nothing is sent until a match list's member list names it,
                                      so every verdict runs through the referrer walk
    the profiles a vsys can use come  its own, shared, Panorama-pushed and vendor-predefined, and
    from FOUR SCOPES                  the last reaches no other read at all

WHICH DIRECTION AN UNKNOWN GOES IS DECIDED UPSTREAM AND IMPLEMENTED HERE UNCHANGED. Every gap
column lists what is MISSING, so an unparsed filter contributes NO coverage and an absent
`send-to-panorama` forwards NOTHING - the firing direction in both cases. Two columns go the
other way on purpose: `central_store_status_collected` and
`VsysLogForwarding.pushed_profile_sources_collected` are false until their read exists, and false
EXCLUDES the row from its control. The choice there is between a silent control and a
high-severity false finding on every correctly configured device.

WHAT THIS MODULE CANNOT SEE, stated here because a reader will look for it:

  * A profile that exists only in a pushed TEMPLATE is stored as though the appliance defined it.
    The scope column has three tokens - shared, vsys, predefined - and no fourth. The per-field
    `template` provenance row beside the value is the only thing that says otherwise.
  * Whether delivery to the central store is working, beyond what one op command reports. An
    unknown here FIRES, per rules.md - `central_store_delivery_healthy` is true only on positive
    evidence of a completed forward, and a connected collector that has never delivered anything
    is false. The read cannot tell "created no logs" from "nothing populates this counter", so
    the reassuring reading of that state is not available to it.
  * A Log Forwarding profile pushed from Panorama is read out of the pushed-shared-policy
    snapshot IF that read carries the node, which has never been measured. When it does not, the
    gap column rests on the local and predefined profiles alone, and
    `pushed_profile_sources_collected` is what keeps the control from over-reporting.
  * Which of two same-named profiles a vsys member resolves to when both a vsys and shared hold
    one. The vsys-first rule here is the one measured for certificates and applied unchanged;
    the Log Settings collision itself was written on a device deliberately and could not be
    settled - `action=complete` on `send-syslog` returned an empty list on both sides.
"""

from __future__ import annotations

import re
from typing import Any

from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    FORWARDING_PROFILE_LOG_TYPES,
    LogServerTarget,
    NormalizationIssue,
    LoggingSettings,
    PANORAMA_FORWARDABLE_LOG_TYPES,
    SYSTEM_LOG_SEVERITIES,
    Snapshot,
    VsysLogForwarding,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication import (
    attribute_references, find_references)
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
    ScopedEntry, scoped_nodes, write_scoped_objects)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ensure_list,
    iter_member_values,
    merge_pushed_entries,
    parse_integer_field,
    parse_text_field,
    parse_yes_no_field,
    pushed_shared,
    pushed_vsys_panorama,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot, latest_merged_snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    write_node_row)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    is_panorama_managed, latest_pushed_shared_snapshot, latest_pushed_vsys_snapshot)


#: The Device > Log Settings kinds. `correlation` exists on one lab platform only and has NO
#: `send-to-panorama` key at all, measured - the vendor says correlation logs cannot be forwarded
#: from a firewall - so it is read for display and excluded from the Panorama gap set.
LOG_SETTINGS_KINDS = (
    "system", "config", "userid", "hipmatch", "globalprotect", "iptag", "correlation",
)

#: The two log-settings children this domain models. `http` and `snmptrap` sit beside them and
#: are not modelled: no logging control asserts them. Named rather than discovered, because an
#: unfamiliar child of this container is a DIFFERENT OBJECT and not an unrecognised kind of the
#: same one - the opposite of `server-profile`, where iterating the children is right.
SERVER_PROFILE_KINDS = (LogServerTarget.Kind.SYSLOG, LogServerTarget.Kind.EMAIL)

#: kind -> the key its server entries use for an address. Reading one name loses the other.
ADDRESS_KEY = {
    LogServerTarget.Kind.SYSLOG: "server",
    LogServerTarget.Kind.EMAIL: "gateway",
}

#: kind -> the member list a forwarding rule names it in.
REFERRER_KEY = {
    LogServerTarget.Kind.SYSLOG: "send-syslog",
    LogServerTarget.Kind.EMAIL: "send-email",
}

#: THE DESTINATIONS THAT COUNT AS OFF-BOX. Email and SNMP-trap are deliberately excluded: they
#: NOTIFY rather than retain, so a match list whose only destination is one of them leaves no
#: durable off-box copy. An HTTP collector counts.
OFFBOX_MEMBER_KEYS = ("send-syslog", "send-http")

#: Most severe first, which is the order a gap list is written in so a reader can see the worst
#: one at the front.
_SEVERITY_RANK = {name: index for index, name in enumerate(reversed(SYSTEM_LOG_SEVERITIES))}

#: What the device itself writes for an unrestricted Log Settings filter, plus the empty string.
#: Measured: the grid renders a written filter as `All Logs`, the vendor's own predefined Log
#: Forwarding profile uses that literal on all eight of its match lists, and `All Logs` was
#: accepted at commit validation on the Log Settings node (validate job 5945, 2026-10-19).
UNRESTRICTED_FILTERS = frozenset({"", "all logs", "all"})

_SEVERITY_TERM = re.compile(r"\bseverity\s+(eq|neq|geq|leq)\s+'?([a-z-]+)'?", re.IGNORECASE)
_CONNECTIVE = re.compile(r"\s+(and|or)\s+", re.IGNORECASE)

#: Every stored value for an ABSENT key, with the measurement that licenses it. They live in one
#: block so a reviewer can read the domain's whole set of claims about PAN-OS in one place, and
#: each `basis` is the upstream artifact's own sentence rather than a paraphrase.
LOG_SETTINGS_IMPLICITS = {
    "send-to-panorama": Implicit.measured(
        False,
        "stage 4, logging domain: send-to-panorama's implicit value measured as `no` on the "
        "System kind against the device's own forwarding counters, 2026-10-19 - an absent key "
        "forwards nothing. Carried to the other five Log Settings kinds and to the Log "
        "Forwarding profile's own copy, which are the same key by completion and were not "
        "exercised; that direction is the firing one"),
    "transport": Implicit.measured(
        LogServerTarget.Transport.UDP,
        "stage 4, 2026-10-19 on fw-core-tpa-a (PA-5220 11.1.13-h3): a committed server entry "
        "holding only its address renders UDP in the grid AND sends UDP datagrams on the wire; "
        "writing TCP moved delivery to tcp/5514, SSL produced a TLS ClientHello, and deleting "
        "the key returned both oracles to UDP"),
    "rule-require-audit-comment": Implicit.measured(
        False,
        "stage 4, 2026-10-19 on fw-core-tpa-a (PA-5220 11.1.13-h3): with the key absent a policy "
        "change committed with no audit comment, and with it set to yes the same commit was "
        "refused at submission with code=13 naming the rule's xpath; deleting the key let the "
        "rule commit again (job 438)"),
    "port": Implicit.not_assumed(
        "stage 4 read 514 off the UI grid with the key absent and DECLINED to licence it: the "
        "grid renders 514 under transport SSL where the vendor's own completion help names 6514, "
        "so nothing there tells a real implicit from a renderer constant. The email side is the "
        "same shape - 25 was read off the grid, and every wire test wrote 2525 because 25 is "
        "privileged on the test host, so absence was never observed on the wire"),
    "server-address": Implicit.not_assumed(
        "stage 4 recorded the syslog address's absence as NOT REACHED - every subject wrote the "
        "address, so its absence was never committed or read. On the email kind `gateway` is "
        "mandatory at commit validation (job 432), so a committed entry never lacks it and an "
        "absence asserts nothing"),
    "protocol": Implicit.not_assumed(
        "stage 4: mandatory at commit validation on BOTH platforms - job 433 on the PA-5220 "
        "11.1.13-h3 and job 46 on the PA-VM 11.2.5 - so no committed relay lacks it and an "
        "absence asserts nothing. The two surfaces that disagreed about a key-less entry "
        "(`SMTP over TLS` in the outer grid, `Unauthenticated SMTP` in the inner) describe a "
        "state no committed device holds"),
    "tls-version": Implicit.not_assumed(
        "stage 4 measured this implicit as a RELATION and not a constant: the dialog's inner "
        "grid renders 1.2 with the key absent UNDER PROTOCOL TLS and renders nothing under "
        "protocol SMTP, while the outer grid stays blank in every state. A constant 1.2 expanded "
        "over every row would claim a hardened setting for relays that have none"),
    "auth": Implicit.not_assumed(
        "stage 4 left it unmeasured and declined to licence a guess: the grids render it blank "
        "with the key absent, and over cleartext SMTP with a username and password set the "
        "client sent NO AUTH command for auth absent, Auto and Login alike, so the one "
        "available oracle does not move with the key"),
    "filter": Implicit.measured(
        "",
        "stage 4: `filter` is mandatory at commit validation on the Log Settings node (job 434) "
        "and on the Log Forwarding profile's match list, so a committed entry always carries "
        "one. An empty reading can only be an uncommitted candidate state, and it is treated as "
        "UNRESTRICTED because that is what the device renders for one"),
}


# ---------------------------------------------------------------------------
# the free-text filter, which is parsed and never compared
# ---------------------------------------------------------------------------

def filter_is_unrestricted(text: str) -> bool:
    """Whether a Log Settings or Log Forwarding filter holds nothing back.

    THE DEVICE SPELLS IT TWO WAYS ON TWO NODES, measured: the Log Forwarding profile's own filter
    completes with the literal `All Logs` while the Log Settings filter completes empty, and the
    grid renders a written filter as `All Logs` either way. So this compares against a small set
    of spellings rather than against one.

    Anything else is treated as narrowing. `filter` is mandatory at commit validation on both
    nodes, so every committed entry carries one and none may be assumed unrestricted until it has
    been read - which is the firing direction for PAN-LOG-004.
    """
    return text.strip().lower() in UNRESTRICTED_FILTERS


def _term_severities(operator: str, value: str) -> set[str]:
    if value not in _SEVERITY_RANK:
        return set()
    rank = _SEVERITY_RANK[value]
    if operator == "eq":
        return {value}
    if operator == "neq":
        return set(SYSTEM_LOG_SEVERITIES) - {value}
    if operator == "geq":
        return {s for s in SYSTEM_LOG_SEVERITIES if _SEVERITY_RANK[s] >= rank}
    if operator == "leq":
        return {s for s in SYSTEM_LOG_SEVERITIES if _SEVERITY_RANK[s] <= rank}
    return set()


def severities_covered(text: str) -> set[str]:
    """Which System-log severities a filter admits.

    THE DEVICE EVALUATES THIS EXPRESSION - it is what decides which System logs reach the
    collector - so it is configuration, and turning it into a severity set is a parse. There is
    no enum to compare against: `action=complete` on the key answers with an empty list.

    Three rules, and the third is the one to know about:

      1. an unrestricted filter covers all five severities;
      2. an expression whose terms are ALL `severity <eq|neq|geq|leq> <value>`, joined by `and`
         or `or`, covers the intersection or the union accordingly;
      3. ANYTHING ELSE COVERS NOTHING.

    Rule 3 is deliberate and it is the firing direction. A filter that also narrows by a
    dimension this cannot see - `(severity geq high) and (subtype eq general)` - has not been
    shown to carry every log of any severity, and a gap column that listed nothing for it would
    claim coverage nobody established. It OVER-REPORTS on such a filter, and over-reporting a
    missing off-box copy is the side an assessor can check in a minute.

    The term split is textual and does not understand nested parentheses, so a nested expression
    falls to rule 3 rather than being read wrongly. That is the same direction.
    """
    if filter_is_unrestricted(text):
        return set(SYSTEM_LOG_SEVERITIES)
    parts = _CONNECTIVE.split(text.strip())
    terms, connectives = parts[0::2], [c.lower() for c in parts[1::2]]
    covered: list[set[str]] = []
    for term in terms:
        match = _SEVERITY_TERM.search(term)
        if match is None:
            return set()
        found = _term_severities(match.group(1).lower(), match.group(2).lower())
        if not found:
            return set()
        covered.append(found)
    if not covered:
        return set()
    result = covered[0]
    for connective, nxt in zip(connectives, covered[1:]):
        result = (result & nxt) if connective == "and" else (result | nxt)
    return result


# ---------------------------------------------------------------------------
# reading the payload
# ---------------------------------------------------------------------------

def _text(node: Any) -> str:
    value, _, _ = scalar_value(node)
    return value


def _members(node: Any) -> list[str]:
    """The member names of a `send-*` list, which `iter_member_values` already knows how to read.

    Shared with the referrer walk rather than re-read, because a member list is the one shape a
    reader written against a scalar leaf returns "" for - the bug that made one AAA control
    report an in-use profile as unused.
    """
    return [name for name, _ in iter_member_values(node) if name]


def _log_settings_nodes(snapshot: Snapshot) -> list[tuple[str, str, dict[str, Any]]]:
    """(scope, vsys name, the `log-settings` node) for every scope that has one.

    `scoped_nodes` is the shared scope walk - shared, then EVERY vsys, not just vsys1 - and this
    passes it the container key rather than an entry key because `log-settings` holds several
    sibling containers below it, exactly as `server-profile` does.
    """
    return [(scope, vsys, node) for scope, vsys, node in scoped_nodes(snapshot, "log-settings")
            if isinstance(node, dict)]


def _shared_log_settings(snapshot: Snapshot) -> dict[str, Any]:
    """The appliance-wide Device > Log Settings node.

    SHARED ONLY, and that is not a simplification: the Device > Log Settings match lists are
    device-wide, which is why `LoggingSettings` is one row per appliance with no scope column.
    The vsys `log-settings` node holds server profiles and Log Forwarding profiles, which are
    other subjects.
    """
    for scope, _, node in _log_settings_nodes(snapshot):
        if scope == "shared":
            return node
    return {}


def _match_lists(log_settings: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    container = log_settings.get(kind)
    if not isinstance(container, dict):
        return []
    match_list = container.get("match-list")
    if not isinstance(match_list, dict):
        return []
    return [e for e in ensure_list(match_list.get("entry")) if isinstance(e, dict)]


def _sends_to_panorama(entry: dict[str, Any]) -> bool:
    value, _, _ = parse_yes_no_field(
        entry.get("send-to-panorama"), implicit=LOG_SETTINGS_IMPLICITS["send-to-panorama"])
    return bool(value)


def _entry_filter(entry: dict[str, Any]) -> str:
    value, _, _ = parse_text_field(entry.get("filter"),
                                   implicit=LOG_SETTINGS_IMPLICITS["filter"])
    return value


def _destinations(entry: dict[str, Any]) -> dict[str, Any]:
    """Every destination a match-list entry names, for display and for the verdicts."""
    return {
        "syslog": _members(entry.get("send-syslog")),
        "email": _members(entry.get("send-email")),
        "http": _members(entry.get("send-http")),
        "snmptrap": _members(entry.get("send-snmptrap")),
        "panorama": _sends_to_panorama(entry),
    }


class _ProfileIndex:
    """Which syslog and email profiles exist, by the scope that defines them.

    Exists so that "a match list names a profile" can be told from "a match list names a profile
    THAT EXISTS". A member naming nothing delivers nothing, and counting it would make an
    appliance with a typo in a member list look like one with a working destination.
    """

    def __init__(self) -> None:
        self.by_kind: dict[str, set[tuple[str, str]]] = {k: set() for k in SERVER_PROFILE_KINDS}

    def add(self, kind: str, vsys_name: str, profile_name: str) -> None:
        self.by_kind[kind].add((vsys_name, profile_name))

    def vsys_definitions(self, kind: str) -> set[tuple[str, str]]:
        return {(vsys, name) for vsys, name in self.by_kind[kind] if vsys}

    def resolves(self, kind: str, vsys_name: str, profile_name: str) -> bool:
        """Whether a member named from inside `vsys_name` reaches a profile of that name.

        VSYS FIRST, THEN SHARED - the rule measured for certificates and applied unchanged. The
        Log Settings collision was written on a device deliberately (the same profile name at
        shared and in vsys3, both accepted at commit) and could NOT be settled: completion on
        `send-syslog` returned an empty list on both sides. So this resolves EXISTENCE rather
        than precedence, which is all either verdict here needs - both ask whether the member
        reaches anything at all.
        """
        names = self.by_kind[kind]
        return (vsys_name, profile_name) in names or ("", profile_name) in names


def _server_profile_rows(snapshot: Snapshot) -> tuple[list[tuple[ScopedEntry, str, dict]],
                                                      _ProfileIndex]:
    """Every server entry of every syslog and email profile, in every scope, and the index.

    The ScopedEntry carries the SERVER entry rather than the profile entry: the server is the row,
    and its `@name` is what `write_scoped_objects` would otherwise reach for. The profile entry
    comes back beside it because the parent's name is part of the row's identity and its own
    `@ptpl` is a separate fact from the server's.
    """
    index = _ProfileIndex()
    rows: list[tuple[ScopedEntry, str, dict]] = []
    for scope, vsys_name, log_settings in _log_settings_nodes(snapshot):
        for kind in SERVER_PROFILE_KINDS:
            container = log_settings.get(kind)
            if not isinstance(container, dict):
                continue
            for profile in ensure_list(container.get("entry")):
                if not isinstance(profile, dict) or not profile.get("@name"):
                    continue
                profile_name = str(profile["@name"])
                index.add(kind, vsys_name if scope != "shared" else "", profile_name)
                servers = profile.get("server")
                servers = servers if isinstance(servers, dict) else {}
                for server in ensure_list(servers.get("entry")):
                    if not isinstance(server, dict) or not server.get("@name"):
                        continue
                    rows.append((ScopedEntry(scope, vsys_name, server), kind, profile))
    return rows, index


def _target_fields(server: dict[str, Any], kind: str,
                   profile_name: str) -> tuple[dict[str, Any], list[tuple]]:
    """(values, provenance triples) for one server entry.

    Returns both because five of these keys carry a DECLARED reading of their own absence and
    three of the five store nothing - a reader cannot tell "the device holds UDP" from "the key
    was absent and UDP is what that means" by looking at the value.
    """
    provenance: list[tuple] = []
    values: dict[str, Any] = {
        "kind": kind,
        "profile_name": profile_name,
        "server_name": str(server["@name"]),
    }

    address, address_rk, address_rv = parse_text_field(
        server.get(ADDRESS_KEY[kind]), implicit=LOG_SETTINGS_IMPLICITS["server-address"])
    values["server_address"] = address[:255]
    provenance.append(("server_address", address_rk, address_rv))

    port, port_rk, port_rv = parse_integer_field(
        server.get("port"), implicit=LOG_SETTINGS_IMPLICITS["port"])
    values["port"] = port
    provenance.append(("port", port_rk, port_rv))

    if kind == LogServerTarget.Kind.SYSLOG:
        transport, transport_rk, transport_rv = parse_text_field(
            server.get("transport"), implicit=LOG_SETTINGS_IMPLICITS["transport"])
        values["transport"] = transport[:8]
        provenance.append(("transport", transport_rk, transport_rv))
        # The email keys hold their field defaults on this kind, which is exactly why every
        # control on this model carries a clause on `kind`.
        values.update({"protocol": "", "tls_version": "", "auth_method": "",
                       "meets_authenticated_tls": False, "transport_grade": ""})
        return values, provenance

    # The syslog key holds its own default here, for the same reason in the other direction.
    values["transport"] = LogServerTarget.Transport.UDP
    protocol, protocol_rk, protocol_rv = parse_text_field(
        server.get("protocol"), implicit=LOG_SETTINGS_IMPLICITS["protocol"])
    tls_version, tls_rk, tls_rv = parse_text_field(
        server.get("tls-version"), implicit=LOG_SETTINGS_IMPLICITS["tls-version"])
    auth, auth_rk, auth_rv = parse_text_field(
        server.get("auth"), implicit=LOG_SETTINGS_IMPLICITS["auth"])
    provenance += [("protocol", protocol_rk, protocol_rv),
                   ("tls_version", tls_rk, tls_rv),
                   ("auth_method", auth_rk, auth_rv)]
    values.update({
        "protocol": protocol[:8],
        "tls_version": tls_version[:8],
        "auth_method": auth[:16],
        "meets_authenticated_tls": _meets_authenticated_tls(protocol, tls_version, auth),
        "transport_grade": _transport_grade(protocol, tls_version),
    })
    return values, provenance


def _meets_authenticated_tls(protocol: str, tls_version: str, auth: str) -> bool:
    """TLS, at the newest version the firewall offers, with an authentication method.

    A conjunction of three, written as one column because the FAILURE is a disjunction and the
    clause grammar is a flat conjunction - three queries would report one relay three times.

    A relay with protocol TLS and NO tls-version key is false: the device may well negotiate 1.2,
    and nothing stored establishes it. `transport_grade` carries that state as a member of its
    own so the report can say which of the three parts failed.
    """
    return protocol == LogServerTarget.Protocol.TLS and tls_version == "1.2" and bool(auth)


def _transport_grade(protocol: str, tls_version: str) -> str:
    """The protocol-and-version pair as one graded value.

    A severity grading places values of ONE column and the vendor keeps the pair in two, so this
    is where they are joined. Four members for two measured enums: SMTP, TLS 1.1, TLS 1.2, and
    protocol TLS with the version key absent.
    """
    if protocol == LogServerTarget.Protocol.SMTP:
        return LogServerTarget.GRADE_SMTP
    if protocol != LogServerTarget.Protocol.TLS:
        # No protocol key at all, which on a committed device cannot happen - the key is
        # mandatory at commit validation. Ungraded rather than graded as the weakest value:
        # a candidate-only state is not a configuration to report.
        return ""
    if tls_version == "1.1":
        return LogServerTarget.GRADE_TLS_11
    if tls_version == "1.2":
        return LogServerTarget.GRADE_TLS_12
    return LogServerTarget.GRADE_TLS_VERSION_UNSET


# ---------------------------------------------------------------------------
# the referrer walk
# ---------------------------------------------------------------------------

#: `deviceconfig/setting/management/audit-tracking` carries its own `send-syslog`, and it does
#: NOT count as a referrer: it is a different subject and was ruled out of scope. Of the three
#: referrers found on this leaf, two count.
_AUDIT_TRACKING = "/audit-tracking"


def _referrer_counts(payload: dict[str, Any],
                     index: _ProfileIndex) -> dict[str, dict[tuple[str, str], int]]:
    """{kind: {(vsys, profile name): how many forwarding rules name it}}.

    WALKS THE WHOLE PAYLOAD rather than the paths the CLI grammar lists, which is the shared
    `find_references` and the same discipline as the two AAA controls on this shape: a "nobody
    references this" claim is only as good as the list of places a reference could hide, and a
    path the grammar missed would make an in-use profile report as unused.

    Attribution is the shared rule too - a reference from inside a vsys resolves to that vsys's
    object of the name when one exists, and to the shared one otherwise - so the rule has one
    home rather than a second copy that can drift.
    """
    references = find_references(payload.get("config"),
                                 keys=tuple(REFERRER_KEY.values()))
    counts: dict[str, dict[tuple[str, str], int]] = {k: {} for k in SERVER_PROFILE_KINDS}
    for kind in SERVER_PROFILE_KINDS:
        marker = f"/{REFERRER_KEY[kind]}"
        mine = [(vsys, name, where) for vsys, name, where in references
                if marker in where and _AUDIT_TRACKING not in where]
        attributed = attribute_references(mine, index.vsys_definitions(kind))
        counts[kind] = {key: len(paths) for key, paths in attributed.items()}
    return counts


# ---------------------------------------------------------------------------
# the Log Forwarding profiles a vsys can use
# ---------------------------------------------------------------------------

def latest_predefined_log_forwarding_snapshot(appliance: Appliance) -> Snapshot | None:
    """The vendor-shipped Log Forwarding profiles, collected separately from the merged config.

    Separate because `/config/predefined` is in NO other read: not the merged config, not the
    running view, and `show predefined` addresses a different namespace with a similar name.
    A missing snapshot is "predefined unknown" and not "there are none" - which is what
    `pushed_profile_sources_collected` records, because the difference decides whether
    PAN-LOG-005 may speak at all.
    """
    return (
        Snapshot.objects.filter(
            appliance=appliance, source_type="config_predefined_log_forwarding_profiles")
        .order_by("-collected_at", "-pk")
        .first()
    )


def _enforcement_points(appliance: Appliance):
    """Every enforcement point that speaks for this appliance.

    BOTH OWNERS, because exactly one of the two FKs is set and WHICH ONE IS NOT ABOUT HA: the
    only production site that creates an enforcement point always sets `appliance_group`, and
    `appliance` is set only in tests - so reading just one of them finds nothing in exactly one
    of the two environments. `management_station.station_type` is the explicit discriminant and
    `snapshots.py::is_panorama_managed` is where that is written down.
    """
    points = list(appliance.enforcement_points.all())
    group = appliance.appliance_group
    if group is not None:
        points += list(group.enforcement_points.all())
    return points


def _pushed_snapshots_by_vsys(appliance: Appliance) -> dict[str, list[Snapshot]]:
    """{vsys name: the pushed-shared-policy reads that speak for it}, plus "" for the group-wide.

    BOTH READS, because an empty one does not mean an empty object set: skipping the shared read
    on the strength of an empty per-vsys one dropped 182 objects on one lab device. The two
    lookups are the shared ones in `snapshots.py`, which also hold the rule that pushed policy
    is meaningless without Panorama.

    WHETHER EITHER READ CARRIES `log-settings/profiles` WAS RECORDED AS UNMEASURED and is now
    measured: on all four lab appliances, 2026-10-22, the device-wide read carries
    `shared/log-settings/profiles` (PA-5220) or `policy/panorama/log-settings/profiles` (PA-VM),
    every element marked @loc - three pushed profiles, one of them with a match list forwarding
    traffic to Panorama. The PA-5220's per-vsys read carries the node with a NULL `profiles`
    child, which is why both are read and neither is treated as authoritative on its own.
    """
    by_vsys: dict[str, list[Snapshot]] = {}
    for point in _enforcement_points(appliance):
        shared = latest_pushed_shared_snapshot(point)
        if shared is not None:
            by_vsys.setdefault("", [])
            if shared not in by_vsys[""]:
                by_vsys[""].append(shared)
        per_vsys = latest_pushed_vsys_snapshot(point)
        if per_vsys is not None:
            by_vsys.setdefault(point.vsys_name, []).append(per_vsys)
    return by_vsys


def _forwarding_profiles_from_node(node: Any) -> list[dict[str, Any]]:
    profiles = node.get("profiles") if isinstance(node, dict) else None
    if not isinstance(profiles, dict):
        return []
    return [e for e in ensure_list(profiles.get("entry")) if isinstance(e, dict)]


def _pushed_forwarding_profiles(snapshots: list[Snapshot], vsys_name: str,
                                label: str) -> tuple[list[dict[str, Any]], list[tuple]]:
    """(profile entries, notes) from the pushed reads, merged and deduplicated by @loc.

    THE TWO READS OVERLAP AND ON A SINGLE-VSYS DEVICE THEY ARE BYTE-IDENTICAL, which this got
    wrong before the readback caught it: concatenating them listed every pushed profile TWICE in
    `profile_names` on both PA-VMs, where the device-wide and per-vsys responses are the same
    payload. `merge_pushed_entries` is the shared helper written for exactly that trap - it keys
    on (name, namespace type, namespace value) read from @loc, so the identical case collapses to
    one row and a genuine cross-scope override pair stays two.

    It is called with the `log-settings` node as the root and `profiles` as the kind, because the
    entries sit one level below the container the helper's other callers pass.
    """
    reads: list[tuple[dict[str, Any], Any]] = []
    for snapshot in snapshots:
        payload = snapshot.payload
        try:
            root = (pushed_shared(payload)
                    if snapshot.source_type == "show_pushed_shared_policy"
                    else pushed_vsys_panorama(payload))
        except ValueError:
            # An unrecognised shape is not evidence of an empty one. The pushed reads belong to
            # another domain's collector and their roots differ by device; a shape neither helper
            # knows is reported by `pushed_profile_sources_collected` staying as it is rather
            # than by this verdict silently losing the profiles.
            continue
        node = root.get("log-settings")
        if isinstance(node, dict):
            reads.append((node, snapshot))
    merged, notes = merge_pushed_entries(
        reads, "profiles", vsys_name=vsys_name, label=label)
    return [entry for entry, _, _, _ in merged], notes


def _available_forwarding_profiles(
    snapshot: Snapshot, vsys_name: str, predefined: Snapshot | None,
    pushed: list[dict[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    """(source, profile entry) for every Log Forwarding profile available to one vsys.

    FOUR SOURCES, AND NO PRECEDENCE LADDER IS APPLIED. The two measured directions disagree
    outright: for `default` only the Panorama-pushed profile was offered to a vsys3 rule and the
    local one was shadowed, while for `IoT Security Default Profile` only the LOCAL one was
    offered and the predefined was dropped from the pool. So this records which source each name
    came from and takes the UNION for the coverage verdict - "no profile available to this vsys
    sends this log type off the box" is a question about the pool, not about which copy wins.
    """
    available: list[tuple[str, dict[str, Any]]] = []
    for scope, scope_vsys, log_settings in _log_settings_nodes(snapshot):
        if scope == "vsys" and scope_vsys != vsys_name:
            continue
        source = "shared" if scope == "shared" else "vsys"
        available += [(source, p) for p in _forwarding_profiles_from_node(log_settings)]
    available += [("device-group", p) for p in pushed]
    if predefined is not None and isinstance(predefined.payload, dict):
        available += [("predefined", p)
                      for p in _forwarding_profiles_from_node(predefined.payload)]
    return available


def _offbox_log_types(profiles: list[tuple[str, dict[str, Any]]], vsys_name: str,
                      index: _ProfileIndex) -> set[str]:
    """Which Log Forwarding log types reach an off-box destination."""
    covered: set[str] = set()
    for _, profile in profiles:
        match_list = profile.get("match-list")
        match_list = match_list if isinstance(match_list, dict) else {}
        for entry in ensure_list(match_list.get("entry")):
            if not isinstance(entry, dict):
                continue
            if not _entry_is_offbox(entry, vsys_name, index):
                continue
            log_type = _text(entry.get("log-type"))
            if log_type:
                covered.add(log_type)
    return covered


def _entry_is_offbox(entry: dict[str, Any], vsys_name: str, index: _ProfileIndex) -> bool:
    """Whether a match-list entry sends a durable copy off the box.

    A syslog member must RESOLVE to a profile - a member naming nothing delivers nothing. An
    HTTP member is counted WITHOUT resolution, which is the one asymmetry here and is recorded
    rather than hidden: no control asserts an HTTP profile, so none is modelled and there is no
    index to resolve against. Counting it unresolved is the non-firing direction for the gap
    columns, and the alternative - ignoring HTTP collectors - would report a gap on an appliance
    that forwards everything to one.
    """
    if any(index.resolves(LogServerTarget.Kind.SYSLOG, vsys_name, name)
           for name in _members(entry.get("send-syslog"))):
        return True
    if _members(entry.get("send-http")):
        return True
    return _sends_to_panorama(entry)


# ---------------------------------------------------------------------------
# show logging-status
# ---------------------------------------------------------------------------

def latest_logging_status_snapshot(appliance: Appliance) -> Snapshot | None:
    return (
        Snapshot.objects.filter(appliance=appliance, source_type="show_logging_status")
        .order_by("-collected_at", "-pk")
        .first()
    )


#: A per-log-type line of `show logging-status verbose` carries SIX FIELDS as PRE-FORMATTED
#: TEXT - "system   2026/10/22 00:58:21   2026/10/22 03:30:07   7698... 7698... 18" - so it is
#: split rather than read as keys. Two of the six are two tokens wide each: a timestamp is
#: "<date> <time>" and an unset one reads "Not Available", so both are collapsed to one token
#: before the split and the line is six tokens exactly.
_TIMESTAMP = re.compile(r"(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})")
_UNSET = re.compile(r"Not\s+Available", re.IGNORECASE)


def _parse_log_type_line(line: str) -> dict[str, Any] | None:
    """One log type's counters, or None where the line is not the expected shape.

    Returns `created`, `forwarded` (each a timestamp string or ""), and the three integers.
    An unparseable line yields None and the verdict treats it as UNKNOWN rather than healthy -
    a reply shape nobody has seen is not evidence that delivery is fine.
    """
    text = " ".join(str(line or "").split())
    if not text:
        return None
    # `Not Available` is TWO tokens and each timestamp is two more, so the two fields are
    # collapsed to one token each BEFORE splitting. Doing it the other way round - counting
    # "Not Available" in the whole line - lost the MIXED case: a log type that has created a log
    # and never forwarded it read as "nothing created", which is precisely the backlog failure
    # the control exists to find. Caught by the test, not by the readback, because no lab
    # appliance is currently in that state.
    collapsed = _TIMESTAMP.sub(r"\1T\2", _UNSET.sub("-", text))
    tokens = collapsed.split(" ")
    if len(tokens) != 6:
        return None
    _, created, forwarded, *numbers = tokens
    try:
        seq_forwarded, seq_acked, total = (int(n) for n in numbers)
    except ValueError:
        return None
    return {"created": "" if created == "-" else created,
            "forwarded": "" if forwarded == "-" else forwarded,
            "seq_forwarded": seq_forwarded, "seq_acked": seq_acked, "total_forwarded": total}


def central_store_delivery(snapshot: Snapshot | None) -> tuple[bool, bool]:
    """(healthy, collected) from a `show logging-status verbose` snapshot.

    AN UNKNOWN FIRES, which is Jason's rule of 2026-10-23 and is why this returns a plain bool:
    "in a production environment, the outcome I would expect is a finding raised if there's no
    evidence of healthy delivery state. That's the only safe assumption." So `healthy` is TRUE
    only where this reading positively shows delivery working, and every other outcome - no
    snapshot, an unreadable reply, a connected collector that has never delivered anything - is
    false and fires.

    It returned `None` for the first three of those until that rule landed. A null matched no
    positive comparison, so an appliance nobody had read came out of the query as HEALTHY.

    HEALTHY REQUIRES THREE THINGS, and the middle one is the one the old version lacked:

      1. at least one log collector connection reports Active. `cms1 Inactive` beside
         `cms0 Active` is the ordinary state on three of the four lab appliances and is NOT a
         fault - the per-appliance question is whether ANY connection is up;
      2. at least one log type positively shows a completed delivery - a creation timestamp, a
         forwarding timestamp, and the acked sequence number level with the forwarded one. THIS
         IS WHAT MAKES "NOTHING HAS EVER BEEN DELIVERED" FIRE. The read cannot tell "this
         appliance created no logs" from "nothing is populating this counter", and rules.md's
         own words for that case are that a reading which cannot tell ZERO from UNKNOWN is an
         unknown;
      3. no log type shows a backlog - created and not forwarded, or acked behind forwarded. A
         connected collector whose counter has not moved since last Tuesday is exactly the
         failure this control exists to find, and it is why condition 1 alone is not enough:
         CONNECTION IS NOT DELIVERY, which is the naive reading stage 3 explicitly narrowed away
         from.

    Condition 2 is the change of direction and it moves real rows: on the lab, 2026-10-23, both
    PA-5220s deliver System logs (and tpa-b Traffic logs) with the counters moving between reads,
    so they are healthy on evidence - while both PA-VMs have every counter at Not Available and
    now fire, where before they passed.
    """
    if snapshot is None or not isinstance(snapshot.payload, dict):
        return False, False
    root = snapshot.payload.get("show-logging-status")
    if not isinstance(root, dict):
        return False, False
    conn = root.get("Conn-Info")
    entries = [e for e in ensure_list((conn or {}).get("entry")) if isinstance(e, dict)]
    if not entries:
        # The command answered and names no connection at all. A real reading, and not healthy:
        # an appliance with no collector connection is not delivering to one.
        return False, True
    active = [e for e in entries if "active" in str(e.get("conn-status") or "").lower()
              and "inactive" not in str(e.get("conn-status") or "").lower()]
    if not active:
        return False, True
    delivered = False
    for entry in active:
        for key, value in entry.items():
            if key.startswith("@") or not isinstance(value, str):
                continue
            if key not in PANORAMA_FORWARDABLE_LOG_TYPES and key not in ("gtp",):
                continue
            row = _parse_log_type_line(value)
            if row is None:
                # A reply shape nobody has seen. It used to read None and so pass; an unknown
                # fires, and an unparseable counter is an unknown.
                return False, True
            if not row["created"]:
                continue
            if not row["forwarded"] or row["seq_acked"] < row["seq_forwarded"]:
                return False, True
            delivered = True
    return delivered, True


# ---------------------------------------------------------------------------
# the appliance row
# ---------------------------------------------------------------------------

def _quota_configured(management: dict[str, Any]) -> bool:
    """Whether any log-retention key is set, in either of the two platform shapes.

    The branches differ BY PLATFORM - chassis-quota and chassis-log-expiration-period split
    mgmt-card/log-card on the PA-5220, disk-quota and log-expiration-period carry 43 log types on
    the PA-VM - so this is a presence test over four branches rather than a reading of one. All
    four are checked on every device: naming the platform would encode a lab where platform,
    version and vsys mode move together.
    """
    quota = management.get("quota-settings")
    if not isinstance(quota, dict):
        return False
    for branch in ("chassis-quota", "chassis-log-expiration-period", "disk-quota",
                   "log-expiration-period"):
        node = quota.get(branch)
        if isinstance(node, dict) and any(not k.startswith("@") for k in node):
            return True
        if node not in (None, "") and not isinstance(node, dict):
            return True
    return False


def _match_list_display(shared: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for kind in LOG_SETTINGS_KINDS:
        entries = _match_lists(shared, kind)
        if not entries:
            continue
        out.append({
            "log_type": kind,
            "entries": [{"name": str(e.get("@name") or ""),
                         "filter": _entry_filter(e),
                         "destinations": _destinations(e)} for e in entries],
        })
    return out


def _appliance_values(appliance: Appliance, snapshot: Snapshot, index: _ProfileIndex,
                      forwarding_by_vsys: dict[str, list[tuple[str, dict[str, Any]]]],
                      status: Snapshot | None) -> tuple[dict[str, Any], list[tuple]]:
    shared = _shared_log_settings(snapshot)
    device_entry = device_entry_from_snapshot(snapshot)
    deviceconfig = device_entry.get("deviceconfig")
    setting = (deviceconfig or {}).get("setting") if isinstance(deviceconfig, dict) else None
    management = (setting or {}).get("management") if isinstance(setting, dict) else None
    management = management if isinstance(management, dict) else {}

    audit, audit_rk, audit_rv = parse_yes_no_field(
        management.get("rule-require-audit-comment"),
        implicit=LOG_SETTINGS_IMPLICITS["rule-require-audit-comment"])

    system_entries = _match_lists(shared, "system")
    config_entries = _match_lists(shared, "config")

    # PAN-LOG-003. Coverage accumulates only over entries that actually leave the box, and the
    # gap is what is left - so an entry whose only destination is email or SNMP contributes
    # nothing, per the settlement that those notify rather than retain.
    severities = set()
    for entry in system_entries:
        if _entry_is_offbox(entry, "", index):
            severities |= severities_covered(_entry_filter(entry))
    severity_gaps = [s for s in SYSTEM_LOG_SEVERITIES if s not in severities]

    # PAN-LOG-004, as two halves and the conjunction over them, so a finding can say which one
    # failed. `config_log_filter_narrows` stays TRUE where no off-box entry exists at all: it is
    # the firing side, and it is also honest - nothing has been shown to be unrestricted.
    offbox_config = [e for e in config_entries if _entry_is_offbox(e, "", index)]
    config_offbox = bool(offbox_config)
    config_narrows = not any(filter_is_unrestricted(_entry_filter(e)) for e in offbox_config)

    # PAN-LOG-008's configuration half: a System match list covering critical severity that
    # names an email profile WHICH EXISTS.
    email_critical = any(
        "critical" in severities_covered(_entry_filter(entry))
        and any(index.resolves(LogServerTarget.Kind.EMAIL, "", name)
                for name in _members(entry.get("send-email")))
        for entry in system_entries)

    # PAN-LOG-001: a syslog profile that a forwarding rule actually names. Both node families
    # count - a Device > Log Settings match list and a Log Forwarding profile match list.
    syslog_in_use = any(
        index.resolves(LogServerTarget.Kind.SYSLOG, "", name)
        for kind in LOG_SETTINGS_KINDS
        for entry in _match_lists(shared, kind)
        for name in _members(entry.get("send-syslog")))
    if not syslog_in_use:
        syslog_in_use = any(
            index.resolves(LogServerTarget.Kind.SYSLOG, vsys_name, name)
            for vsys_name, profiles in forwarding_by_vsys.items()
            for source, profile in profiles
            if source in ("vsys", "shared")
            for entry in ensure_list((profile.get("match-list") or {}).get("entry"))
            if isinstance(entry, dict)
            for name in _members(entry.get("send-syslog")))

    # PAN-LOG-006: the Panorama gap, across BOTH node families. The Log Forwarding side is read
    # at vsys and shared ONLY - a predefined or pushed profile is not this appliance forwarding
    # the type, and the subject that counts those is the per-vsys one.
    to_panorama: set[str] = set()
    for kind in LOG_SETTINGS_KINDS:
        if kind == "correlation":
            continue
        if any(_sends_to_panorama(e) for e in _match_lists(shared, kind)):
            to_panorama.add(kind)
    for profiles in forwarding_by_vsys.values():
        for source, profile in profiles:
            if source not in ("vsys", "shared"):
                continue
            for entry in ensure_list((profile.get("match-list") or {}).get("entry")):
                if isinstance(entry, dict) and _sends_to_panorama(entry):
                    log_type = _text(entry.get("log-type"))
                    if log_type:
                        to_panorama.add(log_type)
    panorama_gaps = [t for t in PANORAMA_FORWARDABLE_LOG_TYPES if t not in to_panorama]

    healthy, collected = central_store_delivery(status)

    values = {
        "require_audit_comment": bool(audit),
        "log_retention_configured": _quota_configured(management),
        "syslog_destination_in_use": syslog_in_use,
        "log_settings_match_lists": _match_list_display(shared),
        "system_log_severity_gaps": ",".join(severity_gaps),
        "config_log_offbox_destination": config_offbox,
        "config_log_filter_narrows": config_narrows,
        "config_log_fully_offbox": config_offbox and not config_narrows,
        "panorama_managed": _panorama_managed(appliance),
        "panorama_log_type_gaps": ",".join(panorama_gaps),
        "email_alerting_for_critical_system_events": email_critical,
        "central_store_delivery_healthy": healthy,
        "central_store_status_collected": collected,
    }
    # ONE PROVENANCE ROW, FOR THE ONE COLUMN THAT READS A KEY. The other twelve are declared in
    # `LoggingSettings.DERIVED_FIELDS`, and a declared derived field that turned out to have a
    # stored row is what the gate in OEI's own tests fails on.
    return values, [("require_audit_comment", audit_rk, audit_rv)]


def _panorama_managed(appliance: Appliance) -> bool:
    """Whether this appliance has a central log store to reach.

    THE RULE IS `snapshots.py::is_panorama_managed` AND IS NOT RESTATED HERE. That function's
    docstring is where the prohibition on inferring this from the `appliance_group` FK is
    written down - `ApplianceGroup` models HA topology and a locally-managed HA pair is exactly
    what it is for - and it was widened to take an appliance for this column rather than copied.

    RESTS ON THE COLLECTION PATH, NOT ON A DEVICE READING, and that is recorded rather than
    hidden: the firewall-side fact is `deviceconfig/system/panorama-server`, which belongs to
    another domain's control and was not measured for this one.

    An appliance with no station reads TRUE, so the control FIRES rather than silently
    excluding the row - which is the direction every unknown in this domain takes.
    """
    if appliance.management_station is None:
        return True
    return is_panorama_managed(appliance)


# ---------------------------------------------------------------------------
# the entry point
# ---------------------------------------------------------------------------

def normalize_log_settings(appliance: Appliance) -> dict[str, int]:
    """Every logging row for one appliance: the server targets, the per-vsys verdicts, the row.

    ONE PASS FOR THREE MODELS because they share the expensive parts - the scope walk, the
    profile index and the referrer walk over the whole payload. Splitting them would walk the
    payload three times and let the three disagree about which profiles exist.
    """
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"log_server_targets": 0, "vsys_log_forwarding": 0, "logging_settings": 0}

    payload = snapshot.payload if isinstance(snapshot.payload, dict) else {}
    server_rows, index = _server_profile_rows(snapshot)
    counts = _referrer_counts(payload, index)

    predefined = latest_predefined_log_forwarding_snapshot(appliance)
    pushed_by_vsys = _pushed_snapshots_by_vsys(appliance)
    sources_collected = bool(pushed_by_vsys) and predefined is not None

    device_entry = device_entry_from_snapshot(snapshot)
    vsys_node = device_entry.get("vsys") if isinstance(device_entry, dict) else None
    vsys_names = [str(v.get("@name") or "").strip()
                  for v in ensure_list((vsys_node or {}).get("entry"))
                  if isinstance(v, dict) and str(v.get("@name") or "").strip()]
    forwarding_by_vsys = {}
    for name in vsys_names:
        pushed_profiles, notes = _pushed_forwarding_profiles(
            pushed_by_vsys.get("", []) + pushed_by_vsys.get(name, []),
            name, f"{appliance} / {name}")
        # REPORTED RATHER THAN DROPPED. An `error` note means the two pushed reads disagree about
        # one profile, which two views of one pushed policy cannot legitimately do, and a
        # `warning` means an entry carries no @loc so its scope is a documented fallback. Either
        # silently discarded would make a collection fault look like a configuration.
        for severity, reason, entry in notes:
            NormalizationIssue.objects.create(
                management_station=appliance.management_station, appliance=appliance,
                kind="log forwarding profile", name=str(entry.get("@name") or ""),
                severity=severity, disposition=NormalizationIssue.Disposition.KEPT,
                reason=reason, raw_entry=entry)
        forwarding_by_vsys[name] = _available_forwarding_profiles(
            snapshot, name, predefined, pushed_profiles)

    rows = []
    for scoped, kind, profile in server_rows:
        values, provenance = _target_fields(scoped.entry, kind, str(profile["@name"]))
        vsys_key = scoped.vsys_name if scoped.scope != "shared" else ""
        values["profile_referrer_count"] = counts[kind].get((vsys_key, values["profile_name"]), 0)
        rows.append((scoped, values, provenance))

    with transaction.atomic():
        written_targets = write_scoped_objects(
            LogServerTarget, appliance, snapshot, rows, extra_key="kind",
            identity=("profile_name", "server_name"))

        seen = []
        for vsys_name, profiles in forwarding_by_vsys.items():
            offbox = _offbox_log_types(profiles, vsys_name, index)
            obj = write_node_row(
                VsysLogForwarding, appliance, snapshot,
                {
                    "profile_names": [
                        {"name": str(profile.get("@name") or ""),
                         "source": source,
                         "offbox_log_types": sorted(
                             _offbox_log_types([(source, profile)], vsys_name, index))}
                        for source, profile in profiles],
                    "offbox_log_type_gaps": ",".join(
                        t for t in FORWARDING_PROFILE_LOG_TYPES if t not in offbox),
                    "pushed_profile_sources_collected": sources_collected,
                },
                lookup={"appliance": appliance, "vsys_name": vsys_name})
            seen.append(obj.pk)
        # A vsys that no longer exists on the device is gone. Leaving the row would report a gap
        # against an enforcement point nobody can configure.
        VsysLogForwarding.objects.filter(appliance=appliance).exclude(pk__in=seen).delete()

        values, provenance = _appliance_values(
            appliance, snapshot, index, forwarding_by_vsys,
            latest_logging_status_snapshot(appliance))
        write_node_row(LoggingSettings, appliance, snapshot, values, provenance)

    return {"log_server_targets": written_targets,
            "vsys_log_forwarding": len(seen),
            "logging_settings": 1}
