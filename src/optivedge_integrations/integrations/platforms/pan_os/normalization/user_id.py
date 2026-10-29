"""Normalization for the `user-id` domain. PAN-UID-002 to PAN-UID-006.

One entry point, three models:

    normalize_user_id(enforcement_point)   the collector settings, the discovery verdict and
                                           every monitored server, in one pass

THREE MODELS IN ONE PASS because they are three readings of ONE payload parse, and because the
third depends on the first: `UserIdMonitoredServer.tls_service_profile_bound` is resolved from
the collector's `syslog-service-profile`, two rows apart. Computing it here from the same parse
rather than from a row another pass wrote means this function carries NO ordering obligation on
its caller - running it first or last gives the same answer, and there is no first collection on
which it would read a previous run's rows or none at all.

A ROW IS WRITTEN FOR THE SETTINGS AND FOR THE DISCOVERY VERDICT EVEN WHERE THE NODE DOES NOT
EXIST, which is the whole reason those two models exist. `user-id-collector/setting` is absent on
all four lab appliances and all twenty vsys, and the agent-setup panel renders the same implicit
values on a vsys whose node was deleted and committed - so a vsys with no node is not a vsys with
no settings, it is a vsys running the vendor's. The same argument the other way round for the
discovery bound: the commonest FAILING state has no entry in it, so a row that only existed where
an entry did could never report the control's baseline failure.

THE MONITORED SERVERS ARE THE OPPOSITE GRAIN and are reconciled by delete-and-recreate. A row's
whole meaning there is that a sender EXISTS, so a leftover row reports a host somebody has
already removed - a finding against a fixed estate, with nothing noticing.

THREE SHAPES IN THIS SUBTREE THAT BREAK A NAIVE READER, all measured:

- AN ABSENT COLLECTION AND A COMMITTED EMPTY ONE ARE DIFFERENT ON THE WIRE AND IDENTICAL TO A
  TRUTHINESS TEST. An absent `include-exclude-network` answers None and raises `No such node`
  under `show`; a committed empty one answers a truthy `{'include-exclude-network': null}` in all
  three views. `entry_container` is the shipped reader that tells the three states apart and is
  used here rather than a fourth private copy of the same idea.
- A COLLECTOR THAT EXISTS DOES NOT IMPLY A SETTINGS NODE. One lab PA-VM holds a committed
  firewall-local `user-id-collector` with two empty child containers and NO `setting` child at
  all, read twice four hours apart. So the parent's presence says nothing, and the two absences -
  no collector, and a collector with no settings - read identically at the settings xpath.
- THE PER-ENTRY `disabled` KEY IS NEGATED WITH IMPLICIT `no`, so an entry carrying no `disabled`
  key is IN FORCE. A count that ignored the key would report a bound where there is none: a
  disabled entry looks configured in the grid and bounds nothing.

NO COLLECTION WORK IS COMMISSIONED BY ANY OF THIS. Every column of all three models arrives in
`<show><config><merged></merged></config></show>`, which `collectors/merged_config.py` already
issues once per appliance, and no operational read reports any of these settings: the state tree
answers NO_MATCHES for *user-id*, *userid*, *probing* and *mapping*timeout* on both lab builds,
and the three op commands that exist report a mapping count, null server-monitor statistics and a
null agent config - none of them a SETTING. The agent-setup panel is the only surface that renders
these values, which is why every implicit below cites a UI measurement and not a command.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    EnforcementPoint,
    FieldProvenance,
    UserIdCollectorSettings,
    UserIdDiscoveryBound,
    UserIdMonitoredServer,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    Implicit,
    choice_child,
    classify_prov_type,
    entry_container,
    entry_provenance,
    merged_vsys_entry,
    parse_integer_field,
    parse_text_field,
    parse_yes_no_field,
    provenance_raw_key,
    provenance_value,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    latest_merged_snapshot,
)

#: The entry-level provenance record, as `FieldProvenance` documents it: the marker on a named
#: PAN-OS entry rather than on one of its fields.
ENTRY_FIELD = "__entry__"

#: What the agent-setup panel renders for an absent key, measured in BOTH directions on one
#: appliance and one surface. Every citation below names the same measurement because it IS the
#: same measurement: a `user-id-collector/setting` node was created bare, validated clean and
#: committed - so none of the fifteen keys is mandatory and every absence is a state a running
#: device holds - then each key written and committed, the panel read, the key deleted and
#: committed, and the panel read again.
#:
#: THERE IS NO SECOND ORACLE FOR ANY OF THESE and it is worth knowing before anyone reaches for
#: one: the system state tree is empty for this domain on both lab builds, and the device's own
#: refusal messages name no effective value. What separates these from a form's construction
#: defaults is the two-directional positive control plus a batch sibling test showing that no
#: reading is a function of a neighbour - `enable-probing` moved to yes without moving Probe
#: Interval, and `enable-session` without moving Server Session Read Frequency.
_PANEL = (
    "stage4-user-id.json, object user-id-collector-setting, field {field}: implicit {value}, "
    "measured on serial 013201001475-class hardware and on 691665AC334B458 (PA-VM 11.2.5) "
    "2026-10-26 - read off the Palo Alto Networks User-ID Agent Setup panel over a COMMITTED "
    "bare `setting` node (validate full job 247 clean, commit 248 OK), with the positive control "
    "paid in BOTH directions: written and committed in job 250 with the panel re-read, then "
    "deleted with its node and committed in job 254 with the panel re-read again")

#: `enable-probing`. FALSE is the compliant side and the measured one: PAN-UID-003 fires where the
#: firewall probes, and the commonest estate state - no node at all, on every lab vsys - satisfies
#: the assertion because the device genuinely does not probe.
PROBING_IMPLICIT = Implicit.measured(
    False, _PANEL.format(field="enable-probing", value="'no'"))

#: `enable-session`. FALSE is the compliant side and the measured one. The vendor agrees twice -
#: Web Interface Help p.973-974 "Do not Enable Session. This setting requires that the User-ID
#: agent have an Active Directory account with Server Operator privileges" and Administrator's
#: Guide p.974 STEP 3 "Ensure that the Enable Session option is not enabled" - which is a
#: documented agreement with a measured implicit rather than the basis for it.
SESSION_IMPLICIT = Implicit.measured(
    False, _PANEL.format(field="enable-session", value="'no'"))

#: `enable-mapping-timeout`. TRUE, AND IT IS THE ONE IMPLICIT IN THIS DOMAIN THAT POINTS THE OTHER
#: WAY: expiry ON is the good state, where probing ON and session-reading ON are the bad ones. A
#: reader carrying "absent means the weak state" across from its two neighbours stores the
#: opposite of the truth here and nothing errors. The vendor agrees at Web Interface Help p.975
#: (Cache): "Enable the timeout to ensure the firewall has the most current user-to-IP-address
#: mapping information".
MAPPING_TIMEOUT_IMPLICIT = Implicit.measured(
    True, _PANEL.format(field="enable-mapping-timeout", value="'yes'"))

#: `ip-user-mapping-timeout`. 45 MINUTES, which the Help documents too - the half of that sentence
#: that is correct. The other half documents the settable range to 3,600 and the device refuses
#: anything over 1440 at the write gate with code=12, measured; `UserIdCollectorSettings.clean`
#: carries that range.
MAPPING_TIMEOUT_MINUTES_IMPLICIT = Implicit.measured(
    45, _PANEL.format(field="ip-user-mapping-timeout", value="45"))

#: `wmi-account`. NOT ASSUMED, so nothing is stored and the column holds the empty string. The key
#: sits on the WMI Authentication tab of the dialog the GEAR opens, and the UI oracle that
#: measured this node's other keys cannot click a gear - its click sites are log in, the login
#: banner, the nav tree, a grid row and a tab inside an already-open dialog. "No control on the
#: surface that tool can reach" is not "no control on this screen", and a wrong guess about a
#: principal name is worse than no answer.
WMI_ACCOUNT_IMPLICIT = Implicit.not_assumed(
    "the key is behind the gear dialog's WMI Authentication tab, which the UI oracle cannot "
    "reach - it has no click site for a gear - so what the device does with an absent key is "
    "unestablished. A wrong guess about a directory principal is worse than no answer")

#: `syslog-service-profile`. NOT ASSUMED for the same reason and with a sharper edge: the obvious
#: reading of an absent reference - nothing is bound - is almost certainly right and is NOT
#: measured, so declaring it a vendor fact would buy a green row with a false claim. The empty
#: string lands in the column either way and the derived boolean beside it reads false, which
#: fires.
SYSLOG_PROFILE_IMPLICIT = Implicit.not_assumed(
    "no positive control was paid on this key and its panel row is one of the fifteen the "
    "measuring run did not move, so what an absent reference asserts is not established beyond "
    "the obvious reading that nothing is bound - which is not the same as having measured it")

#: `disabled` on a discovery entry or a monitored server. NEGATED POLARITY with implicit `no`: the
#: grid column reads `Enabled` and is the negation of the stored key, so an entry carrying no
#: `disabled` key is IN FORCE. Measured on the discovery list, where it is load-bearing - a
#: disabled include entry looks configured and bounds nothing.
#:
#: USED INSIDE A DERIVATION AND DECLARED ON NO COLUMN, which is the price of the discovery
#: subject's verdict grain: a verdict row holds nothing read directly off the collection it is a
#: verdict over, so this measurement cannot carry a provenance row of its own here.
ENTRY_DISABLED_IMPLICIT = Implicit.measured(
    False,
    "stage4-user-id.json, object user-id-include-exclude-network, field disabled: polarity "
    "NEGATED, implicit 'no', status measured - the grid's Enabled column is the negation of the "
    "stored key, so an entry carrying no `disabled` key is in force")

#: The branches of a monitored-server entry, in the order `choice_child` walks them. The device
#: enforces exactly one: an entry with no branch is accepted at the write, accepted by nothing
#: afterwards, and refused by the useridd daemon at commit phase 1 with the bare semantic line
#: `Error: server <name> type is unknown`.
MONITORED_SERVER_KINDS = (
    UserIdMonitoredServer.KIND_ACTIVE_DIRECTORY,
    UserIdMonitoredServer.KIND_E_DIRECTORY,
    UserIdMonitoredServer.KIND_EXCHANGE,
    UserIdMonitoredServer.KIND_SYSLOG,
)

#: The address space a discovery include entry may name WITHOUT reaching publicly routable hosts.
#:
#: RFC 1918 AND RFC 3927, AND NOTHING ELSE, which is what stage 3 and stage 5 both name. It is
#: deliberately NOT `ipaddress.ip_network(...).is_private`, which is a wider and moving set - it
#: counts loopback, the 100.64/10 carrier-grade range, 192.0.0.0/24 and several others, and its
#: membership has changed between Python releases. A verdict that moved with the interpreter
#: would be a different control on a different machine.
#:
#: THE CONSEQUENCE FOR IPv6 IS AN OVER-FIRE AND IT IS DELIBERATE. Neither of those RFCs is about
#: IPv6, so an include entry naming an IPv6 unique-local range (fc00::/7) or a link-local one
#: counts here as covering public space and grades at the higher severity. Stage 5's value set has
#: no IPv6 reading at all, and `rules.md` holds that the direction of the error decides it: a
#: finding raised on an estate that is fine is checkable in a minute with the range attached,
#: where the reverse tells a customer they are bounded when they are not. Reported upstream rather
#: than quietly widened here.
_BOUNDED_NETWORKS = tuple(
    ipaddress.ip_network(cidr) for cidr in (
        "10.0.0.0/8",        # RFC 1918
        "172.16.0.0/12",     # RFC 1918
        "192.168.0.0/16",    # RFC 1918
        "169.254.0.0/16",    # RFC 3927
    )
)


def _text(node: Any) -> str:
    """A leaf may be a bare string or `{'#text': v, '@ptpl': ...}` - see the payload contract."""
    value, _raw_key, _raw_prov = scalar_value(node)
    return value


def _collector_node(vsys_entry: dict[str, Any]) -> dict[str, Any] | None:
    """The `user-id-collector` container, or None where the vsys holds none.

    Returns None for an EMPTY committed container too, and that is right for every caller here:
    each of them reads a named child, and a container with no children holds none of them. The
    distinction between absent and empty is made where it matters, in `entry_container` below.
    """
    node = vsys_entry.get("user-id-collector")
    return node if isinstance(node, dict) else None


def collector_settings_values(
    vsys_entry: dict[str, Any],
) -> tuple[dict[str, Any], list[tuple[str, Any, str | None]]]:
    """(column values, provenance rows) for one vsys's agent settings.

    Returned rather than written so a caller can assert the parse against a payload without a
    database, and so the two models that read `syslog_service_profile` get it from one parse.

    THE SETTINGS NODE IS ABSENT ON EVERY LAB VSYS, so this function's normal output is the four
    measured implicits and two empty strings - and the provenance rows that say so, typed
    `pan_os_default` for the four and `not_configured` for the two. That is the content of every
    row this estate would store, which is exactly why the implicits are the subject of the
    citations above rather than an afterthought.
    """
    collector = _collector_node(vsys_entry)
    setting = collector.get("setting") if collector is not None else None
    # A dict or nothing. A committed-but-empty `setting` node parses to None and reads the same as
    # an absent one here, which is correct: every key under it is then absent, and each
    # `parse_*_field` below resolves its own absence from its own declaration.
    node = setting if isinstance(setting, dict) else {}

    probing, probing_key, probing_prov = parse_yes_no_field(
        node.get("enable-probing"), implicit=PROBING_IMPLICIT)
    session, session_key, session_prov = parse_yes_no_field(
        node.get("enable-session"), implicit=SESSION_IMPLICIT)
    expiry, expiry_key, expiry_prov = parse_yes_no_field(
        node.get("enable-mapping-timeout"), implicit=MAPPING_TIMEOUT_IMPLICIT)
    minutes, minutes_key, minutes_prov = parse_integer_field(
        node.get("ip-user-mapping-timeout"), implicit=MAPPING_TIMEOUT_MINUTES_IMPLICIT)
    account, account_key, account_prov = parse_text_field(
        node.get("wmi-account"), implicit=WMI_ACCOUNT_IMPLICIT)
    profile, profile_key, profile_prov = parse_text_field(
        node.get("syslog-service-profile"), implicit=SYSLOG_PROFILE_IMPLICIT)

    values = {
        "enable_probing": probing,
        "enable_session": session,
        "enable_mapping_timeout": expiry,
        # A present-and-unparseable value falls back to the implicit and keeps the key's own
        # provenance, which `parse_integer_field` already does. The clamp is `clean()`'s and not
        # this function's: a value outside 1-1440 is a payload nobody has seen, and silently
        # moving it here would hide it.
        "ip_user_mapping_timeout": minutes,
        # Sliced to the column's own length. 255 is this store's number, not the device's - no
        # maxLength was measured for any field of this domain - and a narrower column would
        # silently lose the tail of a real UPN.
        "wmi_account": account[:255],
        "syslog_service_profile": profile[:64],
    }
    provenance = [
        ("enable_probing", probing_key, probing_prov),
        ("enable_session", session_key, session_prov),
        ("enable_mapping_timeout", expiry_key, expiry_prov),
        ("ip_user_mapping_timeout", minutes_key, minutes_prov),
        ("wmi_account", account_key, account_prov),
        ("syslog_service_profile", profile_key, profile_prov),
    ]
    return values, provenance


def _entry_is_in_force(entry: dict[str, Any]) -> bool:
    """Is this entry actually in effect? See `ENTRY_DISABLED_IMPLICIT` for the polarity."""
    disabled, _raw_key, _raw_prov = parse_yes_no_field(
        entry.get("disabled"), implicit=ENTRY_DISABLED_IMPLICIT)
    return not disabled


def reaches_public_space(cidr: str) -> bool:
    """Does this configured range reach address space outside RFC 1918 and RFC 3927?

    AN UNPARSEABLE VALUE ANSWERS TRUE, which is the firing side. A range this function cannot read
    is a range nobody has established as bounded, and `rules.md` holds that a missing reading
    reported as compliant is the worse error. The alternative - treating what we cannot parse as
    private - would report the strongest verdict in the set on the strength of a parse failure.
    """
    text = cidr.strip()
    if not text:
        return True
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        try:
            network = ipaddress.ip_network(f"{text}/32", strict=False)
        except ValueError:
            return True
    return not any(
        network.version == bounded.version and network.subnet_of(bounded)
        for bounded in _BOUNDED_NETWORKS
    )


def discovery_bound_verdict(vsys_entry: dict[str, Any]) -> dict[str, Any]:
    """The four columns of one vsys's discovery verdict, from its include/exclude list.

    THE EVALUATION ORDER IS FIXED AND IS WHAT MAKES THIS ONE ANSWER rather than four tests:
    covering public space beats having an include, which beats having only excludes, which beats
    having nothing. `UserIdDiscoveryBound.SHAPE_CHOICES` carries the same order and the model's
    `clean()` refuses a combination the walk cannot produce.

    ORDER-INSENSITIVE, AND THAT IS A LIMIT RATHER THAN A CHOICE: the sibling
    `include-exclude-network-sequence` node holds a custom evaluation order, nothing in the corpus
    says whether that order can change which entries take effect, and this verdict ignores it. Two
    appliances whose entries are identical and whose order differs get the same verdict.
    """
    collector = _collector_node(vsys_entry)
    # ABSENT, EMPTY AND POPULATED, told apart by the shipped reader. The first two are COLLAPSED
    # deliberately for this control - an empty list bounds nothing, exactly as no list does - and
    # the state is kept out of the row rather than stored, because no column stage 5 declares can
    # hold it and inventing one would be this stage deciding what the finding says.
    _state, entries = entry_container(collector or {}, "include-exclude-network")

    in_force = [entry for entry in entries if _entry_is_in_force(entry)]
    includes = [entry for entry in in_force
                if _text(entry.get("discovery")).lower() == "include"]
    excludes = [entry for entry in in_force
                if _text(entry.get("discovery")).lower() == "exclude"]
    # The configured CIDRs, in the order the list holds them, as written. An entry with no
    # `network-address` is kept rather than dropped: it is an include entry that bounds nothing,
    # and `reaches_public_space` answers true for its empty string, which fires.
    include_networks = [_text(entry.get("network-address")) for entry in includes]

    if includes and any(reaches_public_space(cidr) for cidr in include_networks):
        shape = UserIdDiscoveryBound.SHAPE_INCLUDE_COVERS_PUBLIC
    elif includes:
        shape = UserIdDiscoveryBound.SHAPE_INCLUDE_PRESENT
    elif excludes:
        # The vendor's implicit exclude-all rule, stated twice: Administrator's Guide p.975 STEP 4
        # and Web Interface Help p.982 both say an exclude-only list excludes EVERY subnetwork and
        # not only the ones named, so user mapping stops. A functional fault rather than an
        # exposure, which is why it is its own verdict and not folded into `no_entries`.
        shape = UserIdDiscoveryBound.SHAPE_EXCLUDE_ONLY
    else:
        shape = UserIdDiscoveryBound.SHAPE_NO_ENTRIES

    return {
        "list_shape": shape,
        "include_entry_count": len(includes),
        "exclude_entry_count": len(excludes),
        "include_networks": include_networks,
    }


def monitored_servers(
    vsys_entry: dict[str, Any], *, tls_profile_bound: bool,
) -> list[tuple[dict[str, Any], tuple[Any, str | None], tuple[Any, str | None]]]:
    """(column values, entry provenance, connection_type provenance) per monitored server.

    `tls_profile_bound` is passed IN rather than read here, because it is a fact about the
    collector's own settings node and not about any entry - and passing it keeps the resolution in
    one place for every row of the vsys.

    A NAMELESS OR DUPLICATE ENTRY IS DROPPED. A duplicate name within one kind is not expressible
    in PAN-OS, and a row with an empty subject is a finding nobody can act on; the shipped zone
    normalizer drops a nameless entry the same way.
    """
    collector = _collector_node(vsys_entry)
    _state, entries = entry_container(collector or {}, "server-monitor")

    out: list[tuple[dict[str, Any], tuple[Any, str | None], tuple[Any, str | None]]] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        name = _text(entry.get("@name"))
        if not name:
            continue
        # THE DISCRIMINATOR IS WHICH CHILD CONTAINER IS PRESENT and not a value, so there is no
        # leaf to read and no is-present operator a query could use - which is why the kind is a
        # derived column and why it is in the row's identity. `choice_child` is the shipped reader
        # for a PAN-OS choice node and answers ("", {}) for an entry carrying no branch.
        kind, branch = choice_child(entry, MONITORED_SERVER_KINDS)
        if (kind, name) in seen:
            continue
        seen.add((kind, name))

        if kind == UserIdMonitoredServer.KIND_SYSLOG:
            # NOT ASSUMED, and the clause downstream is written so it does not depend on the
            # answer: `is not ssl` fires on the empty string, so whether an absent key is possible
            # on a committed sender changes which rows exist and not which rows fire. What the
            # column holds for an absent key is `` either way, because `parse_text_field` returns
            # the empty text whatever the declaration says.
            connection, conn_key, conn_prov = parse_text_field(
                branch.get("connection-type"),
                implicit=Implicit.not_assumed(
                    "stage 4's own subject on this object was never committable - the useridd "
                    "daemon refuses an entry with no type branch at commit phase 1 - so what a "
                    "COMMITTED syslog sender looks like with this key absent is unestablished. "
                    "Nothing is assumed and nothing is stored"))
        else:
            # The other three branches carry no `connection-type` leaf at all, so the field is not
            # tracked on those rows rather than defaulted: ABSENT is the one thing that still
            # means "nothing tracks this field", and `clean()` refuses a stored transport here.
            connection, conn_key, conn_prov = "", ABSENT, None

        out.append((
            {
                "name": name[:64],
                "monitored_server_kind": kind[:32],
                "connection_type": connection[:16],
                "tls_service_profile_bound": tls_profile_bound,
            },
            entry_provenance(entry),
            (conn_key, conn_prov),
        ))
    return out


def _write_provenance(instance, rows) -> None:
    """Write one `FieldProvenance` row per field that has one, and none for the rest.

    `raw_key is ABSENT` means the field is NOT TRACKED and gets no row, which is the only thing a
    missing row means. An absent key the caller declared an implicit for arrives here AS that
    `Implicit` and does get a row - typed `pan_os_default` where it is measured and
    `not_configured` where nothing is assumed - because "PAN-OS supplied this" is a fact worth
    recording rather than an absence to be inferred later.
    """
    content_type = ContentType.objects.get_for_model(type(instance))
    FieldProvenance.objects.bulk_create([
        FieldProvenance(
            content_type=content_type,
            object_id=instance.pk,
            field_name=field_name,
            provenance_type=classify_prov_type(raw_key),
            raw_key=provenance_raw_key(raw_key)[:32],
            raw_value=provenance_value(raw_key, raw_value)[:128],
        )
        for field_name, raw_key, raw_value in rows if raw_key is not ABSENT
    ])


def _replace_point_rows(model, enforcement_point: EnforcementPoint) -> None:
    """Delete this point's rows of `model` and their provenance, provenance FIRST.

    The sweep has to come first and has to be scoped by `object_id__in`: `FieldProvenance` is a
    generic relation with no cascade, so deleting the subject rows first orphans their provenance
    rows against a primary key the database will reuse - and the orphan then reads as a statement
    about whatever row next takes that id.
    """
    content_type = ContentType.objects.get_for_model(model)
    FieldProvenance.objects.filter(
        content_type=content_type,
        object_id__in=list(
            model.objects.filter(enforcement_point=enforcement_point)
            .values_list("pk", flat=True)),
    ).delete()
    model.objects.filter(enforcement_point=enforcement_point).delete()


def normalize_user_id(enforcement_point: EnforcementPoint) -> dict[str, Any]:
    """Replace one enforcement point's User-ID collector rows. PAN-UID-002 to 006.

    A MISSING MERGED SNAPSHOT RAISES, which is the point-level failure the platform layering says
    still raises: there is nothing to iterate, and a silent empty result would report every vsys
    of an uncollected appliance as a vsys whose collector settings are the vendor's. The caller
    turns that into one failure for this pass and leaves every other pass's rows standing.
    """
    snapshot = latest_merged_snapshot(enforcement_point)
    if snapshot is None:
        raise ValueError(f"missing merged config snapshot for {enforcement_point}")
    payload = snapshot.payload
    if not isinstance(payload, dict):
        raise ValueError(
            f"merged config snapshot for {enforcement_point} is {type(payload).__name__}, "
            f"not a config payload")

    vsys_entry = merged_vsys_entry(payload, enforcement_point.vsys_name)
    settings_values, settings_provenance = collector_settings_values(vsys_entry)
    verdict = discovery_bound_verdict(vsys_entry)
    # THE ONE CROSS-SUBJECT RESOLUTION IN THIS DOMAIN, and it is two rows apart: a query is
    # compiled against exactly one model, a clause has no second field slot, and following a
    # reference to read a property of the target belongs in normalization - so this becomes a
    # derived column here or it becomes nothing.
    tls_bound = bool(settings_values["syslog_service_profile"])
    servers = monitored_servers(vsys_entry, tls_profile_bound=tls_bound)

    with transaction.atomic():
        for model in (UserIdCollectorSettings, UserIdDiscoveryBound, UserIdMonitoredServer):
            _replace_point_rows(model, enforcement_point)

        settings_row = UserIdCollectorSettings.objects.create(
            management_station=enforcement_point.management_station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            **settings_values,
        )
        _write_provenance(settings_row, settings_provenance)

        # NO PROVENANCE ROW AT ALL, not even `__entry__`: the row is not an entry and every column
        # is in `DERIVED_FIELDS`, so `provenance_for` answers `derived` without a stored row and
        # `test_declared_derived_fields` would fail if one existed.
        UserIdDiscoveryBound.objects.create(
            management_station=enforcement_point.management_station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            **verdict,
        )

        for values, (entry_key, entry_value), (conn_key, conn_value) in servers:
            server = UserIdMonitoredServer.objects.create(
                management_station=enforcement_point.management_station,
                enforcement_point=enforcement_point,
                source_snapshot=snapshot,
                **values,
            )
            _write_provenance(server, [
                (ENTRY_FIELD, entry_key, entry_value),
                ("connection_type", conn_key, conn_value),
            ])

    return {
        "user_id_collector_settings": 1,
        "user_id_discovery_bounds": 1,
        "user_id_monitored_servers": len(servers),
        **settings_values,
        **verdict,
        "tls_service_profile_bound": tls_bound,
    }
