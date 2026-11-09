"""Device services - PAN-SVC-001 to PAN-SVC-010, all ten.

One walk of `deviceconfig/system` fills SIX models, the way `services_settings.py` fills two:
the clusters are separate screens but they are one read.

THREE OPERATIONAL SNAPSHOTS JOIN THE WALK, and each is the only instrument for a column a
control is graded on: `show ntp` for whether anything is keeping the clock, `show dhcp client
mgmt-interface-state` for whether an appliance resolves through an address nobody chose, and
`show device-telemetry settings` for whether the firewall can actually deliver what it shares.
A missing snapshot is a READING in its own right and never an ordering problem - `_op_result`
separates "nobody asked" from "the command answered and said nothing", because on this domain
that difference is what `hostname_in_force_known` and
`DefaultCommunityExposure.SET_AND_REACHABILITY_NOT_ESTABLISHED` exist to carry.

ORDER WITHIN THE WALK: `_identity` BEFORE `_dns`. The resolver posture's first two members
differ by whether the management address is leased, which is a `SystemIdentity` column, and
`_dns` reads the row `_identity` just wrote. Run the other way round it would find last pass's
row - or none - and report an appliance resolving through a lease as resolving through nothing.

MUST RUN AFTER `normalize_appliance_management_interfaces`. `SnmpSettings.is_exposed` asks
whether the `snmp` service is enabled on any management surface, which is a `ManagementService`
row written by that normalizer. Run first, this would find last run's rows - or none - and report
a device with SNMP reachable as unexposed. The renormalize flow normalizes surfaces before it
reaches the object-normalizer tuple, which is what makes the ordering hold.
"""

from __future__ import annotations

import re

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, DeviceTelemetry, DnsSettings, FieldProvenance, ManagementInterface,
    ManagementService, NtpSettings,
    ServiceRoute, SnmpSettings, Snapshot, SystemIdentity)
from optivedge_integrations.integrations.models.device_services import (
    AddressingModePosture,
    DefaultCommunityExposure,
    HostnamePosture,
    ManagementResolverPosture,
    PerSystemPathPosture,
    RecordedDecisionReconciliation,
    ResolverMechanism,
    ServerAuthenticationMechanism,
    ServicePathPosture,
    ServiceRouteScope,
    SnmpVersionInForce,
    TimeSourceInForce,
    TimezoneOffsetClass,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ABSENT, choice_child, classify_prov_type, first_text, merged_shared, provenance_raw_key, provenance_value, ensure_list, entry_provenance, parse_text_field, parse_yes_no_field, scalar_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot, latest_merged_snapshot)

#: The community strings the corpus names, and Help p.740 warns about by name. Compared
#: case-insensitively: PAN-OS accepts all characters and is case-sensitive itself, but `Public`
#: is the default string with the shift key held and not a different secret.
DEFAULT_COMMUNITY_STRINGS = frozenset({"public", "private"})

#: `authentication-type` completes to exactly these three on 11.1 and 11.2. Help p.751 states
#: "None (default)".
AUTH_TYPES = ("symmetric-key", "autokey", "none")

#: The two digests a symmetric key can be used with, and PAN-OS OFFERS NO THIRD: `action=complete`
#: returns exactly these two on all three appliances asked and a write of `sha256` is refused at
#: the device with code=12. So a control requiring SHA-256 time authentication would be asking
#: for a state no PAN-OS firewall can be in, which is why stage 3 does not grade WHICH digest is
#: chosen and `primary_algorithm` is stored for display.
NTP_ALGORITHMS = ("sha1", "md5")


#: MOVED TO `common.py::choice_child` on 2026-10-29, when a fourth caller arrived. Kept as a
#: module-level alias rather than renamed at the two call sites below so that the move is one
#: line to read and nothing in this module's behaviour changed with it.
_choice_child = choice_child


def _server(node: Any) -> tuple[str, str, str, Any, str | None]:
    """(address, auth type, algorithm, address raw key, address raw value) for one NTP slot."""
    if not isinstance(node, dict):
        # The whole slot is absent - PAN-OS holds exactly two and an unconfigured one carries
        # no node at all. That is the measured meaning of absence here, not an inference.
        return "", "", "", Implicit.measured(
            None,
            "payload contract, ntp-servers: the node holds exactly TWO slots and an "
            "unconfigured slot is absent entirely"), None
    address, raw_key, raw_value = parse_text_field(
        node.get("ntp-server-address"),
        implicit=Implicit.measured(
            None, "payload contract, ntp-servers: a slot with no address configures no server"))
    auth_type, auth_body = _choice_child(node.get("authentication-type"), AUTH_TYPES)
    # THE ALGORITHM IS A CHOICE CONTAINER AND NOT A SCALAR, and reading it as one returned the
    # empty string on every appliance that has it configured.
    #
    # Measured 2026-10-29 through Panorama on 013201001475, whose first slot holds
    # `symmetric-key/algorithm/{"sha1": {"authentication-key": "-AQ==..."}}`: `scalar_value` on
    # that dict looks for `#text`, finds none, and answers "" - so `primary_algorithm` read
    # EMPTY on the one appliance in this lab that has a digest to report, and on the other two
    # that hold a symmetric key as well. `action=complete` at the node returns exactly `sha1`
    # and `md5` as CHILDREN, which is the shape `choice_child` exists for; stage 5 declares the
    # key's wire form as `element-presence` for the same reason.
    #
    # The key material hangs one level deeper still, under the chosen algorithm, and is never
    # read here - which is why only the branch NAME is taken.
    algorithm, _algorithm_body = (
        _choice_child(auth_body.get("algorithm"), NTP_ALGORITHMS) if auth_body else ("", {}))
    return address, auth_type, algorithm, raw_key, raw_value


def _provenance(model, obj, rows: list[tuple[str, Any, str | None]]) -> None:
    """Replace this object's provenance with `rows` of (field, raw key, raw value).

    A row is written for every tracked field: one typed `local` or `template` where the payload
    carried the key, and one typed `pan_os_default` / `assumed_default` / `not_configured` where
    it did not. Skipping the absent ones - which this did until 2026-09-21 - is what left
    "PAN-OS supplied it", "we inferred it" and "nobody tracks it" sharing one blank.
    """
    content_type = ContentType.objects.get_for_model(model)
    FieldProvenance.objects.filter(content_type=content_type, object_id=obj.pk).delete()
    for field_name, raw_key, raw_value in rows:
        if raw_key is ABSENT:
            continue
        FieldProvenance.objects.create(
            content_type=content_type, object_id=obj.pk, field_name=field_name,
            provenance_type=classify_prov_type(raw_key),
            raw_key=provenance_raw_key(raw_key), raw_value=provenance_value(raw_key, raw_value))


def _exposed_surfaces(appliance: Appliance) -> list[str]:
    """Which management surfaces have the `snmp` service enabled.

    Reads the rows `normalize_appliance_management_interfaces` wrote, which have already
    resolved each plane's polarity - the deviceconfig planes spell it `disable-snmp` and an
    interface profile spells it `snmp`, and both arrive here as `enabled`.
    """
    services = (ManagementService.objects
                .filter(management_interface__appliance=appliance, name="snmp", enabled=True)
                .select_related("management_interface"))
    return [(service.management_interface.interface_name
             or service.management_interface.plane) for service in services]


#: An absent `authentication-type` means none - the contract records the implicit value, and
#: PAN-SVC-002 reads it as the finding rather than as missing data.
#: `community_is_default` is the one field on SnmpSettings whose ROW is the point: the community
#: string's value is never stored, so the row is the only record of who set the credential. See
#: the comment in SnmpSettings.DERIVED_FIELDS saying why it is deliberately not declared derived.
COMMUNITY_UNMEASURED = Implicit.not_assumed(
    "Help p.740 warns about the default community string 'public', and nothing has established "
    "what an access-setting carrying a v2c child and NO snmp-community-string key actually "
    "answers to. PAN-SVC-005 rests on that string, so a stored False would decide the control "
    "on a guess in the permissive direction")


NTP_AUTH_IMPLICIT = Implicit.measured(
    "none", "payload contract, ntp-servers.authentication-type: implicit 'none'")


def _auth_provenance(auth_type: str):
    """`local` when the slot named an authentication type, the measured default when it did
    not. Written here rather than carried out of `_server` because the choice node's own
    provenance is the child element's, and the child is what is or is not there."""
    return None if auth_type else NTP_AUTH_IMPLICIT


def _ntp(appliance, snapshot, system) -> None:
    servers = system.get("ntp-servers") if isinstance(system.get("ntp-servers"), dict) else {}
    primary, p_auth, p_algo, p_rk, p_rv = _server(servers.get("primary-ntp-server"))
    secondary, s_auth, s_algo, s_rk, s_rv = _server(servers.get("secondary-ntp-server"))

    configured = [(name, auth) for name, auth in
                  ((primary, p_auth), (secondary, s_auth)) if name]
    unauthenticated = [name for name, auth in configured if auth != "symmetric-key"]

    # THE OPERATIONAL HALF, and `show ntp` is the only instrument that answers it. Its own
    # `authentication-type` member is deliberately NOT read - see
    # `NtpSettings.server_authentication_mechanism` - so only `synched` is taken from here.
    synched_read, ntp_state = _op_result(_latest(appliance, "show_ntp"))
    synched, time_source = ntp_time_source(
        synched_read, str(ntp_state.get("synched") or ""), [name for name, _auth in configured])

    row, _ = NtpSettings.objects.update_or_create(
        appliance=appliance,
        defaults={
            "management_station": appliance.management_station,
            "appliance_group": appliance.appliance_group,
            "source_snapshot": snapshot,
            "synched_to_a_configured_server": synched,
            "time_source_in_force": time_source,
            "server_authentication_mechanism": ntp_authentication_mechanism(
                [auth for _name, auth in configured]),
            "primary_server": primary[:255],
            "secondary_server": secondary[:255],
            "server_count": len(configured),
            "primary_auth_type": p_auth or NtpSettings.AuthType.NONE,
            "secondary_auth_type": s_auth or NtpSettings.AuthType.NONE,
            "primary_algorithm": (p_algo or "")[:8],
            "secondary_algorithm": (s_algo or "")[:8],
            # Vacuously true on a device with no servers would report an unconfigured device as
            # authenticated, so an empty list is False here rather than all().
            "all_servers_symmetric_key": bool(configured) and not unauthenticated,
            "unauthenticated_servers": unauthenticated,
        },
    )
    _provenance(NtpSettings, row, [
        ("primary_server", p_rk, p_rv),
        ("secondary_server", s_rk, s_rv),
        # PAN-SVC-002 turns on the authentication type, and its absence is measured: no
        # authentication-type node means none, which is the failing state rather than a gap.
        ("primary_auth_type", _auth_provenance(p_auth), None),
        ("secondary_auth_type", _auth_provenance(s_auth), None),
    ])


def _snmp(appliance, snapshot, system) -> None:
    # PRESENCE IS KEY MEMBERSHIP, NOT TRUTHINESS. An empty `<snmp-setting/>` parses to None and
    # an element with no children to `{}`, and both are FALSY while both mean the node exists.
    # Testing truthiness reported a configured device as having no SNMP at all, and read an
    # empty access-setting as "no access-setting" - which silently skipped the implicit-version
    # branch below. Caught by its own test before it shipped; absent, empty and default are
    # three states here as everywhere else in this payload.
    configured = "snmp-setting" in system
    node = system.get("snmp-setting")
    node = node if isinstance(node, dict) else {}
    has_access = "access-setting" in node
    access = node.get("access-setting")
    access = access if isinstance(access, dict) else {}
    version_name, version_body = _choice_child(access.get("version"), ("v2c", "v3"))

    # An access-setting with no version child: Help p.740 says the dialog's default is V2c.
    # Recorded as v2c and FLAGGED, because the control then rests on a vendor sentence rather
    # than on something read off this device.
    implicit = has_access and not version_name
    effective = version_name or ("v2c" if implicit else "")

    community, community_rk, community_rv = (
        parse_text_field(version_body.get("snmp-community-string"), implicit=COMMUNITY_UNMEASURED)
        if version_body else ("", COMMUNITY_UNMEASURED, None))
    users = ensure_list((version_body.get("users") or {}).get("entry")) if version_body else []
    views = ensure_list((version_body.get("views") or {}).get("entry")) if version_body else []

    surfaces = _exposed_surfaces(appliance)
    row, _ = SnmpSettings.objects.update_or_create(
        appliance=appliance,
        defaults={
            "management_station": appliance.management_station,
            "appliance_group": appliance.appliance_group,
            "source_snapshot": snapshot,
            "is_configured": configured,
            "version": effective,
            "version_implicit": implicit,
            "uses_v2c": effective == "v2c",
            "community_set": bool(community),
            "community_is_default": community.strip().lower() in DEFAULT_COMMUNITY_STRINGS,
            "v3_user_count": len(users),
            "v3_view_count": len(views),
            "is_exposed": bool(surfaces),
            "exposed_surfaces": surfaces,
            # PAN-SVC-004's failing set is a DISJUNCTION and stage 5's clause grammar is one
            # conjunction, so the disjunction is stored: on the cleartext version, OR configured
            # with the version unrecorded.
            "answers_on_an_unauthenticated_version": (
                configured and (effective == "v2c" or implicit)),
            "default_community_exposure": snmp_default_community_exposure(
                community.strip().lower() in DEFAULT_COMMUNITY_STRINGS,
                _surfaces_were_walked(appliance),
                surfaces),
            "snmp_version_in_force": snmp_version_in_force(configured, implicit, effective),
        },
    )
    # The community string's VALUE is not stored; its provenance is, because "who set this" is
    # exactly what an assessor asks about a credential they can see in a backup.
    _provenance(SnmpSettings, row, [
        ("community_is_default", community_rk, community_rv),
        # PAN-SVC-004 rests on the version. An access-setting with no version child is v2c by
        # the vendor's own dialog default, and the row says that rather than leaving a reader to
        # wonder whether v2c was chosen or inherited.
        ("version", Implicit.measured(
            "v2c",
            "payload contract, snmp-setting.version: implicit 'v2c' - Help p.740, the dialog's "
            "default") if implicit else (None if version_name else ABSENT), None),
    ])


def _identity(appliance, snapshot, system) -> None:
    # THE IMPLICIT HOSTNAME IS A FUNCTION OF THE APPLIANCE AND NO COLUMN CAN HOLD ONE, so this
    # STORES NOTHING and the verdict lives in `hostname_is_factory_default` instead.
    #
    # CHANGED 2026-10-29, and the previous line materialised `appliance.model`. Stage 5 decided
    # `default.stores: null` for this column and said why in its `not_stored`: a consumer that
    # materialised the implicit would store the literal string `PA-5220` on every appliance of
    # that model, and a control comparing a stored name against it would report every PA-VM in
    # the estate as factory-named, or none of them, depending which way the materialisation
    # went. Which side of its own assertion a default sits on is stage 5's decision and is
    # authoritative, and the previous code sat on the other side of it.
    #
    # THE VERDICT IS UNCHANGED EITHER WAY, which is what makes this safe: `factory` below is
    # `(not stored) or stored == model or ...`, so an empty string and the model string both
    # answer True. What changes is what `hostname` itself reads, and therefore which member
    # `hostname_posture` lands on - `no_name_stored` rather than
    # `stored_name_is_the_model_with_a_numeric_suffix`, which are stage 3's first two ranks.
    #
    # THE CITATION IS KEPT so the provenance row still types `pan_os_default` - the absence IS a
    # measured vendor fact, measured on two appliances of two different models by deleting the
    # key and committing, with both directions paid on each. What it is not is a value a column
    # can carry.
    #
    # MEASURED 2026-10-29 AND IT MATTERS LESS THAN IT LOOKS ON THIS ESTATE: the merged view
    # MATERIALISES the vendor default at this key. `action=get` at
    # `deviceconfig/system/hostname` on 691665AC334B458 answers `PA-VM` where `action=show`
    # raises `No such node`, and `show config merged` carries `PA-VM` too - so the branch below
    # is never reached through the view this collector reads, and the column holds `PA-VM`
    # regardless. `timezone` on the same appliance is NOT materialised, so this is per key and
    # not a property of the view.
    hostname, host_rk, host_rv = parse_text_field(
        system.get("hostname"),
        implicit=Implicit.measured(
            None,
            "stage4-device-services.json objects['system-identity'].fields.hostname.implicit - "
            "an absent hostname asserts that the appliance answers to ITS OWN MODEL, measured "
            "2026-10-25 on two appliances of two different models by deleting the key and "
            "committing (jobs 490/491 and 169/170). The value is a FUNCTION of the appliance, "
            "so nothing is stored - see stage 5's `not_stored`"))
    timezone, tz_rk, tz_rv = parse_text_field(
        system.get("timezone"),
        implicit=Implicit.not_assumed(
            "the system-identity contract records a 566-value enum for timezone and no implicit "
            "value; PAN-SVC-009 compares against UTC and an invented default would decide it"))
    mode, mode_body = _choice_child(system.get("type"), ("static", "dhcp-client"))
    type_rk, type_rv = entry_provenance(system.get("type")) if isinstance(
        system.get("type"), dict) else (
            Implicit.measured(
                SystemIdentity.AddressingMode.STATIC,
                "payload contract, system-identity.type: implicit 'static' - fw-core-tpa-b "
                "carries no type node and reports ip-type static"),
            None)

    accept_hostname, accept_host_rk, accept_host_rv = parse_yes_no_field(
        mode_body.get("accept-dhcp-hostname"),
        implicit=Implicit.assumed(
            False,
            "the system-identity contract measured `type` and `hostname` and not these two. "
            "False reads the device as keeping its configured name, which is what the "
            "hostname control assumes when it compares against the model"))
    accept_domain, accept_domain_rk, accept_domain_rv = parse_yes_no_field(
        mode_body.get("accept-dhcp-domain"),
        implicit=Implicit.assumed(
            False, "same node as accept-dhcp-hostname above, and unmeasured with it"))

    # Help p.700: with no hostname written, PAN-OS uses the model - "for example, PA-5220_2".
    # So the default name is the model, optionally suffixed with an index; an absent hostname is
    # the same state spelled differently.
    #
    # The suffix is matched as DIGITS, not as any suffix. `startswith(f"{model}_")` also matched
    # deliberately chosen names that lead with the model - `PA-5220_EDGE-01`, `PA-5220_DC1` - which
    # is a real naming convention, and on such an estate every device reported as unnamed.
    model_name = (appliance.model or "").strip().lower()
    stored = hostname.strip().lower()
    factory = (not stored) or (bool(model_name) and (
        stored == model_name or re.fullmatch(rf"{re.escape(model_name)}_\d+", stored) is not None))

    declares_zero, offset_class = timezone_offset_class(timezone)

    # THE NAME IN FORCE, from `show system info` - the collector another domain already wrote.
    # `hostname` and `devicename` are both read because stage 4 measured both moving together
    # when the configuration key was deleted, and the first non-empty is taken.
    #
    # KNOWN MEANS THE READ ANSWERED AND CARRIED A NAME, not merely that a snapshot exists.
    # `accept_dhcp_hostname` is never null, so without this column an appliance nobody asked
    # reports "the lease may NOT overwrite the name" - which tells PAN-SVC-010 that the stored
    # name IS the name in force, reached without anybody looking.
    info_read, info = _op_result(_latest(appliance, "show_system_info"))
    info_system = info.get("system") if isinstance(info.get("system"), dict) else {}
    in_force = first_text(info_system, "hostname", "devicename")
    in_force_known = bool(info_read and in_force)

    row, _ = SystemIdentity.objects.update_or_create(
        appliance=appliance,
        defaults={
            "management_station": appliance.management_station,
            "appliance_group": appliance.appliance_group,
            "source_snapshot": snapshot,
            "hostname": hostname[:64],
            "hostname_is_factory_default": factory,
            "timezone": timezone[:64],
            "timezone_is_utc": timezone.strip().upper() == "UTC",
            # Absent resolves to static - measured, not assumed. See the model docstring.
            "addressing_mode": mode or SystemIdentity.AddressingMode.STATIC,
            "addressing_mode_explicit": bool(mode),
            "accept_dhcp_hostname": accept_hostname,
            "accept_dhcp_domain": accept_domain,
            "hostname_in_force_known": in_force_known,
            "hostname_in_force": in_force[:64],
            "hostname_posture": hostname_posture(
                hostname, factory, accept_hostname, in_force_known),
            "timezone_declares_zero_offset": declares_zero,
            "timezone_offset_class": offset_class,
            "addressing_mode_posture": addressing_mode_posture(
                mode or SystemIdentity.AddressingMode.STATIC),
        },
    )
    _provenance(SystemIdentity, row, [
        ("hostname", host_rk, host_rv),
        ("timezone", tz_rk, tz_rv),
        ("addressing_mode", type_rk, type_rv),
        ("accept_dhcp_hostname", accept_host_rk, accept_host_rv),
        ("accept_dhcp_domain", accept_domain_rk, accept_domain_rv),
    ])


# ---------------------------------------------------------------------------
# The operational snapshots this domain's runtime columns rest on
# ---------------------------------------------------------------------------

def _latest(appliance: Appliance, source_type: str) -> Snapshot | None:
    """The newest snapshot of one source type for one appliance.

    ANOTHER COPY of this four-line query, and it stays local for the reason
    `device_identification.py::_latest_appliance_snapshot` and
    `platform_lifecycle.py::_latest` both record in their own docstrings: a shared
    `latest_appliance_snapshot(appliance, source_type)` is the right consolidation and it
    belongs to a change that owns every copy, not to one of four stage 7 runs editing this
    repository at the same time.
    """
    return (
        Snapshot.objects.filter(appliance=appliance, source_type=source_type)
        .order_by("-collected_at", "-pk")
        .first()
    )


def _op_result(snapshot: Snapshot | None) -> tuple[bool, dict[str, Any]]:
    """(did the read answer, its payload) for one operational snapshot.

    THREE STATES AND THE FIRST TWO ARE DIFFERENT:

        no snapshot            (False, {})  nobody asked
        payload present        (True, body)  the command answered - possibly with nothing in it
        empty payload          (True, {})    the command answered and said nothing, which for
                                             `show dhcp client mgmt-interface-state` is what the
                                             collector records for a STATIC interface

    Separating the first two is the whole point. "We never asked" must not look like "we asked
    and it was fine", and on this domain that distinction is what `hostname_in_force_known` and
    `DefaultCommunityExposure.SET_AND_REACHABILITY_NOT_ESTABLISHED` exist to carry.
    """
    if snapshot is None:
        return False, {}
    payload = snapshot.payload
    return True, payload if isinstance(payload, dict) else {}


# ---------------------------------------------------------------------------
# NTP - the operational half
# ---------------------------------------------------------------------------

#: `show ntp` answers this literal where nothing upstream is keeping the clock. Measured
#: 2026-10-29 on three of the four lab appliances, including one with TWO servers configured and
#: BOTH authenticating with a symmetric key - a configuration that passes the countable half and
#: is keeping no time at all.
NTP_SYNCHED_LOCAL = "LOCAL"


def ntp_time_source(synched_read: bool, synched: str, configured: list[str]) -> tuple[bool, str]:
    """(is the clock anchored to a configured server, the three-way class). PAN-SVC-001.

    `configured` is the configured slot ADDRESSES, compared case-insensitively after stripping:
    the reply echoes the configured string, and an FQDN's case is not significant.

    AN UNREAD APPLIANCE GETS THE WORST MEMBER, not the best, and that is the prescribed
    direction - `not_synchronised_or_never_read` deliberately covers both, because nothing
    downstream could act on the difference and the safe answer is the same either way.
    """
    if not synched_read:
        return False, TimeSourceInForce.NOT_SYNCHRONISED_OR_NEVER_READ
    source = (synched or "").strip()
    if not source or source.upper() == NTP_SYNCHED_LOCAL:
        return False, TimeSourceInForce.NOT_SYNCHRONISED_OR_NEVER_READ
    names = {name.strip().lower() for name in configured if name and name.strip()}
    if source.lower() in names:
        return True, TimeSourceInForce.SYNCHRONISED_TO_A_CONFIGURED_SERVER
    return False, TimeSourceInForce.SYNCHRONISED_TO_AN_UNNAMED_SOURCE


def ntp_authentication_mechanism(auth_types: list[str]) -> str:
    """The four-way class over the CONFIGURED slots' authentication branches. PAN-SVC-002.

    `auth_types` is one token per CONFIGURED slot, from the configuration's own branch and never
    from `show ntp` - see `NtpSettings.server_authentication_mechanism` for the measurement that
    rules that command out.

    NO CONFIGURED SLOT AT ALL IS `none`, not a fourth state: it is the baseline-severity member
    and the state the vendor documents for a device nobody configured, which is where an
    unrenormalized row belongs. PAN-SVC-001 is what reports the absence.

    `autokey` WINS OVER A MIXTURE, deliberately. A device holding autokey on one slot and a
    symmetric key on the other is not "some but not others" - stage 3 insists the finding NAME
    autokey because the remediation is not "turn authentication on", and a mixture that hides it
    behind the milder member would lose that sentence.
    """
    tokens = [token for token in auth_types if token]
    if not tokens:
        return ServerAuthenticationMechanism.NONE
    if any(token == "autokey" for token in tokens):
        return ServerAuthenticationMechanism.AUTOKEY
    symmetric = [token for token in tokens if token == "symmetric-key"]
    if not symmetric:
        return ServerAuthenticationMechanism.NONE
    if len(symmetric) == len(tokens):
        return ServerAuthenticationMechanism.EVERY_SERVER
    return ServerAuthenticationMechanism.SOME_BUT_NOT_ALL


# ---------------------------------------------------------------------------
# SNMP - the two gradings
# ---------------------------------------------------------------------------

def snmp_version_in_force(configured: bool, implicit: bool, effective: str) -> str:
    """The four-way class. PAN-SVC-004.

    THE FIRST TWO MEMBERS ARE THE TWO STATES `version` CANNOT TELL APART: an explicit cleartext
    choice and a materialised vendor default are the SAME value of that column, and
    `version_implicit` is the only thing that separates them. Stage 3 requires the finding to
    say which it read, which is why this exists beside `uses_v2c`.
    """
    if not configured:
        return SnmpVersionInForce.NO_AGENT_CONFIGURED
    if implicit:
        return SnmpVersionInForce.CONFIGURED_WITH_NO_VERSION_RECORDED
    if effective == "v3":
        return SnmpVersionInForce.V3
    return SnmpVersionInForce.V2C


def snmp_default_community_exposure(
    community_is_default: bool, surfaces_read: bool, exposed_surfaces: list[str]) -> str:
    """The four-way class PAN-SVC-005's severity varies with.

    `surfaces_read` is whether ANY `ManagementService` row exists for this appliance - which is
    what separates "every surface is shown to be refusing" from "nobody walked the surfaces".
    The query layer has no concept of absence: by the time a query runs, every absent reading has
    been collapsed into a column value and there is no is-null operator to ask with, so the
    distinction has to be stored.

    ONLY A MEASURED REFUSAL EARNS THE REDUCTION. An appliance whose surfaces have not been
    walked keeps the high-severity member, which is stage 3's own direction: the per-surface
    switch's behavior when absent is not obtainable from any corpus this project can reach, so
    the unknown must not relax the finding.

    THE LAB MAKES IT VIVID: the appliance storing `public` is the one where nothing is listening
    - `show system services` omits `snmp` on all four lab appliances, including the one holding a
    complete SNMPv3 agent - so the credential finding is real and the exposure is not.
    """
    if not community_is_default:
        return DefaultCommunityExposure.NO_DEFAULT_CREDENTIAL_SET
    if exposed_surfaces:
        return DefaultCommunityExposure.SET_AND_A_SURFACE_ACCEPTS_QUERIES
    if not surfaces_read:
        return DefaultCommunityExposure.SET_AND_REACHABILITY_NOT_ESTABLISHED
    return DefaultCommunityExposure.SET_AND_EVERY_SURFACE_REFUSES


# ---------------------------------------------------------------------------
# System identity - the three gradings, and the zone classification
# ---------------------------------------------------------------------------

#: THE ZONE KEYS THAT DECLARE ZERO OFFSET IN THEIR OWN TEXT. Eighteen of them, and the count is
#: not a coincidence: stage 3 says "eighteen of the spellings declare zero offset" and names
#: none of them, and stage 5 records that the classification table is in NEITHER of its inputs.
#:
#: MEASURED 2026-10-29, by `action=complete` at
#: `deviceconfig/system/timezone` on 691665AC334B458 and 013201001475 - 566 members on both,
#: identical - filtered to the members whose own text names zero offset. It came to exactly
#: eighteen, which is what makes the NAME test the right reading of stage 3's sentence rather
#: than an offset test.
#:
#: COMPARED CASE-FOLDED, because the device accepts and stores the spelling as offered and a
#: control must not turn on capitalisation.
ZONE_KEYS_DECLARING_ZERO_OFFSET = frozenset({
    "etc/gmt", "etc/gmt+0", "etc/gmt-0", "etc/gmt0", "etc/greenwich", "etc/uct", "etc/utc",
    "etc/universal", "etc/zulu", "gmt", "gmt+0", "gmt-0", "gmt0", "greenwich", "uct", "utc",
    "universal", "zulu",
})

#: THE ZONES THAT SIT AT ZERO OFFSET ALL YEAR AND DO NOT SAY SO IN THEIR KEY. This is the middle
#: rank, and `Atlantic/Reykjavik` is in it - which is the lab subject stage 6 built for exactly
#: this column: "a GEOGRAPHIC zone that sits at zero offset today and observes no daylight rule,
#: but does not declare zero offset in its own key - so it reads correctly now and can move with
#: a vendor time-zone update and no configuration change".
#:
#: DERIVED 2026-10-29 from the device's own 566-member vocabulary and FROZEN HERE rather than
#: computed at normalization time. Each member's UTC offset was evaluated at mid-month for every
#: month of 2026 through Python's `zoneinfo`, and a member qualifies only where every one of the
#: twelve was exactly zero. Frozen because the alternative is a stored verdict that moves with
#: whichever tzdata the host happens to carry, silently - and because a zone LEAVING this set is
#: precisely the event the middle rank exists to warn about, so it should break a test rather
#: than change a finding.
#:
#: `Iceland` IS HERE BY HAND and is the one member that is not from `zoneinfo`: it is a backward
#: alias for `Atlantic/Reykjavik` that the host's tzdata cannot resolve, so the sweep did not
#: see it, while the device offers it as a settable value. An alias the sweep cannot resolve
#: otherwise falls through to the firing member below, which is the safe direction - this one is
#: named because it is the same zone as the lab's own subject under a second spelling.
#:
#: `Factory` IS ALSO HERE and is odd on purpose: the device offers it, `zoneinfo` resolves it at
#: zero offset all year, and it is a zone key nobody would choose deliberately. Classifying it
#: as "zero today, not declared" is the honest answer - it is not a zero-offset SPELLING and it
#: does sit at zero - and it keeps a device set to it out of the most reassuring rank.
ZONE_KEYS_AT_ZERO_OFFSET_TODAY = frozenset({
    "africa/abidjan", "africa/accra", "africa/bamako", "africa/banjul", "africa/bissau",
    "africa/conakry", "africa/dakar", "africa/freetown", "africa/lome", "africa/monrovia",
    "africa/nouakchott", "africa/ouagadougou", "africa/sao_tome", "africa/timbuktu",
    "america/danmarkshavn", "atlantic/reykjavik", "atlantic/st_helena", "factory", "iceland",
})


def timezone_offset_class(timezone: str) -> tuple[bool, str]:
    """(does the key declare zero offset, the four-way class). PAN-SVC-009.

    THIS IS NOT `timezone_is_utc`, which ships and is claused on by the shipped baseline query
    and which REPORTS A FINDING ON A COMPLIANT DEVICE: that column is
    `timezone.strip().upper() == "UTC"`, one spelling of zero offset out of the eighteen the
    device offers. Stage 3 restated the control as whether the zone DECLARES zero offset, and
    the shipped column is superseded here rather than removed.

    AN UNRECOGNIZED KEY FALLS TO `non_zero_offset_or_shifts_under_a_daylight_rule`, which fires.
    That covers a zone the sets above do not name - including every alias this host's tzdata
    could not resolve - and it is the safe direction: the alternative would hand a zone nobody
    has classified the most reassuring rank.
    """
    key = (timezone or "").strip().lower()
    if not key:
        return False, TimezoneOffsetClass.NO_ZONE_RECORDED
    if key in ZONE_KEYS_DECLARING_ZERO_OFFSET:
        return True, TimezoneOffsetClass.DECLARES_ZERO_OFFSET
    if key in ZONE_KEYS_AT_ZERO_OFFSET_TODAY:
        return False, TimezoneOffsetClass.ZERO_TODAY_BUT_NOT_DECLARED
    return False, TimezoneOffsetClass.NON_ZERO_OR_SHIFTS


def hostname_posture(
    stored: str, factory_default: bool, accept_dhcp_hostname: bool, in_force_known: bool) -> str:
    """The four-way class. PAN-SVC-010.

    THE THIRD MEMBER IS WHAT `hostname_is_factory_default` CANNOT COVER and is why this column
    is owed: stage 3's third rank is a CHOSEN name on a device set to take its name from the
    lease, which the shipped boolean reports identically to a chosen name in force.

    `in_force_known` GATES THE MOST REASSURING MEMBER ONLY. A chosen name on an appliance that
    may take its name from the lease stays in the third member whether or not the operational
    read was taken; what the read buys is the right to say the chosen name is actually IN FORCE.
    An appliance nobody asked therefore cannot reach `a_chosen_name_in_force`, which is the
    direction the companion column exists to enforce.
    """
    if not (stored or "").strip():
        return HostnamePosture.NO_NAME_STORED
    if factory_default:
        return HostnamePosture.STORED_NAME_IS_THE_MODEL
    if accept_dhcp_hostname or not in_force_known:
        return HostnamePosture.CHOSEN_NAME_THE_LEASE_MAY_REPLACE
    return HostnamePosture.A_CHOSEN_NAME_IN_FORCE


def addressing_mode_posture(mode: str) -> str:
    """The three-way class. PAN-SVC-007.

    THE CLOUD MEMBER IS NEVER REACHED AND THAT IS DELIBERATE. It is the member that REDUCES the
    severity, and whether a virtual appliance is in a PUBLIC CLOUD is not in either of this
    stage's inputs and is not on the device: `Appliance.model` says `PA-VM`, which is the same
    string for a PA-VM on a laptop and a PA-VM in Azure. Stage 5 records the gap and the
    direction, and an unclassified appliance must not receive the reduction - so a leased
    address lands on the hardware member whatever the platform. Recorded in the artifact's
    `spec_gaps`: what would close it is a column saying which cloud an appliance runs in.
    """
    if mode == SystemIdentity.AddressingMode.DHCP_CLIENT:
        return AddressingModePosture.LEASED_ON_A_HARDWARE_APPLIANCE
    return AddressingModePosture.FIXED

# ---------------------------------------------------------------------------
# DnsSettings - the management resolvers
# ---------------------------------------------------------------------------

#: NOT ASSUMED, and the reason is a fence rather than a failure to try. Stage 4's dispatch
#: forbade writing the resolver node: the resolvers govern whether the firewall can name
#: anything and every read of the Azure half of the lab goes through Panorama's `target=` proxy,
#: so a wrong value cuts the path the next read needs. What a `servers` branch that EXISTS with
#: no `primary` does is therefore unobserved - no appliance is in that state - and storing
#: nothing is the honest answer.
RESOLVER_ADDRESS_UNMEASURED = Implicit.not_assumed(
    "stage4-device-services.json objects['dns-setting'] fences the resolver node for writes, so "
    "a `servers` branch existing with no address leaf has never been observed on this estate. "
    "The absent state IS observed for the SECONDARY on both PA-5220s - a committed `servers` "
    "branch carrying `primary` and no `secondary` - which is a reading about an absent leaf and "
    "not about an empty branch")

#: MEASURED, and it is a reading about the BRANCH rather than about the node: `action=get`
#: returns None and `action=show` "No such node" at this path on all four lab appliances
#: INCLUDING the two that hold a populated `servers` branch in the same pass. `null` means
#: nothing is bound, not that the field is unread.
DNS_PROXY_OBJECT_ABSENT = Implicit.measured(
    None,
    "stage4-device-services.json objects['dns-setting'].fields['dns-proxy-object'].implicit - an "
    "absent branch asserts the firewall is NOT resolving through a proxy object it hosts, "
    "measured as a natural experiment on all four appliances with no write")

#: `not_applicable` RATHER THAN `null`, and the distinction is a build and not a value. Stage 4
#: measured `action=complete` at this path answering `code=6 Invalid sequence` on 11.1.13-h3 and
#: returning three children on 11.2.3-h3 and 11.2.5. `code=6` means NOT VALID ON THE DEVICE YOU
#: ASKED, so on an 11.1 appliance there is no key there to BE absent. The store has no way to
#: say that, which this declaration records rather than papers over.
ENCRYPTED_DNS_NOT_ON_THIS_BUILD = Implicit.not_assumed(
    "stage4-device-services.json objects['dns-setting'].fields['servers/encrypted-dns'] records "
    "`unsettable` on the 11.1 build specifically - code=6 Invalid sequence at complete - and "
    "unmeasured on 11.2, where the node exists and no appliance uses it. Nothing asserts it")


def dns_resolver_posture(
    chosen_count: int, follows_lease: bool, mechanism: str, addressing_mode: str) -> str:
    """The four-way class. PAN-SVC-003.

    ORDERED FROM NOBODY HAVING CHOSEN THE RESOLVERS TO THE ORGANIZATION HAVING CHOSEN THEM, and
    the split between the first two members is the one that matters: an appliance with no
    resolver on a LEASED management address is resolving through an address nobody chose, which
    is a different finding from one with no resolver on a FIXED address, where nothing is
    resolving at all.

    `follows_lease` IS NOT WHAT SEPARATES THEM. The addressing mode is, because a lease read
    that was never taken must not move an appliance from the first member to the second - the
    first is the baseline-severity member and an unread appliance belongs there. `follows_lease`
    is stored beside this for the finding sentence and is False where nothing established a
    lease, which is why no clause rests on it.
    """
    if chosen_count >= 2:
        return ManagementResolverPosture.TWO_OR_MORE
    if chosen_count == 1:
        return ManagementResolverPosture.ONE_RESOLVER_ONLY
    if addressing_mode == SystemIdentity.AddressingMode.DHCP_CLIENT or follows_lease:
        return ManagementResolverPosture.NONE_ON_A_LEASED_ADDRESS
    return ManagementResolverPosture.NONE_ON_A_FIXED_ADDRESS


def _dns(appliance, snapshot, system) -> None:
    node = system.get("dns-setting")
    node = node if isinstance(node, dict) else {}
    # PRESENCE IS KEY MEMBERSHIP AND NOT TRUTHINESS, the same three states `_snmp` separates: an
    # empty `<servers/>` parses to None and an element with no children to `{}`, and both are
    # falsy while both mean the branch exists.
    has_servers = "servers" in node
    servers = node.get("servers")
    servers = servers if isinstance(servers, dict) else {}

    primary, primary_rk, primary_rv = parse_text_field(
        servers.get("primary"), implicit=RESOLVER_ADDRESS_UNMEASURED)
    secondary, secondary_rk, secondary_rv = parse_text_field(
        servers.get("secondary"), implicit=RESOLVER_ADDRESS_UNMEASURED)
    proxy, proxy_rk, proxy_rv = parse_text_field(
        node.get("dns-proxy-object"), implicit=DNS_PROXY_OBJECT_ABSENT)
    # `encrypted-dns` IS A CONTAINER AND THE VALUE IS ONE LEVEL DEEPER THAN STAGE 5's KEY SAYS.
    # Stage 5 gives `servers/encrypted-dns` with `wire: container`; measured 2026-10-29 by
    # `action=complete`, that node's three children are `connection-type`, `enable-fallback` and
    # `tcp-timeout`, and `connection-type` is a plain text leaf completing to `dns-over-https`
    # and `dns-over-tls`. A column named for the connection type reads the connection type, so
    # the key used here is the leaf. Recorded in the artifact's `reads_from`.
    encrypted_node = servers.get("encrypted-dns")
    encrypted_node = encrypted_node if isinstance(encrypted_node, dict) else {}
    encrypted, encrypted_rk, encrypted_rv = parse_text_field(
        encrypted_node.get("connection-type"), implicit=ENCRYPTED_DNS_NOT_ON_THIS_BUILD)

    if proxy.strip():
        mechanism = ResolverMechanism.DNS_PROXY_OBJECT
    elif has_servers and (primary.strip() or secondary.strip()):
        mechanism = ResolverMechanism.SERVERS
    else:
        mechanism = ResolverMechanism.NONE

    configured = [address.strip() for address in (primary, secondary) if address.strip()]

    # THE LEASE HALF. An appliance whose management interface is a DHCP client and whose
    # configuration names no resolver IS resolving - through an address that arrived with the
    # lease - and a query reading configuration alone reports it identically to an appliance
    # with no DNS at all. Measured on two of four lab appliances.
    lease_read, lease = _op_result(_latest(appliance, "show_dhcp_client_mgmt_interface_state"))
    lease_resolver = str(lease.get("dns-server") or "").strip() if lease_read else ""
    follows_lease = bool(lease_resolver) and not configured and not proxy.strip()

    # THE PROXY OBJECT'S OWN RESOLVER LIST IS ONE HOP AWAY AND IS NOT FOLLOWED HERE. Nothing in
    # this lab binds a proxy object - measured on all four appliances - so the hop has never
    # been exercised, and a traversal written against no instance is a traversal proved against
    # its author. The count below therefore counts a bound proxy object as ONE chosen resolver,
    # which is the conservative direction: it cannot reach the two-or-more member on the
    # strength of a list nobody has read.
    chosen_count = len(configured) if configured else (1 if proxy.strip() else 0)

    in_force = list(configured)
    if proxy.strip():
        in_force.append(f"dns-proxy-object:{proxy.strip()}")
    if lease_resolver and lease_resolver not in in_force:
        in_force.append(lease_resolver)

    identity = SystemIdentity.objects.filter(appliance=appliance).first()
    addressing_mode = (
        identity.addressing_mode if identity else SystemIdentity.AddressingMode.STATIC)

    row, _ = DnsSettings.objects.update_or_create(
        appliance=appliance,
        defaults={
            "management_station": appliance.management_station,
            "appliance_group": appliance.appliance_group,
            "source_snapshot": snapshot,
            "primary_resolver_address": primary[:255],
            "secondary_resolver_address": secondary[:255],
            "dns_proxy_object_name": proxy[:64],
            "encrypted_dns_connection_type": (encrypted or "")[:32],
            "resolver_mechanism": mechanism,
            "chosen_resolver_count": chosen_count,
            "resolution_follows_the_management_lease": follows_lease,
            "management_resolvers_in_force": in_force,
            "management_resolver_posture": dns_resolver_posture(
                chosen_count, follows_lease, mechanism, addressing_mode),
        },
    )
    _provenance(DnsSettings, row, [
        ("primary_resolver_address", primary_rk, primary_rv),
        ("secondary_resolver_address", secondary_rk, secondary_rv),
        ("dns_proxy_object_name", proxy_rk, proxy_rv),
        ("encrypted_dns_connection_type", encrypted_rk, encrypted_rv),
    ])


# ---------------------------------------------------------------------------
# DeviceTelemetry - what the firewall shares, and whether anybody decided to
# ---------------------------------------------------------------------------

#: THE MATERIALISED DEFAULT THAT MATTERS MOST IN THIS DOMAIN, AND IT FIRES. `True` means an
#: appliance whose telemetry node was never written reports as SHARING - the state both lab
#: PA-VMs are in - and the vendor's own guide says the reverse verbatim, with three instruments
#: on a committed device agreeing against it.
TELEMETRY_SHARING_IMPLICIT = Implicit.measured(
    True,
    "stage4-device-services.json objects['device-telemetry'] - an absent category key asserts "
    "the firewall IS sharing. Measured 2026-10-25 on 691665AC334B458 by deleting two keys and "
    "setting the third to `no` in ONE commit (job 178 FIN OK): `show device-telemetry settings`, "
    "which reads RUNNING, answered yes/yes/no in a single reply - one instrument, one call, "
    "three elements, two states, which is what makes each attributable. The web interface's "
    "Telemetry panel carried x-grid3-check-col-on with the keys absent. Contradicts "
    "Administrator's Guide p.201, recorded in known-vendor-contradictions.md")

#: MEASURED, and lowercase because that is the wire form the completion offers: the device
#: renders and stores it capitalised. A normaliser comparing a stored value against the
#: vocabulary must fold case, and this column holds the folded form.
TELEMETRY_REGION_IMPLICIT = Implicit.measured(
    "americas",
    "stage4-device-services.json objects['device-telemetry'].fields['region'].implicit - an "
    "absent `region` asserts the Americas region, measured on 691665AC334B458 with the key "
    "deleted and committed (job 173): `show device-telemetry settings` answered `Americas` and "
    "the device's own Telemetry Data Collection dialog, which appears ONLY in that state, says "
    "verbatim \"Your telemetry data will be stored in Americas region.\"")

#: (column, payload key) for the three category switches. KEYED BY NAME AND NEVER BY POSITION:
#: one appliance returns `region` first where the others return it last.
TELEMETRY_SHARING_KEYS = (
    ("shares_device_health_performance", "device-health-performance"),
    ("shares_product_usage", "product-usage"),
    ("shares_threat_prevention", "threat-prevention"),
)


def telemetry_delivery_state(settings_read: bool, settings: dict[str, Any]) -> str:
    """What the device says about whether it CAN deliver, which is not configuration at all.

    Empty means the delivery state was never established, and that is not itself a finding -
    nothing clauses on this column. PAN-SVC-008's finding is about the recorded DECISION, and
    this exists so a report can say what the device is doing alongside.

    THE LAB MAKES THE GAP CONCRETE: measured 2026-10-29, all four appliances answer `Device
    Certificate does not exist` or `Device Certificate is expired` while both PA-VMs have all
    three categories `yes`. So the recorded decision is "share" and the delivery state is
    "cannot", and a control reading either half alone reports the opposite of the other.
    """
    if not settings_read:
        return ""
    return str(settings.get("status") or "").strip()[:64]


def _telemetry(appliance, snapshot, system) -> None:
    """One row per appliance, from the MERGED CONFIGURATION THIS PASS ALREADY COLLECTED.

    USE THE CONFIGURATION THAT WAS COLLECTED. Jason's ruling, 2026-10-30: which config files are
    collected, and why, was decided once; a stage reads them and does not re-open the question of
    whether a value is enforced now or staged to be enforced. No separate collection may be
    planned to answer that question differently. The exception is about MISSING DATA - a control
    needing something no collected config carries, as EDL and FQDN membership is - and not about
    the enforced-versus-staged distinction.

    SO THIS NORMALIZER NO LONGER ISSUES ITS OWN READ, and the history is worth keeping because the
    reasoning was seductive. `0115_one_telemetry_model` moved it ONTO a dedicated
    `type=config&action=show` of this one node, on the ground that the merged view follows the
    candidate and a staged opt-in would read as enforced. That ground is true and MEASURED - on
    691665AC334B458, read-only on 2026-10-30, `action=show` answers `No such node`, `action=get`
    returns all four children marked `@dirtyId=1`, and `show config merged` carries
    `device-telemetry: {device-health-performance: yes, product-usage: yes, threat-prevention:
    yes, region: Americas}` with no dirty marker anywhere in 1,259,801 bytes. **It is also true of
    every other node in that reply**, and of every control in the assessment: `deviceconfig/system`
    alone carries other nodes that controls read, with the same exposure. A per-node workaround
    for a condition that applies to the whole assessment is not a fix; it is one domain paying for
    a question the project has already answered. `reference/standing-rulings.md` section 5.

    TWO STATES, NOT THREE. A merged snapshot that does not exist means NO ROW - the caller returns
    before reaching here, which is the shape every device-wide normalizer in this package uses
    (`grep -c 'if snapshot is None' normalization/*.py` rather than a number here, because a stage
    that adds one invalidates it). So the states are: the node is in the collected
    `deviceconfig/system` subtree, or it is not, which `is_missing` carries.
    `telemetry_switches_known` means the node is there AND carries all three category keys: a node
    holding one switch and not its siblings would leave one read value beside two materialised
    ones with nothing saying which was which.
    """
    read_node = system.get("device-telemetry")
    node = read_node if isinstance(read_node, dict) else {}

    values: dict[str, Any] = {}
    provenance_rows: list[tuple[str, Any, str | None]] = []
    present = 0
    for column, key in TELEMETRY_SHARING_KEYS:
        shares, raw_key, raw_value = parse_yes_no_field(
            node.get(key), implicit=TELEMETRY_SHARING_IMPLICIT)
        values[column] = shares
        provenance_rows.append((column, raw_key, raw_value))
        if key in node:
            present += 1
    # KNOWN MEANS THE NODE IS THERE AND CARRIES ALL THREE, not merely that a row exists. Carried
    # across from the model this one absorbed, with its reasoning: a node holding one switch and
    # not its siblings would leave one read value beside two materialised ones, with nothing
    # saying which was which.
    values["telemetry_switches_known"] = present == len(TELEMETRY_SHARING_KEYS)
    # ABSENT IS NOT EMPTY. A node missing from the collected `system` subtree is `is_missing`; a
    # node present and holding nothing is not.
    values["is_missing"] = read_node is None

    region, region_rk, region_rv = parse_text_field(
        node.get("region"), implicit=TELEMETRY_REGION_IMPLICIT)
    # FOLDED, because the device stores `Americas` and the completion offers `americas`, and a
    # control comparing the stored value against the vocabulary must not turn on capitalisation.
    values["telemetry_region"] = region.strip().lower()[:16]
    provenance_rows.append(("telemetry_region", region_rk, region_rv))

    settings_read, settings = _op_result(_latest(appliance, "show_device_telemetry_settings"))
    # The reply nests two levels, and the useful half is the inner one.
    inner = ((settings.get("deviceTelemetry") or {}).get("settings")
             if isinstance(settings.get("deviceTelemetry"), dict) else None)
    inner = inner if isinstance(inner, dict) else {}
    values["telemetry_delivery_state"] = telemetry_delivery_state(settings_read, inner)

    # NOTHING ON THE FIREWALL RECORDS THAT ANY DECISION WAS TAKEN, only what the device does -
    # and the estate has NO MECHANISM TO INGEST AN ENGINEER'S DOCUMENT. So this holds its firing
    # member on every row until one exists, which is stage 3's own direction: "a device whose
    # sharing nobody has agreed to must not read as compliant because the setting happens to be
    # tidy". Recorded in the artifact's `spec_gaps`.
    values["recorded_decision_reconciliation"] = (
        RecordedDecisionReconciliation.NO_RECORDED_DECISION_LOCATED)

    row, _ = DeviceTelemetry.objects.update_or_create(
        appliance=appliance,
        defaults={
            "management_station": appliance.management_station,
            "appliance_group": appliance.appliance_group,
            "source_snapshot": snapshot,
            **values,
        },
    )
    _provenance(DeviceTelemetry, row, provenance_rows)

# ---------------------------------------------------------------------------
# ServiceRoute - which path each management service leaves by
# ---------------------------------------------------------------------------

#: WHICH SERVICES AN ENFORCEMENT POINT ORIGINATES, AS (service identifier, where the flow is
#: created). This table is the whole difference between a finding and noise, in stage 4's terms:
#: a column reporting "no path chosen" for 31 services on every appliance in an estate is noise,
#: and one reporting it for the services the appliance actually originates is a finding.
#:
#: THE IDENTIFIERS ARE THE DEVICE'S OWN, measured 2026-10-29 by `action=complete` at
#: `deviceconfig/system/route/service` and at `vsys/entry[@name='...']/route/service`: 32
#: firewall-wide on a PA-5220, 31 on a PA-VM, 13 per-vsys on both. The PA-5220 adds `adem` and
#: `panorama-log-forwarding` and LACKS `gp-ip-mgmt`. The corpus gives `paloalto-updates` as an
#: identifier and no build offers it; the real one is `paloalto-networks-services`.
#:
#: STAGE 5 NAMES SEVEN SOURCES AND NOT ONE MAPPING. Its `derived_from` lists the syslog server
#: profiles, the LDAP/RADIUS/TACACS+/Kerberos profiles, the NetFlow collectors, the update-server
#: and telemetry configuration, the Panorama connection, and the configured resolvers and time
#: servers - which is a list of PLACES and not of service identifiers. Working out which
#: identifier each place originates was this stage's, and the artifact's `spec_gaps` says what
#: would close it: a per-service `originated_when` pointer on stage 5's own column record.
#:
#: WHAT IS DELIBERATELY NOT HERE: every identifier whose flow this configuration cannot attest.
#: `autofocus`, `data-services`, `deployments`, `iot`, `mdm`, `proxy`, `url-updates`,
#: `edl-updates`, `wildfire-private`, `ztp`, `ddns`, `hsm`, `crl-status`, `vmmonitor`,
#: `gp-ip-mgmt`, `adem` and `panorama-log-forwarding` each need either a licence state, a
#: feature this estate does not run, or a node no read in this domain takes. Claiming one would
#: manufacture the noise this column exists to remove; omitting it UNDER-reports, which leaves
#: the posture column's firing default doing the work instead of a count nobody can check.
_DEVICE_SERVICES_ORIGINATED = (
    # Device > Setup > Services. A resolver or a time server named here IS an originated flow.
    ("dns", ("deviceconfig", "system", "dns-setting")),
    ("ntp", ("deviceconfig", "system", "ntp-servers")),
    # The vendor's own update and telemetry endpoints, which both hang off `update-server`.
    ("paloalto-networks-services", ("deviceconfig", "system", "update-server")),
    # Device > Setup > Management > Panorama Settings. `panorama/local-panorama/panorama-server`
    # on all four lab appliances, measured 2026-10-29.
    ("panorama", ("deviceconfig", "system", "panorama")),
    # The firewall's own SNMP agent. The service identifier is `snmp` at both scopes and the
    # agent is what makes the appliance answer on it.
    ("snmp", ("deviceconfig", "system", "snmp-setting")),
)

#: The same question at `shared` and at one vsys: (service identifier, path under that subtree).
#: A profile at EITHER scope originates the flow from the enforcement point that holds it, which
#: is why this table is applied to the shared subtree for the device-local row and to the vsys
#: entry for a per-system one.
_PROFILE_SERVICES_ORIGINATED = (
    ("syslog", ("log-settings", "syslog")),
    ("email", ("log-settings", "email")),
    # `snmptrap` is a log-settings profile and the service identifier it originates is `snmp`,
    # the same one the agent above answers on - the device offers no separate trap identifier at
    # either scope.
    ("snmp", ("log-settings", "snmptrap")),
    ("ldap", ("server-profile", "ldap")),
    ("radius", ("server-profile", "radius")),
    # THE SERVICE IS SPELLED `tacplus` AND SO IS THE PROFILE BRANCH, measured on both. Neither
    # is `tacacs` or `tacacs-plus`, which is what the prose calls it.
    ("tacplus", ("server-profile", "tacplus")),
    ("kerberos", ("server-profile", "kerberos")),
    ("mfa", ("server-profile", "mfa")),
    ("netflow", ("server-profile", "netflow")),
    ("scep", ("scep",)),
    # User-ID agents and redistribution both originate `uid-agent` traffic from the vsys that
    # holds them.
    ("uid-agent", ("user-id-collector",)),
    ("uid-agent", ("redistribution-agent",)),
)


def _node_at(root: Any, path: tuple[str, ...]) -> Any:
    """The node at `path` under `root`, or None - no exception for a missing step."""
    node = root
    for step in path:
        if not isinstance(node, dict) or step not in node:
            return None
        node = node.get(step)
    return node


def _originates(root: Any, path: tuple[str, ...]) -> bool:
    """Does `root` carry something at `path` that actually creates a flow?

    PRESENCE IS KEY MEMBERSHIP AND NOT TRUTHINESS for the container, which is the same trap
    `_snmp` separates - but here a container that EXISTS AND IS EMPTY originates nothing, and
    that is the one place this differs. Measured 2026-10-29: vsys6 of both PA-5220s carries
    `log-settings: {"profiles": null}`, an emptied container, and reporting that vsys as
    originating a syslog flow would put a finding on a system that sends no logs anywhere.
    So a dict with entries or a non-empty scalar counts, and `None` or `{}` does not.
    """
    node = _node_at(root, path)
    if node is None:
        return False
    if isinstance(node, dict):
        # Candidate decorations are not content. A node holding only `@ptpl`-style attributes is
        # a marker on an empty container, which originates nothing.
        return any(not str(key).startswith("@") for key in node)
    return bool(str(node).strip())


def services_originated(
    device_entry: dict[str, Any],
    shared: dict[str, Any],
    vsys_entry: dict[str, Any] | None,
) -> list[str]:
    """Which management services this enforcement point originates, sorted and de-duplicated.

    `vsys_entry` None asks the firewall-wide question: the deviceconfig sources above, plus any
    profile at `shared` or at ANY vsys, because a profile anywhere on the appliance originates a
    flow the firewall-wide paths govern. A vsys entry asks the per-system question and reads only
    that vsys's own subtree - the 13-member per-vsys set has no deviceconfig member in it.
    """
    found: set[str] = set()
    if vsys_entry is None:
        for service, path in _DEVICE_SERVICES_ORIGINATED:
            if _originates(device_entry, path):
                found.add(service)
        roots = [shared] + [entry for _name, entry in _vsys_entries_of(device_entry)]
    else:
        roots = [vsys_entry]
    for root in roots:
        for service, path in _PROFILE_SERVICES_ORIGINATED:
            if _originates(root, path):
                found.add(service)
    return sorted(found)


def _vsys_entries_of(device_entry: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """(vsys name, its merged entry) for every vsys the device's own config names.

    A SIXTH CALLER OF THIS WALK, and the fifth one's note in OptivEdgeProbe
    `reference/consumer-repo-notes.md` says the next run should IMPORT rather than copy.
    `globalprotect.py::_vsys_entries` takes a SNAPSHOT and this domain already holds the parsed
    device entry - re-deriving it from the snapshot would be a second parse of the same payload -
    so this takes the entry instead and is otherwise the same four lines.
    `certificates.py::scoped_nodes` cannot be reused for the reason that function's own docstring
    gives: it SKIPS a vsys that does not carry the object key, and this domain's row is a verdict
    over a vsys, so a vsys carrying nothing at all is the state the control exists to report and
    the row has to exist.
    """
    vsys_node = device_entry.get("vsys") if isinstance(device_entry, dict) else None
    out: list[tuple[str, dict[str, Any]]] = []
    for entry in ensure_list((vsys_node or {}).get("entry")) if isinstance(vsys_node, dict) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("@name") or "").strip()
        if name:
            out.append((name, entry))
    return out


def chosen_paths(route_service: Any) -> tuple[set[str], set[str]]:
    """(services with a v4 source, services with a v6 source) from one `route/service` node.

    A PATH SOMEBODY CHOSE NAMES BOTH A SOURCE INTERFACE AND A SOURCE ADDRESS, which is stage 5's
    own definition and is stricter than "an entry exists": an entry naming an interface and no
    address does not determine the source, and PAN-OS accepts it.

    UNOBSERVED IN EVERY STATE. The node is absent on all four lab appliances and at every vsys
    of all four, measured 2026-10-29 and twice before, so no reading here has been exercised
    against a populated instance. What that costs is named in the artifact's `readback`.
    """
    node = route_service if isinstance(route_service, dict) else {}
    v4: set[str] = set()
    v6: set[str] = set()
    for service, value in node.items():
        if str(service).startswith("@") or not isinstance(value, dict):
            continue
        for key, bucket in (("source", v4), ("source-v6", v6)):
            source = value.get(key)
            if not isinstance(source, dict):
                continue
            if str(source.get("interface") or "").strip() and str(
                    source.get("address") or "").strip():
                bucket.add(str(service))
    return v4, v6


def service_path_verdicts(
    originated: list[str], v4: set[str], v6: set[str]) -> dict[str, Any]:
    """The firewall-wide half of PAN-SVC-006, as the four columns that carry it.

    AN EMPTY ORIGINATED SET READS AS TRUE on the boolean and STILL FIRES on the posture, which
    is stage 5's own arrangement: `False` on a device that originates nothing would be vacuous,
    and the posture column carries the firing default instead so that an unrenormalized row
    reports the finding while the list is empty.
    """
    with_path = sorted(set(originated) & v4)
    every = len(with_path) == len(originated)
    both_families = bool(with_path) and set(with_path) <= v6
    if not every:
        posture = ServicePathPosture.NO_PATH_SET
    elif not originated:
        # Every originated service has a path because there are none. Not a pass: nothing has
        # been shown about this enforcement point, so it keeps the firing member.
        posture = ServicePathPosture.NO_PATH_SET
    elif not both_families:
        posture = ServicePathPosture.ONE_FAMILY_ONLY
    else:
        posture = ServicePathPosture.EVERY_SERVICE
    return {
        "services_originated": originated,
        "services_with_a_chosen_path": len(with_path),
        "every_originated_service_has_a_chosen_path": every,
        "path_covers_both_address_families": both_families,
        "service_path_posture": posture,
    }


def per_system_verdicts(
    recorded: bool, originated: list[str], with_path_count: int) -> dict[str, Any]:
    """The per-vsys half of PAN-SVC-006.

    `recorded` is whether a `route/service` subtree exists for this vsys at all - the recorded
    CHOICE and not the reasoning, because the device cannot distinguish a deliberate inheritance
    from an omission and stage 3 puts that in `engineer_supplies`.
    """
    if not recorded:
        posture = PerSystemPathPosture.NEITHER_RECORDED
    elif originated and with_path_count < len(originated):
        posture = PerSystemPathPosture.SOME_SERVICES_ONLY
    else:
        posture = PerSystemPathPosture.DECIDED_EITHER_WAY
    return {
        "per_system_path_choice_recorded": recorded,
        "per_system_path_posture": posture,
    }


def _service_routes(appliance, snapshot, device_entry, shared) -> int:
    """One row per enforcement point: the appliance, then every vsys it names.

    A VSYS CARRYING NOTHING STILL GETS A ROW. That is the whole reason this walk is not
    `certificates.py::scoped_nodes` - a vsys with no recorded path choice is the state
    PAN-SVC-006's second half exists to report, and skipping it would make the commonest finding
    in this domain invisible.

    NO PROVENANCE ROW IS WRITTEN FOR ANY COLUMN. Every one is in `DERIVED_FIELDS`, including the
    two identity columns, because the node carries no key any of them comes from: the scope is
    the subtree a value was read beneath and the rest are computed over other subtrees.
    """
    deviceconfig = device_entry.get("deviceconfig") if isinstance(device_entry, dict) else None
    system = deviceconfig.get("system") if isinstance(deviceconfig, dict) else None
    system = system if isinstance(system, dict) else {}
    device_route = _node_at(system, ("route", "service"))
    v4, v6 = chosen_paths(device_route)
    originated = services_originated(device_entry, shared, None)

    rows = 0
    values = service_path_verdicts(originated, v4, v6)
    values.update(per_system_verdicts(
        # THE FIRWALL-WIDE ROW IS NOT A VSYS and the per-system half does not apply to it. The
        # two per-system columns therefore hold their firing defaults on this row, which is
        # correct rather than missing: the question "did this virtual system record a choice"
        # has no answer for an appliance-wide enforcement point. A query grading the per-system
        # half must clause on `scope eq vsys`, which is what `discriminator.carried_into` names.
        recorded=False, originated=[], with_path_count=0))
    ServiceRoute.objects.update_or_create(
        appliance=appliance,
        scope=ServiceRouteScope.DEVICE_LOCAL,
        vsys_name="",
        defaults={
            "management_station": appliance.management_station,
            "appliance_group": appliance.appliance_group,
            "source_snapshot": snapshot,
            **values,
        },
    )
    rows += 1

    for vsys_name, vsys_entry in _vsys_entries_of(device_entry):
        vsys_route = _node_at(vsys_entry, ("route", "service"))
        vsys_v4, vsys_v6 = chosen_paths(vsys_route)
        vsys_originated = services_originated(device_entry, shared, vsys_entry)
        vsys_values = service_path_verdicts(vsys_originated, vsys_v4, vsys_v6)
        vsys_values.update(per_system_verdicts(
            recorded=_node_at(vsys_entry, ("route", "service")) is not None,
            originated=vsys_originated,
            with_path_count=vsys_values["services_with_a_chosen_path"]))
        ServiceRoute.objects.update_or_create(
            appliance=appliance,
            scope=ServiceRouteScope.VSYS,
            vsys_name=vsys_name[:64],
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": snapshot,
                **vsys_values,
            },
        )
        rows += 1
    return rows


def _surfaces_were_walked(appliance: Appliance) -> bool:
    """Has ANY management surface of this appliance been walked for its services?

    This is what separates "every surface is shown to be refusing" from "nobody looked", and the
    query layer cannot ask it: by the time a query runs, an absent reading has been collapsed
    into a column value and there is no is-null operator left to ask with. A row exists for every
    service a surface's plane supports, so one row anywhere means the walk happened.
    """
    interfaces = ManagementInterface.objects.filter(appliance=appliance)
    if not interfaces.exists():
        return False
    # EVERY SURFACE, NOT ANY SURFACE. Stage 5's own words: "whether a ManagementService row
    # exists for `snmp` on every surface this platform has, as against no row having been
    # collected". A partially walked appliance must not earn the reduced severity either, so a
    # surface with no `snmp` row of its own makes the whole answer False.
    #
    # Measured 2026-10-29: all four lab appliances have an `snmp` row on every surface - eight
    # surfaces each on the PA-5220s, six on 6A9C0A9904E7D6E, one on 691665AC334B458 - so this is
    # True on all four and the stricter reading changes no row in this lab. It changes what an
    # appliance collected halfway reports, which is the point.
    walked = set(
        ManagementService.objects.filter(
            management_interface__appliance=appliance, name="snmp")
        .values_list("management_interface_id", flat=True))
    return all(interface.pk in walked for interface in interfaces)


def normalize_device_services(appliance: Appliance) -> dict[str, int]:
    """Rebuild one appliance's six device-services rows, plus one per vsys for the paths.

    NO MERGED SNAPSHOT MEANS NO ROW AT ALL, for every model here. There is nothing to anchor to
    and nothing any column could honestly say - and an appliance with no row is visibly
    uncollected, where an appliance with a row full of defaults reads as measured.
    """
    snapshot = latest_merged_snapshot(appliance)
    empty = {"ntp_settings": 0, "snmp_settings": 0, "system_identities": 0,
             "dns_settings": 0, "device_services_telemetry": 0, "service_routes": 0}
    if snapshot is None:
        return empty
    entry = device_entry_from_snapshot(snapshot)
    deviceconfig = entry.get("deviceconfig") if isinstance(entry, dict) else None
    deviceconfig = deviceconfig if isinstance(deviceconfig, dict) else {}
    system = deviceconfig.get("system")
    system = system if isinstance(system, dict) else {}
    shared = merged_shared(snapshot.payload if isinstance(snapshot.payload, dict) else {})

    with transaction.atomic():
        _ntp(appliance, snapshot, system)
        _snmp(appliance, snapshot, system)
        # BEFORE `_dns`, which reads the row this writes. See the module docstring.
        _identity(appliance, snapshot, system)
        _dns(appliance, snapshot, system)
        _telemetry(appliance, snapshot, system)
        routes = _service_routes(appliance, snapshot, entry, shared)
    return {"ntp_settings": 1, "snmp_settings": 1, "system_identities": 1,
            "dns_settings": 1, "device_services_telemetry": 1, "service_routes": routes}
