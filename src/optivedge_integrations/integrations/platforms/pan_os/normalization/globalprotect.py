"""GlobalProtect portal normalization - PAN-GPP-001 to PAN-GPP-006.

THIS ADDS NO CONFIGURATION COLLECTION, which is the opposite of what the spec expected. Stage 5
declared the portal read and the enforcement-point read as `issued_today: false` on the strength
of grepping `global` across `collectors/` and `persistence/` and finding nothing. That grep is
right and the conclusion does not follow: `show config merged` is one call for the whole device
and ALREADY CARRIES both nodes. Measured 2026-10-29 through Panorama's target= proxy on all four
lab appliances - every vsys entry of the merged payload carries its own `global-protect` subtree
with the portal entries, their client-auth rows, their agent configurations and their
clientless-vpn branches, and `profiles/hip-objects` sits beside it. The only read this domain
adds is the vendor's app-setting dictionary under /config/predefined, which the merged view
genuinely does not carry.

THREE THINGS THE MERGED VIEW DOES TO THIS DOMAIN IN PARTICULAR, all three measured:

1. `merged` FOLLOWS THE CANDIDATE (`docs/palo-alto/pan-os/read-config-sources.md` A2), so a
   portal an administrator has typed and not committed is in these rows. On an HA pair that is
   not a theoretical worry: measured 2026-10-29, the peer 013201001475 carries all four portals
   of vsys4 in `merged` while stage 6 recorded them answering `No such node` under `action=show`
   on that same peer minutes after the commit. Candidate is synchronised, running is not, and
   this normalizer therefore writes rows for configuration that is not in force on the peer.
   Nothing here can separate them - the merged payload carries no `dirtyId` markers at all.

2. AN ENTRY COUNT IS THE ONLY SAFE PRESENCE TEST. `global-protect` with a present-and-empty
   `global-protect-portal` inside it is a committed, undecorated state in this estate, and a
   truthiness test reports it as a portal. `common.py::entry_container` is what separates
   absent / present-and-empty / populated, and every count below goes through it.

3. THE VSYS LIST COMES FROM THE DEVICE'S OWN `/vsys`, never from a list this code chooses: a
   PA-5220 here reports eight firewall-local vsys under `action=show` and a ninth under
   `action=get`. One `GlobalProtectEnforcementPoint` row is written for EVERY vsys the merged
   payload names, including those with no `global-protect` node at all - that absence is a
   graded state for PAN-GPP-006 and a row is the only place it can be reported.

WHAT IS REUSED RATHER THAN WRITTEN, because the failure mode of a generator is confident
redundant code: `device_configuration.py::latest_merged_snapshot` and `::device_entry_from_snapshot`
for the appliance-grain payload, `common.py::entry_container` for the three container states,
`common.py::parse_text_field` for every measured leaf, `certificates.py::write_scoped_objects`
and `::ScopedEntry` for the scoped-row write with its provenance rows and its delete-what-is-gone
(that module's own docstring says those two are object-type agnostic and that authentication
profiles import them from there), `services_settings.py::write_node_row` for the node-shaped
enforcement-point row, and `device_identification.py::latest_license_info_snapshot` and
`::_licence_entries` for the licence reply - which another domain's stage 7 run collected and
normalized earlier today, so this domain's third read was already issued when its spec was
written.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    GlobalProtectEnforcementPoint,
    GlobalProtectPortal,
    GlobalProtectPortalClientAuthRow,
    Snapshot,
)
from optivedge_integrations.integrations.models.globalprotect import (
    ADMISSION_PASSWORD_AND_CERTIFICATE,
    ADMISSION_PASSWORD_ONLY,
    ADMISSION_PASSWORD_OR_CERTIFICATE,
    ADMISSION_UNKNOWN,
    CLIENTLESS_VPN_ABSENT,
    CLIENTLESS_VPN_PRESENT,
    CLIENTLESS_VPN_UNKNOWN,
    FEATURE_ABSENT,
    FEATURE_LATENT,
    FEATURE_LIVE,
    LICENSED_NO,
    LICENSED_UNKNOWN,
    LICENSED_YES,
    POSTURE_NO_AGENT_CONFIGURATION,
    POSTURE_NOT_SET,
    POSTURE_SEVERAL_MEMBERS,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.predefined import (
    PREDEFINED_GP_APP_CONFIG_SOURCE_TYPE,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
    ScopedEntry,
    write_scoped_objects,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ensure_list,
    entry_container,
    parse_text_field,
    scalar_value,
    was_absent,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_identification import (
    _licence_entries,
    latest_license_info_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    write_node_row,
)


#: The four keys the device refuses to commit a portal without, measured by stage 6 against
#: `validate full`: one job named all four missing from a portal that lacked them, a second
#: named them again, and a third returned the identical refusal after `custom-login-page` was
#: DELETED off a portal that had it. They are the only thing that can tell an absent key apart
#: from a read that did not carry one, which is why their presence is a column.
PORTAL_MANDATORY_KEYS = (
    "local-address",
    "ssl-tls-service-profile",
    "custom-login-page",
    "custom-home-page",
)

#: The app setting PAN-GPP-003 asks about, as its entry name under a portal's agent
#: configuration. THE ENTRY NAME IS NOT VALIDATED BY THE DEVICE - a name for no real setting was
#: stored without comment and `validate full` said nothing - which is why the vendor's
#: dictionary is collected beside it.
CLIENT_UPGRADE_SETTING = "client-upgrade"

#: The feature string `request license info` reports for the portal entitlement. A PROSE LABEL
#: matched by equality, which is the whole fragility: nothing guarantees it stable across
#: releases, and a rename would move every row to `unknown` rather than to `no` - the direction
#: that keeps PAN-GPP-006 reporting. Measured 2026-10-29: the only appliance in this estate
#: naming it is 691665AC334B458, which also names `GlobalProtect Gateway`.
GLOBALPROTECT_PORTAL_FEATURE = "globalprotect portal"

#: Mandatory on a committed portal, so an absent key is a statement about the READ and never
#: about the device. The column stores the empty string and the provenance row records
#: `not_configured`: there is nothing for an absence to assert, so nothing is licensed here.
PORTAL_MANDATORY_AT_COMMIT = Implicit.not_assumed(
    "mandatory on a committed GlobalProtect portal, measured three ways by stage 6 against "
    "`validate full` - so an absent key is evidence about the read and not a device state, and "
    "`mandatory_keys_present` is the column that reports it")

#: Mandatory on a committed client-auth row: `os` and `authentication-profile` were reported
#: together in ONE validate job and again after an unrelated delete.
ROW_MANDATORY_AT_COMMIT = Implicit.not_assumed(
    "mandatory on a committed client-auth row, reported together with its sibling in one "
    "`validate full` job and again after an unrelated delete - so an absent key here is a "
    "reading nobody took rather than a device state")

#: OPTIONAL on a committed portal and its meaning NOT measured. The absence is a real state -
#: the estate's one pre-existing portal carries no certificate profile - and what the device then
#: DOES is unrendered by any oracle this domain has: there is no UI route for the portal screen,
#: `show system state filter` answers NO_MATCHES for every GlobalProtect concept, and the
#: sibling-refusal oracle that settles the SSL/TLS profile's version keys does not fire on this
#: node. So nothing is licensed and the verdict columns carry the direction.
PORTAL_OPTIONAL_UNMEASURED = Implicit.not_assumed(
    "optional on a committed GlobalProtect portal and its absent meaning unmeasured - no "
    "oracle in this estate renders what the device does without the key, so materialising "
    "either candidate would report a value nobody read")

#: OPTIONAL on a committed row and the two candidate answers are the two ENDS of PAN-GPP-002's
#: grading - `no` is its acceptable rank and `yes` its high rank - so materialising the schema
#: default would report every unconfigured row as HARDENED. The two sources also point opposite
#: ways: `action=complete` marks `no` the schema default on both builds, while the estate's one
#: committed portal omits the key and demands only a password.
ROW_SWITCH_UNMEASURED = Implicit.not_assumed(
    "optional on a committed client-auth row, measured, and its absent meaning unmeasured - the "
    "two candidate answers are the two ends of this control's grading, so materialising either "
    "would report a rank nobody read")


def latest_gp_app_config_dictionary_snapshot(appliance: Appliance) -> Snapshot | None:
    """The vendor's GlobalProtect app-setting dictionary for one appliance, or None.

    Its own `latest_*_snapshot` rather than a registry lookup, because there is no registry:
    nothing maps a source type to a reader, so the normalizer that wants one writes it and
    imports the source-type constant from the collector that defines it. The same function
    exists in four other normalization modules, which is the convention here and not a defect
    to tidy.
    """
    return (
        Snapshot.objects.filter(
            appliance=appliance, source_type=PREDEFINED_GP_APP_CONFIG_SOURCE_TYPE)
        .order_by("-collected_at", "-pk")
        .first()
    )


def gp_app_setting_dictionary(snapshot: Snapshot | None) -> dict[str, dict[str, Any]]:
    """The dictionary as {setting name: its entry}, or {} when the read did not arrive.

    Collected per appliance and never carried between them: the entry count differs by
    appliance in this estate - 89 on both PA-5220s against 98 on both PA-VMs - and the 89 are a
    strict SUBSET, so one appliance's copy applied to another under-reports by nine settings.

    NOTHING IN THIS DOMAIN GRADES ON IT. It is a decoding input: it carries each setting's
    label, its permitted value set and its form default, which is what makes a stored member
    list legible and a typo recognisable. A `{}` here means a column cannot be LABELLED, not
    that a value cannot be read.
    """
    if snapshot is None:
        return {}
    payload = snapshot.payload if isinstance(snapshot.payload, dict) else {}
    _state, entries = entry_container(payload, "config")
    return {str(e.get("@name") or ""): e for e in entries if e.get("@name")}


def _vsys_entries(snapshot: Snapshot) -> list[tuple[str, dict[str, Any]]]:
    """(vsys name, its merged entry) for every vsys the device's own config names.

    A FOURTH PRIVATE COPY OF THIS WALK, and it is private deliberately rather than promoted.
    `certificates.py::scoped_nodes`, `log_settings.py::normalize_log_settings` and
    `decryption.py` each carry their own four-line version; the judgement
    `common.py::choice_child` recorded when it was promoted on its fourth caller applies in the
    other direction here, because the three existing copies are load-bearing for shipped
    controls and this run is one of four changing this repository at the same time. Recorded in
    `OptivEdgeProbe reference/consumer-repo-notes.md` so somebody can promote it in a change
    that owns all four.

    THE DIFFERENCE FROM `scoped_nodes` IS WHY IT CANNOT SIMPLY BE REUSED: that function skips a
    vsys that does not carry the object key, and this domain needs a row for a vsys carrying
    nothing at all.
    """
    device_entry = device_entry_from_snapshot(snapshot)
    vsys_node = device_entry.get("vsys") if isinstance(device_entry, dict) else None
    out = []
    for entry in ensure_list((vsys_node or {}).get("entry")) if isinstance(vsys_node, dict) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("@name") or "").strip()
        if name:
            out.append((name, entry))
    return out


def _text_or_null(node: Any, *, implicit: Implicit) -> tuple[str | None, Any, str | None]:
    """`parse_text_field`, for a column whose absent state is stored as NULL rather than "".

    `parse_text_field` answers "" for an absent key, which is right for the columns a control
    compares with `is_empty` - the only absence operator the query layer offers - and wrong for
    the three here that stage 5 declares as storing NULL. Those three are compared by clauses
    that must NOT match an unread row: a NULL satisfies no comparison, which is the behaviour
    stage 5 reasoned from and built a companion boolean beside. Converting here keeps the
    provenance row intact - the absence still records `not_configured` through the `Implicit`.
    """
    value, raw_key, raw_value = parse_text_field(node, implicit=implicit)
    return (value or None), raw_key, raw_value


@dataclass(slots=True)
class NormalizedPortal:
    """One portal before persistence, with the rows beneath it."""

    vsys_name: str
    name: str
    values: dict[str, Any]
    provenance: list[tuple[str, Any, str | None]]
    auth_rows: list["NormalizedClientAuthRow"] = field(default_factory=list)
    entry: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedClientAuthRow:
    """One client-authentication row before persistence."""

    name: str
    values: dict[str, Any]
    provenance: list[tuple[str, Any, str | None]]
    entry: dict[str, Any] = field(default_factory=dict)


def _agent_configurations(entry: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """(container state, the ordered agent configuration entries).

    THE ORDER IS THE SEMANTICS: the collection is a flat entry list with no priority key, so
    the order is the DOCUMENT order and the vendor states the portal delivers the FIRST match
    and stops. Nothing here sorts, and a consumer that does destroys the reading.
    """
    return entry_container(entry, "client-config", "configs")


def _upgrade_posture(configs: list[dict[str, Any]]) -> str:
    """The upgrade instruction the FIRST matching agent configuration would deliver.

    Which configuration an endpoint matches depends on its operating system, its user or group,
    a machine-account check, a certificate profile and custom registry or plist checks - none of
    which anything here can evaluate - so the first configuration in document order is read, and
    that is the vendor's own tie-break rather than an approximation of one.

    Three sentinels for the states a single value cannot express, and none of them may be
    collapsed onto a real value: `no_agent_configuration` because nothing will move an endpoint
    and there is nothing to edit, `not_set` because the dictionary's form default is this
    control's ACCEPTABLE rank and collapsing onto it turns "this portal says nothing about
    upgrades" into a pass, and `several_members` because a second write APPENDS rather than
    replaces on a setting the vendor's own schema marks single-valued - so the stored list can
    hold two values and there is no effective one to report.
    """
    if not configs:
        return POSTURE_NO_AGENT_CONFIGURATION
    first = configs[0]
    _state, settings = entry_container(first, "gp-app-config", "config")
    for setting in settings:
        if str(setting.get("@name") or "") != CLIENT_UPGRADE_SETTING:
            continue
        value = setting.get("value")
        members = [str(m) for m in ensure_list(
            value.get("member") if isinstance(value, dict) else value) if m is not None]
        if not members:
            return POSTURE_NOT_SET
        if len(members) > 1:
            return POSTURE_SEVERAL_MEMBERS
        return members[0][:32]
    return POSTURE_NOT_SET


def _saved_credentials_posture(configs: list[dict[str, Any]]) -> str:
    """What the first matching agent configuration permits the app to keep.

    The same first-match problem as the upgrade posture: a portal holding one hardened
    configuration BELOW a permissive one caches credentials for everybody the permissive one
    matches, and a check reporting the best configuration it found reports the opposite of the
    truth.

    Stored as the device's own NUMERIC STRING and not as an integer and not as a label - written
    `0`, read back {'#text': '0'} - because the stored order is not the exposure order and a
    consumer that casts to an integer invites a threshold over it.
    """
    if not configs:
        return POSTURE_NO_AGENT_CONFIGURATION
    raw_value, raw_key, _raw_prov = scalar_value(configs[0].get("save-user-credentials"))
    if was_absent(raw_key) or not raw_value:
        return POSTURE_NOT_SET
    return str(raw_value)[:32]


def _clientless_vpn_state(entry: dict[str, Any], mandatory_keys_present: bool) -> str:
    """`present`, `absent`, or `unknown` where the portal arrived incomplete.

    THERE IS NO OFF SWITCH TO READ. Ten children under `clientless-vpn` and not one of them is a
    boolean, measured on three builds - the UI control that reads as a top-level switch REVEALS
    the group rather than writing an element - so `absent OR disabled` collapses to "the element
    exists or it does not".

    KEY PRESENCE AND NOT TRUTHINESS, for the reason the module docstring gives: a committed
    empty container parses to None and a staged one to a dict of @admin/@dirtyId/@time, so
    `if node:` gives opposite wrong answers from one test. `dns-proxy` is the branch's one
    mandatory child, so a branch in RUNNING config is always at least minimally configured and
    `present` is not a state an administrator reaches by accident - it is read here as
    corroboration and NOT as a second condition, because a candidate-only branch with the child
    still missing is a real surface somebody is building and reading it as `absent` would report
    it compliant.

    `unknown` where the mandatory key set is incomplete: such a row is a read that did not carry
    the portal, so nothing can be said about a branch it may or may not have carried either.
    """
    if not mandatory_keys_present:
        return CLIENTLESS_VPN_UNKNOWN
    return CLIENTLESS_VPN_PRESENT if "clientless-vpn" in entry else CLIENTLESS_VPN_ABSENT


def _admission_demand(switch: str | None, certificate_profile_bound: bool) -> str:
    """What one client-auth row demands, from the row's switch and the PORTAL's binding.

    THE SEVERITY IS A FUNCTION OF TWO COLUMNS AND A GRADING NAMES ONE, which is why this is a
    column and not a predicate: `yes` on the switch is one rank where a certificate profile is
    bound and a worse one where none is, and a clause has no second field slot.

    The order of the tests is the reading, and it is not interchangeable:

      switch absent                  -> `unknown`. Two states at once - the key absent on a
                                       committed row, whose meaning nobody measured, or a row
                                       the collector did not carry - and both must report.
      no certificate profile bound   -> `password_only`. Whatever the switch says, no client
                                       certificate can be demanded of anybody: there is nothing
                                       for the OR to reach and nothing for the AND to check.
      bound, switch `yes`            -> `password_or_certificate`
      bound, switch `no`             -> `password_and_certificate`. The vendor's polarity: `no`
                                       is the HARDENED value, spelled in the device's own help
                                       string as "No (User Credentials AND Client Certificate
                                       Required)".
      bound, anything else           -> `unknown`. A value outside the measured pair is a row
                                       nothing here can read, and reading it as either end
                                       would invent a rank.
    """
    if not switch:
        return ADMISSION_UNKNOWN
    if not certificate_profile_bound:
        return ADMISSION_PASSWORD_ONLY
    if switch == "yes":
        return ADMISSION_PASSWORD_OR_CERTIFICATE
    if switch == "no":
        return ADMISSION_PASSWORD_AND_CERTIFICATE
    return ADMISSION_UNKNOWN


def _client_auth_rows(portal_entry: dict[str, Any], portal_config: dict[str, Any],
                      portal_name: str, certificate_profile_bound: bool,
                      ) -> list[NormalizedClientAuthRow]:
    """Every row of one portal's client-authentication table.

    The table is OPTIONAL on a committed portal, measured - `validate full` never named it on a
    portal that lacked one - and a portal with no row at all demands nothing of anybody, which
    is weaker than every rank PAN-GPP-002 grades. That state produces NO ROW HERE, by
    construction, and the portal's own `client_auth_row_count` is where it is visible.
    """
    _state, entries = entry_container(portal_config, "client-auth")
    rows: list[NormalizedClientAuthRow] = []
    for entry in entries:
        name = str(entry.get("@name") or "").strip()
        if not name:
            continue
        os_value, os_rk, os_rv = parse_text_field(
            entry.get("os"), implicit=ROW_MANDATORY_AT_COMMIT)
        profile, profile_rk, profile_rv = parse_text_field(
            entry.get("authentication-profile"), implicit=ROW_MANDATORY_AT_COMMIT)
        switch, switch_rk, switch_rv = _text_or_null(
            entry.get("user-credential-or-client-cert-required"),
            implicit=ROW_SWITCH_UNMEASURED)
        rows.append(NormalizedClientAuthRow(
            name=name,
            values={
                "name": name,
                "portal_name": portal_name,
                "os": os_value[:32],
                "authentication_profile": profile[:64],
                "user_credential_or_client_cert_required": (
                    switch[:8] if switch is not None else None),
                "certificate_profile_bound": certificate_profile_bound,
                "admission_demand": _admission_demand(switch, certificate_profile_bound),
            },
            provenance=[
                ("os", os_rk, os_rv),
                ("authentication_profile", profile_rk, profile_rv),
                ("user_credential_or_client_cert_required", switch_rk, switch_rv),
            ],
            entry=entry,
        ))
    return rows


def normalized_portals(snapshot: Snapshot) -> list[NormalizedPortal]:
    """Every GlobalProtect portal of every vsys in one appliance's merged payload.

    Pure: takes a snapshot, touches no model and writes nothing, so a test and a stage 7
    readback can both assert over the result without a database.
    """
    portals: list[NormalizedPortal] = []
    for vsys_name, vsys in _vsys_entries(snapshot):
        _state, entries = entry_container(vsys, "global-protect", "global-protect-portal")
        for entry in entries:
            name = str(entry.get("@name") or "").strip()
            if not name:
                continue
            portal_config = entry.get("portal-config")
            if not isinstance(portal_config, dict):
                portal_config = {}
            mandatory_keys_present = all(key in portal_config for key in PORTAL_MANDATORY_KEYS)

            tls_profile, tls_rk, tls_rv = parse_text_field(
                portal_config.get("ssl-tls-service-profile"),
                implicit=PORTAL_MANDATORY_AT_COMMIT)
            certificate_profile, cert_rk, cert_rv = _text_or_null(
                portal_config.get("certificate-profile"),
                implicit=PORTAL_OPTIONAL_UNMEASURED)
            login_page, login_rk, login_rv = parse_text_field(
                portal_config.get("custom-login-page"), implicit=PORTAL_MANDATORY_AT_COMMIT)

            clientless = entry.get("clientless-vpn")
            if not isinstance(clientless, dict):
                clientless = {}
            ssl_protocol = (clientless.get("crypto-settings") or {})
            ssl_protocol = (ssl_protocol.get("ssl-protocol")
                            if isinstance(ssl_protocol, dict) else None)
            if not isinstance(ssl_protocol, dict):
                ssl_protocol = {}
            min_version, min_rk, min_rv = _text_or_null(
                ssl_protocol.get("min-version"), implicit=PORTAL_OPTIONAL_UNMEASURED)
            max_version, max_rk, max_rv = _text_or_null(
                ssl_protocol.get("max-version"), implicit=PORTAL_OPTIONAL_UNMEASURED)

            state = _clientless_vpn_state(entry, mandatory_keys_present)
            configs_state, configs = _agent_configurations(entry)

            auth_rows = _client_auth_rows(
                entry, portal_config, name, bool(certificate_profile))

            portals.append(NormalizedPortal(
                vsys_name=vsys_name,
                name=name,
                values={
                    "name": name,
                    "mandatory_keys_present": mandatory_keys_present,
                    "ssl_tls_service_profile": tls_profile[:64],
                    # The verdict beside the name it came from, computed here because this is
                    # the one place that holds both. `GlobalProtectPortal.clean` asserts they
                    # agree.
                    "tls_profile_binding_missing": not tls_profile,
                    "certificate_profile": (
                        certificate_profile[:64] if certificate_profile is not None else None),
                    "custom_login_page": login_page[:64],
                    "clientless_vpn_state": state,
                    "clientless_vpn_min_version": (
                        min_version[:16] if min_version is not None else None),
                    # TRUE ONLY ON A BRANCH THAT EXISTS AND NAMES A FLOOR. A portal with no
                    # branch has no floor to name, and PAN-GPP-006's applicability clause
                    # narrows those rows away through `clientless_vpn_state` instead.
                    "clientless_vpn_floor_known": (
                        state == CLIENTLESS_VPN_PRESENT and min_version is not None),
                    "clientless_vpn_max_version": (
                        max_version[:16] if max_version is not None else None),
                    "client_auth_row_count": len(auth_rows),
                    # An ABSENT list is not an EMPTY one and nobody has measured which, so the
                    # two are kept apart: None where the node does not exist, a list - possibly
                    # empty - where it does.
                    "agent_configurations": (
                        None if configs_state == "absent" else configs),
                    "upgrade_posture": _upgrade_posture(configs),
                    "saved_credentials_posture": _saved_credentials_posture(configs),
                },
                provenance=[
                    ("ssl_tls_service_profile", tls_rk, tls_rv),
                    ("certificate_profile", cert_rk, cert_rv),
                    ("custom_login_page", login_rk, login_rv),
                    ("clientless_vpn_min_version", min_rk, min_rv),
                    ("clientless_vpn_max_version", max_rk, max_rv),
                ],
                auth_rows=auth_rows,
                entry=entry,
            ))
    return portals


def _hip_client_version_criteria(vsys: dict[str, Any]) -> tuple[int, list[dict[str, str]]]:
    """(how many HIP objects test the client version, what each one matches).

    THE CRITERION IS A CHOICE OF EXACTLY ONE OPERATOR, ENFORCED BY REPLACEMENT RATHER THAN BY
    REFUSAL: writing a second operator onto a client-version that already had one was ACCEPTED
    and silently removed the first, with no refusal and no warning. So a consumer only ever sees
    one operator per criterion, and the three are the whole set - `contains`, `is`, `is-not`,
    every one a string match with no numeric comparison anywhere beneath them.

    The residue here runs THREE DEEP - a vsys may have no `profiles` node at all - which is why
    this reads through `entry_container` rather than indexing.
    """
    _state, entries = entry_container(vsys, "profiles", "hip-objects")
    criteria: list[dict[str, str]] = []
    count = 0
    for entry in entries:
        host_info = entry.get("host-info")
        criteria_node = host_info.get("criteria") if isinstance(host_info, dict) else None
        client_version = (criteria_node.get("client-version")
                          if isinstance(criteria_node, dict) else None)
        if not isinstance(client_version, dict):
            continue
        count += 1
        for operator in ("contains", "is", "is-not"):
            if operator in client_version:
                criteria.append({
                    "hip_object": str(entry.get("@name") or ""),
                    "operator": operator,
                    "value": str(client_version.get(operator) or ""),
                })
    return count, criteria


def _clientless_vpn_feature_state(publishing_portals: int, app_count: int,
                                  group_count: int) -> str:
    """How much of the Clientless VPN feature is present in one vsys.

    THE VERDICT SPANS THREE COLLECTIONS AT TWO XPATHS WITH A QUANTIFIER OVER EACH, and a
    predicate has no quantifier over related rows, no count and no arithmetic. What is graded is
    PRESENCE, so there is no acceptable RANK: the acceptable state is the absence of every rank
    below it.

    A PORTAL PUBLISHING WITH NO DEFINITION IN THE VSYS READS AS `live`, and the spec's three
    sentences do not cover that case - they give `live` as "a portal publishes applications and
    definitions exist". Decided here, with the direction of error `rules.md` fixes: the branch on
    an internet-facing portal IS the surface, and reading a configured feature as `absent`
    because no application is defined yet would report it compliant. Named in the handback.
    """
    if publishing_portals > 0:
        return FEATURE_LIVE
    if app_count > 0 or group_count > 0:
        return FEATURE_LATENT
    return FEATURE_ABSENT


def _licence_verdicts(appliance: Appliance) -> dict[str, Any]:
    """The four licence columns, from `request license info`.

    THE REPLY CANNOT TELL "HOLDS NOTHING" FROM "NOBODY ASKED", which is why the boolean exists:
    `{'licenses': None}` arrives with status=success and the container empty, so a consumer
    testing the reply's truthiness concludes licences are present on an appliance that has none.
    Measured 2026-10-29: ten entries on 691665AC334B458, three on 6A9C0A9904E7D6E and that empty
    envelope on both PA-5220s.

    `expired` IS READ AND DELIBERATELY NOT USED. `device_identification.py` requires
    `expired: no` for its own feature test, and copying that here would point the wrong way:
    an expired portal licence would make `licence_excludes_globalprotect` TRUE, which is the one
    value that SUPPRESSES PAN-GPP-006 - so an entitlement that lapsed last week would silence a
    control about a portal that is still configured and still serving. The spec's rule is
    presence of the feature NAME, and presence is what this reads. Every lab entry carries
    `expired: no`, so nothing in this estate exercises the difference.
    """
    snapshot = latest_license_info_snapshot(appliance)
    entries = _licence_entries(snapshot.payload) if snapshot is not None else None
    collected = entries is not None
    entries = entries or []
    if not collected or not entries:
        # An empty POPULATED list and a read nobody took are both "no answer yet", and neither
        # is a `no`: an absent feature name in a reply that enumerates only what IS installed is
        # not evidence the feature was refused.
        licensed = LICENSED_UNKNOWN
    else:
        names = {str(e.get("feature") or "").strip().lower() for e in entries}
        licensed = LICENSED_YES if GLOBALPROTECT_PORTAL_FEATURE in names else LICENSED_NO
    return {
        "licence_reply_collected": collected,
        "licence_entry_count": len(entries),
        "globalprotect_portal_licensed": licensed,
        # FALSE ON AN UNKNOWN, DELIBERATELY. This is the only value that suppresses the control,
        # and suppressing on a precondition nobody could answer is the applicability trap
        # `rules.md` names: it reads as careful and tells a customer they are safe on the
        # strength of nothing. `GlobalProtectEnforcementPoint.clean` asserts this shape.
        "licence_excludes_globalprotect": (
            collected and len(entries) > 0 and licensed == LICENSED_NO),
    }


def normalize_globalprotect(appliance: Appliance) -> dict[str, int]:
    """Every GlobalProtect row for one appliance: portals, their auth rows, the vsys verdicts.

    Appliance grain, because the merged read is one call for the whole device and is anchored to
    the appliance - the per-vsys loop is this function's. Returns counts, which is what
    `flows.py::APPLIANCE_OBJECT_NORMALIZERS` requires of a member: that loop wraps the result in
    `dict(counts or {})`, so a normalizer returning rows there fails every appliance and records
    it as a normalization failure rather than raising.
    """
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"globalprotect_portals": 0, "globalprotect_portal_client_auth_rows": 0,
                "globalprotect_enforcement_points": 0}

    portals = normalized_portals(snapshot)
    licence = _licence_verdicts(appliance)

    portal_rows = [
        (ScopedEntry(GlobalProtectPortal.SCOPE_VSYS, portal.vsys_name, portal.entry),
         portal.values, portal.provenance)
        for portal in portals
    ]
    written_portals = write_scoped_objects(GlobalProtectPortal, appliance, snapshot, portal_rows)

    # Resolve the saved portals once so each row can carry its foreign key. Keyed on the
    # identity the constraint uses rather than on the primary key, because the write above may
    # have updated a row that already existed.
    by_key = {(saved.vsys_name, saved.name): saved
              for saved in GlobalProtectPortal.objects.filter(appliance=appliance)}

    auth_row_rows = []
    for portal in portals:
        parent = by_key.get((portal.vsys_name, portal.name))
        for row in portal.auth_rows:
            values = dict(row.values)
            values["portal"] = parent
            auth_row_rows.append((
                ScopedEntry(GlobalProtectPortalClientAuthRow.SCOPE_VSYS,
                            portal.vsys_name, row.entry),
                values, row.provenance))
    written_rows = write_scoped_objects(
        GlobalProtectPortalClientAuthRow, appliance, snapshot, auth_row_rows,
        identity=("name", "portal_name"))

    publishing_by_vsys: dict[str, int] = {}
    for portal in portals:
        if portal.values["clientless_vpn_state"] == CLIENTLESS_VPN_PRESENT:
            publishing_by_vsys[portal.vsys_name] = publishing_by_vsys.get(
                portal.vsys_name, 0) + 1

    seen_points: list[int] = []
    with transaction.atomic():
        for vsys_name, vsys in _vsys_entries(snapshot):
            _portal_state, portal_entries = entry_container(
                vsys, "global-protect", "global-protect-portal")
            _app_state, app_entries = entry_container(
                vsys, "global-protect", "clientless-app")
            _group_state, group_entries = entry_container(
                vsys, "global-protect", "clientless-app-group")
            hip_count, hip_criteria = _hip_client_version_criteria(vsys)
            publishing = publishing_by_vsys.get(vsys_name, 0)
            row = write_node_row(
                GlobalProtectEnforcementPoint, appliance, snapshot,
                {
                    "portal_count": len(portal_entries),
                    "clientless_app_count": len(app_entries),
                    "clientless_app_group_count": len(group_entries),
                    "portals_publishing_clientless_apps": publishing,
                    "hip_objects_testing_client_version": hip_count,
                    "hip_client_version_criteria": hip_criteria or None,
                    "clientless_vpn_feature_state": _clientless_vpn_feature_state(
                        publishing, len(app_entries), len(group_entries)),
                    **licence,
                },
                # No provenance rows: every column on this model is computed, which is what
                # `DERIVED_FIELDS` declares and what `write_node_row`'s empty `provenance`
                # expresses.
                provenance=(),
                lookup={"appliance": appliance,
                        "scope": GlobalProtectEnforcementPoint.SCOPE_VSYS,
                        "vsys_name": vsys_name},
            )
            seen_points.append(row.pk)
        # A vsys removed from the device leaves a stale verdict row, and a stale one is a false
        # finding on this domain in both directions - it reports counts for configuration that
        # is gone.
        GlobalProtectEnforcementPoint.objects.filter(appliance=appliance).exclude(
            pk__in=seen_points).delete()

    return {
        "globalprotect_portals": written_portals,
        "globalprotect_portal_client_auth_rows": written_rows,
        "globalprotect_enforcement_points": len(seen_points),
    }
