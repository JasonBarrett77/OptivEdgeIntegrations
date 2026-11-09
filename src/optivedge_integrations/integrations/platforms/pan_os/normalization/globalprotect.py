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
`::_licence_entries` for the license reply - which another domain's stage 7 run collected and
normalized earlier today, so this domain's third read was already issued when its spec was
written.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    AuthenticationProfile,
    CertificateProfile,
    GlobalProtectEnforcementPoint,
    GlobalProtectGateway,
    GlobalProtectGatewayAgentConfig,
    GlobalProtectGatewayClientAuth,
    GlobalProtectPortal,
    GlobalProtectPortalClientAuthRow,
    Snapshot,
    SslTlsServiceProfile,
)
from optivedge_integrations.integrations.models.base import ApplianceScopedObject
from optivedge_integrations.integrations.models.globalprotect import (
    ADMISSION_PASSWORD_AND_CERTIFICATE,
    APP_CRYPTO_PREFERRED_FIRST_ENCRYPTION,
    ADMISSION_PASSWORD_ONLY,
    ADMISSION_PASSWORD_OR_CERTIFICATE,
    ADMISSION_UNKNOWN,
    CLIENTLESS_VPN_ABSENT,
    CLIENTLESS_VPN_PRESENT,
    CLIENTLESS_VPN_UNKNOWN,
    COOKIE_LIFETIME_BRANCHES,
    COOKIE_LIFETIME_HOURS_PER_UNIT,
    FEATURE_ABSENT,
    FEATURE_LATENT,
    FEATURE_LIVE,
    GLOBALPROTECT_GATEWAY_FEATURE,
    LICENSED_NO,
    LICENSED_UNKNOWN,
    LICENSED_YES,
    LOGIN_LIFETIME_BRANCHES,
    LOGIN_LIFETIME_HOURS_PER_UNIT,
    POSTURE_NO_AGENT_CONFIGURATION,
    POSTURE_NOT_SET,
    POSTURE_SEVERAL_MEMBERS,
    SECOND_FACTOR_CAPABLE_BACKENDS,
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
    choice_child,
    ensure_list,
    entry_container,
    merged_shared,
    parse_text_field,
    parse_yes_no_field,
    scalar_value,
    was_absent,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_identification import (
    HIP_KEYWORDS,
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
    list legible and a typo recognizable. A `{}` here means a column cannot be LABELED, not
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
    `decryption.py` each carry their own four-line version; the judgment
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
    that must NOT match an unread row: a NULL satisfies no comparison, which is the behavior
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
    """The four license columns, from `request license info`.

    THE REPLY CANNOT TELL "HOLDS NOTHING" FROM "NOBODY ASKED", which is why the boolean exists:
    `{'licenses': None}` arrives with status=success and the container empty, so a consumer
    testing the reply's truthiness concludes licenses are present on an appliance that has none.
    Measured 2026-10-29: ten entries on 691665AC334B458, three on 6A9C0A9904E7D6E and that empty
    envelope on both PA-5220s.

    `expired` IS READ AND DELIBERATELY NOT USED. `device_identification.py` requires
    `expired: no` for its own feature test, and copying that here would point the wrong way:
    an expired portal license would make `licence_excludes_globalprotect` TRUE, which is the one
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


# ===========================================================================
# The `globalprotect-gateway` domain. PAN-GPG-001 to PAN-GPG-007.
#
# NO COLLECTOR IS ADDED HERE EITHER, and the spec expected two plus an operational read.
# MEASURED 2026-10-30 through Panorama's `target=` proxy on all four lab appliances, read-only:
# `show config merged` carries BOTH halves of a gateway and every collection this domain counts.
#
#     result.config.devices.entry[0].vsys.entry[N].global-protect.global-protect-gateway
#     result.config.devices.entry[0].network.tunnel.global-protect-gateway
#     result.config.devices.entry[0].network.ike.crypto-profiles.global-protect-app-crypto-profiles
#     result.config.devices.entry[0].vsys.entry[N].profiles.hip-objects / hip-profiles
#     result.config.devices.entry[0].vsys.entry[N].rulebase.security.rules
#     result.config.shared.log-settings.hipmatch
#
# and the licence reply is `collect_request_license_info`, which another domain's stage 7 run
# already issues. So the `issued_today: false` on all four of this domain's reads is the same
# false negative the portal run recorded above, from the same grep of the collector modules: the
# generic whole-tree reads do not name the nodes they carry.
#
# WHAT THE MERGED VIEW COSTS, and the gateway is the worst-placed node in this estate for it:
# merged follows the CANDIDATE and carries no `@dirtyId` markers at all, while the one read that
# says ABSENT out loud is `action=show`. An uncommitted staged edit was sitting on
# 691665AC334B458 at `deviceconfig/system/device-telemetry` while this ran. Every absence this
# module reports was therefore cross-read with `action=show` per node before the readback, and
# the two views agreed on every gateway node on every appliance.
# ===========================================================================


@dataclass(slots=True)
class GatewayBindings:
    """What a gateway's name bindings resolve to, for ONE vsys of one appliance.

    THE RESOLUTION IS THE WORK AND IT IS NOT A JOIN THE QUERY LAYER CAN MAKE: a clause compares
    one field to one literal, with no second field slot and no edge the model does not define.
    Five of the gateway's columns are a property of the thing a NAME reaches, so following the
    name is normalization's job or it is nobody's.

    Passed in rather than looked up inside the parse, for the reason `normalized_portals` is
    pure: a test and a stage 7 readback can both build these three maps directly and assert over
    the result without a database, and `_bindings_for` below is the one place that reads rows.

    EACH MAP'S PRECEDENCE IS THAT OBJECT TYPE'S OWN and they are not interchangeable:

      ssl_tls           predefined, then shared, then vsys. Higher scope wins WHOLE on this
                        object type - a predefined definition BEATS a same-named writable entry
                        outright rather than extending it, which is the opposite of what the
                        policy side assumes. An order copied from another object type resolves
                        to a definition that is not in force.
      certificate       shared, then vsys. Only the shared position was exercised on a device;
                        a vsys position exists and nothing says which wins when one name sits at
                        both, so the measured one is taken as stronger and the choice is
                        recorded rather than hidden.
      authentication    vsys, then shared. Nothing exercised one name at two scopes, which is
                        the only case precedence decides.
      app_crypto        device-local only - there is no other position for it.
    """

    ssl_tls: dict[str, Any] = field(default_factory=dict)
    certificate: dict[str, Any] = field(default_factory=dict)
    authentication: dict[str, Any] = field(default_factory=dict)
    app_crypto: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedGateway:
    """One gateway before persistence, with the two child collections beneath it."""

    vsys_name: str
    name: str
    values: dict[str, Any]
    provenance: list[tuple[str, Any, str | None]]
    client_auth_rows: list["NormalizedGatewayClientAuth"] = field(default_factory=list)
    agent_configs: list["NormalizedGatewayAgentConfig"] = field(default_factory=list)
    entry: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedGatewayClientAuth:
    """One client-authentication row of one gateway, before persistence."""

    name: str
    values: dict[str, Any]
    provenance: list[tuple[str, Any, str | None]]
    entry: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedGatewayAgentConfig:
    """One agent client-settings row of one gateway, before persistence."""

    name: str
    values: dict[str, Any]
    provenance: list[tuple[str, Any, str | None]]
    entry: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedPosture:
    """One vsys's host-posture verdict, before it is merged onto the enforcement point."""

    vsys_name: str
    values: dict[str, Any]


#: Mandatory on a committed gateway, so an absent key is a statement about the READ and never
#: about the device. Measured by stage 4 at `validate full` job 259, which named both in one
#: refusal: "global-protect-gateway -> <name> is missing ssl-tls-service-profile" and
#: "... is missing tunnel-mode".
GATEWAY_MANDATORY_AT_COMMIT = Implicit.not_assumed(
    "mandatory on a committed GlobalProtect gateway, measured at `validate full` job 259, which "
    "named the two keys in one refusal - so an absent key here is evidence about the read rather "
    "than a device state, and the failing state a query looks for is a stored value")

#: OPTIONAL on a committed gateway and the absent meaning UNMEASURED. Three of this domain's
#: switches share this declaration and the reason is one: a feature switch a reader turns ON
#: suggests absent means `no`, and the SIBLING PAIR on this very object type points opposite
#: ways - stage 4 measured `log-success` rendering UNTICKED on a bare gateway and `log-fail`
#: TICKED. Polarity here is not uniform, so a wrong number would be worse than no number.
GATEWAY_SWITCH_UNMEASURED = Implicit.not_assumed(
    "optional on a committed GlobalProtect gateway and its absent meaning unmeasured - the "
    "sibling yes/no pair on this same object type renders one ticked and one unticked on a bare "
    "gateway, so the polarity of an absence is not uniform and materialising either candidate "
    "would store a reading nobody took")

#: OPTIONAL and unmeasured on the two reference leaves of the networking half. An absent
#: reference ORDINARILY asserts that nothing is bound; on the crypto profile it may instead mean
#: the gateway falls back to the shipped profile the vendor also calls `default`, and which of
#: the two was not measured. The two are different postures and the shipped one stores exactly
#: the single algorithm PAN-GPG-006 argues against.
GATEWAY_REFERENCE_UNMEASURED = Implicit.not_assumed(
    "optional on a committed GlobalProtect gateway and its absent meaning unmeasured - an absent "
    "reference ordinarily asserts that nothing is bound, and on the crypto leaf it may instead "
    "mean the shipped profile of the same name applies, which was not measured")

#: MEASURED, and the one implicit in this whole domain that can be declared as such: an absent
#: `cookie-encrypt-decrypt-cert` asserts that NOTHING is bound. Settled by config silence in
#: candidate and running on an entry built to carry no child key at all - legal, because this
#: entry has no mandatory key - with the positive control paid on the REFERENCE POOL, which is
#: the control available for a reference field: completion at the leaf returns the appliance's
#: certificate collection, so the leaf is a live reference and not an inert string.
#:
#: A NULL HERE IS A READING AND NOT A GAP, and a consumer must not render it as "not collected".
COOKIE_CERT_ABSENT_MEANS_NOTHING_BOUND = Implicit.measured(
    None,
    "stage4-globalprotect-gateway.json objects['globalprotect-gateway-tunnel-config'].fields"
    "['authentication-override/cookie-encrypt-decrypt-cert'].implicit - measured 2026-10-26 on a "
    "PA-VM at 11.2.5, single-vsys, vsys1: config silence in candidate and running on an entry "
    "carrying no child key, with the positive control paid on the reference pool")

#: An absent member list is NOT an empty one and stage 4 did not measure which. What it did
#: measure is the consequence: an absent list means nothing is excluded on that axis. Kept apart
#: in the store - None where the node does not exist, a list where it does - because the egress
#: count has to treat them the same and a reader must still be able to see the difference.
SPLIT_TUNNEL_LIST_UNMEASURED = Implicit.not_assumed(
    "an absent member list is not an empty one and which it is was not measured; what was "
    "measured is that an absent list excludes nothing on that axis, which is what the egress "
    "count reads")


def _member_list(node: Any) -> list[str] | None:
    """A PAN-OS `member` list as a list of strings, or None where the node is ABSENT.

    THE THREE STATES AGAIN, and `ensure_list` alone collapses two of them: absent, present and
    empty, and populated. `common.py::iter_member_values` is the reader for a member model that
    stores one row per member with its own provenance; this domain stores the list itself for a
    reader, so it needs the list and the absence apart.
    """
    if node is None:
        return None
    if isinstance(node, dict):
        members = [str(m).strip() for m in ensure_list(node.get("member")) if m is not None]
        return [m for m in members if m]
    return [str(node).strip()] if str(node).strip() else []


def _domain_entries(node: Any) -> list[dict[str, Any]] | None:
    """A split-tunnel domain collection, or None where the node is absent.

    NOT A MEMBER LIST, unlike its four siblings: the shape is `list/entry[@name]` where the
    entry NAME is a domain and carries an optional `ports` key. A reader written for a member
    list loses every port restriction and one written for a scalar loses the whole thing, so the
    entries are stored as they arrive.
    """
    if node is None:
        return None
    state, entries = entry_container(node, "list")
    if state == "absent":
        # The container exists and holds no `list` child - a real present-and-empty state.
        return []
    return [
        {"domain": str(e.get("@name") or ""),
         "ports": _member_list(e.get("ports")) or []}
        for e in entries if str(e.get("@name") or "")
    ]


def _lifetime(container: Any, branches: tuple[str, ...],
              hours_per_unit: dict[str, float]) -> tuple[str, int | None, int | None]:
    """(which unit branch exists, the integer in it, that integer in HOURS).

    ONE VALUE IN THREE KEYS, AND EXACTLY ONE KEY EVER EXISTS: writing a second branch REPLACES
    the first rather than adding to it, measured on four appliances across two models and three
    PAN-OS builds. A normalizer storing three nullable columns and summing them is wrong in a
    way nothing will catch, and a clause on any single branch reads ABSENT on a row configured
    in another unit.

    `common.py::choice_child` is the reader - the unit is WHICH CHILD ELEMENT EXISTS and not a
    value, so there is nothing for a text parser to find. It returns ("", {}) for an absent
    container, which this converts to ("", None, None): the companion boolean beside the hours
    column is what reports that, because a null satisfies no comparison.

    THE CONVERSION IS WHAT MAKES THE GRADING REACHABLE. On the cookie lifetime the asserted
    hours leaf caps at 72, so no value of it produces the top severity band, while a lifetime
    set in days reaches 365; rounding is UP, so a 90-minute cookie grades as 2 hours rather than
    as 1 and the boundary is never crossed in the reassuring direction.
    """
    unit, _child = choice_child(container, branches)
    if not unit:
        return "", None, None
    raw = container.get(unit) if isinstance(container, dict) else None
    value, _raw_key, _raw_prov = scalar_value(raw)
    try:
        entered = int(value)
    except (TypeError, ValueError):
        return unit, None, None
    hours = hours_per_unit[unit] * entered
    # Ceiling, not rounding: a limit is only acceptable if it is acceptable at its worst
    # reading, and int() would move a 90-minute cookie from 2 hours to 1.
    whole_hours = int(hours) if float(hours).is_integer() else int(hours) + 1
    return unit, entered, whole_hours


def _networking_halves(snapshot: Snapshot) -> dict[str, dict[str, Any]]:
    """{gateway name: its device-local networking entry}, for the whole appliance.

    A DEVICE-WIDE READ THAT CANNOT SAY WHICH VSYS A GATEWAY BELONGS TO, so the join runs the
    other way: the vsys half is enumerated and each entry looks its own name up here. Measured
    on this estate: three of four appliances carry `network/tunnel/global-protect-gateway`
    PRESENT AND EMPTY and the fourth has no `network/tunnel` node at all, which `entry_container`
    reports as the same `absent`/`empty` pair of states and which this function therefore
    returns as the same empty map - the one thing a reader of this node must not do is report
    two different things about one estate.
    """
    device_entry = device_entry_from_snapshot(snapshot)
    network = device_entry.get("network")
    _state, entries = entry_container(network, "tunnel", "global-protect-gateway")
    return {str(e.get("@name") or ""): e for e in entries if str(e.get("@name") or "")}


def _app_crypto_profiles(snapshot: Snapshot) -> dict[str, list[str]]:
    """{profile name: its ENCRYPTION proposal list, in document order}.

    `network/ike/crypto-profiles/global-protect-app-crypto-profiles`, and the collection name is
    the whole point: the SITE-TO-SITE `ipsec-crypto-profiles` collection sits beside it and holds
    a same-named `default` that is a DIFFERENT OBJECT. Wave 5 measured `action=complete` at the
    gateway's own crypto leaf returning this collection's names and the satellite leaf returning
    the other's, and `models/ipsec.py` carries the note. Resolving a gateway's binding against
    `IpsecCryptoProfile` would resolve to a profile that is not in force.

    THE ORDER IS PRESERVED AND MUST BE: the vendor states the firewall applies the proposals in
    the order they are listed, so the head of the list is the algorithm most endpoints will
    negotiate. Nothing here sorts.
    """
    device_entry = device_entry_from_snapshot(snapshot)
    crypto = ((device_entry.get("network") or {}).get("ike")
              if isinstance(device_entry.get("network"), dict) else None)
    _state, entries = entry_container(crypto, "crypto-profiles",
                                      "global-protect-app-crypto-profiles")
    out: dict[str, list[str]] = {}
    for entry in entries:
        name = str(entry.get("@name") or "").strip()
        if name:
            out[name] = _member_list(entry.get("encryption")) or []
    return out


def _hipmatch_quarantine_present(snapshot: Snapshot) -> bool:
    """Does any shared HIP Match log setting carry the built-in `quarantine` action?

    THE ONLY NODE IN THE CONFIGURATION THAT AUTOMATES QUARANTINE WITHOUT A SECURITY RULE. The
    vendor's own words for it: "Unlike a log forwarding profile, you do not need to attach this
    log setting to a security policy for it to take effect." The other documented route - a log
    forwarding profile's built-in Quarantine action - must be attached to a rule, so an appliance
    quarantining that way reads as having no automation here. Stated rather than hidden.

    THE CONTENT IS READ HERE AND NOT FROM `log_settings.py`, which already iterates `hipmatch`
    among its log kinds: that module's own model stores the match lists as display JSON and its
    docstring records that "actions and quarantine are reachable by nothing". A finding must rest
    on a column rather than on a key inside a blob, and `log_settings.py` is being changed by
    another run in this wave - so the column lives on this domain's own model and reads the node
    itself. Recorded in the handback as a near-duplicate a person should reconcile.

    `action/quarantine` is the shape the node uses for a built-in action; `send-*` siblings are
    destinations and say nothing about quarantine.
    """
    payload = snapshot.payload if isinstance(snapshot.payload, dict) else {}
    shared = merged_shared(payload)
    _state, entries = entry_container(shared, "log-settings", "hipmatch", "match-list")
    for entry in entries:
        actions = entry.get("actions")
        if isinstance(actions, dict) and "quarantine" in actions:
            return True
        # The singular spelling, which the CLI grammar also carries at this position.
        action = entry.get("action")
        if isinstance(action, dict) and "quarantine" in action:
            return True
    return False


def _hip_profile_names(vsys: dict[str, Any]) -> set[str]:
    """The `@name` of every HIP profile defined in one vsys.

    VSYS SCOPE ONLY. A shared `profiles/hip-profiles` position exists in the schema and nothing
    on this estate exercises it, so nothing says which wins when one name sits at both. Reading
    the vsys alone means a rule naming a shared profile resolves to nothing and the posture
    verdict reports FALSE - the firing side, which is the safe direction, and it is recorded
    rather than left to be discovered.
    """
    _state, entries = entry_container(vsys, "profiles", "hip-profiles")
    return {str(e.get("@name") or "").strip()
            for e in entries if str(e.get("@name") or "").strip()}


def _rules_matching_a_hip_profile(vsys: dict[str, Any], profile_names: set[str]) -> int:
    """How many LOCAL security rules of one vsys name a HIP profile of that vsys.

    NOT `rule_device_match_counts`, AND THE REASON IS ORDERING RATHER THAN SHAPE.
    `normalization/device_identification.py::rule_device_match_counts` walks exactly this
    element over the STORED `SecurityRule` rows and resolves each member against the
    device-object namespace; its own docstring names PAN-GPG-005 as the control that lands in the
    same element for host posture. It could not be reused: it is called from an
    ENFORCEMENT-POINT normalizer that `flows.py` runs AFTER the security-rule loop, while this
    domain's normalizer is appliance-grained and runs in `APPLIANCE_OBJECT_NORMALIZERS`, which
    `flows.py` runs BEFORE any rule row is written. Reusing it here would read the PREVIOUS
    collection's rules, silently, and a count over stale rules is a finding against an estate
    that has already changed.

    So the members are read from the merged payload, which is the read stage 5 declared for this
    column anyway. `HIP_KEYWORDS` IS IMPORTED RATHER THAN RESTATED: `any`, `no-hip` and
    `quarantine` are keywords measured at the write path, never references, and `any` is the
    commonest member in this estate and constrains nothing - a count of populated member lists
    would report the whole lab as matching on posture.

    LOCAL RULEBASE ONLY. The pushed pre- and post-rulebases arrive through the pushed-policy
    reads and are not at this xpath, so this under-reports on exactly the devices a customer
    manages centrally; `source-hip` also exists on the authentication, decryption, QoS and
    network-packet-broker rulebases and only the security one is read. Both omissions land on
    the firing side of the verdict.
    """
    if not profile_names:
        return 0
    _state, rules = entry_container(vsys, "rulebase", "security", "rules")
    matching = 0
    for rule in rules:
        members = set()
        for key in ("source-hip", "destination-hip"):
            members.update(_member_list(rule.get(key)) or [])
        resolved = {m for m in members
                    if m and m.lower() not in HIP_KEYWORDS and m in profile_names}
        if resolved:
            matching += 1
    return matching


def normalized_posture(snapshot: Snapshot) -> list[NormalizedPosture]:
    """The host-posture verdict for every vsys of one appliance's merged payload. PAN-GPG-005.

    Pure: takes a snapshot, touches no model and writes nothing, so a test and a stage 7
    readback can both assert over the result without a database - the same split
    `normalized_portals` above carries and for the same reason.

    ONE ROW PER VSYS AND NEVER ONE PER OBJECT, because the commonest failing state is that NONE
    of the four things exists: at the entry grain there would be no row to report "posture
    decides nothing on this enforcement point" with, which is the sentence an engineer acts on.

    The quarantine reading is DEVICE-WIDE and replicated onto every vsys row of the appliance -
    the node is `/config/shared/log-settings/hipmatch`, so one appliance-level cause reports
    nine times on a PA-5220 here. Stated rather than hidden; there is no device-local scope in
    the store to report it at instead.
    """
    quarantine = _hipmatch_quarantine_present(snapshot)
    out: list[NormalizedPosture] = []
    for vsys_name, vsys in _vsys_entries(snapshot):
        _object_state, hip_objects = entry_container(vsys, "profiles", "hip-objects")
        profile_names = _hip_profile_names(vsys)
        rules = _rules_matching_a_hip_profile(vsys, profile_names)
        out.append(NormalizedPosture(
            vsys_name=vsys_name,
            values={
                "hip_object_count": len(hip_objects),
                "hip_profile_count": len(profile_names),
                "rules_referencing_a_hip_profile_count": rules,
                # END TO END OR NOTHING. Posture that is collected and never referenced gives a
                # non-compliant endpoint exactly the access a compliant one gets, and a profile
                # with no object behind it matches nothing - so the verdict is the conjunction
                # and not any one of the three. `GlobalProtectEnforcementPoint.clean` asserts it.
                "posture_referenced_in_policy": (
                    len(hip_objects) > 0 and len(profile_names) > 0 and rules > 0),
                "automatic_quarantine_action_present": quarantine,
            },
        ))
    return out


def _gateway_client_auth_rows(entry: dict[str, Any], gateway_name: str,
                              bindings: GatewayBindings) -> list[NormalizedGatewayClientAuth]:
    """Every row of one gateway's client-authentication table. PAN-GPG-002.

    THE LEAF ACCEPTS A PROFILE OR A SEQUENCE and the stored string does not say which, so a row
    naming a SEQUENCE resolves to nothing here and `authentication_backend_method` is empty - the
    state a sequence-backed gateway is in, and the one an unresolved back end reported as
    compliant would pass. `backend_can_deliver_a_second_factor` is false on it, which fires.
    """
    _state, entries = entry_container(entry, "client-auth")
    rows: list[NormalizedGatewayClientAuth] = []
    for row in entries:
        name = str(row.get("@name") or "").strip()
        if not name:
            continue
        os_value, os_rk, os_rv = parse_text_field(
            row.get("os"), implicit=GATEWAY_MANDATORY_AT_COMMIT)
        profile, profile_rk, profile_rv = parse_text_field(
            row.get("authentication-profile"), implicit=GATEWAY_MANDATORY_AT_COMMIT)
        switch, switch_rk, switch_rv = parse_yes_no_field(
            row.get("user-credential-or-client-cert-required"),
            implicit=GATEWAY_SWITCH_UNMEASURED)
        resolved = bindings.authentication.get(profile)
        # The element NAME under the profile's `method`, which is how the device models the
        # choice - `AuthenticationProfile.method` already stores it that way, and an empty
        # method on the device is {'none': None}, so a blank method and the child named `none`
        # are different wire states that both arrive here as a string.
        backend = str(getattr(resolved, "method", "") or "")[:16]
        rows.append(NormalizedGatewayClientAuth(
            name=name,
            values={
                "name": name,
                "gateway_name": gateway_name,
                "client_os": os_value[:16],
                "authentication_profile_name": profile[:64],
                "user_credential_or_client_cert_required": switch,
                "authentication_backend_method": backend,
                "backend_can_deliver_a_second_factor": (
                    backend in SECOND_FACTOR_CAPABLE_BACKENDS),
            },
            provenance=[
                ("client_os", os_rk, os_rv),
                ("authentication_profile_name", profile_rk, profile_rv),
                ("user_credential_or_client_cert_required", switch_rk, switch_rv),
            ],
            entry=row,
        ))
    return rows


def _gateway_agent_configs(entry: dict[str, Any], gateway_name: str,
                           video_traffic_excluded: bool | None,
                           ) -> list[NormalizedGatewayAgentConfig]:
    """Every agent client-settings row of one gateway. PAN-GPG-003, PAN-GPG-004.

    THE EIGHTH EGRESS AXIS IS ON THE GATEWAY AND NOT ON THIS ROW, which is why
    `video_traffic_excluded` is a parameter: `client/exclude-video-traffic/enabled` sits on the
    device-local networking half, so an exclusion inventory built on this collection alone
    returns zero on a gateway that excludes all video streaming.

    THE COUNT COUNTS A NULL LOCAL-NETWORK SWITCH AS OPEN. `no-direct-access-to-local-network`
    reads as null where the key is absent, and the key's name is the negation of what it
    permits, so an absence most likely leaves direct access allowed - the weaker state. Counting
    the null as a path is the firing direction, which is what that column's own `fires` reading
    requires; counting it as closed would read an unread row as a full tunnel.

    AN INCLUDE LIST OF EXACTLY `any` IS NOT NARROWER THAN EVERYTHING and is not counted. The
    literal `any` is an accepted member, measured at the write and stored verbatim, and a list
    holding only it routes everything into the tunnel. Decided here because stage 5 names the
    axis as "an include list that is narrower than everything" without saying what `any` does to
    it; the direction of error is that a gateway including only `any` is reported as a full
    tunnel, which is what it is.
    """
    _state, entries = entry_container(entry, "remote-user-tunnel-configs")
    rows: list[NormalizedGatewayAgentConfig] = []
    for row in entries:
        name = str(row.get("@name") or "").strip()
        if not name:
            continue
        override = row.get("authentication-override")
        override = override if isinstance(override, dict) else {}
        accept = override.get("accept-cookie")
        accept = accept if isinstance(accept, dict) else {}

        generate, generate_rk, generate_rv = parse_yes_no_field(
            override.get("generate-cookie"), implicit=GATEWAY_SWITCH_UNMEASURED)
        cookie_cert, cert_rk, cert_rv = parse_text_field(
            override.get("cookie-encrypt-decrypt-cert"),
            implicit=COOKIE_CERT_ABSENT_MEANS_NOTHING_BOUND)
        local_closed, local_rk, local_rv = parse_yes_no_field(
            row.get("no-direct-access-to-local-network"),
            implicit=GATEWAY_SWITCH_UNMEASURED)

        unit, entered, hours = _lifetime(
            accept.get("cookie-lifetime"), COOKIE_LIFETIME_BRANCHES,
            COOKIE_LIFETIME_HOURS_PER_UNIT)

        split = row.get("split-tunneling")
        split = split if isinstance(split, dict) else {}
        exclude_routes = _member_list(split.get("exclude-access-route"))
        include_routes = _member_list(split.get("access-route"))
        exclude_apps = _member_list(split.get("exclude-applications"))
        include_apps = _member_list(split.get("include-applications"))
        exclude_domains = _domain_entries(split.get("exclude-domains"))
        include_domains = _domain_entries(split.get("include-domains"))

        def _narrower_than_everything(members: list[str] | None) -> bool:
            if not members:
                return False
            return {m.lower() for m in members} != {"any"}

        axes = [
            bool(exclude_routes),
            _narrower_than_everything(include_routes),
            bool(exclude_apps),
            _narrower_than_everything(include_apps),
            bool(exclude_domains),
            bool(include_domains),
            local_closed is not True,
            video_traffic_excluded is True,
        ]

        rows.append(NormalizedGatewayAgentConfig(
            name=name,
            values={
                "name": name,
                "gateway_name": gateway_name,
                "generate_cookie": generate,
                # PRESENCE OF A CONTAINER AND NOT TRUTHINESS. A committed empty container parses
                # to None and a staged one to a dict of @admin/@dirtyId/@time, so `if node:`
                # gives opposite wrong answers from one test - the key test is the only one that
                # answers the question asked.
                "accept_cookie_configured": "accept-cookie" in override,
                "authentication_override_configured": "authentication-override" in row,
                # NOT SLICED. The column is 24 characters for the reason the model's own
                # comment gives: stage 5 declared 16, and two of the three values it declared
                # for this column are longer than that.
                "cookie_lifetime_unit": unit,
                "cookie_lifetime_as_entered": entered,
                "cookie_lifetime_hours": hours,
                "cookie_lifetime_known": hours is not None,
                "cookie_encrypt_decrypt_cert": cookie_cert or None,
                "no_direct_access_to_local_network": local_closed,
                "split_tunnel_exclude_access_routes": exclude_routes,
                "split_tunnel_include_access_routes": include_routes,
                "split_tunnel_exclude_applications": exclude_apps,
                "split_tunnel_include_applications": include_apps,
                "split_tunnel_exclude_domains": exclude_domains,
                "split_tunnel_include_domains": include_domains,
                "uninspected_egress_path_count": sum(1 for axis in axes if axis),
                # TRUE ON EVERY ROW THIS FUNCTION PRODUCES, and that is the whole point: the
                # count's own empty value is zero, which is indistinguishable from a correctly
                # configured full tunnel, so the only thing that can separate "we counted and
                # found none" from "nobody counted" is a column saying the pass ran.
                "egress_inventory_computed": True,
            },
            provenance=[
                ("generate_cookie", generate_rk, generate_rv),
                ("cookie_encrypt_decrypt_cert", cert_rk, cert_rv),
                ("no_direct_access_to_local_network", local_rk, local_rv),
            ],
            entry=row,
        ))
    return rows


def normalized_gateways(snapshot: Snapshot,
                        bindings_for) -> list[NormalizedGateway]:
    """Every GlobalProtect gateway of every vsys in one appliance's merged payload.

    Pure: takes a snapshot and a callable, touches no model and writes nothing, so a test and a
    stage 7 readback can both assert over the result without a database. `bindings_for` is
    `(vsys_name) -> GatewayBindings`; `_bindings_for` below is the one implementation that reads
    rows, and a test passes a lambda over three literal maps.

    THE TWO SUBTREES ARE JOINED ON THE ENTRY NAME and on nothing else. Stage 4 measured it:
    commit job 260 aborted at phase 1 naming the VSYS ENTRY'S OWN NAME as the thing it could not
    find in the network level, which contradicts the `remote-user-tunnel` leaf stage 2 had named
    as the only candidate - and completion at `remote-user-tunnel` returned no completions with
    a networking entry present, so that leaf is a separate reference whose target is most likely
    a tunnel interface unit. A normalizer joining on anything but the name joins them wrong.
    """
    halves = _networking_halves(snapshot)
    app_crypto = _app_crypto_profiles(snapshot)
    quarantine = _hipmatch_quarantine_present(snapshot)
    gateways: list[NormalizedGateway] = []

    for vsys_name, vsys in _vsys_entries(snapshot):
        bindings = bindings_for(vsys_name)
        bindings.app_crypto = app_crypto
        _state, entries = entry_container(vsys, "global-protect", "global-protect-gateway")
        for entry in entries:
            name = str(entry.get("@name") or "").strip()
            if not name:
                continue
            half = halves.get(name)
            networking_half_present = half is not None
            half = half if isinstance(half, dict) else {}

            tls_name, tls_rk, tls_rv = parse_text_field(
                entry.get("ssl-tls-service-profile"), implicit=GATEWAY_MANDATORY_AT_COMMIT)
            tunnel_mode, tunnel_rk, tunnel_rv = parse_yes_no_field(
                entry.get("tunnel-mode"), implicit=GATEWAY_MANDATORY_AT_COMMIT)
            cert_name, cert_rk, cert_rv = _text_or_null(
                entry.get("certificate-profile"), implicit=GATEWAY_REFERENCE_UNMEASURED)
            blocked, blocked_rk, blocked_rv = parse_yes_no_field(
                entry.get("block-quarantined-devices"), implicit=GATEWAY_SWITCH_UNMEASURED)

            ipsec = half.get("ipsec")
            ipsec = ipsec if isinstance(ipsec, dict) else {}
            ipsec_enabled, ipsec_rk, ipsec_rv = parse_yes_no_field(
                ipsec.get("enable"), implicit=GATEWAY_SWITCH_UNMEASURED)
            crypto_name, crypto_rk, crypto_rv = _text_or_null(
                ipsec.get("ipsec-crypto-profile"), implicit=GATEWAY_REFERENCE_UNMEASURED)
            client = half.get("client")
            client = client if isinstance(client, dict) else {}
            video = client.get("exclude-video-traffic")
            video = video if isinstance(video, dict) else {}
            video_excluded, video_rk, video_rv = parse_yes_no_field(
                video.get("enabled"), implicit=GATEWAY_SWITCH_UNMEASURED)

            # --- the four name resolutions, each onto another object's definition
            tls_profile = bindings.ssl_tls.get(tls_name)
            bound_min_version = str(getattr(tls_profile, "min_version", "") or "")[:16]
            explicit_floor = bool(
                tls_profile is not None
                and getattr(tls_profile, "has_explicit_protocol_settings", False))
            certificate_profile = bindings.certificate.get(cert_name or "")
            blocks_unauthenticated = bool(
                certificate_profile is not None
                and getattr(certificate_profile, "block_unauthenticated_cert", False))
            proposals = bindings.app_crypto.get(crypto_name or "") or []
            first_encryption = (proposals[0] if proposals else "")[:32]

            # --- the role entries, which hold the two session bounds
            _roles_state, roles = entry_container(entry, "roles")
            login_unit, login_entered, login_hours = "", None, None
            inactivity: int | None = None
            for role in roles:
                unit, entered, hours = _lifetime(
                    role.get("login-lifetime"), LOGIN_LIFETIME_BRANCHES,
                    LOGIN_LIFETIME_HOURS_PER_UNIT)
                # THE WEAKEST BOUND ACROSS THE ROLES, not the first and not the strictest: a
                # gateway whose weakest role leaves a session up for a month is a gateway that
                # leaves a session up for a month, whatever its other roles say. In this estate
                # the loop runs at most once - the `roles` entry name is constrained to
                # `default`, measured, so a gateway carries ONE role - and the aggregate is
                # written for the estate where that is not true.
                if hours is not None and (login_hours is None or hours > login_hours):
                    login_unit, login_entered, login_hours = unit, entered, hours
                idle, _idle_rk, _idle_rv = scalar_value(role.get("inactivity-logout"))
                try:
                    idle_value = int(idle)
                except (TypeError, ValueError):
                    idle_value = None
                if idle_value is not None and (inactivity is None or idle_value > inactivity):
                    inactivity = idle_value

            client_auth_rows = _gateway_client_auth_rows(entry, name, bindings)
            agent_configs = _gateway_agent_configs(
                entry, name, video_excluded if networking_half_present else None)

            # ANY ROW PERMITTING EITHER-OR, COUNTING AN UNMEASURED ABSENCE AS PERMISSIVE. A
            # certificate accepted INSTEAD of credentials makes a copied certificate file a
            # complete credential on its own, so a row whose polarity nobody read must not be
            # reported as enforcing two factors. A gateway with NO rows at all permits nothing
            # either-or, which is why the generator is over the rows that exist.
            permits_either_or = any(
                row.values["user_credential_or_client_cert_required"] is not False
                for row in client_auth_rows)

            gateways.append(NormalizedGateway(
                vsys_name=vsys_name,
                name=name,
                values={
                    "name": name,
                    "ssl_tls_service_profile": tls_name[:64],
                    "bound_tls_min_version": bound_min_version,
                    "tls_profile_resolves_to_an_explicit_floor": explicit_floor,
                    "networking_half_present": networking_half_present,
                    "tunnel_mode": tunnel_mode,
                    "ipsec_enabled": ipsec_enabled,
                    "ipsec_enabled_known": ipsec_enabled is not None,
                    "ipsec_crypto_profile_name": crypto_name or None,
                    "bound_app_crypto_first_encryption": first_encryption,
                    "app_crypto_offers_gcm_first": (
                        first_encryption == APP_CRYPTO_PREFERRED_FIRST_ENCRYPTION),
                    "certificate_profile_name": cert_name or None,
                    "bound_certificate_profile_blocks_unauthenticated_cert": (
                        blocks_unauthenticated),
                    "any_client_auth_row_permits_either_or": permits_either_or,
                    # THE OR THE QUERY GRAMMAR CANNOT WRITE, collapsed here. "No client
                    # certificates in use" is read as "names no certificate profile": there is
                    # no key saying a per-platform row ASKS for one, so the second limb of the
                    # control's own applicability collapses into the first.
                    "client_certificate_is_a_second_factor": (
                        not cert_name
                        or (blocks_unauthenticated and not permits_either_or)),
                    "block_quarantined_devices": blocked,
                    "automatic_quarantine_path_exists": quarantine,
                    "login_lifetime_unit": login_unit[:16],
                    "login_lifetime_as_entered": login_entered,
                    "login_lifetime_hours": login_hours,
                    "login_lifetime_known": login_hours is not None,
                    "inactivity_logout_minutes": inactivity,
                    "inactivity_logout_known": inactivity is not None,
                    "video_traffic_excluded": (
                        video_excluded if networking_half_present else None),
                },
                provenance=[
                    ("ssl_tls_service_profile", tls_rk, tls_rv),
                    ("tunnel_mode", tunnel_rk, tunnel_rv),
                    ("certificate_profile_name", cert_rk, cert_rv),
                    ("block_quarantined_devices", blocked_rk, blocked_rv),
                    # The networking half's four leaves. Their provenance is the half's own and
                    # NOT the vsys entry's: markers sit at the highest node of a contribution and
                    # inheriting one mislabels every local value beneath it, so a gateway whose
                    # vsys half is local and whose networking half is pushed must report two
                    # different things - which is the asymmetry stage 4 measured on this path.
                    ("ipsec_enabled", ipsec_rk, ipsec_rv),
                    ("ipsec_crypto_profile_name", crypto_rk, crypto_rv),
                    ("video_traffic_excluded", video_rk, video_rv),
                ] if networking_half_present else [
                    ("ssl_tls_service_profile", tls_rk, tls_rv),
                    ("tunnel_mode", tunnel_rk, tunnel_rv),
                    ("certificate_profile_name", cert_rk, cert_rv),
                    ("block_quarantined_devices", blocked_rk, blocked_rv),
                ],
                client_auth_rows=client_auth_rows,
                agent_configs=agent_configs,
                entry=entry,
            ))
    return gateways


def gateway_licence_verdicts(appliance: Appliance) -> dict[str, Any]:
    """The gateway's two license columns, from `request license info`.

    A SEPARATE FEATURE FROM THE PORTAL'S, measured: 691665AC334B458 names both
    `GlobalProtect Gateway` and `GlobalProtect Portal`, so a control asserting "a GlobalProtect
    license" has to say which. `_licence_entries` is imported rather than rewritten for the
    reason its own docstring gives - `{'licenses': None}` is truthy at the outer dict and falsy
    one level in, and both PA-5220s answer exactly that.

    `expired` IS READ HERE, which is the opposite of `_licence_verdicts` above, and the
    difference is deliberate rather than an inconsistency: that function's column SUPPRESSES its
    control, so an entitlement that lapsed last week would silence a finding about a portal that
    is still serving. This column is never claused on at all - it goes into the finding's
    WORDING - so reading `expired` costs nothing and the stage 5 declaration asks for it in as
    many words: "a GlobalProtect Gateway entry with expired = no".

    `licence_state_known` IS NOT `licence_reply_collected`. The shipped column says the reply
    ARRIVED; this one says it carried AN ENTRY. Both PA-5220s answered and carried none, so the
    two differ on half this estate, and conflating them would suppress on exactly the appliances
    whose license state nobody knows.
    """
    snapshot = latest_license_info_snapshot(appliance)
    entries = _licence_entries(snapshot.payload) if snapshot is not None else None
    entries = entries or []
    licensed = any(
        str(entry.get("feature") or "").strip().lower() == GLOBALPROTECT_GATEWAY_FEATURE
        and str(entry.get("expired") or "").strip().lower() == "no"
        for entry in entries)
    return {
        "globalprotect_gateway_licensed": licensed,
        "licence_state_known": bool(entries),
    }


def _bindings_for(appliance: Appliance):
    """`(vsys_name) -> GatewayBindings`, over the rows three other domains' normalizers wrote.

    THE ONLY PART OF THIS DOMAIN THAT READS ANOTHER MODEL, and it is why
    `normalize_globalprotect_gateways` must run AFTER `certificate objects` and `authentication
    profiles` in `flows.py::APPLIANCE_OBJECT_NORMALIZERS` - the same ordering obligation
    "management TLS" and "decryption settings" already carry, and for the same reason: run
    first, it would resolve against the previous collection's rows or against none.

    THE PREDEFINED SCOPE IS THE REASON THIS READS ROWS RATHER THAN THE MERGED PAYLOAD. `show
    config merged` does not carry `/config/predefined` at all, measured, and a predefined
    SSL/TLS service profile BEATS a same-named writable entry whole on that object type - so the
    most plausible correctly-hardened gateway is the one whose profile the merged view cannot
    find. `certificates.py::scoped_entries` already folds the predefined snapshot into those
    rows, so resolving through them is the only path that reaches it.
    """
    tls_rows = list(SslTlsServiceProfile.objects.filter(appliance=appliance))
    cert_rows = list(CertificateProfile.objects.filter(appliance=appliance))
    auth_rows = list(AuthenticationProfile.objects.filter(appliance=appliance))

    def _resolved(rows, order: tuple[str, ...], vsys_name: str) -> dict[str, Any]:
        # Walked from WEAKEST to strongest so the strongest writes last and wins whole. The
        # order is the object type's own - see `GatewayBindings`.
        out: dict[str, Any] = {}
        for scope in reversed(order):
            for row in rows:
                if row.scope != scope:
                    continue
                if scope == ApplianceScopedObject.SCOPE_VSYS and row.vsys_name != vsys_name:
                    continue
                out[row.name] = row
        return out

    def bindings_for(vsys_name: str) -> GatewayBindings:
        return GatewayBindings(
            ssl_tls=_resolved(tls_rows, ("predefined", "shared", "vsys"), vsys_name),
            certificate=_resolved(cert_rows, ("shared", "vsys"), vsys_name),
            authentication=_resolved(auth_rows, ("vsys", "shared"), vsys_name),
        )

    return bindings_for


def normalize_globalprotect_gateways(appliance: Appliance) -> dict[str, int]:
    """Every GlobalProtect gateway row for one appliance, and the posture verdict per vsys.

    Appliance grain, because the merged read is one call for the whole device - the per-vsys loop
    is this function's. Returns counts, which is what `flows.py::APPLIANCE_OBJECT_NORMALIZERS`
    requires of a member: that loop wraps the result in `dict(counts or {})`, so a normalizer
    returning rows there fails every appliance and records it as a normalization failure rather
    than raising.

    A SEPARATE ENTRY POINT FROM `normalize_globalprotect`, not a branch inside it: one failure
    must not cost the other, which is the judgment `platform_lifecycle.py`'s six entry points
    record. The two write the SAME `GlobalProtectEnforcementPoint` row from two concerns, which
    is what `write_node_row` is built for - it deletes only the provenance rows for the fields it
    writes, because a wide delete would have each silently erase the other's and a missing row
    means "not tracked", so the erasure would read as a deliberate statement. Neither function
    depends on the other's order: each `write_node_row` call is an `update_or_create` on the same
    lookup, and the stale-row sweep in `normalize_globalprotect` enumerates the same vsys list.
    """
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"globalprotect_gateways": 0,
                "globalprotect_gateway_client_auth_rows": 0,
                "globalprotect_gateway_agent_configs": 0,
                "globalprotect_posture_points": 0}

    gateways = normalized_gateways(snapshot, _bindings_for(appliance))
    licence = gateway_licence_verdicts(appliance)

    gateway_rows = [
        (ScopedEntry(GlobalProtectGateway.SCOPE_VSYS, gateway.vsys_name, gateway.entry),
         {**gateway.values, **licence}, gateway.provenance)
        for gateway in gateways
    ]
    written_gateways = write_scoped_objects(
        GlobalProtectGateway, appliance, snapshot, gateway_rows)

    # Resolve the saved gateways once so each child row can carry its foreign key. Keyed on the
    # identity the constraint uses rather than on the primary key, because the write above may
    # have updated a row that already existed.
    by_key = {(saved.vsys_name, saved.name): saved
              for saved in GlobalProtectGateway.objects.filter(appliance=appliance)}

    auth_rows = []
    agent_rows = []
    for gateway in gateways:
        parent = by_key.get((gateway.vsys_name, gateway.name))
        for row in gateway.client_auth_rows:
            values = dict(row.values)
            values["gateway"] = parent
            auth_rows.append((
                ScopedEntry(GlobalProtectGatewayClientAuth.SCOPE_VSYS,
                            gateway.vsys_name, row.entry),
                values, row.provenance))
        for row in gateway.agent_configs:
            values = dict(row.values)
            values["gateway"] = parent
            agent_rows.append((
                ScopedEntry(GlobalProtectGatewayAgentConfig.SCOPE_VSYS,
                            gateway.vsys_name, row.entry),
                values, row.provenance))

    written_auth = write_scoped_objects(
        GlobalProtectGatewayClientAuth, appliance, snapshot, auth_rows,
        identity=("name", "gateway_name"))
    written_agent = write_scoped_objects(
        GlobalProtectGatewayAgentConfig, appliance, snapshot, agent_rows,
        identity=("name", "gateway_name"))

    points = 0
    with transaction.atomic():
        for posture in normalized_posture(snapshot):
            write_node_row(
                GlobalProtectEnforcementPoint, appliance, snapshot, posture.values,
                # No provenance rows: every column written here is computed, which is what
                # `DERIVED_FIELDS` declares and what an empty `provenance` expresses.
                provenance=(),
                lookup={"appliance": appliance,
                        "scope": GlobalProtectEnforcementPoint.SCOPE_VSYS,
                        "vsys_name": posture.vsys_name},
            )
            points += 1
        # NO STALE-ROW SWEEP HERE, deliberately: this function does not own this model. A vsys
        # removed from the device is swept by `normalize_globalprotect`, which enumerates the
        # same vsys list from the same payload, and a second sweep over a shared model is how
        # two normalizers delete each other's rows.

    return {
        "globalprotect_gateways": written_gateways,
        "globalprotect_gateway_client_auth_rows": written_auth,
        "globalprotect_gateway_agent_configs": written_agent,
        "globalprotect_posture_points": points,
    }
