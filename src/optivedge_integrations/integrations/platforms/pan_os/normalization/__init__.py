"""PAN-OS normalization package.

This package owns translation from vendor-specific PAN-OS payloads into OptivEdge
domain models. Raw response persistence should remain a separate concern.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import (
    Appliance,
    EnforcementPoint,
    ManagementStation,
    Zone,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import PANOSCollectedResponse
from optivedge_integrations.integrations.platforms.pan_os.normalization.panorama import (
    normalize_show_managed_devices,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import (
    normalize_addresses,
    normalize_appliance_group_shared_objects,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.dynamic_address_content import (
    NormalizedDynamicAddressContent,
    normalize_enforcement_point_dynamic_address_content,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
    normalize_security_rules,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_profiles import (
    normalize_appliance_group_security_profiles,
    normalize_security_profiles,
    normalize_security_rule_profile_coverage,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.types import PANOSNormalizedCollection
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication_settings import (
    normalize_authentication_settings,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.login_banner import (
    normalize_login_banner,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.globalprotect import (
    normalize_globalprotect,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.high_availability import (
    normalize_high_availability,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.panorama_registration import (
    normalize_panorama_registration,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_ssh import (
    normalize_management_ssh,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_tls import (
    normalize_management_tls,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_identification import (
    normalize_device_identification_state,
    normalize_rulebase_device_match,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.platform_lifecycle import (
    normalize_configuration_backup_evidence,
    normalize_dataplane_utilisation,
    normalize_device_telemetry_settings,
    normalize_globalprotect_portal_presence,
    normalize_licence_inventory,
    normalize_log_alarm_settings,
    normalize_platform_content_streams,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.master_key import (
    normalize_master_key,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.wildfire_settings import (
    normalize_wildfire_settings,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    normalize_services_settings,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_plane import (
    normalize_management_plane,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_services import (
    normalize_device_services,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.log_settings import (
    normalize_log_settings,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.password_complexity import (
    normalize_password_complexity,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.password_profiles import (
    normalize_password_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication import (
    normalize_authentication_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.admin_users import (
    normalize_admin_users,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.admin_role_posture import (
    normalize_admin_role_posture,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication_sequences import (
    normalize_authentication_sequences,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.server_profiles import (
    normalize_server_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificate_settings import (
    normalize_certificate_settings,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
    normalize_certificate_objects,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.interface_management_profiles import (
    normalize_interface_management_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.interfaces import (
    NormalizedInterfaces,
    normalize_interfaces,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.network_hardening import (
    normalize_dhcp_interface_configs,
    normalize_lldp_global_settings,
    normalize_routing_adjacencies,
    normalize_session_settings,
    normalize_tunnel_inspection_coverage,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.ike import (
    normalize_ike_crypto_profiles,
    normalize_ike_gateways,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_interfaces import (
    normalize_management_interfaces,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.decryption import (
    normalize_decryption_policy,
    normalize_decryption_settings,
    normalize_ssl_decryption_exclusions,
    normalize_ssl_decryption_vendor_exclusion_optout,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.zones import (
    normalize_zones,
)


def normalize_collected_response(
    management_station: ManagementStation,
    collected: PANOSCollectedResponse,
) -> PANOSNormalizedCollection:
    if collected.source_type == "show_managed_devices":
        return normalize_show_managed_devices(management_station, collected)

    return PANOSNormalizedCollection(
        address_objects=[],
        address_groups=[],
        appliances=[],
        appliance_groups=[],
        enforcement_points=[],
        enforcement_nodes=[],
        security_rules=[],
    )


def normalize_enforcement_point_security_rules(enforcement_point: EnforcementPoint) -> PANOSNormalizedCollection:
    return normalize_security_rules(enforcement_point)


def normalize_enforcement_point_addresses(enforcement_point: EnforcementPoint) -> PANOSNormalizedCollection:
    return normalize_addresses(enforcement_point)


def normalize_appliance_group_shared_scope(appliance_group) -> PANOSNormalizedCollection:
    """Shared-scope objects for a group. MUST run before its enforcement points."""
    return normalize_appliance_group_shared_objects(appliance_group)


def normalize_enforcement_point_decryption_policy(
    enforcement_point: EnforcementPoint,
) -> dict:
    """One enforcement point's decryption rules AND its rulebase verdict. PAN-DEC-001 to 010.

    DEPENDS ON NOTHING ELSE IN THIS MODULE, deliberately. The verdict is computed from the rules
    this same call parsed rather than from the rows it just wrote, so unlike
    `normalize_enforcement_point_rulebase_device_match` it carries no ordering obligation on its
    caller - running it first or last gives the same answer, and there is no first collection on
    which it could read nothing.

    A verdict row is written even where the enforcement point holds NO decryption rulebase at
    all, which is the commonest state in this estate and is the finding PAN-DEC-001 exists to
    raise. The per-rule grain has no row for it.
    """
    return normalize_decryption_policy(enforcement_point)


def normalize_enforcement_point_zones(enforcement_point: EnforcementPoint) -> list[Zone]:
    return normalize_zones(enforcement_point)


def normalize_enforcement_point_rulebase_device_match(
    enforcement_point: EnforcementPoint,
) -> dict:
    """Whether this point's rule set names what a device IS. PAN-IOT-004.

    MUST RUN AFTER `normalize_enforcement_point_security_rules`: the verdict is taken over the
    `SecurityRule` rows that normalizer writes, so run first it would find last run's rules or
    none at all - and a point with no rules reads as a point with no device dimension, which is
    the firing side. The dependency is on the caller's order, not on an import.
    """
    return normalize_rulebase_device_match(enforcement_point)


def normalize_appliance_ssl_decryption_exclusions(appliance: Appliance) -> dict:
    """Every SSL decryption exclusion the ORGANISATION added, in both writable scopes. PAN-DEC-004.

    Depends on nothing else in the appliance tuple: it reads the same merged device entry as its
    neighbours. The vendor's own 330 or 385 shipped exclusions are NOT here - they live at
    /config/predefined/ssl-exclude-cert and are a separate object, which the sibling normalizer
    below reads for its set difference.

    COUNTS AND NOT ROWS, because `APPLIANCE_OBJECT_NORMALIZERS`' loop does `dict(counts or {})`
    on whatever a member returns and a list of model instances is not a mapping. The underlying
    normalizer returns the rows, which is what a test and a readback want.
    """
    rows = normalize_ssl_decryption_exclusions(appliance)
    return {
        "ssl_decryption_exclusions": len(rows),
        "vsys_scoped": sum(1 for r in rows if r.scope == r.SCOPE_VSYS),
        "shared_scoped": sum(1 for r in rows if r.scope == r.SCOPE_SHARED),
        "in_force": sum(1 for r in rows if r.exclude),
    }


def normalize_appliance_ssl_decryption_vendor_exclusion_optout(appliance: Appliance) -> dict:
    """Which VENDOR SSL decryption exclusions somebody switched off on this appliance. PAN-DEC-004.

    Depends on nothing else in the tuple, and its stale-residue count depends on a `show
    predefined ssl-exclude-cert` SNAPSHOT existing. Where it does not the count is zero, which is
    stage 5's declared default and which no column distinguishes from "no departure is stale" -
    the returned dict carries `predefined_list_collected` for a caller that needs the difference.
    """
    return normalize_ssl_decryption_vendor_exclusion_optout(appliance)


def normalize_appliance_decryption_settings(appliance: Appliance) -> dict:
    """Which certificate this appliance signs with when it stands in for a destination.
    PAN-DCP-003, 004 and 006.

    MUST RUN AFTER `normalize_appliance_certificate_objects`, and it is the only ordering this
    normalizer has: the `forward_trust_is_designated_local_ca` verdict follows the designated
    NAME into the certificate rows to ask whether that certificate is a self-signed authority
    this appliance holds. Certificates are normalized earlier in the same per-appliance tuple.
    Where they are not, the map comes back empty and the verdict reads FALSE, which is the
    firing side - a designation whose target cannot be confirmed has not been shown good.
    """
    return normalize_decryption_settings(appliance)


def normalize_appliance_management_tls(appliance: Appliance) -> dict:
    """The management interface's SSL/TLS binding. PAN-MGT-010 and PAN-CRT-006.

    Must run after `normalize_appliance_certificate_objects`: it resolves over the profile ROWS.
    """
    return normalize_management_tls(appliance)


def normalize_appliance_management_ssh(appliance: Appliance) -> dict:
    """The management SSH server's configured offer. PAN-MCR-001 and 003."""
    return normalize_management_ssh(appliance)


def normalize_appliance_high_availability(appliance: Appliance) -> dict:
    """The appliance's HA relationship and its pair's runtime state. PAN-HAP-001 to 004.

    Depends on nothing else in the appliance normalizer tuple. It reads the same merged device
    entry as its neighbours, plus the `show_high_availability_all` snapshot if one exists - and
    where none does, every verdict that rests on it holds its FIRING default and
    `ha_runtime_state_collected` is false.
    """
    return normalize_high_availability(appliance)


def normalize_appliance_panorama_registration(appliance: Appliance) -> dict:
    """The appliance's channel to its management estate. PAN-HAP-005.

    Depends on nothing else in the tuple. The certificate NAME it stores is deliberately NOT
    resolved against the certificate rows: an unresolvable name means the firewall presents no
    customer certificate, which is the same verdict as no name at all, so the hardening column
    is computed from this node alone and does not need the certificate normalizer to have run.
    """
    return normalize_panorama_registration(appliance)


def normalize_appliance_master_key(appliance: Appliance) -> dict:
    """The master key state. PAN-CRT-007."""
    return normalize_master_key(appliance)


def normalize_appliance_device_identification(appliance: Appliance) -> dict:
    """The appliance's device-identification service state. PAN-IOT-001 and PAN-IOT-003.

    Three operational reads and one configuration leaf, all device-wide, so this produces a row
    per HA NODE rather than per pair: a licence is per serial and the two peers can legitimately
    differ. Depends on nothing else in the appliance tuple.
    """
    return normalize_device_identification_state(appliance)



def normalize_appliance_platform_content_streams(appliance: Appliance) -> dict:
    """The installed content streams, and the device certificate the same reply carries.

    PAN-PLT-002, with one column for PAN-PLT-003 and PAN-PLT-004. Reads the appliance's own
    `show system info` snapshot - the one another domain's collector already takes - and anchors
    its row to the merged snapshot, so an appliance nobody asked still gets a row with
    `content_streams_collected` false, which FIRES. Depends on nothing else in the tuple.
    """
    return normalize_platform_content_streams(appliance)


def normalize_appliance_device_telemetry(appliance: Appliance) -> dict:
    """The three telemetry sharing switches, as COMMITTED. An input to PAN-PLT-003.

    Its own committed-local snapshot, which no other normalizer reads. A missing one leaves all
    three switches NULL and `telemetry_switches_known` false - not `no`, which is a different
    claim about the appliance. Depends on nothing else in the tuple.
    """
    return normalize_device_telemetry_settings(appliance)


def normalize_appliance_globalprotect_portal_presence(appliance: Appliance) -> dict:
    """Whether the appliance is a GlobalProtect portal, across EVERY vsys. PAN-PLT-003's input.

    Reads the same merged payload as its neighbours and sweeps every vsys the device's own
    `/vsys` names, because a vsys1-only reading answers "not a portal" on an appliance that is
    one - both PA-5220s in this lab. ONE ROW PER APPLIANCE, which is not the grain of
    `normalize_appliance_globalprotect`'s per-vsys verdict beside it; the two are different
    questions over one subtree and neither reads the other's rows. Depends on nothing else in
    the tuple and may be moved within it.
    """
    return normalize_globalprotect_portal_presence(appliance)


def normalize_appliance_licence_inventory(appliance: Appliance) -> dict:
    """The entitlement verdict AND the per-entitlement rows. PAN-PLT-004, and PAN-PLT-001's half.

    Two models in one pass, because both come from one `request license info` reply and reading
    it twice would let the count disagree with the rows it counted. That snapshot is taken by
    another domain's collector already. Depends on nothing else in the tuple.
    """
    return normalize_licence_inventory(appliance)


def normalize_appliance_log_alarm_settings(appliance: Appliance) -> dict:
    """The log-database alarm mechanism, as COMMITTED. PAN-PLT-006's first half.

    Its own committed-local snapshot. THE ABSENCE IS THE READING on three of four lab
    appliances, and the row keeps three states apart that every obvious reader collapses: the
    node absent, the node present with the master switch unset, and nobody having asked.
    Depends on nothing else in the tuple.
    """
    return normalize_log_alarm_settings(appliance)


def normalize_appliance_configuration_backup_evidence(appliance: Appliance) -> dict:
    """What the firewall records about its own backups, which is nothing usable. PAN-PLT-005.

    Reads no collector's snapshot at all, deliberately: `show config saved` cannot enumerate its
    own argument, so the row is written at its firing values and the companion column is the
    record that the firewall was asked and could not answer. Depends on nothing else in the tuple.
    """
    return normalize_configuration_backup_evidence(appliance)


def normalize_appliance_dataplane_utilisation(appliance: Appliance) -> dict:
    """The dataplane load for one named window. PAN-PLT-006's second half.

    Its own operational snapshot. A wall of zeroes is not an absence - all four lab appliances
    report `0,0,0,...` - so the companion is the only column that can tell an idle appliance from
    one nobody read. Depends on nothing else in the tuple.
    """
    return normalize_dataplane_utilisation(appliance)


def normalize_appliance_services_settings(appliance: Appliance) -> dict:
    """Update server verification and the high-DP-load logging setting. PAN-MGT-009 and 011."""
    return normalize_services_settings(appliance)


def normalize_appliance_management_plane(appliance: Appliance) -> dict:
    """The management plane's own addressing, and the appliance's operational mode.

    PAN-MGT-004 and PAN-MGT-012. Two models, both one row per APPLIANCE and therefore a row per
    HA node rather than per pair - the peers have different management addresses and are
    separately reachable, and the mode is set per appliance from maintenance mode and is
    synchronised by nothing.

    Reads the same merged device entry as its neighbours and additionally the appliance's own
    `show system info` snapshot where one exists; a missing one is a reading in its own right -
    the operational-mode column holds the blank that FIRES - rather than an ordering problem.
    Depends on nothing else in the appliance tuple.
    """
    return normalize_management_plane(appliance)


def normalize_appliance_log_settings(appliance: Appliance) -> dict:
    """Device > Log Settings, the log-settings server profiles and per-vsys Log Forwarding.

    PAN-LOG-001 to 010. Writes three models in one pass - `LogServerTarget`,
    `VsysLogForwarding` and the logging columns of `LoggingSettings` - because they share the
    scope walk, the profile index and the referrer walk over the whole payload.

    MUST RUN AFTER `normalize_appliance_services_settings`, which owns the other column on the
    `LoggingSettings` row. Not for correctness of the values - the two write disjoint column
    sets and each deletes only its own provenance rows - but so that a fresh row is created by
    the normalizer whose columns PAN-MGT-011 reads, keeping that control's behaviour unchanged
    on an appliance where this one fails.
    """
    return normalize_log_settings(appliance)


def normalize_appliance_wildfire_settings(appliance: Appliance) -> dict:
    """Device > Setup > WildFire, the device-wide settings. PAN-AVW-004 and PAN-AVW-005.

    Distinct from the WildFire ANALYSIS PROFILE that PAN-AVW-003 reads: a profile decides what
    is asked for, this decides what the platform forwards.
    """
    return normalize_wildfire_settings(appliance)


def normalize_appliance_device_services(appliance: Appliance) -> dict:
    """NTP, SNMP and system identity. PAN-SVC-001, 002, 004, 005, 007 and 009.

    MUST run after `normalize_appliance_management_interfaces`: whether SNMP is reachable is a
    property of the surfaces that normalizer writes, not of the `snmp-setting` subtree.
    """
    return normalize_device_services(appliance)


def normalize_appliance_login_banner(appliance: Appliance) -> dict:
    """The management login banner and its acknowledgement. PAN-MGT-007 and 008."""
    return normalize_login_banner(appliance)


def normalize_appliance_authentication_settings(appliance: Appliance) -> dict:
    """Device-wide administrator authentication settings. PAN-AUTH-014 to 017."""
    return normalize_authentication_settings(appliance)


def normalize_appliance_password_complexity(appliance: Appliance) -> dict:
    """The global minimum password complexity. PAN-AUTH-001 to 013."""
    return normalize_password_complexity(appliance)


def normalize_appliance_password_profiles(appliance: Appliance) -> dict:
    """Password profiles, with the global policy each one would override."""
    return normalize_password_profiles(appliance)


def normalize_appliance_server_profiles(appliance: Appliance) -> dict:
    """Every AAA server profile on one appliance, in every scope, with its referrer count."""
    return normalize_server_profiles(appliance)


def normalize_appliance_admin_users(appliance: Appliance) -> dict:
    """Every administrator account under mgt-config/users, with the superuser total."""
    return normalize_admin_users(appliance)


def normalize_appliance_admin_role_posture(appliance: Appliance) -> dict:
    """Whether this appliance defines and uses any scoped administrator role. One row."""
    return normalize_admin_role_posture(appliance)


def normalize_appliance_authentication_profiles(appliance: Appliance) -> dict:
    """Authentication profiles, in every scope they occupy."""
    return normalize_authentication_profiles(appliance)


def normalize_appliance_authentication_sequences(appliance: Appliance) -> dict:
    """Authentication sequences, in every scope - after profiles, before admin users."""
    return normalize_authentication_sequences(appliance)


def normalize_appliance_certificate_objects(appliance: Appliance) -> dict:
    """Every certificate, SSL/TLS service, certificate and SCEP profile, in every scope."""
    return normalize_certificate_objects(appliance)


def normalize_appliance_globalprotect(appliance: Appliance) -> dict:
    """Every GlobalProtect portal, its client-auth rows, and one verdict row per vsys.

    Reads the SAME merged payload as its neighbours and the licence snapshot another domain's
    collector already takes, so it depends on nothing else in the tuple and may be moved within
    it. Returns counts, which is what `APPLIANCE_OBJECT_NORMALIZERS` requires.
    """
    return normalize_globalprotect(appliance)


def normalize_appliance_certificate_settings(appliance: Appliance) -> dict:
    """The appliance's certificate-expiry check. Depends on nothing else in the tuple."""
    return normalize_certificate_settings(appliance)


def normalize_appliance_interface_management_profiles(appliance: Appliance) -> list:
    """Every interface management profile on one appliance, bound or not."""
    return normalize_interface_management_profiles(appliance)


def normalize_appliance_interfaces(appliance: Appliance) -> NormalizedInterfaces:
    """Every interface on one appliance, with whatever could not be made sense of."""
    return normalize_interfaces(appliance)


def normalize_appliance_session_settings(appliance: Appliance) -> dict:
    """Device > Setup > Session - policy rematch and IPv6 firewalling. PAN-NET-002 and 005.

    Two sibling leaves under `deviceconfig/setting`, one row per appliance. Reads the same
    merged device entry as its neighbours and depends on nothing else in the appliance
    tuple.
    """
    return normalize_session_settings(appliance)


def normalize_appliance_lldp_global_settings(appliance: Appliance) -> dict:
    """Network > LLDP, the device-wide enable. PAN-NET-003's preferred value.

    One leaf, one row per appliance, out of the same merged device entry. Independent of
    the per-interface LLDP columns, which `normalize_appliance_interfaces` writes.
    """
    return normalize_lldp_global_settings(appliance)


def normalize_appliance_dhcp_interface_configs(appliance: Appliance) -> dict:
    """Network > DHCP - server and relay, per interface. PAN-NET-004.

    A row exists only where `network/dhcp/interface` carries an entry, so an appliance
    with no DHCP produces none - which is the control's passing state. Depends on nothing
    else in this tuple; it does NOT read the `Interface` rows, because the entry's name is
    the interface and a DHCP configuration can name a port the interface walk skipped.
    """
    return normalize_dhcp_interface_configs(appliance)


def normalize_appliance_tunnel_inspection_coverage(appliance: Appliance) -> dict:
    """Policies > Tunnel Inspection, as a coverage verdict per vsys. PAN-NET-006.

    Reads the merged payload for the firewall-local rulebase and, where one was collected,
    the per-vsys `show config pushed-shared-policy` snapshot for the Panorama device
    group's. Depends on nothing else in this tuple - the verdict is computed over the
    payload rather than over stored rule rows, because no normalizer stores a
    tunnel-inspect rule.
    """
    return normalize_tunnel_inspection_coverage(appliance)


def normalize_appliance_routing_adjacencies(appliance: Appliance) -> dict:
    """Network > Virtual Routers - the adjacencies that carry authentication. PAN-NET-007.

    One row per BGP peer and per OSPF attachment, with the authentication reference
    resolved against the profiles on the SAME router. Depends on nothing else in this
    tuple.
    """
    return normalize_routing_adjacencies(appliance)


def normalize_appliance_management_interfaces(appliance: Appliance) -> list:
    """Every administrative surface on one appliance - MGT, aux, and bound layer-3 interfaces."""
    return normalize_management_interfaces(appliance)


__all__ = [
    "NormalizedDynamicAddressContent",
    "NormalizedInterfaces",
    "PANOSNormalizedCollection",
    "normalize_addresses",
    "normalize_appliance_group_security_profiles",
    "normalize_appliance_group_shared_scope",
    "normalize_appliance_admin_users",
    "normalize_appliance_admin_role_posture",
    "normalize_appliance_server_profiles",
    "normalize_appliance_authentication_profiles",
    "normalize_appliance_authentication_sequences",
    "normalize_appliance_authentication_settings",
    "normalize_appliance_log_settings",
    "normalize_appliance_login_banner",
    "normalize_appliance_management_tls",
    "normalize_appliance_high_availability",
    "normalize_appliance_management_ssh",
    "normalize_appliance_master_key",
    "normalize_appliance_services_settings",
    "normalize_appliance_management_plane",
    "normalize_management_plane",
    "normalize_appliance_device_services",
    "normalize_appliance_panorama_registration",
    "normalize_appliance_password_complexity",
    "normalize_appliance_password_profiles",
    "normalize_appliance_certificate_objects",
    "normalize_appliance_certificate_settings",
    "normalize_appliance_globalprotect",
    "normalize_appliance_interface_management_profiles",
    "normalize_appliance_interfaces",
    "normalize_appliance_session_settings",
    "normalize_appliance_lldp_global_settings",
    "normalize_appliance_dhcp_interface_configs",
    "normalize_appliance_tunnel_inspection_coverage",
    "normalize_appliance_routing_adjacencies",
    "normalize_session_settings",
    "normalize_lldp_global_settings",
    "normalize_dhcp_interface_configs",
    "normalize_tunnel_inspection_coverage",
    "normalize_routing_adjacencies",
    "normalize_appliance_management_interfaces",
    "normalize_enforcement_point_addresses",
    "normalize_enforcement_point_dynamic_address_content",
    "normalize_enforcement_point_security_rules",
    "normalize_appliance_device_identification",
    "normalize_device_identification_state",
    "normalize_appliance_configuration_backup_evidence",
    "normalize_appliance_dataplane_utilisation",
    "normalize_appliance_device_telemetry",
    "normalize_appliance_globalprotect_portal_presence",
    "normalize_appliance_licence_inventory",
    "normalize_appliance_log_alarm_settings",
    "normalize_appliance_platform_content_streams",
    "normalize_configuration_backup_evidence",
    "normalize_dataplane_utilisation",
    "normalize_device_telemetry_settings",
    "normalize_globalprotect_portal_presence",
    "normalize_licence_inventory",
    "normalize_log_alarm_settings",
    "normalize_platform_content_streams",
    "normalize_enforcement_point_rulebase_device_match",
    "normalize_enforcement_point_zones",
    "normalize_rulebase_device_match",
    "normalize_collected_response",
    "normalize_security_profiles",
    "normalize_security_rule_profile_coverage",
    "normalize_security_rules",
    "normalize_show_managed_devices",
    "normalize_ike_crypto_profiles",
    "normalize_ike_gateways",
    "normalize_zones",
]
