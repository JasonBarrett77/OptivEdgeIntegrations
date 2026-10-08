import ipaddress
from datetime import timedelta
from pathlib import Path
import tempfile
import re
import base64
import textwrap
import warnings
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone

from optivedge_integrations.integrations.models import (
    ServerProfile,
    Interface,
    FieldProvenance,
    InterfaceManagementProfile,
    ManagementInterface,
    PermittedSource,
    AddressGroup,
    AddressObject,
    AddressObjectResolvedEntry,
    Appliance,
    DeviceGroup,
    DeviceGroupBinding,
    ApplianceGroup,
    EnforcementNode,
    EnforcementPoint,
    AuthenticationSettings,
    LoggingSettings,
    LoginBanner,
    ManagementTlsBinding,
    SslTlsServiceProfile,
    MasterKey,
    UpdateServerSettings,
    PasswordComplexityPolicy,
    IntegrationEvent,
    IntegrationRun,
    ManagementStation,
    NormalizationIssue,
    Note,
    PolicyObjectNamespace,
    PolicyObjectPrecedence,
    PolicyObjectScope,
    Region,
    precedence_for,
    scope_for,
    SecurityRule,
    SecurityRuleProfile,
    SecurityRuleProfileGroup,
    SecurityProfile,
    SecurityProfileGroup,
    SecurityProfileSeverityVerdict,
    SecurityRuleApplication,
    SecurityRuleSearchVocabularyEntry,
    SecurityRuleService,
    SecurityRuleDestinationAddressRef,
    SecurityRuleSourceAddressRef,
    Snapshot,
    Zone,
    ZoneInterface,
)
from optivedge_integrations.integrations.platforms.pan_os import (
    PANOSInScopeConfigCollection,
    PANOSInScopeRefreshCollection,
    PANOSInScopeRenormalizationResult,
    PANOSDynamicContentRefreshResult,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import (
    build_normalized_addresses,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.regions import (
    build_normalized_regions,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_profiles import (
    PROFILE_KINDS,
    ml_model_catalogue,
    normalize_security_profile,
    profile_ml_models,
    profile_application_overrides,
    profile_decoders,
    resolve_decoder_action,
    normalize_security_rule_profile_coverage,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
    ISO_3166_1_ALPHA2_REGIONS,
    NormalizedSecurityRuleMember,
    build_normalized_security_rules,
    build_address_lookup_maps,
    first_effective_object,
    literal_namespace,
    name_is_owned,
    build_address_lookup_maps,
    resolve_rule_address_refs,
    realize_literal_address_objects,
    NormalizedSecurityRule,
    NormalizedSecurityRuleMember,
    resolve_rule_address_refs,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.admin_users import (
    resolve_role,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    pushed_shared,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.interface_management_profiles import (
    ENTRY_FIELD,
    normalize_interface_management_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.interfaces import (
    bound_management_profiles,
    normalize_interfaces,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_interfaces import (
    normalize_management_interfaces,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.zones import (
    build_interface_address_index,
    build_normalized_zones,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    is_panorama_managed,
    latest_pushed_shared_snapshot,
)
from optivedge_integrations.integrations.diagnostics import (
    capture_census,
    diagnose_collisions,
    has_normalization_errors,
    normalization_health,
    normalization_indicator,
    explain_address_reference,
    unmarked_pushed_entries,
    CENSUS_VERSION,
    compare_censuses,
    load_census,
    write_census,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_server_profiles,
    normalize_appliance_authentication_settings,
    normalize_appliance_login_banner,
    normalize_appliance_management_tls,
    normalize_appliance_certificate_objects,
    normalize_appliance_master_key,
    normalize_appliance_services_settings,
    normalize_appliance_password_complexity,
    normalize_appliance_group_shared_scope,
    normalize_enforcement_point_addresses,
    normalize_enforcement_point_dynamic_address_content,
    normalize_enforcement_point_security_rules,
    normalize_enforcement_point_zones,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors import (
    external_list as external_list_collector,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.external_list import (
    LIST_TYPE_CUSTOM,
    LIST_TYPE_PREDEFINED,
    build_show_external_list_command,
    collect_show_external_list,
    members_from_result,
    total_valid_from_result,
)
from optivedge_integrations.integrations.platforms.pan_os.flows import _candidate_edl_names
from optivedge_integrations.integrations import query_chunking
from optivedge_integrations.integrations import views as views_module
from optivedge_integrations.integrations.query_chunking import chunked
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    merge_intervals,
    num_hosts_from_intervals,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
    decode_certificate,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
    ResolvedAddressRef,
    _member_intervals_or_none,
    compute_negated_complement_intervals,
    side_num_hosts,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.dynamic_address_content import (
    _edl_members_from_snapshot,
    _fqdn_addresses_by_name,
    _intervals_from_values,
)
from optivedge_integrations.integrations.platforms.pan_os.persistence.common import extract_result_payload
from optivedge_integrations.integrations.orchestration import refresh_panorama_in_scope_data
from optivedge_integrations.integrations.search_vocabulary import (
    rebuild_all_security_rule_search_vocabulary,
    rebuild_security_rule_search_vocabulary,
)


def _create_grouped_enforcement_point(
    *,
    serial_number,
    appliance_hostname,
    station_hostname,
    station_type,
    group_name,
    group_type=ApplianceGroup.TYPE_STANDALONE,
    vsys_name="vsys1",
):
    """Build a station/group/appliance/EnforcementPoint chain with the point on the GROUP.

    This is the shape production actually creates - `normalization/panorama.py` is the
    only site that creates an EnforcementPoint, and it always sets `appliance_group`.
    `_create_panorama_enforcement_point()` above sets `appliance` instead, a shape no
    collection path produces, so anything exercising group-scoped lookups needs this
    helper or it will silently test nothing.

    `station_type` is a required argument because it - not the presence of a group - is
    what decides whether Panorama data should exist for the point.
    """
    station = ManagementStation.objects.create(
        station_type=station_type,
        hostname=station_hostname,
    )
    group = ApplianceGroup.objects.create(
        management_station=station,
        name=group_name,
        group_type=group_type,
    )
    appliance = Appliance.objects.create(
        management_station=station,
        appliance_group=group,
        serial_number=serial_number,
        hostname=appliance_hostname,
    )
    group.active_appliance = appliance
    group.save()
    enforcement_point = EnforcementPoint.objects.create(
        management_station=station,
        appliance_group=group,
        vsys_name=vsys_name,
    )
    EnforcementNode.objects.create(
        management_station=station,
        enforcement_point=enforcement_point,
        appliance=appliance,
    )
    return station, group, appliance, enforcement_point


def _create_panorama_enforcement_point(
    *,
    serial_number,
    appliance_hostname,
    station_hostname="panorama.local",
    vsys_name="vsys1",
    vsys_display_name=None,
    with_pushed_shared=True,
):
    """Build a Panorama-managed station/group/appliance/EnforcementPoint chain.

    Produces the shape production actually creates: the enforcement point hangs off an
    `ApplianceGroup`, because `normalization/panorama.py` is the only site that creates
    one and it always sets `appliance_group`. This helper previously set `appliance`
    instead - a shape no collection path produces - which left the group-scoped
    pushed-shared branch inert in every test that used it.

    A Panorama-managed point always has a pushed-shared-policy snapshot in reality, so
    one is created here too. Pass `with_pushed_shared=False` to assert on its absence.
    """
    station, group, appliance, enforcement_point = _create_grouped_enforcement_point(
        serial_number=serial_number,
        appliance_hostname=appliance_hostname,
        station_hostname=station_hostname,
        station_type=ManagementStation.StationType.PAN_PANORAMA,
        group_name=f"grp-{serial_number}",
        vsys_name=vsys_name,
    )
    if vsys_display_name is not None:
        enforcement_point.vsys_display_name = vsys_display_name
        enforcement_point.save()
    if with_pushed_shared:
        Snapshot.objects.create(
            management_station=station,
            appliance_group=group,
            source_type="show_pushed_shared_policy",
            collected_at=timezone.now(),
            payload={"shared": {}},
        )
    return station, appliance, enforcement_point


def _create_empty_pushed_policy_snapshot(*, station, enforcement_point):
    """Create a `show_pushed_shared_policy_vsys` snapshot with no pre/post-rulebase content.

    Shared by tests whose fixtures only need the merged-config side of normalization to
    have content - the pushed-policy snapshot must still exist (normalization requires it)
    but its rulebases are deliberately empty.
    """
    return Snapshot.objects.create(
        management_station=station,
        enforcement_point=enforcement_point,
        source_type="show_pushed_shared_policy_vsys",
        collected_at=timezone.now(),
        payload={
            "policy": {
                "panorama": {
                    "pre-rulebase": {"security": {"rules": {"entry": []}}},
                    "post-rulebase": {
                        "security": {"rules": {"entry": []}},
                        "default-security-rules": {"rules": {"entry": []}},
                    },
                }
            }
        },
    )


def _empty_in_scope_refresh_collection():
    """A PANOSInScopeRefreshCollection with every collection/failure list empty.

    `inventory` is left as None - none of the action views under test read it, only
    `.configuration_snapshots`, so a full PANOSProcessedCollection isn't needed here.
    """
    return PANOSInScopeRefreshCollection(
        inventory=None,
        configuration_snapshots=PANOSInScopeConfigCollection(
            appliances=[],
            appliance_groups=[],
            enforcement_points=[],
            merged_config_collections=[],
            merged_config_failures=[],
            predefined_lists_collections=[],
            predefined_lists_failures=[],
            shared_policy_collections=[],
            shared_policy_failures=[],
            vsys_policy_collections=[],
            vsys_policy_failures=[],
            address_normalizations=[],
            address_failures=[],
            security_rule_normalizations=[],
            security_rule_failures=[],
            security_rule_item_failures=[],
            zone_normalizations=[],
            zone_failures=[],
        ),
    )


def _empty_renormalization_result():
    return PANOSInScopeRenormalizationResult(
        appliances=[],
        enforcement_points=[],
        address_normalizations=[],
        address_failures=[],
        security_rule_normalizations=[],
        security_rule_failures=[],
        security_rule_item_failures=[],
        zone_normalizations=[],
        zone_failures=[],
    )


def _empty_dynamic_content_refresh_result():
    return PANOSDynamicContentRefreshResult(
        appliances=[],
        enforcement_points=[],
        fqdn_cache_collections=[],
        fqdn_cache_failures=[],
        external_list_collections=[],
        external_list_failures=[],
        dynamic_content_normalizations=[],
        dynamic_content_failures=[],
    )


class AddressNormalizationTests(TestCase):
    def test_normalize_enforcement_point_addresses_populates_derived_fields_and_builtin_any(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-001",
            appliance_hostname="fw-01",
        )

        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "address": {
                                        "entry": [
                                            {"@name": "net-obj", "ip-netmask": "10.1.2.3/24"},
                                            {"@name": "range-obj", "ip-range": "10.2.0.10-10.2.0.20"},
                                            {"@name": "fqdn-obj", "fqdn": "Example.COM"},
                                            {"@name": "wild-obj", "ip-wildcard": "10.3.0.0/0.0.255.0"},
                                        ]
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        Snapshot.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_type="show_pushed_shared_policy_vsys",
            collected_at=timezone.now(),
            payload={"policy": {"panorama": {}}},
        )

        normalized = normalize_enforcement_point_addresses(enforcement_point)

        self.assertEqual(len(normalized.address_objects), 5)

        net_obj = next(obj for obj in normalized.address_objects if obj.name == "net-obj")
        self.assertEqual(net_obj.normalized_value, "10.1.2.0/24")
        self.assertEqual(net_obj.ipv4_start_int, 167838208)
        self.assertEqual(net_obj.ipv4_end_int, 167838463)
        self.assertEqual(net_obj.num_hosts, 256)
        self.assertFalse(net_obj.is_any)

        range_obj = next(obj for obj in normalized.address_objects if obj.name == "range-obj")
        self.assertEqual(range_obj.normalized_value, "10.2.0.10-10.2.0.20")
        self.assertEqual(range_obj.ipv4_start_int, 167903242)
        self.assertEqual(range_obj.ipv4_end_int, 167903252)
        self.assertEqual(range_obj.num_hosts, 11)

        fqdn_obj = next(obj for obj in normalized.address_objects if obj.name == "fqdn-obj")
        self.assertEqual(fqdn_obj.normalized_value, "example.com")
        self.assertIsNone(fqdn_obj.ipv4_start_int)
        self.assertIsNone(fqdn_obj.ipv4_end_int)
        self.assertIsNone(fqdn_obj.num_hosts)

        wildcard_obj = next(obj for obj in normalized.address_objects if obj.name == "wild-obj")
        self.assertEqual(wildcard_obj.normalized_value, "10.3.0.0/0.0.255.0")
        self.assertIsNone(wildcard_obj.ipv4_start_int)
        self.assertIsNone(wildcard_obj.ipv4_end_int)
        self.assertIsNone(wildcard_obj.num_hosts)

        any_obj = next(obj for obj in normalized.address_objects if obj.name == "any")
        self.assertEqual(any_obj.address_type, any_obj.TYPE_BUILTIN_ANY)
        self.assertEqual(any_obj.normalized_value, "any")
        self.assertEqual(any_obj.ipv4_start_int, 0)
        self.assertEqual(any_obj.ipv4_end_int, 4_294_967_295)
        self.assertEqual(any_obj.num_hosts, 4_294_967_296)
        self.assertTrue(any_obj.is_any)

    def test_normalize_enforcement_point_security_rules_builds_address_refs(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-002",
            appliance_hostname="fw-02",
        )

        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "address": {
                                        "entry": [
                                            {"@name": "host-a", "ip-netmask": "10.10.10.10/32"},
                                            {"@name": "host-b", "ip-netmask": "10.10.10.11/32"},
                                        ]
                                    },
                                    "address-group": {
                                        "entry": [
                                            {
                                                "@name": "static-src",
                                                "static": {"member": ["host-a", "host-b"]},
                                            },
                                            {
                                                "@name": "dag-src",
                                                "dynamic": {"filter": "'tag1'"},
                                            },
                                        ]
                                    },
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-direct",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["host-a"]},
                                                        "destination": {"member": ["any"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                    },
                                                    {
                                                        "@name": "rule-static-group",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["static-src"]},
                                                        "destination": {"member": ["host-b"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                    },
                                                    {
                                                        "@name": "rule-dynamic-group",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["dag-src"]},
                                                        "destination": {"member": ["host-a"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                    },
                                                ]
                                            }
                                        },
                                        "default-security-rules": {"rules": {"entry": []}},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        _create_empty_pushed_policy_snapshot(station=station, enforcement_point=enforcement_point)

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        self.assertEqual(len(normalized.security_rules), 3)

        direct_rule = next(rule for rule in normalized.security_rules if rule.name == "rule-direct")
        direct_source_refs = list(direct_rule.source_address_refs.all())
        direct_destination_refs = list(direct_rule.destination_address_refs.all())
        self.assertEqual(len(direct_source_refs), 1)
        self.assertEqual(direct_source_refs[0].ref_type, SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT)
        self.assertEqual(direct_source_refs[0].address_object.name, "host-a")
        self.assertIsNone(direct_source_refs[0].address_group)
        self.assertEqual(len(direct_destination_refs), 1)
        self.assertEqual(direct_destination_refs[0].ref_type, SecurityRuleDestinationAddressRef.RefType.ANY)
        self.assertTrue(direct_destination_refs[0].address_object.is_any)

        static_rule = next(rule for rule in normalized.security_rules if rule.name == "rule-static-group")
        static_source_refs = list(static_rule.source_address_refs.order_by("id"))
        self.assertEqual(len(static_source_refs), 2)
        self.assertEqual(
            {ref.address_object.name for ref in static_source_refs},
            {"host-a", "host-b"},
        )
        self.assertEqual(
            {ref.address_group.name for ref in static_source_refs},
            {"static-src"},
        )
        self.assertEqual(
            {ref.ref_type for ref in static_source_refs},
            {SecurityRuleSourceAddressRef.RefType.STATIC_ADDRESS_GROUP},
        )

        dynamic_rule = next(rule for rule in normalized.security_rules if rule.name == "rule-dynamic-group")
        dynamic_source_refs = list(dynamic_rule.source_address_refs.all())
        self.assertEqual(len(dynamic_source_refs), 1)
        self.assertEqual(
            dynamic_source_refs[0].ref_type,
            SecurityRuleSourceAddressRef.RefType.DYNAMIC_ADDRESS_GROUP,
        )
        self.assertIsNone(dynamic_source_refs[0].address_object)
        self.assertEqual(dynamic_source_refs[0].address_group.name, "dag-src")

    def test_normalize_enforcement_point_security_rules_defaults_missing_source_and_destination_to_any(self):
        """PAN-OS omits <source>/<destination> entirely (rather than an explicit "any" member)
        for some rules - that must still resolve to an ANY ref, not zero address refs."""
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-002B",
            appliance_hostname="fw-02b",
        )

        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-no-source-dest",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                    },
                                                ]
                                            }
                                        },
                                        "default-security-rules": {"rules": {"entry": []}},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        _create_empty_pushed_policy_snapshot(station=station, enforcement_point=enforcement_point)

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        rule = normalized.security_rules[0]
        source_refs = list(rule.source_address_refs.all())
        destination_refs = list(rule.destination_address_refs.all())
        self.assertEqual(len(source_refs), 1)
        self.assertEqual(source_refs[0].ref_type, SecurityRuleSourceAddressRef.RefType.ANY)
        self.assertEqual(source_refs[0].raw_value, "any")
        self.assertTrue(source_refs[0].address_object.is_any)
        self.assertEqual(len(destination_refs), 1)
        self.assertEqual(destination_refs[0].ref_type, SecurityRuleDestinationAddressRef.RefType.ANY)
        self.assertEqual(destination_refs[0].raw_value, "any")
        self.assertTrue(destination_refs[0].address_object.is_any)

    def test_normalize_enforcement_point_security_rules_resolves_nested_static_address_groups(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-003",
            appliance_hostname="fw-03",
        )

        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "address": {
                                        "entry": [
                                            {"@name": "host-a", "ip-netmask": "10.10.10.10/32"},
                                            {"@name": "host-b", "ip-netmask": "10.10.10.11/32"},
                                            {"@name": "host-c", "ip-netmask": "10.10.10.12/32"},
                                            {"@name": "host-d", "ip-netmask": "10.10.10.13/32"},
                                        ]
                                    },
                                    "address-group": {
                                        "entry": [
                                            {
                                                "@name": "leaf-shared",
                                                "static": {"member": ["host-d"]},
                                            },
                                            {
                                                "@name": "branch-a",
                                                "static": {"member": ["host-a", "leaf-shared"]},
                                            },
                                            {
                                                "@name": "branch-b",
                                                "static": {"member": ["host-b", "leaf-shared"]},
                                            },
                                            {
                                                "@name": "nested-dynamic",
                                                "dynamic": {"filter": "'tag2'"},
                                            },
                                            {
                                                "@name": "top-group",
                                                "static": {
                                                    "member": [
                                                        "branch-a",
                                                        "branch-b",
                                                        "host-c",
                                                        "nested-dynamic",
                                                    ]
                                                },
                                            },
                                        ]
                                    },
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-nested-static-group",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["top-group"]},
                                                        "destination": {"member": ["any"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                    },
                                                ]
                                            }
                                        },
                                        "default-security-rules": {"rules": {"entry": []}},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        _create_empty_pushed_policy_snapshot(station=station, enforcement_point=enforcement_point)

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        rule = next(rule for rule in normalized.security_rules if rule.name == "rule-nested-static-group")
        source_refs = list(rule.source_address_refs.order_by("id"))

        # host-a, host-b, host-c direct/nested, host-d once despite being reachable via both
        # branch-a and branch-b (diamond de-duplication), plus one dynamic ref for nested-dynamic.
        self.assertEqual(len(source_refs), 5)

        static_refs = [
            ref for ref in source_refs if ref.ref_type == SecurityRuleSourceAddressRef.RefType.STATIC_ADDRESS_GROUP
        ]
        self.assertEqual(
            {ref.address_object.name for ref in static_refs},
            {"host-a", "host-b", "host-c", "host-d"},
        )
        # every static ref is attributed to the top-level group named by the rule, never
        # an intermediate nested group.
        self.assertEqual({ref.address_group.name for ref in static_refs}, {"top-group"})

        dynamic_refs = [
            ref for ref in source_refs if ref.ref_type == SecurityRuleSourceAddressRef.RefType.DYNAMIC_ADDRESS_GROUP
        ]
        self.assertEqual(len(dynamic_refs), 1)
        self.assertIsNone(dynamic_refs[0].address_object)
        self.assertEqual(dynamic_refs[0].address_group.name, "nested-dynamic")

    def test_normalize_enforcement_point_security_rules_skips_circular_static_address_group(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-004",
            appliance_hostname="fw-04",
        )

        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "address": {"entry": []},
                                    "address-group": {
                                        "entry": [
                                            {
                                                "@name": "cycle-a",
                                                "static": {"member": ["cycle-b"]},
                                            },
                                            {
                                                "@name": "cycle-b",
                                                "static": {"member": ["cycle-a"]},
                                            },
                                        ]
                                    },
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-cycle",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["cycle-a"]},
                                                        "destination": {"member": ["any"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                    },
                                                ]
                                            }
                                        },
                                        "default-security-rules": {"rules": {"entry": []}},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        _create_empty_pushed_policy_snapshot(station=station, enforcement_point=enforcement_point)

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        self.assertEqual(normalized.security_rules, [])
        self.assertEqual(len(normalized.security_rule_failures), 1)
        self.assertEqual(normalized.security_rule_failures[0].name, "rule-cycle")
        self.assertFalse(
            SecurityRule.objects.filter(enforcement_point=enforcement_point, name="rule-cycle").exists()
        )

    def test_normalize_enforcement_point_security_rules_resolves_vendor_region_codes(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-005",
            appliance_hostname="fw-05",
        )

        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "address": {"entry": []},
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-vendor-region",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["BY", "DN", "XK"]},
                                                        "destination": {"member": ["any"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                    },
                                                ]
                                            }
                                        },
                                        "default-security-rules": {"rules": {"entry": []}},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        _create_empty_pushed_policy_snapshot(station=station, enforcement_point=enforcement_point)

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        rule = next(rule for rule in normalized.security_rules if rule.name == "rule-vendor-region")
        source_refs = list(rule.source_address_refs.order_by("id"))
        self.assertEqual(len(source_refs), 3)
        self.assertEqual(
            {ref.ref_type for ref in source_refs},
            {SecurityRuleSourceAddressRef.RefType.REGION},
        )
        self.assertEqual({ref.raw_value for ref in source_refs}, {"BY", "DN", "XK"})

    def test_normalize_enforcement_point_security_rules_skips_unresolved_two_letter_value(self):
        """An unresolvable reference fails and skips only its own rule - it must not abort
        normalization for every other rule on the same enforcement point (the previous
        behavior: one bad region/vendor code anywhere would leave the whole enforcement
        point's rules stuck on stale data)."""
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-006",
            appliance_hostname="fw-06",
        )

        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "address": {"entry": []},
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-bad-ref",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        # ZZ is not a real ISO code, a PAN-OS
                                                        # vendor code, or a configured object/group -
                                                        # should surface as an unresolved reference,
                                                        # not be silently treated as a region.
                                                        "source": {"member": ["ZZ"]},
                                                        "destination": {"member": ["any"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                    },
                                                    {
                                                        "@name": "rule-good-ref",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["any"]},
                                                        "destination": {"member": ["any"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                    },
                                                ]
                                            }
                                        },
                                        "default-security-rules": {"rules": {"entry": []}},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        _create_empty_pushed_policy_snapshot(station=station, enforcement_point=enforcement_point)

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        self.assertEqual([rule.name for rule in normalized.security_rules], ["rule-good-ref"])
        self.assertEqual(len(normalized.security_rule_failures), 1)
        failure = normalized.security_rule_failures[0]
        self.assertEqual(failure.name, "rule-bad-ref")
        self.assertIn("ZZ", failure.error_text)
        self.assertTrue(
            SecurityRule.objects.filter(enforcement_point=enforcement_point, name="rule-good-ref").exists()
        )
        self.assertFalse(
            SecurityRule.objects.filter(enforcement_point=enforcement_point, name="rule-bad-ref").exists()
        )

    def test_normalize_enforcement_point_security_rules_realizes_literal_address_objects(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-003",
            appliance_hostname="fw-03",
        )

        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-literal",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["10.0.0.0/8"]},
                                                        "destination": {"member": ["any"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                    }
                                                ]
                                            }
                                        },
                                        "default-security-rules": {"rules": {"entry": []}},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        _create_empty_pushed_policy_snapshot(station=station, enforcement_point=enforcement_point)

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        self.assertEqual(len(normalized.security_rules), 1)
        literal_object = enforcement_point.address_objects.get(name="10.0.0.0/8")
        self.assertFalse(literal_object.field_provenance.filter(field_name="__entry__").exists())
        self.assertEqual(literal_object.address_type, literal_object.TYPE_IP_NETMASK)
        self.assertEqual(literal_object.normalized_value, "10.0.0.0/8")
        self.assertEqual(literal_object.namespace_type, "local_vsys")
        self.assertEqual(literal_object.namespace_value, "vsys1")

    def test_normalize_enforcement_point_security_rules_resolves_predefined_edl_references(self):
        """PAN-OS-shipped predefined IP block/URL lists (e.g. panw-known-ip-list) never appear
        in a rule's own config_source snapshot - only via `show predefined`, appliance-scoped.
        Rules referencing them by name must resolve (address_type=EDL, is_builtin=True), not
        raise "unresolved address reference"."""
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-007",
            appliance_hostname="fw-07",
        )

        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "address": {"entry": []},
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-predefined-edl",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["any"]},
                                                        "destination": {
                                                            "member": ["panw-known-ip-list"]
                                                        },
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "deny",
                                                    },
                                                ]
                                            }
                                        },
                                        "default-security-rules": {"rules": {"entry": []}},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        _create_empty_pushed_policy_snapshot(station=station, enforcement_point=enforcement_point)
        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_predefined_ip_block_lists",
            collected_at=timezone.now(),
            payload={
                "ip-block-list-v2": {
                    "@max-ip-files": "4",
                    "@min-version": "9.0.0",
                    "entry": [
                        {
                            "@name": "panw-known-ip-list",
                            "@max-entries": "20000",
                            "filename": "panw-known-ip-list",
                            "display-name": "Palo Alto Networks - Known malicious IP addresses",
                            "description": "IP addresses used almost exclusively by malicious actors.",
                        },
                        {
                            "@name": "panw-highrisk-ip-list",
                            "@max-entries": "20000",
                            "filename": "panw-highrisk-ip-list",
                            "display-name": "Palo Alto Networks - High risk IP addresses",
                            "description": "IP addresses featured in threat activity advisories.",
                        },
                    ],
                }
            },
        )
        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_predefined_url_lists",
            collected_at=timezone.now(),
            payload={
                "url-predefined": {
                    "@max-url-files": "1",
                    "@min-version": "9.2.0",
                    "entry": [
                        {
                            "@name": "panw-auth-portal-exclude-list",
                            "@max-entries": "2000",
                            "filename": "panw-auth-portal-exclude-list",
                            "display-name": "Palo Alto Networks - Authentication Portal Exclude List",
                            "description": "Domains and URLs to exclude from Authentication Policy.",
                        },
                    ],
                }
            },
        )

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        self.assertEqual(normalized.security_rule_failures, [])
        rule = next(rule for rule in normalized.security_rules if rule.name == "rule-predefined-edl")
        destination_refs = list(rule.destination_address_refs.all())
        self.assertEqual(len(destination_refs), 1)
        self.assertEqual(destination_refs[0].ref_type, SecurityRuleDestinationAddressRef.RefType.ADDRESS_OBJECT)
        predefined_object = destination_refs[0].address_object
        self.assertEqual(predefined_object.name, "panw-known-ip-list")
        self.assertEqual(predefined_object.address_type, predefined_object.TYPE_EDL)
        self.assertTrue(predefined_object.is_edl)
        self.assertTrue(predefined_object.is_builtin)
        self.assertEqual(predefined_object.edl_list_type, "ip")
        self.assertEqual(predefined_object.namespace_type, "predefined")

        # The whole catalog normalizes, not just the referenced entry.
        self.assertTrue(
            enforcement_point.address_objects.filter(name="panw-highrisk-ip-list", is_builtin=True).exists()
        )
        self.assertTrue(
            enforcement_point.address_objects.filter(
                name="panw-auth-portal-exclude-list", edl_list_type="url"
            ).exists()
        )


# Captured verbatim from pan-fw-111 on 2026-09-22 (snapshot 394). `show dns-proxy fqdn all`
# answers with a plain text table, not XML - the reason every FQDN object resolved to nothing
# while the tests below were green against an invented `{"entry": [...]}` payload.
REAL_FQDN_CACHE_TABLE = """FQDN Table : Request time 2026-09-22 22:07:46
--------------------------------------------------------------------------------
\tIP Address
--------------------------------------------------------------------------------

VSYS : (using mgmt-obj dnsproxy object)
\tShared
\tvsys1

example.com
\t104.20.23.154
\t172.66.147.243
\t2606:4700:10::ac42:93f3
\t2606:4700:10::6814:179a

sinkhole.paloaltonetworks.com
\t198.135.184.22
\t::  unknown
"""


def _external_list_payload(*, name, members, total_invalid=0, reported_total=None):
    """A `request system external-list show` result in the shape a real device returns.

    Measured on pan-fw-111: members live under external-list > valid-members > member, and the
    stored snapshot payload is the `result` element only (persistence extracts it).
    """
    payload = {
        "external-list": {
            "vsys": "vsys1",
            "name": name,
            "total-valid": str(reported_total if reported_total is not None else len(members)),
            "total-ignored": "0",
            "total-invalid": str(total_invalid),
        }
    }
    if members:
        payload["external-list"]["valid-members"] = {"member": list(members)}
    return payload


class CertificateDecodeNonConformanceTests(SimpleTestCase):
    """A certificate that breaks RFC 5280 but still parses.

    Reported from a remote environment on cryptography 50.0.1: every normalization printed
    "Parsed a serial number which wasn't positive ... disallowed by RFC 5280". Two things were
    wrong with leaving it. The warning subclasses UserWarning rather than DeprecationWarning,
    so Python shows it by default and one bad certificate spams every refresh - twice, since
    loading it and reading its serial each warn. And the fact itself was going nowhere: the
    certificate decodes fine, so `parse_error` stays empty, and `parse_error` is what a control
    reads as "could not be decoded".
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "serial-probe")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256())
        )
        der = certificate.public_bytes(serialization.Encoding.DER)
        cls.valid_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()

        # CertificateBuilder refuses a non-positive serial, so the only way to get one is to
        # edit the DER: the version block A0 03 02 01 02 is followed by serialNumber as
        # INTEGER 02 01 01, and the value byte becomes 00. Nothing verifies the signature on
        # load, so the certificate still parses - which is the whole point.
        marker = bytes.fromhex("a003020102" "020101")
        assert der.count(marker) == 1
        bad_der = der.replace(marker, bytes.fromhex("a003020102" "020100"), 1)
        cls.serial_zero_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            + "\n".join(textwrap.wrap(base64.b64encode(bad_der).decode(), 64))
            + "\n-----END CERTIFICATE-----\n"
        )

    def test_a_non_positive_serial_is_recorded_without_warning_or_parse_error(self):
        with warnings.catch_warnings(record=True) as raised:
            warnings.simplefilter("always")
            decoded = decode_certificate(self.serial_zero_pem)

        # Nothing reaches the caller's log.
        self.assertEqual([str(w.message) for w in raised], [])
        # It decoded, so this is NOT a parse failure - conflating the two would make a control
        # report a readable certificate as unreadable.
        self.assertEqual(decoded["parse_error"], "")
        self.assertEqual(decoded["serial_number"], 0)
        self.assertIn("RFC 5280", decoded["nonconformance"])
        # And the data the certificate controls actually need survives.
        self.assertEqual(decoded["key_algorithm"], "RSA")
        self.assertEqual(decoded["key_size_bits"], 2048)

    def test_a_conformant_certificate_reports_no_nonconformance(self):
        decoded = decode_certificate(self.valid_pem)

        self.assertEqual(decoded["parse_error"], "")
        self.assertEqual(decoded["nonconformance"], "")
        self.assertEqual(decoded["serial_number"], 1)

    def test_unreadable_data_is_still_a_parse_error(self):
        decoded = decode_certificate("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")

        self.assertNotEqual(decoded["parse_error"], "")
        self.assertNotIn("serial_number", decoded)


class DynamicAddressContentNormalizationTests(TestCase):
    def _build_enforcement_point(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-EDL-001",
            appliance_hostname="fw-edl-01",
        )
        return station, appliance, enforcement_point

    def _build_candidate_rule(self, *, enforcement_point, source_address_object, destination_address_object):
        snapshot = Snapshot.objects.create(
            management_station=enforcement_point.management_station,
            appliance=enforcement_point.appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={},
        )
        rule = SecurityRule.objects.create(
            management_station=enforcement_point.management_station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            effective_order=100000,
            rule_position=0,
            name="rule-dynamic-content",
            action="allow",
        )
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=rule,
            raw_value=source_address_object.name,
            position=0,
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=source_address_object,
        )
        SecurityRuleDestinationAddressRef.objects.create(
            security_rule=rule,
            raw_value=destination_address_object.name,
            position=0,
            ref_type=SecurityRuleDestinationAddressRef.RefType.ADDRESS_OBJECT,
            address_object=destination_address_object,
        )
        return rule

    def test_normalize_enforcement_point_dynamic_address_content_merges_and_resolves(self):
        station, appliance, enforcement_point = self._build_enforcement_point()

        edl_object = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=Snapshot.objects.create(
                management_station=station,
                appliance=appliance,
                source_type="show_pushed_shared_policy_vsys",
                collected_at=timezone.now(),
                payload={},
            ),
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name="my-edl",
            namespace_type="pushed_vsys_effective",
            namespace_value="vsys1",
            precedence_rank=30,
            address_type=AddressObject.TYPE_EDL,
            is_edl=True,
            edl_list_type="ip",
            value="ip",
            normalized_value="ip",
        )
        fqdn_object = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=Snapshot.objects.create(
                management_station=station,
                appliance=appliance,
                source_type="show_merged_config",
                collected_at=timezone.now(),
                payload={},
            ),
            config_source=SecurityRule.SOURCE_LOCAL,
            name="example.com",
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=10,
            address_type=AddressObject.TYPE_FQDN,
            value="example.com",
            normalized_value="example.com",
        )
        # Never-collected candidate, to prove graceful "no snapshot yet" degradation.
        never_refreshed_edl = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=edl_object.source_snapshot,
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name="unrefreshed-edl",
            namespace_type="pushed_vsys_effective",
            namespace_value="vsys1",
            precedence_rank=30,
            address_type=AddressObject.TYPE_EDL,
            is_edl=True,
            edl_list_type="ip",
            value="ip",
            normalized_value="ip",
        )

        self._build_candidate_rule(
            enforcement_point=enforcement_point,
            source_address_object=edl_object,
            destination_address_object=fqdn_object,
        )
        rule2 = SecurityRule.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=edl_object.source_snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            effective_order=100001,
            rule_position=1,
            name="rule-unrefreshed",
            action="allow",
        )
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=rule2,
            raw_value=never_refreshed_edl.name,
            position=0,
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=never_refreshed_edl,
        )

        # Adjacent host entries (1.2.3.4 and 1.2.3.5) should merge into a single range.
        Snapshot.objects.create(
            appliance=appliance,
            source_type="show_external_list",
            scope_name="vsys1:my-edl",
            collected_at=timezone.now(),
            payload=_external_list_payload(name="my-edl", members=["1.2.3.4", "1.2.3.5"]),
        )
        Snapshot.objects.create(
            appliance=appliance,
            source_type="show_dns_proxy_fqdn_all",
            collected_at=timezone.now(),
            payload=REAL_FQDN_CACHE_TABLE,
        )

        result = normalize_enforcement_point_dynamic_address_content(enforcement_point)

        self.assertEqual(result.total_resolved_entries, 3)
        self.assertEqual(
            {obj.name for obj in result.updated_address_objects},
            {"my-edl", "example.com"},
        )

        edl_entries = list(edl_object.resolved_entries.order_by("ipv4_start_int"))
        self.assertEqual(len(edl_entries), 1)
        self.assertEqual(
            (edl_entries[0].ipv4_start_int, edl_entries[0].ipv4_end_int),
            (
                int(ipaddress.IPv4Address("1.2.3.4")),
                int(ipaddress.IPv4Address("1.2.3.5")),
            ),
        )

        # The A records only: the two AAAA answers in the same block are out of scope for
        # interval search and must not be mistaken for IPv4 literals.
        fqdn_entries = list(fqdn_object.resolved_entries.order_by("ipv4_start_int"))
        self.assertEqual(len(fqdn_entries), 2)
        self.assertEqual(
            [(entry.ipv4_start_int, entry.ipv4_end_int) for entry in fqdn_entries],
            [
                (int(ipaddress.IPv4Address(host)), int(ipaddress.IPv4Address(host)))
                for host in ("104.20.23.154", "172.66.147.243")
            ],
        )

        self.assertEqual(never_refreshed_edl.resolved_entries.count(), 0)

    def test_normalize_enforcement_point_dynamic_address_content_replaces_stale_entries(self):
        station, appliance, enforcement_point = self._build_enforcement_point()
        edl_object = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=Snapshot.objects.create(
                management_station=station,
                appliance=appliance,
                source_type="show_pushed_shared_policy_vsys",
                collected_at=timezone.now(),
                payload={},
            ),
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name="my-edl",
            namespace_type="pushed_vsys_effective",
            namespace_value="vsys1",
            precedence_rank=30,
            address_type=AddressObject.TYPE_EDL,
            is_edl=True,
            edl_list_type="ip",
            value="ip",
            normalized_value="ip",
        )
        self._build_candidate_rule(
            enforcement_point=enforcement_point,
            source_address_object=edl_object,
            destination_address_object=edl_object,
        )
        AddressObjectResolvedEntry.objects.create(
            address_object=edl_object,
            ipv4_start_int=1,
            ipv4_end_int=2,
            source_snapshot=edl_object.source_snapshot,
            collected_at=timezone.now(),
        )
        Snapshot.objects.create(
            appliance=appliance,
            source_type="show_external_list",
            scope_name="vsys1:my-edl",
            collected_at=timezone.now(),
            payload=_external_list_payload(name="my-edl", members=["10.0.0.0/24"]),
        )

        normalize_enforcement_point_dynamic_address_content(enforcement_point)

        entries = list(edl_object.resolved_entries.all())
        self.assertEqual(len(entries), 1)
        self.assertNotEqual(entries[0].ipv4_start_int, 1)


    def test_unresolvable_external_list_resolves_to_no_entries(self):
        """An EDL the device could not fetch must stay empty, not guess.

        `prod_west_edl` on the lab answers total-valid 0 / total-invalid 1 ("web request failed
        to complete, error:28"). There is nothing to resolve it to, and an object with no
        resolved entries correctly falls back to exclusion from IP-semantic search.
        """
        station, appliance, enforcement_point = self._build_enforcement_point()
        edl_object = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=Snapshot.objects.create(
                management_station=station,
                appliance=appliance,
                source_type="show_pushed_shared_policy_vsys",
                collected_at=timezone.now(),
                payload={},
            ),
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name="my-edl",
            namespace_type="pushed_vsys_effective",
            namespace_value="vsys1",
            precedence_rank=30,
            address_type=AddressObject.TYPE_EDL,
            is_edl=True,
            edl_list_type="ip",
            value="ip",
            normalized_value="ip",
        )
        self._build_candidate_rule(
            enforcement_point=enforcement_point,
            source_address_object=edl_object,
            destination_address_object=edl_object,
        )
        Snapshot.objects.create(
            appliance=appliance,
            source_type="show_external_list",
            scope_name="vsys1:my-edl",
            collected_at=timezone.now(),
            payload=_external_list_payload(name="my-edl", members=[], total_invalid=1),
        )

        result = normalize_enforcement_point_dynamic_address_content(enforcement_point)

        self.assertEqual(result.total_resolved_entries, 0)
        self.assertEqual(edl_object.resolved_entries.count(), 0)


    def test_resolved_content_gives_the_object_a_size(self):
        """An EDL's size is knowable only from its runtime content, so nothing filled
        num_hosts for one until the resolved entries existed. Anything scoring address
        breadth reads that column, and a null on the broadest object type is the gap."""
        station, appliance, enforcement_point = self._build_enforcement_point()
        edl_object = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=Snapshot.objects.create(
                management_station=station, appliance=appliance,
                source_type="show_pushed_shared_policy_vsys",
                collected_at=timezone.now(), payload={},
            ),
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name="my-edl", namespace_type="pushed_vsys_effective", namespace_value="vsys1",
            precedence_rank=30, address_type=AddressObject.TYPE_EDL, is_edl=True,
            edl_list_type="ip", value="ip", normalized_value="ip",
        )
        self._build_candidate_rule(
            enforcement_point=enforcement_point,
            source_address_object=edl_object, destination_address_object=edl_object,
        )
        # 1.2.3.4 and 1.2.3.5 merge to one interval of two; 10.0.0.0/24 is 256.
        Snapshot.objects.create(
            appliance=appliance, source_type="show_external_list",
            scope_name="vsys1:my-edl", collected_at=timezone.now(),
            payload=_external_list_payload(
                name="my-edl", members=["1.2.3.4", "1.2.3.5", "10.0.0.0/24"]),
        )

        normalize_enforcement_point_dynamic_address_content(enforcement_point)

        edl_object.refresh_from_db()
        self.assertEqual(edl_object.num_hosts, 258)

    def test_an_edl_that_resolved_to_nothing_has_a_NULL_size_not_zero(self):
        """0 is the narrowest possible value. An EDL the device could not fetch covers an
        UNKNOWN number of addresses, and storing 0 would make it score as the tightest object
        on the rule - the safe-looking wrong answer."""
        station, appliance, enforcement_point = self._build_enforcement_point()
        edl_object = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=Snapshot.objects.create(
                management_station=station, appliance=appliance,
                source_type="show_pushed_shared_policy_vsys",
                collected_at=timezone.now(), payload={},
            ),
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name="my-edl", namespace_type="pushed_vsys_effective", namespace_value="vsys1",
            precedence_rank=30, address_type=AddressObject.TYPE_EDL, is_edl=True,
            edl_list_type="ip", value="ip", normalized_value="ip",
            num_hosts=999,  # stale from an earlier refresh
        )
        self._build_candidate_rule(
            enforcement_point=enforcement_point,
            source_address_object=edl_object, destination_address_object=edl_object,
        )
        Snapshot.objects.create(
            appliance=appliance, source_type="show_external_list",
            scope_name="vsys1:my-edl", collected_at=timezone.now(),
            payload=_external_list_payload(name="my-edl", members=[], total_invalid=1),
        )

        normalize_enforcement_point_dynamic_address_content(enforcement_point)

        edl_object.refresh_from_db()
        self.assertIsNone(edl_object.num_hosts)

    def test_a_truncated_edl_is_marked_incomplete_and_the_mark_clears(self):
        """A partially-collected EDL must be readable as partial.

        Resolved entries alone cannot say it: an address in the discarded tail looks exactly
        like an address the list does not contain, so "not in this EDL" is unanswerable unless
        the shortfall is recorded. It is measured against the device's own total, never against
        the members in hand.
        """
        station, appliance, enforcement_point = self._build_enforcement_point()
        edl_object = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=Snapshot.objects.create(
                management_station=station,
                appliance=appliance,
                source_type="show_pushed_shared_policy_vsys",
                collected_at=timezone.now(),
                payload={},
            ),
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name="my-edl",
            namespace_type="pushed_vsys_effective",
            namespace_value="vsys1",
            precedence_rank=30,
            address_type=AddressObject.TYPE_EDL,
            is_edl=True,
            edl_list_type="ip",
            value="ip",
            normalized_value="ip",
        )
        self._build_candidate_rule(
            enforcement_point=enforcement_point,
            source_address_object=edl_object,
            destination_address_object=edl_object,
        )
        truncated_snapshot = Snapshot.objects.create(
            appliance=appliance,
            source_type="show_external_list",
            scope_name="vsys1:my-edl",
            collected_at=timezone.now(),
            payload=_external_list_payload(
                name="my-edl", members=["1.2.3.4", "5.6.7.8"], reported_total=4000
            ),
        )

        normalize_enforcement_point_dynamic_address_content(enforcement_point)

        edl_object.refresh_from_db()
        self.assertTrue(edl_object.resolved_content_truncated)
        self.assertEqual(edl_object.resolved_content_source_total, 4000)
        # Truncated is not empty - what WAS collected still resolves.
        self.assertEqual(edl_object.resolved_entries.count(), 2)

        # A later refresh that captures the whole list must clear the mark, not leave the
        # object permanently suspect.
        truncated_snapshot.delete()
        Snapshot.objects.create(
            appliance=appliance,
            source_type="show_external_list",
            scope_name="vsys1:my-edl",
            collected_at=timezone.now(),
            payload=_external_list_payload(name="my-edl", members=["1.2.3.4", "5.6.7.8"]),
        )

        normalize_enforcement_point_dynamic_address_content(enforcement_point)

        edl_object.refresh_from_db()
        self.assertFalse(edl_object.resolved_content_truncated)
        self.assertEqual(edl_object.resolved_content_source_total, 2)

    def test_truncated_resolved_content_is_never_inverted_into_a_complement(self):
        """Partial content is usable for "does it contain this" and unsound once inverted.

        A complement turns the intervals a truncated EDL is MISSING into intervals it claims,
        so a negated rule would be recorded as matching addresses the list actually holds -
        a false clean result, which is the failure direction that matters.
        """
        station, appliance, enforcement_point = self._build_enforcement_point()
        snapshot = Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={},
        )
        edl_object = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name="partial-edl",
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=10,
            address_type=AddressObject.TYPE_EDL,
            is_edl=True,
            edl_list_type="ip",
            value="ip",
            normalized_value="ip",
        )
        AddressObjectResolvedEntry.objects.create(
            address_object=edl_object,
            ipv4_start_int=int(ipaddress.IPv4Address("1.2.3.4")),
            ipv4_end_int=int(ipaddress.IPv4Address("1.2.3.4")),
            source_snapshot=snapshot,
            collected_at=timezone.now(),
        )
        ref = ResolvedAddressRef(
            raw_value="partial-edl",
            position=0,
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=edl_object,
            address_group=None,
        )

        # Complete: the intervals are usable.
        self.assertEqual(
            _member_intervals_or_none(ref),
            [(int(ipaddress.IPv4Address("1.2.3.4")),) * 2],
        )

        edl_object.resolved_content_truncated = True
        edl_object.save(update_fields=["resolved_content_truncated"])

        self.assertIsNone(_member_intervals_or_none(ref))

    def test_candidate_edls_are_paired_with_the_command_type_that_can_read_them(self):
        """`type ip` and `type predefined-ip` accept disjoint sets of names (measured
        2026-09-22 on pan-fw-111), so a candidate name alone cannot be read - every predefined
        list was unreachable while the builder only ever emitted `ip`, and the device's
        rejection blames target-vsys, which sends you looking in the wrong place entirely."""
        station, appliance, enforcement_point = self._build_enforcement_point()
        snapshot = Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={},
        )

        def _edl(name, namespace_type, precedence_rank):
            return AddressObject.objects.create(
                management_station=station,
                enforcement_point=enforcement_point,
                source_snapshot=snapshot,
                config_source=SecurityRule.SOURCE_LOCAL,
                name=name,
                namespace_type=namespace_type,
                namespace_value="vsys1",
                precedence_rank=precedence_rank,
                address_type=AddressObject.TYPE_EDL,
                is_edl=True,
                edl_list_type="ip",
                value="ip",
                normalized_value="ip",
            )

        predefined = _edl("panw-highrisk-ip-list", PolicyObjectNamespace.PREDEFINED, 90)
        custom = _edl("prod_west_edl", PolicyObjectNamespace.LOCAL_VSYS, 10)
        self._build_candidate_rule(
            enforcement_point=enforcement_point,
            source_address_object=predefined,
            destination_address_object=custom,
        )

        self.assertEqual(
            _candidate_edl_names(enforcement_point),
            [("panw-highrisk-ip-list", LIST_TYPE_PREDEFINED), ("prod_west_edl", LIST_TYPE_CUSTOM)],
        )

    def test_show_external_list_command_carries_the_requested_type(self):
        self.assertIn(
            "<predefined-ip><name>panw-highrisk-ip-list</name>",
            build_show_external_list_command(
                name="panw-highrisk-ip-list", anchor=1, list_type=LIST_TYPE_PREDEFINED
            ),
        )
        self.assertIn(
            "<ip><name>prod_west_edl</name>",
            build_show_external_list_command(name="prod_west_edl", anchor=1, list_type=LIST_TYPE_CUSTOM),
        )


class DynamicAddressContentPayloadParsingTests(SimpleTestCase):
    """Parsing guards on the two real payload shapes, measured 2026-09-22 on pan-fw-111.

    Both parsers previously read a shape no device produces, and no test caught it because the
    fixtures were invented from the same guess as the code.
    """

    def test_fqdn_cache_table_parses_names_and_skips_banner_lines(self):
        parsed = _fqdn_addresses_by_name(REAL_FQDN_CACHE_TABLE)

        self.assertEqual(set(parsed), {"example.com", "sinkhole.paloaltonetworks.com"})
        self.assertEqual(
            parsed["example.com"],
            [
                "104.20.23.154",
                "172.66.147.243",
                "2606:4700:10::ac42:93f3",
                "2606:4700:10::6814:179a",
            ],
        )

    def test_fqdn_cache_intervals_skip_ipv6_and_the_unknown_placeholder(self):
        parsed = _fqdn_addresses_by_name(REAL_FQDN_CACHE_TABLE)

        # Four answers, two of them AAAA: only the A records become intervals.
        self.assertEqual(len(_intervals_from_values(parsed["example.com"])), 2)
        # `::  unknown` is the device's placeholder for a family it did not resolve. It must be
        # skipped WITHOUT discarding the IPv4 answer sitting beside it.
        self.assertEqual(
            _intervals_from_values(parsed["sinkhole.paloaltonetworks.com"]),
            [(int(ipaddress.IPv4Address("198.135.184.22")),) * 2],
        )

    def test_external_list_members_are_read_from_valid_members(self):
        result = _external_list_payload(name="panw-highrisk-ip-list", members=["94.156.14.17"])

        self.assertEqual(members_from_result(result), ["94.156.14.17"])
        # The shape this code used to assume. It must not quietly resolve to anything.
        self.assertEqual(members_from_result({"entry": [{"member": "94.156.14.17"}]}), [])

    def test_external_list_ignores_invalid_and_ignored_counts(self):
        self.assertEqual(
            members_from_result(_external_list_payload(name="prod_west_edl", members=[], total_invalid=1)),
            [],
        )


class ExternalListCollectorPaginationTests(SimpleTestCase):
    """Paging and the keep-ceiling.

    The ceiling is a TOTAL across pages (50,000) and the page size is 10,000, so a large list
    is walked up to five times before being cut. The constants are driven explicitly here
    rather than left at their shipped values, because a test that only ever exercises "one
    page, nothing dropped" is how this collector came to have a paging loop that had never once
    executed against anything.
    """

    def _run_with_pages(self, pages, *, page_size=None, max_members=None, reported_total=None):
        calls = []

        def fake_collect(session, *, source_type, request):
            calls.append(request.metadata["anchor"])
            page = pages[len(calls) - 1]
            return SimpleNamespace(
                response={
                    "response": {
                        "result": _external_list_payload(
                            name="edl", members=page, reported_total=reported_total
                        )
                    }
                }
            )

        patches = [
            patch(
                "optivedge_integrations.integrations.platforms.pan_os.collectors.external_list."
                "collect_op_response",
                side_effect=fake_collect,
            )
        ]
        if page_size is not None:
            patches.append(patch.object(external_list_collector, "NUM_RECORDS_PER_PAGE", page_size))
        if max_members is not None:
            patches.append(patch.object(external_list_collector, "MAX_MEMBERS_COLLECTED", max_members))

        with ExitStack() as stack:
            for one in patches:
                stack.enter_context(one)
            collected = collect_show_external_list(SimpleNamespace(target=None), name="edl")
        result = collected.response["response"]["result"]
        members = result["external-list"]["valid-members"]["member"]
        return calls, members, result

    def _members(self, count, *, start=1):
        return [str(ipaddress.IPv4Address(index)) for index in range(start, start + count)]

    def test_a_short_first_page_ends_collection(self):
        calls, members, _ = self._run_with_pages([["1.2.3.4", "1.2.3.5"]])

        self.assertEqual(calls, [1])
        self.assertEqual(members, ["1.2.3.4", "1.2.3.5"])

    def test_an_empty_final_page_ends_the_loop(self):
        """The exact-multiple case, and the reason the loop counts members rather than reading
        the `count` attribute: asking past the end of a 4,000-member list answers
        `count="100"` with zero members (measured), so `count` cannot end the loop."""
        calls, members, _ = self._run_with_pages(
            [self._members(100), []], page_size=100, max_members=10_000
        )

        self.assertEqual(calls, [1, 101])
        self.assertEqual(len(members), 100)

    def test_a_full_page_advances_the_anchor_and_concatenates(self):
        calls, members, _ = self._run_with_pages(
            [self._members(100), ["9.9.9.9"]], page_size=100, max_members=10_000
        )

        self.assertEqual(calls, [1, 101])
        self.assertEqual(len(members), 101)
        self.assertEqual(members[-1], "9.9.9.9")

    def test_the_ceiling_stops_collection_and_keeps_the_first_members(self):
        """A list longer than the ceiling is kept up to it - the FIRST members, and no more."""
        calls, members, _ = self._run_with_pages(
            [self._members(100), self._members(100, start=101), self._members(100, start=201)],
            page_size=100,
            max_members=250,
            reported_total=4000,
        )

        self.assertEqual(calls, [1, 101, 201])
        self.assertEqual(len(members), 250)
        self.assertEqual(members[0], "0.0.0.1")
        self.assertEqual(members[-1], "0.0.0.250")

    def test_the_stored_payload_reports_the_devices_total_not_what_was_kept(self):
        """The shortfall is the only evidence anything was dropped, so the device's own count
        has to survive into the snapshot - overwriting it with len(kept) would erase it."""
        _calls, members, result = self._run_with_pages(
            [self._members(100), self._members(100, start=101)],
            page_size=100,
            max_members=150,
            reported_total=4000,
        )

        self.assertEqual(len(members), 150)
        self.assertEqual(result["external-list"]["total-valid"], "4000")
        self.assertEqual(total_valid_from_result(result), 4000)


    def test_collector_output_survives_persistence_into_the_normalizer(self):
        """The seam between the two modules this pair of bugs lived in.

        Each side was tested against its own idea of the payload and never against the other,
        which is exactly how a shape nobody had measured stayed wrong in both places. This
        asserts the contract directly: what the collector emits, put through the persistence
        step that decides what lands in Snapshot.payload, is what the normalizer's reader
        parses - no fixture standing in for either side.
        """
        calls_pages = [["1.2.3.4", "10.0.0.0/24"]]

        def fake_collect(session, *, source_type, request):
            return SimpleNamespace(
                response={"response": {"result": _external_list_payload(name="edl", members=calls_pages[0])}}
            )

        with patch(
            "optivedge_integrations.integrations.platforms.pan_os.collectors.external_list.collect_op_response",
            side_effect=fake_collect,
        ):
            collected = collect_show_external_list(SimpleNamespace(target=None), name="edl")

        payload = extract_result_payload(collected)

        self.assertEqual(
            _edl_members_from_snapshot(SimpleNamespace(payload=payload)),
            ["1.2.3.4", "10.0.0.0/24"],
        )


class NegatedComplementNormalizationTests(TestCase):
    def _build_enforcement_point(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-NEG-001",
            appliance_hostname="fw-neg-01",
        )
        return station, appliance, enforcement_point

    def _build_pushed_snapshot(self, *, station, enforcement_point):
        _create_empty_pushed_policy_snapshot(station=station, enforcement_point=enforcement_point)

    def test_a_negated_complement_is_sized_like_any_other_object(self):
        """A complement is usually the broadest thing on a rule - inverting two hosts leaves
        4,294,967,294 addresses - and it carried no num_hosts at all, so a scorer reading that
        column saw the widest object on the rule as size-unknown."""
        station, appliance, enforcement_point = self._build_enforcement_point()
        Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": {"vsys": {"entry": {
                "@name": "vsys1",
                "address": {"entry": [
                    {"@name": "host-a", "ip-netmask": "10.0.0.5/32"},
                    {"@name": "host-b", "ip-netmask": "10.0.0.10/32"},
                ]},
                "address-group": {"entry": [
                    {"@name": "static-src", "static": {"member": ["host-a", "host-b"]}},
                ]},
                "rulebase": {
                    "security": {"rules": {"entry": [{
                        "@name": "rule-negated",
                        "from": {"member": ["trust"]}, "to": {"member": ["untrust"]},
                        "source": {"member": ["static-src"]},
                        "destination": {"member": ["any"]},
                        "application": {"member": ["ssl"]},
                        "service": {"member": ["application-default"]},
                        "action": "allow", "negate-source": "yes",
                    }]}},
                    "default-security-rules": {"rules": {"entry": []}},
                },
            }}}}}},
        )
        self._build_pushed_snapshot(station=station, enforcement_point=enforcement_point)
        normalize_enforcement_point_addresses(enforcement_point)
        normalize_enforcement_point_security_rules(enforcement_point)

        complement = AddressObject.objects.get(
            synthetic_kind=AddressObject.SYNTHETIC_KIND_NEGATED_COMPLEMENT)
        # The whole space minus the two hosts that were negated.
        self.assertEqual(complement.num_hosts, 4_294_967_296 - 2)
        self.assertEqual(
            complement.num_hosts,
            sum(e.ipv4_end_int - e.ipv4_start_int + 1 for e in complement.resolved_entries.all()),
        )

    def test_negated_source_with_resolvable_members_creates_complement_with_multiple_gaps(self):
        station, appliance, enforcement_point = self._build_enforcement_point()

        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "address": {
                                        "entry": [
                                            {"@name": "host-a", "ip-netmask": "10.0.0.5/32"},
                                            {"@name": "host-b", "ip-netmask": "10.0.0.10/32"},
                                        ]
                                    },
                                    "address-group": {
                                        "entry": [
                                            {
                                                "@name": "static-src",
                                                "static": {"member": ["host-a", "host-b"]},
                                            },
                                        ]
                                    },
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-negated",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["static-src"]},
                                                        "destination": {"member": ["any"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                        "negate-source": "yes",
                                                    },
                                                ]
                                            }
                                        },
                                        "default-security-rules": {"rules": {"entry": []}},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        self._build_pushed_snapshot(station=station, enforcement_point=enforcement_point)

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        rule = next(r for r in normalized.security_rules if r.name == "rule-negated")
        self.assertTrue(rule.negate_source)
        self.assertFalse(rule.negate_destination)

        source_refs = list(rule.source_address_refs.order_by("id"))
        # 2 flattened static-group members (unchanged, kept for name search/audit) + 1
        # synthetic complement ref.
        self.assertEqual(len(source_refs), 3)

        complement_refs = [
            ref for ref in source_refs if ref.address_object is not None and ref.address_object.is_synthetic
        ]
        self.assertEqual(len(complement_refs), 1)
        complement_object = complement_refs[0].address_object
        self.assertEqual(complement_object.synthetic_kind, AddressObject.SYNTHETIC_KIND_NEGATED_COMPLEMENT)
        self.assertEqual(complement_object.address_type, AddressObject.TYPE_NEGATED_COMPLEMENT)

        host_a_int = int(ipaddress.IPv4Address("10.0.0.5"))
        host_b_int = int(ipaddress.IPv4Address("10.0.0.10"))
        expected_intervals = {
            (0, host_a_int - 1),
            (host_a_int + 1, host_b_int - 1),
            (host_b_int + 1, 4_294_967_295),
        }
        actual_intervals = {
            (entry.ipv4_start_int, entry.ipv4_end_int) for entry in complement_object.resolved_entries.all()
        }
        self.assertEqual(actual_intervals, expected_intervals)

        # Re-running normalization must not accumulate stale/duplicate complement objects.
        normalize_enforcement_point_security_rules(enforcement_point)
        self.assertEqual(
            AddressObject.objects.filter(
                enforcement_point=enforcement_point,
                synthetic_kind=AddressObject.SYNTHETIC_KIND_NEGATED_COMPLEMENT,
            ).count(),
            1,
        )

    def test_negated_source_with_dynamic_group_member_skips_complement(self):
        station, appliance, enforcement_point = self._build_enforcement_point()

        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "address": {"entry": []},
                                    "address-group": {
                                        "entry": [
                                            {"@name": "dyn-src", "dynamic": {"filter": "'tag1'"}},
                                        ]
                                    },
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-negated-dynamic",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["dyn-src"]},
                                                        "destination": {"member": ["any"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                        "negate-source": "yes",
                                                    },
                                                ]
                                            }
                                        },
                                        "default-security-rules": {"rules": {"entry": []}},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        self._build_pushed_snapshot(station=station, enforcement_point=enforcement_point)

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        rule = next(r for r in normalized.security_rules if r.name == "rule-negated-dynamic")
        self.assertTrue(rule.negate_source)
        source_refs = list(rule.source_address_refs.all())
        self.assertEqual(len(source_refs), 1)
        self.assertEqual(source_refs[0].ref_type, SecurityRuleSourceAddressRef.RefType.DYNAMIC_ADDRESS_GROUP)
        self.assertEqual(
            AddressObject.objects.filter(
                enforcement_point=enforcement_point,
                synthetic_kind=AddressObject.SYNTHETIC_KIND_NEGATED_COMPLEMENT,
            ).count(),
            0,
        )

    def test_negated_source_with_unrefreshed_edl_member_skips_complement(self):
        station, appliance, enforcement_point = self._build_enforcement_point()

        merged_snapshot = Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "devices": {
                        "entry": {
                            "vsys": {
                                "entry": {
                                    "@name": "vsys1",
                                    "address": {"entry": []},
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-negated-edl",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["my-edl"]},
                                                        "destination": {"member": ["any"]},
                                                        "application": {"member": ["ssl"]},
                                                        "service": {"member": ["application-default"]},
                                                        "action": "allow",
                                                        "negate-source": "yes",
                                                    },
                                                ]
                                            }
                                        },
                                        "default-security-rules": {"rules": {"entry": []}},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        )
        self._build_pushed_snapshot(station=station, enforcement_point=enforcement_point)

        # Pre-created directly (bypassing normalize_enforcement_point_addresses, which would
        # wipe it since the merged config's own address book is empty above) with zero
        # resolved entries - i.e. never refreshed via "Refresh EDL/FQDN Cache". The builtin
        # "any" object is likewise pre-created directly since the normal address-normalization
        # pass (which would create it) is skipped in this test.
        AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=merged_snapshot,
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name="my-edl",
            namespace_type="pushed_vsys_effective",
            namespace_value="vsys1",
            precedence_rank=30,
            address_type=AddressObject.TYPE_EDL,
            is_edl=True,
            edl_list_type="ip",
            value="ip",
            normalized_value="ip",
        )
        AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=merged_snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name="any",
            namespace_type="builtin",
            namespace_value="any",
            precedence_rank=90,
            address_type=AddressObject.TYPE_BUILTIN_ANY,
            value="any",
            normalized_value="any",
            ipv4_start_int=0,
            ipv4_end_int=4_294_967_295,
            num_hosts=4_294_967_296,
            is_any=True,
            is_builtin=True,
        )

        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        rule = next(r for r in normalized.security_rules if r.name == "rule-negated-edl")
        self.assertTrue(rule.negate_source)
        source_refs = list(rule.source_address_refs.all())
        self.assertEqual(len(source_refs), 1)
        self.assertEqual(source_refs[0].ref_type, SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT)
        self.assertFalse(source_refs[0].address_object.is_synthetic)
        self.assertEqual(
            AddressObject.objects.filter(
                enforcement_point=enforcement_point,
                synthetic_kind=AddressObject.SYNTHETIC_KIND_NEGATED_COMPLEMENT,
            ).count(),
            0,
        )


class SecurityRuleSearchVocabularyEntryTests(TestCase):
    def test_save_populates_lookup_fields(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )

        entry = SecurityRuleSearchVocabularyEntry.objects.create(
            management_station=station,
            field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.DESTINATION_ADDRESS_NAME,
            canonical_value="ao-sanctioned-saas-provider-endpoints-01",
            rule_count=7,
            usage_count=9,
        )

        self.assertEqual(
            entry.normalized_value,
            "ao sanctioned saas provider endpoints 01",
        )
        self.assertEqual(
            entry.compact_value,
            "aosanctionedsaasproviderendpoints01",
        )

    def test_unique_constraint_is_scoped_by_station_and_field_family(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        SecurityRuleSearchVocabularyEntry.objects.create(
            management_station=station,
            field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.APPLICATION,
            canonical_value="ms-teams",
        )

        duplicate = SecurityRuleSearchVocabularyEntry(
            management_station=station,
            field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.APPLICATION,
            canonical_value="ms-teams",
        )

        with self.assertRaises(IntegrityError):
            duplicate.save()


class SecurityRuleSearchVocabularyRebuildTests(TestCase):
    def test_rebuild_security_rule_search_vocabulary_populates_entries_from_normalized_data(self):
        station, enforcement_point, snapshot = self._create_rule_scope("panorama-vocab.local", "SERIAL-V1", "fw-v1")

        remote_user = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source="local",
            name="ao-remote-workforce-vpn-users-01",
            namespace_type="local_vsys",
            namespace_value=enforcement_point.vsys_name,
            precedence_rank=10,
            address_type=AddressObject.TYPE_IP_NETMASK,
        )
        managed_laptop = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source="local",
            name="ao-managed-wireless-laptops-01",
            namespace_type="local_vsys",
            namespace_value=enforcement_point.vsys_name,
            precedence_rank=10,
            address_type=AddressObject.TYPE_IP_NETMASK,
        )
        sanctioned_saas = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source="local",
            name="ao-sanctioned-saas-provider-endpoints-01",
            namespace_type="local_vsys",
            namespace_value=enforcement_point.vsys_name,
            precedence_rank=10,
            address_type=AddressObject.TYPE_IP_NETMASK,
        )
        workforce_group = AddressGroup.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source="local",
            name="ag-remote-workforce",
            namespace_type="local_vsys",
            namespace_value=enforcement_point.vsys_name,
            precedence_rank=10,
        )

        first_rule = self._create_security_rule(
            station=station,
            enforcement_point=enforcement_point,
            snapshot=snapshot,
            name="rule-01",
            effective_order=1,
            rule_position=1,
        )
        second_rule = self._create_security_rule(
            station=station,
            enforcement_point=enforcement_point,
            snapshot=snapshot,
            name="rule-02",
            effective_order=2,
            rule_position=2,
        )

        SecurityRuleSourceAddressRef.objects.create(
            security_rule=first_rule,
            raw_value="ao-remote-workforce-vpn-users-01",
            position=1,
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=remote_user,
        )
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=second_rule,
            raw_value="ag-remote-workforce",
            position=1,
            ref_type=SecurityRuleSourceAddressRef.RefType.STATIC_ADDRESS_GROUP,
            address_object=managed_laptop,
            address_group=workforce_group,
        )
        SecurityRuleDestinationAddressRef.objects.create(
            security_rule=first_rule,
            raw_value="ao-sanctioned-saas-provider-endpoints-01",
            position=1,
            ref_type=SecurityRuleDestinationAddressRef.RefType.ADDRESS_OBJECT,
            address_object=sanctioned_saas,
        )
        SecurityRuleDestinationAddressRef.objects.create(
            security_rule=second_rule,
            raw_value="ao-sanctioned-saas-provider-endpoints-01",
            position=1,
            ref_type=SecurityRuleDestinationAddressRef.RefType.ADDRESS_OBJECT,
            address_object=sanctioned_saas,
        )
        SecurityRuleApplication.objects.create(
            security_rule=first_rule,
            value="ms-office365-base",
            position=1,
        )
        SecurityRuleApplication.objects.create(
            security_rule=second_rule,
            value="ms-office365-base",
            position=1,
        )
        SecurityRuleApplication.objects.create(
            security_rule=second_rule,
            value="ms-teams",
            position=2,
        )
        SecurityRuleService.objects.create(
            security_rule=first_rule,
            value="application-default",
            position=1,
        )
        SecurityRuleService.objects.create(
            security_rule=second_rule,
            value="any",
            position=1,
        )

        result = rebuild_security_rule_search_vocabulary(station)

        self.assertEqual(result.deleted_entry_count, 0)
        self.assertGreater(result.created_entry_count, 0)

        office_entry = SecurityRuleSearchVocabularyEntry.objects.get(
            management_station=station,
            field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.APPLICATION,
            canonical_value="ms-office365-base",
        )
        self.assertEqual(office_entry.rule_count, 2)
        self.assertEqual(office_entry.usage_count, 2)

        destination_entry = SecurityRuleSearchVocabularyEntry.objects.get(
            management_station=station,
            field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.DESTINATION_ADDRESS_NAME,
            canonical_value="ao-sanctioned-saas-provider-endpoints-01",
        )
        self.assertEqual(destination_entry.rule_count, 2)
        self.assertEqual(destination_entry.usage_count, 4)

        group_entry = SecurityRuleSearchVocabularyEntry.objects.get(
            management_station=station,
            field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.SOURCE_ADDRESS_NAME,
            canonical_value="ag-remote-workforce",
        )
        self.assertEqual(group_entry.rule_count, 1)
        self.assertEqual(group_entry.usage_count, 2)

    def test_rebuild_security_rule_search_vocabulary_replaces_only_target_station_entries(self):
        station_one, enforcement_point_one, snapshot_one = self._create_rule_scope(
            "panorama-one.local",
            "SERIAL-R1",
            "fw-r1",
        )
        station_two, enforcement_point_two, snapshot_two = self._create_rule_scope(
            "panorama-two.local",
            "SERIAL-R2",
            "fw-r2",
        )

        rule_one = self._create_security_rule(
            station=station_one,
            enforcement_point=enforcement_point_one,
            snapshot=snapshot_one,
            name="rule-one",
            effective_order=1,
            rule_position=1,
        )
        SecurityRuleApplication.objects.create(
            security_rule=rule_one,
            value="ms-teams",
            position=1,
        )

        rule_two = self._create_security_rule(
            station=station_two,
            enforcement_point=enforcement_point_two,
            snapshot=snapshot_two,
            name="rule-two",
            effective_order=1,
            rule_position=1,
        )
        SecurityRuleApplication.objects.create(
            security_rule=rule_two,
            value="ms-office365-base",
            position=1,
        )

        rebuild_all_security_rule_search_vocabulary()

        stale_entry = SecurityRuleSearchVocabularyEntry.objects.create(
            management_station=station_one,
            field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.SERVICE,
            canonical_value="stale-value",
        )

        result = rebuild_security_rule_search_vocabulary(station_one)

        self.assertGreaterEqual(result.deleted_entry_count, 1)
        self.assertFalse(SecurityRuleSearchVocabularyEntry.objects.filter(pk=stale_entry.pk).exists())
        self.assertTrue(
            SecurityRuleSearchVocabularyEntry.objects.filter(
                management_station=station_two,
                field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.APPLICATION,
                canonical_value="ms-office365-base",
            ).exists()
        )

    def _create_rule_scope(self, hostname: str, serial_number: str, appliance_hostname: str):
        station, _appliance, enforcement_point = _create_panorama_enforcement_point(
            station_hostname=hostname,
            serial_number=serial_number,
            appliance_hostname=appliance_hostname,
        )
        snapshot = Snapshot.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_type="unit_test_snapshot",
            collected_at=timezone.now(),
            payload={},
        )
        return station, enforcement_point, snapshot

    def _create_security_rule(
        self,
        *,
        station: ManagementStation,
        enforcement_point: EnforcementPoint,
        snapshot: Snapshot,
        name: str,
        effective_order: int,
        rule_position: int,
    ) -> SecurityRule:
        return SecurityRule.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source="local",
            effective_order=effective_order,
            rule_position=rule_position,
            name=name,
        )


class IntegrationOrchestrationTests(TestCase):
    def test_refresh_panorama_in_scope_data_runs_platform_refresh_then_vocabulary_rebuild(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-orch.local",
        )
        call_order: list[tuple[str, object]] = []

        platform_result = object()

        def fake_platform_refresh(*args, **kwargs):
            call_order.append(("platform", args[0]))
            return platform_result

        def fake_vocab_rebuild(management_station):
            call_order.append(("vocab", management_station))
            return "vocab-result"

        with patch(
            "optivedge_integrations.integrations.orchestration.pan_os.refresh_in_scope_configuration_snapshots",
            side_effect=fake_platform_refresh,
        ), patch(
            "optivedge_integrations.integrations.orchestration.pan_os.rebuild_security_rule_search_vocabulary",
            side_effect=fake_vocab_rebuild,
        ):
            result = refresh_panorama_in_scope_data(station)

        self.assertIs(result.platform_refresh, platform_result)
        self.assertEqual(result.security_rule_search_vocabulary, "vocab-result")
        self.assertEqual(
            call_order,
            [
                ("platform", station),
                ("vocab", station),
            ],
        )

class ManagementStationBulkInScopeSyncViewTests(TestCase):
    def test_post_starts_background_refresh_and_redirects_immediately(self):
        panorama_one = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-view-one.local",
        )
        panorama_two = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-view-two.local",
        )
        ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_FIREWALL,
            hostname="firewall-view.local",
        )

        with (
            patch("optivedge_integrations.integrations.views.threading.Thread") as mocked_thread_cls,
            patch("optivedge_integrations.integrations.views._refresh_station_in_scope_with_tracking") as mocked_refresh,
            patch("optivedge_integrations.integrations.views.rebuild_all_security_rule_search_vocabulary") as mocked_vocab,
        ):
            response = self.client.post(reverse("management_station_bulk_in_scope_sync"))

            # The view starts a background thread instead of running the refresh inline.
            mocked_thread_cls.assert_called_once()
            _, kwargs = mocked_thread_cls.call_args
            self.assertTrue(kwargs["daemon"])
            mocked_thread_cls.return_value.start.assert_called_once()
            mocked_refresh.assert_not_called()
            mocked_vocab.assert_not_called()

            # Invoking the thread's target directly simulates the background thread running,
            # while the patches above are still active.
            kwargs["target"]()

            # Only the Panorama stations are refreshed, one call each, in hostname order;
            # the vocabulary rebuild runs once afterward, covering all stations.
            self.assertEqual(
                [call_args.args[0] for call_args in mocked_refresh.call_args_list],
                [panorama_one, panorama_two],
            )
            mocked_vocab.assert_called_once_with()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("management_station_list"))

        messages = list(response.wsgi_request._messages)
        self.assertEqual(len(messages), 1)
        self.assertIn("started in the background", messages[0].message)

    def test_post_continues_remaining_stations_when_one_fails(self):
        panorama_one = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-view-one.local",
        )
        panorama_two = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-view-two.local",
        )

        with (
            patch("optivedge_integrations.integrations.views.threading.Thread") as mocked_thread_cls,
            patch(
                "optivedge_integrations.integrations.views._refresh_station_in_scope_with_tracking",
                side_effect=[RuntimeError("boom"), None],
            ) as mocked_refresh,
            patch("optivedge_integrations.integrations.views.rebuild_all_security_rule_search_vocabulary") as mocked_vocab,
        ):
            self.client.post(reverse("management_station_bulk_in_scope_sync"))
            _, kwargs = mocked_thread_cls.call_args
            kwargs["target"]()

        # The second station is still refreshed even though the first raised.
        self.assertEqual(
            [call_args.args[0] for call_args in mocked_refresh.call_args_list],
            [panorama_one, panorama_two],
        )
        mocked_vocab.assert_called_once_with()

    def test_the_list_no_longer_offers_the_bulk_or_per_row_actions(self):
        """The bulk sweep, Renormalize and the EDL/FQDN refresh were taken off the list:
        the station detail's workflow is where collection is driven from now. The routes
        stay by decision - this pins only that the page stopped linking them."""
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-list-actions.local",
        )
        response = self.client.get(reverse("management_station_list"))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Refresh All In Scope")
        self.assertNotContains(response, reverse("management_station_bulk_in_scope_sync"))
        self.assertNotContains(
            response, reverse("management_station_renormalize", kwargs={"pk": station.pk}))
        self.assertNotContains(
            response,
            reverse("management_station_refresh_dynamic_content", kwargs={"pk": station.pk}),
        )


class ManagementStationCrudViewTests(TestCase):
    def test_create_view_creates_station_and_redirects_to_detail(self):
        response = self.client.post(
            reverse("management_station_create"),
            {
                "station_type": ManagementStation.StationType.PAN_PANORAMA,
                "name": "Test Panorama",
                "hostname": "panorama-create.local",
                "port": 443,
                "username": "admin",
                "password": "",
                "api_key": "",
                "ca_bundle_path": "",
                "notes": "",
            },
        )

        station = ManagementStation.objects.get(hostname="panorama-create.local")
        self.assertRedirects(
            response,
            reverse("management_station_detail", kwargs={"pk": station.pk}),
        )
        self.assertEqual(station.name, "Test Panorama")

    def test_detail_view_renders_default_and_each_tab(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-detail.local",
        )

        for tab in ("details", "enforcement-points", "events"):
            response = self.client.get(
                reverse("management_station_detail", kwargs={"pk": station.pk}),
                {"tab": tab},
            )
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, station.hostname)

    def test_update_view_updates_station_and_redirects_to_detail(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-update.local",
        )

        response = self.client.post(
            reverse("management_station_update", kwargs={"pk": station.pk}),
            {
                "station_type": ManagementStation.StationType.PAN_PANORAMA,
                "name": "Updated name",
                "hostname": "panorama-update.local",
                "port": 443,
                "username": "",
                "password": "",
                "api_key": "",
                "ca_bundle_path": "",
                "notes": "",
            },
        )

        station.refresh_from_db()
        self.assertRedirects(
            response,
            reverse("management_station_detail", kwargs={"pk": station.pk}),
        )
        self.assertEqual(station.name, "Updated name")

    def test_delete_view_deletes_station_and_redirects_to_list(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-delete.local",
        )

        response = self.client.post(
            reverse("management_station_delete", kwargs={"pk": station.pk})
        )

        self.assertRedirects(response, reverse("management_station_list"))
        self.assertFalse(ManagementStation.objects.filter(pk=station.pk).exists())


class ManagementStationActionViewTests(TestCase):
    def _create_panorama_station(self, hostname):
        return ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname=hostname,
        )

    def _create_firewall_station(self, hostname):
        return ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_FIREWALL,
            hostname=hostname,
        )

    def test_sync_view_rejects_non_panorama_station(self):
        station = self._create_firewall_station("firewall-sync.local")

        with patch(
            "optivedge_integrations.integrations.views.collect_persist_and_normalize"
        ) as mocked_collect:
            response = self.client.post(
                reverse("management_station_sync", kwargs={"pk": station.pk})
            )

        mocked_collect.assert_not_called()
        self.assertRedirects(
            response,
            reverse("management_station_detail", kwargs={"pk": station.pk}),
        )
        messages = list(response.wsgi_request._messages)
        self.assertIn("only supported for Panorama", messages[0].message)

    def test_sync_view_collects_for_panorama_station(self):
        station = self._create_panorama_station("panorama-sync.local")

        with patch(
            "optivedge_integrations.integrations.views.collect_persist_and_normalize"
        ) as mocked_collect, patch(
            "optivedge_integrations.integrations.views.collect_and_normalize_device_groups"
        ) as mocked_device_groups:
            response = self.client.post(
                reverse("management_station_sync", kwargs={"pk": station.pk})
            )

        mocked_collect.assert_called_once()
        # A station sync collects the device-group tree as well as the devices.
        mocked_device_groups.assert_called_once()
        self.assertRedirects(
            response,
            reverse("management_station_detail", kwargs={"pk": station.pk}),
        )
        run = IntegrationRun.objects.get(management_station=station)
        self.assertEqual(run.status, IntegrationRun.STATUS_SUCCEEDED)

    def test_sync_view_records_failed_run_when_collection_raises(self):
        station = self._create_panorama_station("panorama-sync-fail.local")

        with patch(
            "optivedge_integrations.integrations.views.collect_persist_and_normalize",
            side_effect=RuntimeError("device unreachable"),
        ):
            response = self.client.post(
                reverse("management_station_sync", kwargs={"pk": station.pk})
            )

        self.assertRedirects(
            response,
            reverse("management_station_detail", kwargs={"pk": station.pk}),
        )
        run = IntegrationRun.objects.get(management_station=station)
        self.assertEqual(run.status, IntegrationRun.STATUS_FAILED)
        self.assertTrue(
            IntegrationEvent.objects.filter(
                management_station=station,
                reason="InventoryCollectionFailed",
            ).exists()
        )

    def test_in_scope_sync_view_rejects_non_panorama_station(self):
        station = self._create_firewall_station("firewall-in-scope.local")

        with patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_configuration_snapshots"
        ) as mocked_refresh:
            response = self.client.post(
                reverse("management_station_in_scope_sync", kwargs={"pk": station.pk})
            )

        mocked_refresh.assert_not_called()
        self.assertRedirects(
            response,
            reverse("management_station_detail", kwargs={"pk": station.pk}),
        )

    def test_in_scope_sync_view_starts_a_background_collection_and_returns_at_once(self):
        station = self._create_panorama_station("panorama-in-scope.local")

        with patch("optivedge_integrations.integrations.views.threading.Thread") as mocked_thread_cls, patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_configuration_snapshots",
        ) as mocked_refresh:
            response = self.client.post(
                reverse("management_station_in_scope_sync", kwargs={"pk": station.pk})
            )

        self.assertRedirects(
            response,
            reverse("management_station_detail", kwargs={"pk": station.pk}),
        )
        # Nothing is collected inside the request.
        mocked_refresh.assert_not_called()
        mocked_thread_cls.return_value.start.assert_called_once()
        _, kwargs = mocked_thread_cls.call_args
        self.assertTrue(kwargs["daemon"])
        self.assertIs(kwargs["target"], views_module._run_station_collection_in_background)
        # The run is opened BEFORE the redirect, so the page landed on already shows it.
        run = IntegrationRun.objects.get(management_station=station)
        self.assertEqual(run.status, IntegrationRun.STATUS_RUNNING)
        self.assertEqual(kwargs["args"], (station.pk, run.pk))
        self.assertTrue(views_module.collection_in_progress(station))
        messages = [m.message for m in response.wsgi_request._messages]
        self.assertIn("started in the background", messages[0])

    def test_a_second_collection_is_refused_while_one_is_running(self):
        station = self._create_panorama_station("panorama-in-scope-busy.local")
        views_module._open_in_scope_refresh_run(station)

        with patch("optivedge_integrations.integrations.views.threading.Thread") as mocked_thread_cls:
            response = self.client.post(
                reverse("management_station_in_scope_sync", kwargs={"pk": station.pk})
            )

        mocked_thread_cls.assert_not_called()
        self.assertEqual(IntegrationRun.objects.filter(management_station=station).count(), 1)
        messages = [m.message for m in response.wsgi_request._messages]
        self.assertIn("already running", messages[0])

    def test_an_orphaned_running_run_does_not_lock_the_button_for_ever(self):
        """A daemon thread dies with the server and leaves its run RUNNING."""
        station = self._create_panorama_station("panorama-in-scope-orphan.local")
        orphan = views_module._open_in_scope_refresh_run(station)
        IntegrationRun.objects.filter(pk=orphan.pk).update(
            started_at=timezone.now() - views_module.COLLECTION_LOCK_MAX_AGE - timedelta(minutes=1),
        )
        self.assertFalse(views_module.collection_in_progress(station))

        with patch("optivedge_integrations.integrations.views.threading.Thread") as mocked_thread_cls:
            self.client.post(
                reverse("management_station_in_scope_sync", kwargs={"pk": station.pk})
            )

        mocked_thread_cls.return_value.start.assert_called_once()

    def test_the_background_collection_runs_every_collection_type(self):
        """Step 3 is one action for every collection type: configuration, then EDL/FQDN
        content, then the search grounding built from the rules just written."""
        station = self._create_panorama_station("panorama-in-scope-body.local")
        run = views_module._open_in_scope_refresh_run(station)

        with patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_configuration_snapshots",
            return_value=_empty_in_scope_refresh_collection(),
        ), patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_dynamic_content",
            return_value=_empty_dynamic_content_refresh_result(),
        ) as mocked_dynamic, patch(
            "optivedge_integrations.integrations.views.rebuild_security_rule_search_vocabulary",
        ) as mocked_vocab:
            views_module._collect_and_normalize_station(station, run)

        mocked_dynamic.assert_called_once_with(station)
        mocked_vocab.assert_called_once_with(station)
        runs = IntegrationRun.objects.filter(management_station=station)
        self.assertEqual(runs.count(), 2)
        self.assertEqual({r.status for r in runs}, {IntegrationRun.STATUS_SUCCEEDED})
        self.assertFalse(views_module.collection_in_progress(station))

    def test_the_background_collection_skips_edl_fqdn_when_the_configuration_refresh_failed(self):
        """EDL/FQDN candidates are read from the rules the configuration refresh writes, so
        after an outright failure there is nothing current to resolve against."""
        station = self._create_panorama_station("panorama-in-scope-fail.local")
        run = views_module._open_in_scope_refresh_run(station)

        with patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_configuration_snapshots",
            side_effect=RuntimeError("panorama unreachable"),
        ), patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_dynamic_content",
        ) as mocked_dynamic, patch(
            "optivedge_integrations.integrations.views.rebuild_security_rule_search_vocabulary",
        ):
            views_module._collect_and_normalize_station(station, run)

        mocked_dynamic.assert_not_called()
        run.refresh_from_db()
        self.assertEqual(run.status, IntegrationRun.STATUS_FAILED)

    def test_an_edl_fqdn_refresh_that_raises_still_closes_its_run(self):
        station = self._create_panorama_station("panorama-dynamic-raise.local")
        run = views_module._open_in_scope_refresh_run(station)

        with patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_configuration_snapshots",
            return_value=_empty_in_scope_refresh_collection(),
        ), patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_dynamic_content",
            side_effect=RuntimeError("edl endpoint exploded"),
        ), patch(
            "optivedge_integrations.integrations.views.rebuild_security_rule_search_vocabulary",
        ):
            views_module._collect_and_normalize_station(station, run)

        self.assertFalse(
            IntegrationRun.objects.filter(
                management_station=station, status=IntegrationRun.STATUS_RUNNING,
            ).exists()
        )
        self.assertTrue(
            IntegrationEvent.objects.filter(
                management_station=station, reason="DynamicContentRefreshFailed",
            ).exists()
        )

    def test_the_thread_entry_point_closes_the_run_when_something_unexpected_raises(self):
        station = self._create_panorama_station("panorama-thread-raise.local")
        run = views_module._open_in_scope_refresh_run(station)
        # A renormalize beside it is not this collection's to close.
        other = IntegrationRun.objects.create(
            management_station=station,
            run_scope=IntegrationRun.SCOPE_APPLIANCE,
            status=IntegrationRun.STATUS_RUNNING,
        )

        with patch(
            "optivedge_integrations.integrations.views._collect_and_normalize_station",
            side_effect=RuntimeError("bookkeeping bug"),
        ), patch("optivedge_integrations.integrations.views.connections") as mocked_connections:
            views_module._run_station_collection_in_background(station.pk, run.pk)

        mocked_connections.close_all.assert_called_once_with()
        run.refresh_from_db()
        other.refresh_from_db()
        self.assertEqual(run.status, IntegrationRun.STATUS_FAILED)
        self.assertIsNotNone(run.completed_at)
        self.assertEqual(other.status, IntegrationRun.STATUS_RUNNING)

    def test_renormalize_view_starts_a_background_thread_and_returns(self):
        """Renormalize rewrites every rule, address and profile for every in-scope enforcement
        point. Held in the request the browser waited for all of it - a collection's work minus
        the device contact - so it is a thread now, like the collection beside it.

        The thread is not actually started: a real one opens its own database connection and
        would not see this test's transaction. The work itself is covered by
        `test_renormalize_completes_the_run_it_was_given`."""
        station = self._create_panorama_station("panorama-renorm.local")

        with patch("optivedge_integrations.integrations.views.threading.Thread") as thread:
            response = self.client.post(
                reverse("management_station_renormalize", kwargs={"pk": station.pk})
            )

        # Offered from step 3 on the station details tab now, so it returns there.
        self.assertRedirects(
            response, reverse("management_station_detail", kwargs={"pk": station.pk}))
        run = IntegrationRun.objects.get(management_station=station)
        # Opened in the REQUEST, so the page it redirects to always finds work in progress.
        self.assertEqual(run.status, IntegrationRun.STATUS_RUNNING)
        thread.assert_called_once()
        self.assertEqual(thread.call_args.kwargs["args"], (station.pk, run.pk))
        self.assertTrue(thread.call_args.kwargs["daemon"])
        thread.return_value.start.assert_called_once()

    def test_renormalize_completes_the_run_it_was_given(self):
        """What the thread does, called directly."""
        station = self._create_panorama_station("panorama-renorm-work.local")
        run = views_module._open_renormalize_run(station)

        with patch(
            "optivedge_integrations.integrations.views.renormalize_in_scope_configuration",
            return_value=_empty_renormalization_result(),
        ):
            views_module._renormalize_station_with_tracking(station, run)

        run.refresh_from_db()
        self.assertEqual(run.status, IntegrationRun.STATUS_SUCCEEDED)

    def test_renormalize_is_refused_while_a_collection_is_running(self):
        """The two write the SAME ROWS - a collection normalizes what it collects, and a
        renormalize rewrites exactly that - so running them together would interleave
        delete-and-recreate on the same enforcement points."""
        station = self._create_panorama_station("panorama-renorm-busy.local")
        views_module._open_in_scope_refresh_run(station)

        with patch("optivedge_integrations.integrations.views.threading.Thread") as thread:
            self.client.post(
                reverse("management_station_renormalize", kwargs={"pk": station.pk})
            )

        thread.assert_not_called()
        self.assertFalse(views_module.renormalization_in_progress(station))

    def test_refresh_dynamic_content_view_succeeds(self):
        station = self._create_panorama_station("panorama-dynamic.local")

        with patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_dynamic_content",
            return_value=_empty_dynamic_content_refresh_result(),
        ):
            response = self.client.post(
                reverse(
                    "management_station_refresh_dynamic_content",
                    kwargs={"pk": station.pk},
                )
            )

        self.assertRedirects(response, reverse("management_station_list"))
        run = IntegrationRun.objects.get(management_station=station)
        self.assertEqual(run.status, IntegrationRun.STATUS_SUCCEEDED)


class ManagementStationWorkflowTests(TestCase):
    """The station list's currency columns and the three-step workflow on the details tab:
    sync inventory, choose scope, collect and normalize."""

    def setUp(self):
        self.station, self.appliance, self.point = _create_panorama_enforcement_point(
            serial_number="SERIAL-WF-001",
            appliance_hostname="fw-workflow",
            station_hostname="panorama-workflow.local",
        )
        EnforcementPoint.objects.create(
            management_station=self.station,
            appliance_group=self.point.appliance_group,
            vsys_name="vsys2",
        )
        self.detail_url = reverse("management_station_detail", kwargs={"pk": self.station.pk})

    def _record_inventory(self, at):
        return Snapshot.objects.create(
            management_station=self.station,
            source_type="show_managed_devices",
            collected_at=at,
        )

    def _record_collection(self, at, status=IntegrationRun.STATUS_SUCCEEDED):
        run = IntegrationRun.objects.create(
            management_station=self.station,
            run_scope=IntegrationRun.SCOPE_APPLIANCE,
            status=status,
            completed_at=at,
        )
        IntegrationRun.objects.filter(pk=run.pk).update(started_at=at)
        IntegrationEvent.objects.create(
            management_station=self.station, run=run, level=IntegrationEvent.LEVEL_INFO,
            stage="", reason="InScopeRefreshStarted", message="started",
        )
        return run

    def _workflow(self):
        return self.client.get(self.detail_url).context["workflow"]

    def test_the_list_shows_inventory_currency_and_enforcement_point_counts(self):
        response = self.client.get(reverse("management_station_list"))
        self.assertContains(response, "Inventory")
        self.assertContains(response, "Never synced")
        self.assertContains(response, "(0 in scope)")

        self._record_inventory(timezone.now())
        self.point.in_scope = True
        self.point.save()
        response = self.client.get(reverse("management_station_list"))
        station = response.context["management_stations"].get(pk=self.station.pk)
        self.assertIsNotNone(station.inventory_as_of)
        self.assertEqual(station.enforcement_point_count, 2)
        self.assertEqual(station.in_scope_enforcement_point_count, 1)
        self.assertContains(response, "As of ")
        self.assertContains(response, "(1 in scope)")

    def test_inventory_currency_ignores_other_station_snapshots(self):
        Snapshot.objects.create(
            management_station=self.station,
            source_type="show_dg_hierarchy",
            collected_at=timezone.now(),
        )
        response = self.client.get(reverse("management_station_list"))
        station = response.context["management_stations"].get(pk=self.station.pk)
        self.assertIsNone(station.inventory_as_of)

    def test_the_next_step_walks_inventory_then_scope_then_collect(self):
        workflow = self._workflow()
        self.assertEqual(workflow["next_step"], "inventory")

        inventory_at = timezone.now() - timedelta(hours=2)
        self._record_inventory(inventory_at)
        workflow = self._workflow()
        self.assertEqual(workflow["next_step"], "scope")
        self.assertTrue(workflow["scope_needs_attention"])
        self.assertEqual(workflow["scope_summary"], "0 of 2 enforcement points in scope.")

        self.point.in_scope = True
        self.point.save()
        workflow = self._workflow()
        self.assertEqual(workflow["next_step"], "collect")
        self.assertFalse(workflow["scope_needs_attention"])

        self._record_collection(inventory_at + timedelta(hours=1))
        workflow = self._workflow()
        self.assertIsNone(workflow["next_step"])
        self.assertFalse(workflow["collection_is_stale"])

    def test_each_step_reports_its_own_completion(self):
        """`next_step` names the first thing missing and says nothing about the steps after
        it, so the template cannot read "not next, so finished" - the three flags are what it
        styles on."""
        workflow = self._workflow()
        self.assertEqual(
            [workflow["inventory_complete"], workflow["scope_complete"],
             workflow["collection_complete"]],
            [False, False, False])

        inventory_at = timezone.now() - timedelta(hours=2)
        self._record_inventory(inventory_at)
        workflow = self._workflow()
        self.assertEqual(
            [workflow["inventory_complete"], workflow["scope_complete"],
             workflow["collection_complete"]],
            [True, False, False])

        self.point.in_scope = True
        self.point.save()
        workflow = self._workflow()
        self.assertEqual(
            [workflow["inventory_complete"], workflow["scope_complete"],
             workflow["collection_complete"]],
            [True, True, False])

        self._record_collection(inventory_at + timedelta(hours=1))
        workflow = self._workflow()
        self.assertEqual(
            [workflow["inventory_complete"], workflow["scope_complete"],
             workflow["collection_complete"]],
            [True, True, True])
        self.assertIsNone(workflow["next_step"])

    def test_completion_and_the_next_step_cannot_disagree(self):
        """The invariant the two are worth having: a step that is the next step is not done,
        and on a Panorama station with nothing running, no next step means all three are."""
        cases = (
            ("nothing done", lambda: None),
            ("inventory only", lambda: self._record_inventory(timezone.now())),
            ("scope too", lambda: EnforcementPoint.objects.filter(pk=self.point.pk)
                .update(in_scope=True)),
            ("collected", lambda: self._record_collection(timezone.now())),
            ("collection failed", lambda: self._record_collection(
                timezone.now(), status=IntegrationRun.STATUS_FAILED)),
        )
        for label, arrange in cases:
            with self.subTest(case=label):
                arrange()
                workflow = self._workflow()
                complete = {
                    "inventory": workflow["inventory_complete"],
                    "scope": workflow["scope_complete"],
                    "collect": workflow["collection_complete"],
                }
                if workflow["next_step"] is not None:
                    self.assertFalse(complete[workflow["next_step"]])
                elif not workflow["collection_in_progress"]:
                    self.assertEqual(list(complete.values()), [True, True, True])

    def test_a_failed_collection_is_not_a_completed_step(self):
        self.point.in_scope = True
        self.point.save()
        now = timezone.now()
        self._record_inventory(now - timedelta(hours=1))
        self._record_collection(now, status=IntegrationRun.STATUS_FAILED)

        self.assertFalse(self._workflow()["collection_complete"])

    def test_a_collection_in_progress_is_not_yet_a_completed_step(self):
        """It is not the next step either - the button is disabled while it runs - so a
        template keying off `next_step` alone would style step 3 as finished mid-collection."""
        self.point.in_scope = True
        self.point.save()
        self._record_inventory(timezone.now())
        views_module._open_in_scope_refresh_run(self.station)

        workflow = self._workflow()
        self.assertTrue(workflow["collection_in_progress"])
        self.assertIsNone(workflow["next_step"])
        self.assertFalse(workflow["collection_complete"])

    def test_a_completed_step_is_marked_done_on_the_details_tab(self):
        response = self.client.get(self.detail_url)
        self.assertNotContains(response, ">Done<")

        self.point.in_scope = True
        self.point.save()
        now = timezone.now()
        self._record_inventory(now - timedelta(hours=1))
        self._record_collection(now)

        response = self.client.get(self.detail_url)
        # The chip carries the state in words as well as in colour, which is why it is what is
        # asserted on rather than the emerald classes beside it.
        self.assertContains(response, ">Done<", count=3)
        self.assertNotContains(response, "Next step")

    def test_a_collection_older_than_the_inventory_is_the_next_step_again(self):
        self.point.in_scope = True
        self.point.save()
        now = timezone.now()
        self._record_collection(now - timedelta(days=1))
        self._record_inventory(now)

        workflow = self._workflow()
        self.assertEqual(workflow["next_step"], "collect")
        self.assertTrue(workflow["collection_is_stale"])

    def test_the_inventory_a_collection_takes_itself_does_not_make_it_stale(self):
        """The in-scope refresh re-reads `show devices all`, so its inventory snapshot is
        always newer than the moment the run began. Measured against lab data, where
        comparing to the start reported every collection as stale."""
        self.point.in_scope = True
        self.point.save()
        now = timezone.now()
        run = self._record_collection(now)
        IntegrationRun.objects.filter(pk=run.pk).update(started_at=now - timedelta(minutes=5))
        self._record_inventory(now - timedelta(minutes=4))

        workflow = self._workflow()
        self.assertFalse(workflow["collection_is_stale"])
        self.assertIsNone(workflow["next_step"])

    def test_a_running_collection_is_not_stale(self):
        self.point.in_scope = True
        self.point.save()
        now = timezone.now()
        self._record_inventory(now)
        run = self._record_collection(now - timedelta(minutes=1), status=IntegrationRun.STATUS_RUNNING)
        IntegrationRun.objects.filter(pk=run.pk).update(completed_at=None)

        self.assertFalse(self._workflow()["collection_is_stale"])

    def test_a_failed_collection_is_the_next_step_again(self):
        self.point.in_scope = True
        self.point.save()
        now = timezone.now()
        self._record_inventory(now - timedelta(hours=1))
        self._record_collection(now, status=IntegrationRun.STATUS_FAILED)

        self.assertEqual(self._workflow()["next_step"], "collect")

    def test_an_edl_run_is_not_mistaken_for_a_configuration_collection(self):
        run = IntegrationRun.objects.create(
            management_station=self.station,
            run_scope=IntegrationRun.SCOPE_APPLIANCE,
            status=IntegrationRun.STATUS_SUCCEEDED,
        )
        IntegrationEvent.objects.create(
            management_station=self.station, run=run, level=IntegrationEvent.LEVEL_INFO,
            stage="", reason="DynamicContentRefreshStarted", message="started",
        )
        workflow = self._workflow()
        self.assertIsNone(workflow["collection_run"])
        self.assertEqual(workflow["dynamic_content_run"], run)

    def test_the_details_tab_renders_all_three_steps_with_their_actions(self):
        response = self.client.get(self.detail_url)

        self.assertContains(response, 'data-step="inventory"')
        self.assertContains(response, 'data-step="scope"')
        self.assertContains(response, 'data-step="collect"')
        self.assertContains(
            response, reverse("management_station_sync", kwargs={"pk": self.station.pk}))
        self.assertContains(
            response, reverse("management_station_in_scope_sync", kwargs={"pk": self.station.pk}))
        self.assertContains(
            response, reverse("management_station_renormalize", kwargs={"pk": self.station.pk}))
        self.assertContains(response, "?tab=enforcement-points")
        self.assertContains(response, "Next step")
        # Edit and Delete stay in the header.
        self.assertContains(
            response, reverse("management_station_update", kwargs={"pk": self.station.pk}))
        self.assertContains(
            response, reverse("management_station_delete", kwargs={"pk": self.station.pk}))

    def test_the_details_tab_renders_every_run_status(self):
        self.point.in_scope = True
        self.point.save()
        self._record_inventory(timezone.now())
        for status in (
            IntegrationRun.STATUS_RUNNING,
            IntegrationRun.STATUS_PARTIAL,
            IntegrationRun.STATUS_FAILED,
            IntegrationRun.STATUS_SUCCEEDED,
        ):
            with self.subTest(status=status):
                self._record_collection(timezone.now(), status=status)
                response = self.client.get(self.detail_url)
                self.assertEqual(response.status_code, 200)
                label = "Running" if status == IntegrationRun.STATUS_RUNNING else dict(
                    IntegrationRun.STATUS_CHOICES)[status]
                self.assertContains(response, label)

    def test_a_running_collection_disables_step_3_and_refreshes_the_page(self):
        self.point.in_scope = True
        self.point.save()
        self._record_inventory(timezone.now())
        views_module._open_in_scope_refresh_run(self.station)

        response = self.client.get(self.detail_url)

        self.assertTrue(response.context["workflow"]["collection_in_progress"])
        self.assertIsNone(response.context["workflow"]["next_step"])
        self.assertContains(response, "data-collection-in-progress")
        self.assertContains(response, "window.location.reload()")
        self.assertContains(response, "Collecting…")

    def test_a_renormalize_in_progress_disables_both_buttons_and_refreshes(self):
        """Both, not just its own: a collection normalizes what it collects and a renormalize
        rewrites exactly that, so the two would interleave delete-and-recreate on the same
        enforcement points."""
        self.point.in_scope = True
        self.point.save()
        self._record_inventory(timezone.now())
        self._record_collection(timezone.now())
        views_module._open_renormalize_run(self.station)

        response = self.client.get(self.detail_url)
        workflow = response.context["workflow"]

        self.assertTrue(workflow["renormalization_in_progress"])
        self.assertTrue(workflow["work_in_progress"])
        self.assertFalse(workflow["collection_in_progress"])
        self.assertContains(response, "data-renormalization-in-progress")
        self.assertContains(response, "window.location.reload()")
        self.assertContains(response, "Renormalizing…")
        # Step 3 is not "the next thing to do" while work is running, as with a collection.
        self.assertIsNone(workflow["next_step"])

    def test_a_finished_renormalize_reports_its_outcome_on_the_page(self):
        """The counts were a Django message from the view, and the view no longer waits for the
        work. The RUN carries the outcome now, and the Events tab carries the detail."""
        self.point.in_scope = True
        self.point.save()
        self._record_inventory(timezone.now())
        run = views_module._open_renormalize_run(self.station)
        run.status = IntegrationRun.STATUS_SUCCEEDED
        run.completed_at = timezone.now()
        run.save(update_fields=["status", "completed_at"])

        response = self.client.get(self.detail_url)

        self.assertEqual(response.context["workflow"]["renormalize_run"], run)
        self.assertContains(response, "Renormalize")
        self.assertNotContains(response, "data-renormalization-in-progress")

    def test_an_idle_page_does_not_refresh_itself(self):
        response = self.client.get(self.detail_url)

        self.assertNotContains(response, "window.location.reload()")

    def test_a_non_panorama_station_says_why_it_cannot_collect(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_FIREWALL,
            hostname="firewall-workflow.local",
        )
        response = self.client.get(
            reverse("management_station_detail", kwargs={"pk": station.pk}))

        self.assertIsNone(response.context["workflow"]["next_step"])
        self.assertContains(response, "supported only for Panorama")
        self.assertNotContains(response, "Next step")

    def test_the_appliance_groups_tab_is_gone(self):
        response = self.client.get(self.detail_url, {"tab": "appliance-groups"})

        self.assertEqual(response.context["active_tab"], "details")
        self.assertNotContains(response, "?tab=appliance-groups")

    def test_the_enforcement_points_tab_drops_owner_group_and_actions_columns(self):
        response = self.client.get(self.detail_url, {"tab": "enforcement-points"})

        self.assertContains(response, "vsys2")
        for heading in ("Owner Type", "Appliance Group", "Actions"):
            self.assertNotContains(response, f">{heading}</th>")
        self.assertNotContains(
            response,
            reverse(
                "enforcement_point_addresses",
                kwargs={"pk": self.station.pk, "enforcement_point_pk": self.point.pk},
            ),
        )


class ApplianceGroupSnapshotViewTests(TestCase):
    def test_get_renders_latest_snapshots_for_appliance_group(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-snap.local",
        )
        appliance_group = ApplianceGroup.objects.create(
            management_station=station,
            name="group-snap",
        )
        appliance = Appliance.objects.create(
            management_station=station,
            appliance_group=appliance_group,
            serial_number="SERIAL-SNAP-001",
            hostname="fw-snap",
        )
        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": "value"},
        )
        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_predefined_ip_block_lists",
            collected_at=timezone.now(),
            payload={"ip-block-list-v2": {"entry": []}},
        )
        Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_predefined_url_lists",
            collected_at=timezone.now(),
            payload={"url-predefined": {"entry": []}},
        )

        response = self.client.get(
            reverse(
                "appliance_group_snapshots",
                kwargs={"pk": station.pk, "appliance_group_pk": appliance_group.pk},
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Merged Config")
        self.assertContains(response, "Predefined IP Block Lists")
        self.assertContains(response, "Predefined URL Lists")

    def test_get_404s_when_appliance_group_belongs_to_different_station(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-snap-a.local",
        )
        other_station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-snap-b.local",
        )
        appliance_group = ApplianceGroup.objects.create(
            management_station=other_station,
            name="group-other",
        )

        response = self.client.get(
            reverse(
                "appliance_group_snapshots",
                kwargs={"pk": station.pk, "appliance_group_pk": appliance_group.pk},
            )
        )

        self.assertEqual(response.status_code, 404)


ZONE_MERGED_CONFIG_PAYLOAD = {
    "config": {
        "devices": {
            "entry": {
                "network": {
                    "interface": {
                        "ethernet": {
                            "entry": [
                                {
                                    "@name": "ethernet1/1",
                                    "layer3": {
                                        "ip": {
                                            "entry": [
                                                {"@name": "10.1.1.1/24"},
                                                {"@name": "10.1.2.1/24"},
                                            ]
                                        }
                                    },
                                },
                                {
                                    "@name": "ethernet1/2",
                                    "layer3": {
                                        "units": {
                                            "entry": {
                                                "@name": "ethernet1/2.100",
                                                "ip": {"entry": {"@name": "192.168.100.1/24"}},
                                            }
                                        }
                                    },
                                },
                                {"@name": "ethernet1/3", "layer2": {}},
                            ]
                        },
                        "loopback": {
                            "units": {
                                "entry": {
                                    "@name": "loopback.1",
                                    "ip": {"entry": {"@name": "172.16.0.1/32"}},
                                }
                            }
                        },
                    }
                },
                "vsys": {
                    "entry": {
                        "@name": "vsys1",
                        "zone": {
                            "entry": [
                                {
                                    "@name": "trust",
                                    "network": {
                                        "layer3": {"member": ["ethernet1/1", "ethernet1/2.100"]},
                                        "zone-protection-profile": "zp-strict",
                                        "log-setting": "log-fwd",
                                        "enable-packet-buffer-protection": "yes",
                                    },
                                    "enable-user-identification": "yes",
                                    "user-acl": {
                                        "include-list": {"member": ["10.0.0.0/8"]},
                                        "exclude-list": {"member": "10.9.9.0/24"},
                                    },
                                },
                                {
                                    "@name": "dmz",
                                    "network": {"layer3": {"member": "loopback.1"}},
                                },
                                {
                                    "@name": "l2-segment",
                                    "network": {"layer2": {"member": ["ethernet1/3"]}},
                                },
                            ]
                        },
                    }
                },
            }
        }
    }
}


class ZoneNormalizationTests(TestCase):
    def setUp(self):
        self.station, self.appliance, self.enforcement_point = _create_panorama_enforcement_point(
            serial_number="Z001",
            appliance_hostname="fw-zone",
            station_hostname="panorama-zone.local",
        )
        self.snapshot = Snapshot.objects.create(
            management_station=self.station,
            appliance=self.appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload=ZONE_MERGED_CONFIG_PAYLOAD,
        )

    def test_interface_address_index_covers_physical_units_and_logical_interfaces(self):
        index = build_interface_address_index(ZONE_MERGED_CONFIG_PAYLOAD)

        self.assertEqual(index["ethernet1/1"], ["10.1.1.1/24", "10.1.2.1/24"])
        self.assertEqual(index["ethernet1/2.100"], ["192.168.100.1/24"])
        self.assertEqual(index["loopback.1"], ["172.16.0.1/32"])
        # A layer 2 interface carries no address, but must still be indexed - otherwise
        # "not in the index" and "has no addresses" become indistinguishable.
        self.assertEqual(index["ethernet1/3"], [])

    def test_build_normalized_zones_reads_type_members_and_common_details(self):
        zones = {zone.name: zone for zone in build_normalized_zones(ZONE_MERGED_CONFIG_PAYLOAD, "vsys1")}

        trust = zones["trust"]
        self.assertEqual(trust.zone_type, Zone.TYPE_LAYER3)
        self.assertEqual([i.name for i in trust.interfaces], ["ethernet1/1", "ethernet1/2.100"])
        self.assertEqual(trust.interfaces[0].ip_addresses, ["10.1.1.1/24", "10.1.2.1/24"])
        self.assertEqual(trust.interfaces[1].ip_addresses, ["192.168.100.1/24"])
        self.assertTrue(trust.enable_user_identification)
        self.assertEqual(trust.zone_protection_profile, "zp-strict")
        self.assertEqual(trust.log_setting, "log-fwd")
        self.assertIs(trust.packet_buffer_protection, True)
        self.assertEqual(trust.include_acl, ["10.0.0.0/8"])
        self.assertEqual(trust.exclude_acl, ["10.9.9.0/24"])

        self.assertEqual(zones["l2-segment"].zone_type, Zone.TYPE_LAYER2)
        self.assertEqual([i.name for i in zones["l2-segment"].interfaces], ["ethernet1/3"])

    def test_absent_packet_buffer_protection_is_unset_rather_than_disabled(self):
        """Not reported and reported-as-no are different facts; don't collapse them.

        None is the COMMON case, not an edge one: PAN-OS omits the element when it matches
        the default, and the default is enabled. Every zone on the lab device reads None
        while the UI shows the box ticked.
        """
        zones = {zone.name: zone for zone in build_normalized_zones(ZONE_MERGED_CONFIG_PAYLOAD, "vsys1")}

        self.assertIsNone(zones["dmz"].packet_buffer_protection)
        self.assertFalse(zones["dmz"].enable_user_identification)

    def test_the_legacy_element_name_is_not_read(self):
        """`packet-buffer-protection` is what this read for its first year, and PAN-OS
        rejects that element outright - "packet-buffer-protection unexpected here" on a
        fresh zone. Measured 11.1.13-h3. A payload carrying the wrong name must not
        satisfy the field, or the bug comes back invisibly."""
        payload = {"config": {"devices": {"entry": [{"vsys": {"entry": [{
            "@name": "vsys1", "zone": {"entry": [{
                "@name": "z", "network": {"layer3": None, "packet-buffer-protection": "yes"}}]}}]}}]}}}
        zone = build_normalized_zones(payload, "vsys1")[0]
        self.assertIsNone(zone.packet_buffer_protection)

    def test_single_member_is_read_as_one_interface_not_characters(self):
        """xmltodict collapses a one-element member list to a bare string."""
        zones = {zone.name: zone for zone in build_normalized_zones(ZONE_MERGED_CONFIG_PAYLOAD, "vsys1")}

        self.assertEqual([i.name for i in zones["dmz"].interfaces], ["loopback.1"])

    def test_every_container_shape_a_real_device_uses_is_indexed(self):
        """Measured on a PA-5220 (11.1.13-h3), 2026-08-25, with all five created live.

        Two container shapes exist and both are real:

            ethernet / aggregate-ethernet   entry -> layer3 -> ip, and layer3 -> units
            loopback / tunnel / vlan        units directly on the container, ip on the unit

        The second was written from the schema and had never met a real payload. It is
        also the one that fails silently: an unhandled container yields no addresses, which
        is indistinguishable from an interface that has none.
        """
        payload = {"config": {"devices": {"entry": [{"network": {"interface": {
            "aggregate-ethernet": {"entry": [{"@name": "ae1", "layer3": {
                "ip": {"entry": [{"@name": "10.200.4.1/24"}]},
                "units": {"entry": [{"@name": "ae1.10", "tag": "10",
                                     "ip": {"entry": [{"@name": "10.200.5.1/24"}]}}]}}}]},
            "loopback": {"units": {"entry": [{"@name": "loopback.1", "ip": {"entry": [
                {"@name": "10.200.1.1/32"}, {"@name": "10.200.1.2/32"}]}}]}},
            "tunnel": {"units": {"entry": [{"@name": "tunnel.1",
                                            "ip": {"entry": [{"@name": "10.200.2.1/32"}]}}]}},
            "vlan": {"units": {"entry": [{"@name": "vlan.1",
                                          "ip": {"entry": [{"@name": "10.200.3.1/24"}]}}]}},
        }}}]}}}

        index = build_interface_address_index(payload)
        self.assertEqual(index["ae1"], ["10.200.4.1/24"])
        self.assertEqual(index["ae1.10"], ["10.200.5.1/24"])
        self.assertEqual(index["tunnel.1"], ["10.200.2.1/32"])
        self.assertEqual(index["vlan.1"], ["10.200.3.1/24"])
        # More than one address on a single interface is ordinary, not exotic.
        self.assertEqual(index["loopback.1"], ["10.200.1.1/32", "10.200.1.2/32"])

    def test_ipv6_addresses_are_collected_alongside_ipv4(self):
        """Measured on 11.1.13-h3: IPv4 and IPv6 sit under different nodes.

        Reading only `ip` dropped every IPv6 address, and an IPv6-only interface then
        reported none at all - which ZoneInterface documents as meaning "we did not reach
        them", so the loss was invisible.
        """
        payload = {"config": {"devices": {"entry": [{"network": {"interface": {
            "loopback": {"units": {"entry": [{
                "@name": "loopback.9",
                "ip": {"entry": [{"@name": "10.201.1.1/32"}]},
                "ipv6": {"enabled": "yes",
                         "address": {"entry": [{"@name": "2001:db8:1::1/128"}]}}}]}},
            "ethernet": {"entry": [{"@name": "ethernet1/9", "layer3": {
                "ipv6": {"enabled": "yes",
                         "address": {"entry": [{"@name": "2001:db8:2::1/64"}]}}}}]},
        }}}]}}}

        index = build_interface_address_index(payload)
        self.assertEqual(index["loopback.9"], ["10.201.1.1/32", "2001:db8:1::1/128"])
        # IPv6-only, under layer3 rather than directly on the unit.
        self.assertEqual(index["ethernet1/9"], ["2001:db8:2::1/64"])

    def test_device_id_acl_and_prenat_flags_are_read_from_their_real_elements(self):
        """Shapes captured from a zone configured in the PAN-OS UI (11.1.13-h3, 2026-08-25).

        Every element here is worth pinning because none is derivable from its UI label:
        "Enable L3 & L4 Header Inspection" is `net-inspection`, "Source Lookup" is
        `enable-prenat-source-policy-lookup`, and the Device-ID ACL is `device-acl` rather
        than `device-id-acl`. A typo in any of them yields a silent False.
        """
        payload = {"config": {"devices": {"entry": [{"vsys": {"entry": [{
            "@name": "vsys1", "zone": {"entry": [{
                "@name": "scratch_zone",
                "network": {
                    "layer3": {},
                    "net-inspection": "yes",
                    "log-setting": "default",
                    "prenat-identification": {
                        "enable-prenat-user-identification": "yes",
                        "enable-prenat-source-policy-lookup": "yes",
                        "enable-prenat-device-identification": "yes",
                        "enable-prenat-source-ip-downstream": "yes"}},
                "enable-device-identification": "yes",
                "device-acl": {
                    "include-list": {"member": ["99.99.98.0/24", "ag-agent-desktop-services"]},
                    "exclude-list": {"member": ["88.88.88.0/24", "ag-b2b-integration-services-dg"]}},
            }]}}]}}]}}}

        zone = build_normalized_zones(payload, "vsys1")[0]
        self.assertTrue(zone.net_inspection)
        self.assertTrue(zone.enable_device_identification)
        self.assertTrue(zone.prenat_user_identification)
        self.assertTrue(zone.prenat_device_identification)
        self.assertTrue(zone.prenat_source_policy_lookup)
        self.assertTrue(zone.prenat_source_ip_downstream)
        # Members mix literal addresses with address-GROUP names, kept as written.
        self.assertEqual(zone.device_include_acl, ["99.99.98.0/24", "ag-agent-desktop-services"])
        self.assertEqual(zone.device_exclude_acl, ["88.88.88.0/24", "ag-b2b-integration-services-dg"])
        # The User-ID ACL is a separate list and this zone has none - the two must not bleed.
        self.assertFalse(zone.enable_user_identification)
        self.assertEqual(zone.include_acl, [])

    def test_the_new_flags_default_to_false_when_absent(self):
        """Unlike packet-buffer protection, these default OFF - absent means False, and a
        bare zone must not report Device-ID or Pre-NAT as enabled."""
        zone = {z.name: z for z in build_normalized_zones(ZONE_MERGED_CONFIG_PAYLOAD, "vsys1")}["dmz"]
        self.assertFalse(zone.net_inspection)
        self.assertFalse(zone.enable_device_identification)
        self.assertFalse(zone.prenat_user_identification)
        self.assertFalse(zone.prenat_source_ip_downstream)
        self.assertEqual(zone.device_include_acl, [])

    def test_unrecognised_payload_yields_no_zones_instead_of_raising(self):
        """These payload shapes are inferred, not measured - degrade, don't fail the run."""
        for payload in ({}, {"config": "not-a-dict"}, {"config": {"devices": {}}}):
            self.assertEqual(build_normalized_zones(payload, "vsys1"), [])
            self.assertEqual(build_interface_address_index(payload), {})

    def test_normalize_zones_persists_zones_and_interfaces(self):
        zones = normalize_enforcement_point_zones(self.enforcement_point)

        self.assertEqual([zone.name for zone in zones], ["dmz", "l2-segment", "trust"])
        trust = Zone.objects.get(enforcement_point=self.enforcement_point, name="trust")
        self.assertEqual(trust.source_snapshot, self.snapshot)
        self.assertEqual(
            [(i.name, i.ip_addresses) for i in trust.interfaces.all()],
            [("ethernet1/1", ["10.1.1.1/24", "10.1.2.1/24"]), ("ethernet1/2.100", ["192.168.100.1/24"])],
        )

    def test_normalize_zones_replaces_previous_zones(self):
        normalize_enforcement_point_zones(self.enforcement_point)
        Zone.objects.create(
            management_station=self.station,
            enforcement_point=self.enforcement_point,
            source_snapshot=self.snapshot,
            name="stale-zone",
        )

        normalize_enforcement_point_zones(self.enforcement_point)

        names = list(Zone.objects.filter(enforcement_point=self.enforcement_point).values_list("name", flat=True))
        self.assertNotIn("stale-zone", names)
        self.assertEqual(ZoneInterface.objects.filter(zone__name="stale-zone").count(), 0)

    def test_normalize_zones_without_a_merged_snapshot_returns_nothing(self):
        self.snapshot.delete()

        self.assertEqual(normalize_enforcement_point_zones(self.enforcement_point), [])


class ZoneViewTests(TestCase):
    def setUp(self):
        self.station, self.appliance, self.enforcement_point = _create_panorama_enforcement_point(
            serial_number="Z100",
            appliance_hostname="fw-zone-view",
            station_hostname="panorama-zone-view.local",
        )
        Snapshot.objects.create(
            management_station=self.station,
            appliance=self.appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload=ZONE_MERGED_CONFIG_PAYLOAD,
        )
        normalize_enforcement_point_zones(self.enforcement_point)
        self.trust = Zone.objects.get(enforcement_point=self.enforcement_point, name="trust")

    def test_zones_tab_lists_zones_with_interface_names_and_addresses(self):
        response = self.client.get(
            reverse("enforcement_point_detail", kwargs={"pk": self.enforcement_point.pk}),
            {"tab": "zones"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual([z.name for z in response.context["zones"]], ["dmz", "l2-segment", "trust"])
        self.assertContains(response, "ethernet1/2.100")
        self.assertContains(response, "10.1.1.1/24")
        self.assertContains(
            response,
            reverse(
                "enforcement_point_zone_detail",
                kwargs={"pk": self.enforcement_point.pk, "zone_pk": self.trust.pk},
            ),
        )

    def test_zones_tab_keeps_one_truncated_line_per_interface(self):
        """The two columns line up only while each interface occupies exactly one line.

        A wrapping address list would push its own row taller than the interface name
        beside it and silently break the pairing, so the cell truncates and carries the
        full list as a tooltip instead.
        """
        response = self.client.get(
            reverse("enforcement_point_detail", kwargs={"pk": self.enforcement_point.pk}),
            {"tab": "zones"},
        )
        html = response.content.decode()

        self.assertIn("table-fixed", html)
        trust_row = next(
            row
            for row in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S)
            if ">trust<" in row
        )
        cells = re.findall(r"<td[^>]*>(.*?)</td>", trust_row, re.S)
        interface_lines = re.findall(r'<div class="truncate"', cells[2])
        address_lines = re.findall(r'<div class="truncate font-mono text-xs" title="([^"]*)"', cells[3])

        self.assertEqual(len(interface_lines), 2)
        self.assertEqual(address_lines, ["10.1.1.1/24, 10.1.2.1/24", "192.168.100.1/24"])

    def test_zone_detail_renders_details_and_interfaces(self):
        response = self.client.get(
            reverse(
                "enforcement_point_zone_detail",
                kwargs={"pk": self.enforcement_point.pk, "zone_pk": self.trust.pk},
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["zone"], self.trust)
        self.assertEqual(response.context["enforcement_point"], self.enforcement_point)
        self.assertContains(response, "zp-strict")
        self.assertContains(response, "192.168.100.1/24")
        self.assertContains(response, "10.9.9.0/24")

    def test_zone_detail_404s_for_a_zone_on_another_enforcement_point(self):
        """The zone pk is only meaningful under its own point; don't let one leak across."""
        _, _, _, other_point = _create_grouped_enforcement_point(
            serial_number="Z200",
            appliance_hostname="fw-other",
            station_hostname="panorama-other-zone.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            group_name="grp-other-zone",
        )

        response = self.client.get(
            reverse(
                "enforcement_point_zone_detail",
                kwargs={"pk": other_point.pk, "zone_pk": self.trust.pk},
            )
        )

        self.assertEqual(response.status_code, 404)


class ManagementStationEventsTabTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-events.local",
        )
        self.url = reverse("management_station_detail", kwargs={"pk": self.station.pk})
        for level, reason in (
            (IntegrationEvent.LEVEL_INFO, "InfoThing"),
            (IntegrationEvent.LEVEL_WARNING, "WarningThing"),
            (IntegrationEvent.LEVEL_ERROR, "ErrorThing"),
        ):
            IntegrationEvent.objects.create(
                management_station=self.station, level=level, stage="", reason=reason, message="m",
            )

    def reasons(self, level=None):
        query = {"tab": "events"}
        if level is not None:
            query["level"] = level
        response = self.client.get(self.url, query)
        self.assertEqual(response.status_code, 200)
        return response, sorted(e.reason for e in response.context["integration_events"])

    def test_all_levels_by_default(self):
        response, reasons = self.reasons()

        self.assertEqual(reasons, ["ErrorThing", "InfoThing", "WarningThing"])
        self.assertEqual(response.context["event_level_filter"], "all")

    def test_each_level_filters_to_itself(self):
        for level, reason in (("info", "InfoThing"), ("warning", "WarningThing"), ("error", "ErrorThing")):
            with self.subTest(level=level):
                response, reasons = self.reasons(level)
                self.assertEqual(reasons, [reason])
                self.assertEqual(response.context["event_level_filter"], level)

    def test_unknown_level_falls_back_to_all(self):
        response, reasons = self.reasons("catastrophic")

        self.assertEqual(len(reasons), 3)
        self.assertEqual(response.context["event_level_filter"], "all")

    def test_the_filter_buttons_render_for_every_level(self):
        response, _ = self.reasons()

        for value in ("all", "info", "warning", "error"):
            self.assertContains(response, f'href="?tab=events&level={value}"')

    def test_the_filter_applies_before_the_display_cap(self):
        """Errors only means the latest errors, not the errors among the latest events."""
        IntegrationEvent.objects.bulk_create(
            IntegrationEvent(
                management_station=self.station, level=IntegrationEvent.LEVEL_INFO,
                stage="", reason="Noise", message="m",
            )
            for _ in range(1000)
        )
        _, reasons = self.reasons("error")

        self.assertEqual(reasons, ["ErrorThing"])

    def test_empty_state_names_the_filter(self):
        IntegrationEvent.objects.filter(level=IntegrationEvent.LEVEL_WARNING).delete()

        self.assertContains(self.reasons("warning")[0], "No events at this level.")


class ManagementStationEnforcementPointTabTests(TestCase):
    """The station's Enforcement Points tab absorbed the standalone /enforcement-points/
    list: its scope filter and its links to each point's detail page."""

    def setUp(self):
        self.station, self.group, self.appliance, self.in_scope = _create_grouped_enforcement_point(
            serial_number="0001",
            appliance_hostname="fw-a",
            station_hostname="panorama-a.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            group_name="grp-a",
            vsys_name="vsys1",
        )
        self.in_scope.in_scope = True
        self.in_scope.save()
        self.out_of_scope = EnforcementPoint.objects.create(
            management_station=self.station,
            appliance_group=self.group,
            vsys_name="vsys2",
        )
        # Another station's point must never appear on this station's tab.
        _, _, _, self.elsewhere = _create_grouped_enforcement_point(
            serial_number="0002",
            appliance_hostname="fw-b",
            station_hostname="firewall-b.local",
            station_type=ManagementStation.StationType.PAN_FIREWALL,
            group_name="grp-b",
            vsys_name="vsys9",
        )
        self.url = reverse("management_station_detail", kwargs={"pk": self.station.pk})

    def listed_pks(self, scope=None):
        query = {"tab": "enforcement-points"}
        if scope is not None:
            query["scope"] = scope
        response = self.client.get(self.url, query)
        self.assertEqual(response.status_code, 200)
        return response, sorted(point.pk for point in response.context["enforcement_points"])

    def test_the_tab_shows_every_point_of_this_station_by_default(self):
        """All, not in-scope: this is where scope is chosen, so out-of-scope rows must show."""
        response, pks = self.listed_pks()

        self.assertEqual(pks, sorted([self.in_scope.pk, self.out_of_scope.pk]))
        self.assertEqual(response.context["scope_filter"], "all")

    def test_scope_filter_selects_in_scope_points(self):
        _, pks = self.listed_pks("in")

        self.assertEqual(pks, [self.in_scope.pk])

    def test_scope_filter_selects_out_of_scope_points(self):
        _, pks = self.listed_pks("out")

        self.assertEqual(pks, [self.out_of_scope.pk])

    def test_unknown_scope_filter_falls_back_to_all(self):
        response, pks = self.listed_pks("not-a-scope")

        self.assertEqual(pks, sorted([self.in_scope.pk, self.out_of_scope.pk]))
        self.assertEqual(response.context["scope_filter"], "all")

    def test_rows_link_to_each_enforcement_point_detail_page(self):
        response, _ = self.listed_pks()

        self.assertContains(response, reverse("enforcement_point_detail", kwargs={"pk": self.in_scope.pk}))
        self.assertContains(response, reverse("enforcement_point_detail", kwargs={"pk": self.out_of_scope.pk}))
        self.assertNotContains(response, reverse("enforcement_point_detail", kwargs={"pk": self.elsewhere.pk}))

    def test_columns(self):
        response, _ = self.listed_pks()

        headers = re.findall(r"<th[^>]*>\s*(.*?)\s*</th>", response.content.decode())
        self.assertEqual(headers, ["Appliance Names", "VSYS", "Last Synced", "In Scope"])

    def test_the_scope_toggle_returns_to_the_filter_it_was_pressed_under(self):
        response, _ = self.listed_pks("out")
        self.assertContains(response, '<input type="hidden" name="scope" value="out">')

        response = self.client.post(
            reverse(
                "enforcement_point_scope_toggle",
                kwargs={"pk": self.station.pk, "enforcement_point_pk": self.out_of_scope.pk},
            ),
            {"scope": "out"},
        )
        self.assertRedirects(response, f"{self.url}?tab=enforcement-points&scope=out")

    def test_empty_state_names_the_active_filter(self):
        EnforcementPoint.objects.filter(management_station=self.station).delete()

        self.assertContains(self.listed_pks("in")[0], "No in-scope enforcement points")
        self.assertContains(self.listed_pks("out")[0], "No out-of-scope enforcement points")
        self.assertContains(self.listed_pks("all")[0], "No enforcement points recorded for this station")

    def test_the_standalone_list_page_is_gone(self):
        self.assertEqual(self.client.get("/integrations/enforcement-points/").status_code, 404)


class EnforcementPointDetailViewTests(TestCase):
    def setUp(self):
        self.station, self.group, self.appliance, self.enforcement_point = _create_grouped_enforcement_point(
            serial_number="0010",
            appliance_hostname="fw-detail",
            station_hostname="panorama-detail-ep.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            group_name="grp-detail",
            group_type=ApplianceGroup.TYPE_HA_PAIR,
            vsys_name="vsys7",
        )
        self.url = reverse("enforcement_point_detail", kwargs={"pk": self.enforcement_point.pk})

    def test_detail_view_renders_each_tab(self):
        for tab in ("details", "appliances"):
            response = self.client.get(self.url, {"tab": tab})

            self.assertEqual(response.status_code, 200)
            self.assertContains(response, "vsys7")

    def test_details_tab_is_the_default_and_the_fallback_for_an_unknown_tab(self):
        for query in ({}, {"tab": "not-a-tab"}):
            response = self.client.get(self.url, query)

            self.assertEqual(response.context["active_tab"], "details")
            self.assertContains(response, "Discovery Key")

    def test_details_tab_links_back_to_the_management_station(self):
        response = self.client.get(self.url)

        self.assertContains(
            response,
            reverse("management_station_detail", kwargs={"pk": self.station.pk}),
        )

    def test_appliances_tab_lists_nodes_and_marks_the_active_ha_member(self):
        standby = Appliance.objects.create(
            management_station=self.station,
            appliance_group=self.group,
            serial_number="0011",
            hostname="fw-detail-standby",
        )
        EnforcementNode.objects.create(
            management_station=self.station,
            enforcement_point=self.enforcement_point,
            appliance=standby,
        )

        response = self.client.get(self.url, {"tab": "appliances"})

        self.assertEqual([a.pk for a in response.context["appliances"]], [self.appliance.pk, standby.pk])
        self.assertContains(response, "fw-detail-standby")
        self.assertContains(response, "Active")
        self.assertContains(response, "Member")

    def test_appliances_tab_falls_back_to_an_appliance_scoped_point(self):
        """Only tests build this shape, but the template renders it, so pin the behaviour."""
        appliance_scoped = EnforcementPoint.objects.create(
            management_station=self.station,
            appliance=self.appliance,
            vsys_name="vsys-local",
        )

        response = self.client.get(
            reverse("enforcement_point_detail", kwargs={"pk": appliance_scoped.pk}),
            {"tab": "appliances"},
        )

        self.assertEqual([a.pk for a in response.context["appliances"]], [self.appliance.pk])

    def test_detail_view_404s_for_an_unknown_point(self):
        response = self.client.get(reverse("enforcement_point_detail", kwargs={"pk": self.enforcement_point.pk + 1000}))

        self.assertEqual(response.status_code, 404)


class EnforcementPointNavigationTests(TestCase):
    def test_sidebar_has_no_enforcement_points_item(self):
        """Enforcement points are browsed from their station's tab."""
        from optivedge.app_registry import sidebar_sections

        sections = [s for s in sidebar_sections() if s["label"] == "Firewall Integrations"]
        self.assertEqual(len(sections), 1)

        labels = [item["label"] for item in sections[0]["items"]]
        self.assertEqual(
            labels, ["Management Stations", "Collection Script"]
        )

    def test_enforcement_point_pages_light_up_management_stations(self):
        """A route missing from active_names silently stops highlighting its own page."""
        from optivedge_integrations.integrations import app_meta

        item = next(
            item
            for section in app_meta.SIDEBAR_SECTION
            for item in section["items"]
            if item["label"] == "Management Stations"
        )
        self.assertLessEqual(
            {"enforcement_point_detail", "enforcement_point_zone_detail"},
            item["active_names"],
        )


class EnforcementPointAddressListViewTests(TestCase):
    def test_get_renders_address_objects_for_enforcement_point(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-ADDR-001",
            appliance_hostname="fw-addr",
        )
        snapshot = Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={},
        )
        AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name="listed-object",
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=10,
            address_type=AddressObject.TYPE_IP_NETMASK,
            value="10.5.5.5/32",
            normalized_value="10.5.5.5/32",
        )

        response = self.client.get(
            reverse(
                "enforcement_point_addresses",
                kwargs={"pk": station.pk, "enforcement_point_pk": enforcement_point.pk},
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "listed-object")

    def test_get_filters_by_query_string(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-ADDR-002",
            appliance_hostname="fw-addr-2",
        )
        snapshot = Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={},
        )
        AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name="matching-object",
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=10,
            address_type=AddressObject.TYPE_IP_NETMASK,
            value="10.5.5.6/32",
            normalized_value="10.5.5.6/32",
        )
        AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name="other-object",
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=10,
            address_type=AddressObject.TYPE_IP_NETMASK,
            value="10.5.5.7/32",
            normalized_value="10.5.5.7/32",
        )

        response = self.client.get(
            reverse(
                "enforcement_point_addresses",
                kwargs={"pk": station.pk, "enforcement_point_pk": enforcement_point.pk},
            ),
            {"q": "matching"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "matching-object")
        self.assertNotContains(response, "other-object")


class EnforcementPointScopeToggleViewTests(TestCase):
    def test_post_toggles_in_scope_flag_and_redirects_to_detail(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-SCOPE-001",
            appliance_hostname="fw-scope",
        )
        self.assertFalse(enforcement_point.in_scope)

        response = self.client.post(
            reverse(
                "enforcement_point_scope_toggle",
                kwargs={"pk": station.pk, "enforcement_point_pk": enforcement_point.pk},
            )
        )

        enforcement_point.refresh_from_db()
        self.assertTrue(enforcement_point.in_scope)
        self.assertRedirects(
            response,
            f"{reverse('management_station_detail', kwargs={'pk': station.pk})}?tab=enforcement-points&scope=all",
        )

        # Toggling again flips it back.
        self.client.post(
            reverse(
                "enforcement_point_scope_toggle",
                kwargs={"pk": station.pk, "enforcement_point_pk": enforcement_point.pk},
            )
        )
        enforcement_point.refresh_from_db()
        self.assertFalse(enforcement_point.in_scope)


class NoteViewTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="notes-panorama.local",
        )
        self.group = ApplianceGroup.objects.create(
            management_station=self.station,
            name="notes-ha-pair",
            group_type=ApplianceGroup.TYPE_HA_PAIR,
        )
        Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="NOTE-SN-A", hostname="note-fw-a",
        )
        Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="NOTE-SN-B", hostname="note-fw-b",
        )

    def test_note_list_shows_appliance_names_and_body(self):
        Note.objects.create(
            content_type=ContentType.objects.get_for_model(ApplianceGroup),
            object_id=self.group.pk,
            body="Scheduled maintenance window Saturday.",
        )
        response = self.client.get(reverse("note_list"))
        self.assertEqual(response.status_code, 200)
        # The appliance name(s) are the presentation, not the group/target internals.
        self.assertContains(response, "note-fw-a")
        self.assertContains(response, "note-fw-b")
        self.assertContains(response, "Scheduled maintenance window Saturday.")

    def test_note_list_empty_state(self):
        response = self.client.get(reverse("note_list"))
        self.assertContains(response, "No notes yet.")

    def test_create_note_attaches_generic_target_to_appliance_group(self):
        response = self.client.post(
            reverse("note_create"),
            {"appliance_group": self.group.pk, "body": "First note."},
            follow=True,
        )
        self.assertRedirects(response, reverse("note_list"))
        note = Note.objects.get()
        self.assertEqual(note.body, "First note.")
        self.assertEqual(note.content_type, ContentType.objects.get_for_model(ApplianceGroup))
        self.assertEqual(note.object_id, self.group.pk)
        self.assertEqual(note.target, self.group)

    def test_update_note_edits_body(self):
        note = Note.objects.create(
            content_type=ContentType.objects.get_for_model(ApplianceGroup),
            object_id=self.group.pk,
            body="Original.",
        )
        response = self.client.post(
            reverse("note_update", kwargs={"pk": note.pk}),
            {"appliance_group": self.group.pk, "body": "Revised."},
            follow=True,
        )
        self.assertRedirects(response, reverse("note_list"))
        note.refresh_from_db()
        self.assertEqual(note.body, "Revised.")

    def test_notes_cascade_when_appliance_group_deleted(self):
        Note.objects.create(
            content_type=ContentType.objects.get_for_model(ApplianceGroup),
            object_id=self.group.pk,
            body="Doomed with the group.",
        )
        self.group.delete()
        self.assertEqual(Note.objects.count(), 0)

    def test_note_picker_orders_in_scope_first_by_active_appliance(self):
        from optivedge_integrations.integrations.forms import appliance_group_note_choice_queryset

        def make_group(name, active_hostname, in_scope):
            group = ApplianceGroup.objects.create(management_station=self.station, name=name)
            appliance = Appliance.objects.create(
                management_station=self.station, appliance_group=group,
                serial_number=f"SN-{name}", hostname=active_hostname,
            )
            group.active_appliance = appliance
            group.save(update_fields=["active_appliance"])
            EnforcementPoint.objects.create(
                management_station=self.station, appliance_group=group,
                vsys_name=f"vsys-{name}", in_scope=in_scope,
            )
            return group

        g_in_b = make_group("g-in-b", "b-fw", True)
        g_out_z = make_group("g-out-z", "z-fw", False)
        g_in_a = make_group("g-in-a", "a-fw", True)
        g_out_a = make_group("g-out-a", "a-fw-out", False)

        ordered = list(appliance_group_note_choice_queryset())
        # In scope first (sorted by active appliance name), then out of scope (same sort);
        # setUp's self.group has no in-scope EP and no active appliance -> out, nulls last.
        self.assertEqual(ordered, [g_in_a, g_in_b, g_out_a, g_out_z, self.group])


class PanoramaManagementDiscriminantTests(TestCase):
    """Whether Panorama data should exist is read from station_type, not from topology.

    These cover a path that previously had no tests at all, which is how the proxy
    survived: `latest_pushed_shared_snapshot()` inferred Panorama-management from
    `EnforcementPoint.appliance_group` being set. That inference held only because the
    non-Panorama collection path was never completed. `ApplianceGroup` models HA and
    multi-appliance topology, so a locally-managed HA pair - the thing it exists for -
    would have been misread as Panorama-managed and failed normalization.
    """

    def _merged_snapshot(self, station, appliance, enforcement_point):
        return Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={
                "config": {
                    "shared": {},
                    "devices": {
                        "entry": [{
                            "@name": "localhost.localdomain",
                            "vsys": {"entry": [{"@name": enforcement_point.vsys_name}]},
                        }]
                    },
                }
            },
        )

    def test_station_type_decides_not_the_presence_of_an_appliance_group(self):
        _, _, _, panorama_point = _create_grouped_enforcement_point(
            serial_number="0001", appliance_hostname="fw-a",
            station_hostname="panorama.local", group_name="grp-pan",
            station_type=ManagementStation.StationType.PAN_PANORAMA,
        )
        _, _, _, local_point = _create_grouped_enforcement_point(
            serial_number="0002", appliance_hostname="fw-b",
            station_hostname="firewall.local", group_name="grp-local",
            station_type=ManagementStation.StationType.PAN_FIREWALL,
            group_type=ApplianceGroup.TYPE_HA_PAIR,
        )

        # Both have an appliance group; only the station type differs.
        self.assertIsNotNone(panorama_point.appliance_group)
        self.assertIsNotNone(local_point.appliance_group)
        self.assertTrue(is_panorama_managed(panorama_point))
        self.assertFalse(is_panorama_managed(local_point))

    def test_pushed_shared_snapshot_is_not_returned_for_a_locally_managed_group(self):
        station, group, _, point = _create_grouped_enforcement_point(
            serial_number="0003", appliance_hostname="fw-c",
            station_hostname="firewall.local", group_name="grp-ha",
            station_type=ManagementStation.StationType.PAN_FIREWALL,
            group_type=ApplianceGroup.TYPE_HA_PAIR,
        )
        # Even if a snapshot somehow exists, it must not be attributed to a device with
        # no Panorama - the old code would have returned it purely because a group exists.
        Snapshot.objects.create(
            management_station=station,
            appliance_group=group,
            source_type="show_pushed_shared_policy",
            collected_at=timezone.now(),
            payload={"shared": {}},
        )
        self.assertIsNone(latest_pushed_shared_snapshot(point))

    def test_pushed_shared_snapshot_is_returned_for_a_panorama_managed_group(self):
        station, group, _, point = _create_grouped_enforcement_point(
            serial_number="0004", appliance_hostname="fw-d",
            station_hostname="panorama.local", group_name="grp-pan",
            station_type=ManagementStation.StationType.PAN_PANORAMA,
        )
        snapshot = Snapshot.objects.create(
            management_station=station,
            appliance_group=group,
            source_type="show_pushed_shared_policy",
            collected_at=timezone.now(),
            payload={"shared": {}},
        )
        self.assertEqual(latest_pushed_shared_snapshot(point), snapshot)

    def test_locally_managed_ha_pair_normalizes_without_panorama_snapshots(self):
        """The regression: this raised "missing pushed shared policy snapshot" for a
        device that never had one, and could not have."""
        station, _, appliance, point = _create_grouped_enforcement_point(
            serial_number="0005", appliance_hostname="fw-e",
            station_hostname="firewall.local", group_name="grp-ha2",
            station_type=ManagementStation.StationType.PAN_FIREWALL,
            group_type=ApplianceGroup.TYPE_HA_PAIR,
        )
        self._merged_snapshot(station, appliance, point)

        objects, groups, _issues = build_normalized_addresses(point)
        # Only the synthesized builtin "any" survives - nothing Panorama-derived, because
        # there is no Panorama. Previously this call raised instead of returning.
        self.assertEqual(
            [(obj.name, obj.namespace_type) for obj in objects],
            [("any", "builtin")],
        )
        self.assertEqual(groups, [])
        self.assertEqual(build_normalized_regions(point)[0], [])
        self.assertEqual(build_normalized_security_rules(point), [])

    def test_panorama_managed_point_still_requires_its_pushed_snapshots(self):
        """The guard must keep firing where it means something - a Panorama-managed
        point missing pushed data is a collection failure, not an empty result."""
        station, _, appliance, point = _create_grouped_enforcement_point(
            serial_number="0006", appliance_hostname="fw-f",
            station_hostname="panorama.local", group_name="grp-pan2",
            station_type=ManagementStation.StationType.PAN_PANORAMA,
        )
        self._merged_snapshot(station, appliance, point)

        with self.assertRaisesMessage(ValueError, "missing pushed shared policy snapshot"):
            build_normalized_addresses(point)
        with self.assertRaisesMessage(ValueError, "missing pushed VSYS snapshot"):
            build_normalized_security_rules(point)


class PushedScopeClassificationTests(TestCase):
    """Pushed objects are scoped by @loc, never by which read returned them.

    Grounded in what both lab devices actually return:
      PA-5220  non-vsys 352 objects all @loc=shared; per-vsys 1 object @loc=<dg>;
               the one overlapping name carries DIFFERENT @loc in each - a real
               cross-scope override pair.
      PA-VM    non-vsys and per-vsys are byte-identical, 52 objects, @loc=shared x51
               plus one @loc=prod-west - so read position mis-scopes 51 of them.
    """

    def _point(self):
        station, appliance, point = _create_panorama_enforcement_point(
            serial_number="9001", appliance_hostname="fw-scope", with_pushed_shared=False,
        )
        Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [
                {"@name": "localhost.localdomain",
                 "vsys": {"entry": [{"@name": point.vsys_name}]}}]}}},
        )
        return station, point

    def _pushed(self, station, point, *, group_payload, vsys_payload):
        Snapshot.objects.create(
            management_station=station, appliance_group=point.appliance_group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload=group_payload,
        )
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload=vsys_payload,
        )

    @staticmethod
    def _addr(name, loc, value):
        return {"@name": name, "@loc": loc, "ip-netmask": value}

    def test_identical_reads_yield_one_row_scoped_by_loc_not_read_position(self):
        """The PA-VM case. Read position would call these vsys-scoped and duplicate them."""
        station, point = self._point()
        entries = [self._addr("shared-a", "shared", "10.0.0.1"),
                   self._addr("dg-b", "prod-west", "10.0.0.2")]
        payload = {"shared": {"address": {"entry": entries}}}
        # Byte-identical responses, as measured on the single-vsys device.
        self._pushed(station, point, group_payload=payload,
                     vsys_payload={"policy": {"panorama": {"address": {"entry": entries}}}})

        objects, _, _issues = build_normalized_addresses(point)
        by_name = {o.name: o for o in objects if o.name in {"shared-a", "dg-b"}}
        self.assertEqual(len(by_name), 2, "each object must appear exactly once")
        self.assertEqual(by_name["shared-a"].namespace_type, PolicyObjectNamespace.PANORAMA_SHARED)
        self.assertEqual(by_name["shared-a"].namespace_value, "shared")
        # Carried by the non-vsys read, but device-group authored -> vsys scope.
        self.assertEqual(by_name["dg-b"].namespace_type, PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE)
        self.assertEqual(by_name["dg-b"].namespace_value, point.vsys_name)

    def test_same_name_in_both_scopes_is_kept_as_two_rows(self):
        """The PA-5220 override pair. Both definitions are delivered and both must persist."""
        station, point = self._point()
        self._pushed(
            station, point,
            group_payload={"shared": {"address": {"entry": [
                self._addr("ovr", "shared", "10.213.1.1")]}}},
            vsys_payload={"policy": {"panorama": {"address": {"entry": [
                self._addr("ovr", "dg_app", "10.214.1.1")]}}}},
        )
        objects, _, _issues = build_normalized_addresses(point)
        ovr = sorted((o for o in objects if o.name == "ovr"), key=lambda o: o.namespace_type)
        self.assertEqual(
            [(o.namespace_type, o.value) for o in ovr],
            [(PolicyObjectNamespace.PANORAMA_SHARED, "10.213.1.1"),
             (PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE, "10.214.1.1")],
        )

    def test_conflicting_definitions_are_reported_per_name_not_raised(self):
        """This used to raise and discard every pushed object for the point. One name the
        two reads disagree about is now scoped to that name - as an ERROR, since two views
        of one pushed policy cannot legitimately differ, but KEPT so referencing rules do
        not fail and misattribute the fault."""
        station, point = self._point()
        self._pushed(
            station, point,
            group_payload={"shared": {"address": {"entry": [
                self._addr("clash", "shared", "10.0.0.1"),
                self._addr("fine", "shared", "10.0.0.2")]}}},
            vsys_payload={"policy": {"panorama": {"address": {"entry": [
                self._addr("clash", "shared", "10.0.0.99")]}}}},
        )
        objects, _, issues = build_normalized_addresses(point)

        conflict = [i for i in issues if i.name == "clash"]
        self.assertEqual(len(conflict), 1)
        self.assertEqual(conflict[0].severity, "error")
        self.assertEqual(conflict[0].disposition, "kept")
        self.assertIn("disagree", conflict[0].reason)
        # the unaffected object survives, which is the whole point
        self.assertIn("fine", {o.name for o in objects})
        self.assertIn("clash", {o.name for o in objects}, "first definition kept")

    def test_an_entry_without_loc_falls_back_to_vsys_scope_and_keeps_the_build_alive(self):
        """This used to raise. An Azure cloud firewall pushes `azure-healthcheck-address`
        with no marker, and the raise took down that point's entire address build - 242
        objects and every rule on it - over one vendor-injected entry.

        Vsys is the conservative fallback: the narrower scope, so an unmarked entry cannot
        leak across the other vsys of a group the way a wrong shared classification would.
        """
        station, point = self._point()
        self._pushed(
            station, point,
            group_payload={"shared": {"address": {"entry": [
                {"@name": "azure-healthcheck-address", "ip-netmask": "168.63.129.16"},
                self._addr("shared-ok", "shared", "10.0.0.1"),
            ]}}},
            vsys_payload={"policy": {"panorama": {}}},
        )
        objects, _, _issues = build_normalized_addresses(point)
        by_name = {o.name: o for o in objects}

        self.assertIn("azure-healthcheck-address", by_name, "the unmarked entry is kept")
        self.assertEqual(by_name["azure-healthcheck-address"].namespace_type,
                         PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE)
        self.assertEqual(by_name["azure-healthcheck-address"].namespace_value, point.vsys_name)
        # and, critically, it does not take the marked objects down with it
        self.assertIn("shared-ok", by_name)
        self.assertEqual(by_name["shared-ok"].namespace_type,
                         PolicyObjectNamespace.PANORAMA_SHARED)


class PushedSharedPayloadShapeTests(TestCase):
    """The non-vsys pushed response roots differently by device; both are accepted.

        result.shared            multi-vsys PA-5220, 11.1.13-h3
        result.policy.panorama   single-vsys PA-VM,  11.2.3

    Reading only `shared` returned {} silently on the second shape. Nothing was lost
    on the lab PA-VM only because its two pushed reads are byte-identical, so the
    per-vsys read caught what this one dropped.
    """

    ENTRY = {"@name": "shr-1", "@loc": "shared", "ip-netmask": "10.0.0.1"}

    def test_both_payload_roots_yield_the_same_subtree(self):
        by_shared = pushed_shared({"shared": {"address": {"entry": [self.ENTRY]}}})
        by_panorama = pushed_shared({"policy": {"panorama": {"address": {"entry": [self.ENTRY]}}}})
        self.assertEqual(by_shared, by_panorama)
        self.assertEqual(by_shared["address"]["entry"], [self.ENTRY])

    def test_unrecognised_root_raises_rather_than_reporting_an_empty_subtree(self):
        """An unrecognised shape is not evidence of an empty one - returning {} here
        would report "this device has no shared objects" for an unexplained response."""
        with self.assertRaisesMessage(ValueError, "unrecognised pushed shared payload root"):
            pushed_shared({"something-else": {}})

    def test_non_dict_payload_still_raises_with_its_value(self):
        """Kept asymmetric with pushed_vsys_panorama(), which absorbs this string."""
        with self.assertRaisesMessage(ValueError, "No shared policy pushed to device"):
            pushed_shared("No shared policy pushed to device")

    def test_empty_shared_subtree_is_a_valid_empty_result(self):
        self.assertEqual(pushed_shared({"shared": {}}), {})

    def test_pa_vm_shape_end_to_end_produces_correctly_scoped_objects(self):
        """The shape that used to yield nothing now normalizes, and the merge absorbs
        the duplicate arrival that made this fix unsafe before @loc classification."""
        station, appliance, point = _create_panorama_enforcement_point(
            serial_number="9100", appliance_hostname="fw-pavm", with_pushed_shared=False,
        )
        Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [
                {"@name": "localhost.localdomain",
                 "vsys": {"entry": [{"@name": point.vsys_name}]}}]}}},
        )
        # Byte-identical reads in the PA-VM's root shape, as measured.
        entries = [self.ENTRY, {"@name": "dg-1", "@loc": "prod-west", "ip-netmask": "10.0.0.2"}]
        body = {"policy": {"panorama": {"address": {"entry": entries}}}}
        Snapshot.objects.create(
            management_station=station, appliance_group=point.appliance_group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(), payload=body,
        )
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(), payload=body,
        )

        objects, _, _issues = build_normalized_addresses(point)
        got = {o.name: (o.namespace_type, o.namespace_value)
               for o in objects if o.name in {"shr-1", "dg-1"}}
        self.assertEqual(got, {
            "shr-1": (PolicyObjectNamespace.PANORAMA_SHARED, "shared"),
            "dg-1": (PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE, point.vsys_name),
        }, "each object once, scoped by @loc - not duplicated across the two reads")


class CrossNamespaceNameResolutionTests(TestCase):
    """A name matching more than one object namespace - which is NOT always a fault.

    Measured on a PA-VM 11.2.3, 2026-08:

        address object + address group   rejected by PAN-OS at the candidate WRITE
        address object + EDL             rejected at COMMIT VALIDATION
        address group  + EDL             rejected at COMMIT VALIDATION
        anything above + REGION          LEGAL, and the REGION wins

    The address-namespace collisions cannot reach us from a device, so they indicate our
    own fault and raise. The region case is legal, was committed on a real firewall, and
    must resolve to the region - it previously raised, failing normalization for a
    configuration PAN-OS had accepted.
    """

    def _members(self, name):
        return [NormalizedSecurityRuleMember(
            model=SecurityRuleSourceAddressRef, value=name, prov="", position=0
        )]

    def _object(self, name, value="10.0.0.1/32", is_any=False,
                namespace_type=PolicyObjectNamespace.LOCAL_VSYS):
        obj = AddressObject(name=name, value=value, is_any=is_any,
                            namespace_type=namespace_type, namespace_value="vsys1")
        obj.pk = abs(hash(name)) % 10_000
        return obj

    def _group(self, name, dynamic_filter="",
               namespace_type=PolicyObjectNamespace.LOCAL_VSYS):
        grp = AddressGroup(name=name, dynamic_filter=dynamic_filter,
                           namespace_type=namespace_type, namespace_value="vsys1")
        grp.pk = abs(hash(name)) % 10_000
        return grp

    def _region(self, name, namespace_type=PolicyObjectNamespace.LOCAL_VSYS):
        reg = Region(name=name, namespace_type=namespace_type, namespace_value="vsys1")
        reg.pk = abs(hash(name)) % 10_000
        return reg

    def test_region_wins_over_an_address_object_of_the_same_name(self):
        name = "US"
        refs = resolve_rule_address_refs(
            members=self._members(name),
            address_objects_by_name={name: [self._object(name, "10.77.2.1/32")]},
            address_groups_by_name={},
            regions_by_name={name: [self._region(name)]},
        )
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].ref_type, SecurityRuleSourceAddressRef.RefType.REGION)
        # The address object is inert on the device; it must not be attached here either.
        self.assertIsNone(refs[0].address_object)
        self.assertIsNone(refs[0].address_group)
        self.assertEqual(refs[0].region.name, name)

    def test_region_wins_over_an_address_group_of_the_same_name(self):
        name = "v9-grp-region"
        refs = resolve_rule_address_refs(
            members=self._members(name),
            address_objects_by_name={},
            address_groups_by_name={name: [self._group(name)]},
            regions_by_name={name: [self._region(name)]},
        )
        self.assertEqual(refs[0].ref_type, SecurityRuleSourceAddressRef.RefType.REGION)
        self.assertIsNone(refs[0].address_group)

    def test_builtin_region_code_wins_over_an_address_object_without_a_custom_region(self):
        """Predefined region names are not reserved - an address object may be named GB.
        The builtin code still wins, and `region` stays null as the model allows."""
        name = "GB"
        self.assertIn(name, ISO_3166_1_ALPHA2_REGIONS)
        refs = resolve_rule_address_refs(
            members=self._members(name),
            address_objects_by_name={name: [self._object(name)]},
            address_groups_by_name={},
            regions_by_name={},
        )
        self.assertEqual(refs[0].ref_type, SecurityRuleSourceAddressRef.RefType.REGION)
        self.assertIsNone(refs[0].region)
        self.assertIsNone(refs[0].address_object)

    def test_address_object_and_group_sharing_a_name_raises_as_our_fault(self):
        """PAN-OS rejects this at the candidate write, so a device cannot present it."""
        name = "collide"
        with self.assertRaisesMessage(ValueError, "PAN-OS rejects this configuration"):
            resolve_rule_address_refs(
                members=self._members(name),
                address_objects_by_name={name: [self._object(name)]},
                address_groups_by_name={name: [self._group(name)]},
                regions_by_name={},
            )

    def test_an_unambiguous_address_object_still_resolves_normally(self):
        name = "web-servers"
        refs = resolve_rule_address_refs(
            members=self._members(name),
            address_objects_by_name={name: [self._object(name)]},
            address_groups_by_name={},
            regions_by_name={},
        )
        self.assertEqual(refs[0].ref_type, SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT)
        self.assertEqual(refs[0].address_object.name, name)


class ScopePrecedenceTests(TestCase):
    """Scope is the only precedence axis; ownership is provenance.

    Measured against a PA-5220 11.1.13-h3 and a PA-VM 11.2.3, 2026-08, from compiled
    policy. The four-level ladder this replaced was wrong twice: it put LOCAL_SHARED
    ahead of PUSHED_VSYS_EFFECTIVE, and it gave distinct ranks to pairs PAN-OS rejects.
    """

    def test_vsys_scope_namespaces_all_rank_together(self):
        vsys = [PolicyObjectNamespace.LOCAL_VSYS,
                PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE,
                PolicyObjectNamespace.PANORAMA_DEVICE_GROUP]
        for ns in vsys:
            self.assertEqual(scope_for(ns), PolicyObjectScope.VSYS, ns)
        self.assertEqual({precedence_for(ns) for ns in vsys}, {PolicyObjectPrecedence.VSYS})

    def test_shared_scope_namespaces_all_rank_together(self):
        shared = [PolicyObjectNamespace.LOCAL_SHARED, PolicyObjectNamespace.PANORAMA_SHARED]
        for ns in shared:
            self.assertEqual(scope_for(ns), PolicyObjectScope.SHARED, ns)
        self.assertEqual({precedence_for(ns) for ns in shared}, {PolicyObjectPrecedence.SHARED})

    def test_a_pushed_device_group_object_outranks_a_local_shared_one(self):
        """The measurement that refuted the ladder: pushed-DG 10.221.1.1 beat
        local-shared 10.222.1.1 in compiled policy. Ownership is not precedence."""
        self.assertLess(
            precedence_for(PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE),
            precedence_for(PolicyObjectNamespace.LOCAL_SHARED),
        )

    def test_every_namespace_has_a_scope(self):
        for ns in PolicyObjectNamespace:
            self.assertIn(scope_for(ns), PolicyObjectScope.ORDER, ns)

    def test_an_unmapped_namespace_raises_rather_than_defaulting(self):
        with self.assertRaisesMessage(ValueError, "no scope defined for namespace"):
            scope_for("something_new")

    def _obj(self, name, namespace_type, value):
        obj = AddressObject(name=name, value=value, namespace_type=namespace_type,
                            namespace_value="vsys1")
        obj.pk = abs(hash(f"{name}{namespace_type}{value}")) % 100_000
        return obj

    def test_vsys_scope_wins_over_shared_regardless_of_owner(self):
        """Both cross-scope directions, since the ladder got one of them backwards."""
        name = "dual"
        cases = [
            (PolicyObjectNamespace.LOCAL_VSYS, PolicyObjectNamespace.PANORAMA_SHARED),
            (PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE, PolicyObjectNamespace.LOCAL_SHARED),
        ]
        for vsys_ns, shared_ns in cases:
            with self.subTest(vsys=vsys_ns, shared=shared_ns):
                candidates = [self._obj(name, shared_ns, "10.2.2.2/32"),
                              self._obj(name, vsys_ns, "10.1.1.1/32")]
                winner = first_effective_object(name, {name: candidates})
                self.assertEqual(winner.namespace_type, vsys_ns)
                self.assertEqual(winner.value, "10.1.1.1/32")

    def test_two_definitions_in_one_scope_raise_instead_of_picking_one(self):
        """PAN-OS rejects this configuration, so a device cannot present it. Reaching
        here means our collection or @loc classification is wrong."""
        name = "impossible"
        candidates = [self._obj(name, PolicyObjectNamespace.LOCAL_VSYS, "10.1.1.1/32"),
                      self._obj(name, PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE, "10.9.9.9/32")]
        with self.assertRaisesMessage(ValueError, "in vsys scope"):
            first_effective_object(name, {name: candidates})

    def test_vendor_objects_are_the_fallback_tier(self):
        name = "any"
        builtin = self._obj(name, PolicyObjectNamespace.BUILTIN, "any")
        local = self._obj(name, PolicyObjectNamespace.LOCAL_VSYS, "10.1.1.1/32")
        self.assertEqual(first_effective_object(name, {name: [builtin, local]}), local)
        self.assertEqual(first_effective_object(name, {name: [builtin]}), builtin)

    def test_literal_namespace_no_longer_returns_a_rank(self):
        """It returned hardcoded 10 and 30, bypassing PolicyObjectPrecedence entirely.
        Both literal cases are vsys scope; they differ only in provenance."""
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pan.local")
        appliance = Appliance.objects.create(
            management_station=station, serial_number="7000", hostname="fw-lit")
        point = EnforcementPoint.objects.create(
            management_station=station, appliance=appliance, vsys_name="vsys1")
        local_snap = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        pushed_snap = Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(), payload={})

        for snapshot, expected_ns in [(local_snap, PolicyObjectNamespace.LOCAL_VSYS),
                                      (pushed_snap, PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE)]:
            ns, value = literal_namespace(enforcement_point=point, source_snapshot=snapshot)
            self.assertEqual(ns, expected_ns)
            self.assertEqual(value, "vsys1")
            self.assertEqual(scope_for(ns), PolicyObjectScope.VSYS)
            self.assertEqual(precedence_for(ns), PolicyObjectPrecedence.VSYS)


class RuleLiteralDedupeTests(TestCase):
    """One inline IP is one address, however many rulebases mention it.

    A literal's namespace records provenance - local rule or pushed rule - and provenance
    is not a precedence level. Keying the dedupe on it produced two identical rows for
    172.200.255.254 on a live enforcement point, which blocked the Stage B unique
    constraint on a duplicate we manufactured.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pan.local")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="grp", group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="9100", hostname="fw-lit")
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.group, vsys_name="vsys1")
        self.local_snap = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        self.pushed_snap = Snapshot.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(), payload={})

    def _realize(self, rules):
        """Call it the way production does: maps built first, then passed in."""
        maps = build_address_lookup_maps(self.point)
        realize_literal_address_objects(self.point, rules, *maps)
        return maps

    def _rule(self, snapshot, value):
        member = NormalizedSecurityRuleMember(
            model=SecurityRuleSourceAddressRef, value=value, prov="", position=0)
        return NormalizedSecurityRule(
            source_snapshot=snapshot, config_source="local", effective_order=0, rule_position=0,
            name="r", uuid="", action="allow", disabled=False, rule_type="universal",
            description="", log_start=None, log_end=None, log_setting="",
            negate_source=False, negate_destination=False, raw_rule={},
            members=[member], source_address_members=[member], destination_address_members=[],
            field_provenance_data=[])

    def test_one_literal_in_a_local_and_a_pushed_rule_makes_one_row(self):
        self._realize([
            self._rule(self.local_snap, "172.200.255.254"),
            self._rule(self.pushed_snap, "172.200.255.254"),
        ])
        rows = self.point.address_objects.filter(name="172.200.255.254")
        self.assertEqual(rows.count(), 1, "one inline IP is one address")

    def test_the_surviving_row_records_both_provenances(self):
        """namespace_type can only carry one. Losing the other silently would be worse."""
        self._realize([
            self._rule(self.pushed_snap, "172.200.255.254"),
            self._rule(self.local_snap, "172.200.255.254"),
        ])
        row = self.point.address_objects.get(name="172.200.255.254")
        self.assertEqual(row.namespace_type, PolicyObjectNamespace.LOCAL_VSYS)
        self.assertEqual(
            row.raw_object["namespaces"],
            [PolicyObjectNamespace.LOCAL_VSYS, PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE])

    def test_the_choice_does_not_depend_on_rule_order(self):
        for rules in ([self.local_snap, self.pushed_snap], [self.pushed_snap, self.local_snap]):
            self.point.address_objects.all().delete()
            self._realize([self._rule(s, "10.9.9.9") for s in rules])
            self.assertEqual(
                self.point.address_objects.get(name="10.9.9.9").namespace_type,
                PolicyObjectNamespace.LOCAL_VSYS)

    def test_a_collected_object_of_that_name_suppresses_the_literal(self):
        """A rule member is a name reference first. An object named for an IP is legal."""
        AddressObject.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.local_snap, config_source="local", name="172.200.255.254",
            namespace_type=PolicyObjectNamespace.LOCAL_VSYS, namespace_value="vsys1",
            precedence_rank=precedence_for(PolicyObjectNamespace.LOCAL_VSYS),
            address_type=AddressObject.TYPE_IP_NETMASK, value="1.1.1.1/32",
            last_synced_at=timezone.now())

        self._realize([self._rule(self.pushed_snap, "172.200.255.254")])
        rows = self.point.address_objects.filter(name="172.200.255.254")
        self.assertEqual(rows.count(), 1)
        self.assertFalse(rows.get().is_synthetic, "must not shadow a collected object")

    def test_a_shared_scope_object_of_that_name_also_suppresses_it(self):
        """Shared objects live on the group now, so the point's own rows cannot see them."""
        AddressObject.objects.create(
            management_station=self.station, appliance_group=self.group,
            source_snapshot=self.local_snap, config_source="local", name="172.16.5.5",
            namespace_type=PolicyObjectNamespace.LOCAL_SHARED, namespace_value="shared",
            precedence_rank=precedence_for(PolicyObjectNamespace.LOCAL_SHARED),
            address_type=AddressObject.TYPE_IP_NETMASK, value="2.2.2.2/32",
            last_synced_at=timezone.now())

        self._realize([self._rule(self.local_snap, "172.16.5.5")])
        self.assertEqual(self.point.address_objects.filter(name="172.16.5.5").count(), 0)

    def test_the_new_row_is_added_to_the_map_the_resolve_pass_uses(self):
        """The maps are built once. If synthesis did not append, resolution would raise
        UnresolvedAddressReference on a name it had just created."""
        maps = self._realize([self._rule(self.local_snap, "10.7.7.7")])
        address_objects_by_name, _groups, _regions = maps
        self.assertIn("10.7.7.7", address_objects_by_name)

        resolved = resolve_rule_address_refs(
            members=[NormalizedSecurityRuleMember(
                model=SecurityRuleSourceAddressRef, value="10.7.7.7", prov="", position=0)],
            address_objects_by_name=address_objects_by_name,
            address_groups_by_name=_groups,
            regions_by_name=_regions,
        )
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0].address_object.name, "10.7.7.7")

    def test_a_region_name_is_owned_and_is_never_synthesized_over(self):
        """The flat-set guard omitted regions entirely. name_is_owned does not."""
        self.assertTrue(name_is_owned("US", {}, {}, {}))
        self.assertFalse(name_is_owned("10.4.4.4", {}, {}, {}))

    def test_an_address_group_of_that_name_suppresses_the_literal(self):
        AddressGroup.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.local_snap, config_source="local", name="10.5.5.5",
            namespace_type=PolicyObjectNamespace.LOCAL_VSYS, namespace_value="vsys1",
            precedence_rank=precedence_for(PolicyObjectNamespace.LOCAL_VSYS),
            last_synced_at=timezone.now())

        self._realize([self._rule(self.local_snap, "10.5.5.5")])
        self.assertEqual(self.point.address_objects.filter(name="10.5.5.5").count(), 0)


class SharedScopeOwnershipTests(TestCase):
    """Shared-scope objects belong to the appliance group, not to each enforcement point.

    Every vsys on a group reads the same /config/shared and receives the same
    Panorama-Shared push, so storing shared scope per point copied one observation once
    per vsys - 264 objects became 1,320 rows on a five-vsys PA-5220.
    """

    def _station_with_two_points(self):
        station, group, appliance, point_a = _create_grouped_enforcement_point(
            serial_number="8100", appliance_hostname="fw-shared",
            station_hostname="panorama.local", group_name="grp-shared",
            station_type=ManagementStation.StationType.PAN_PANORAMA, vsys_name="vsys1",
        )
        point_b = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group,
            vsys_name="vsys2", in_scope=True,
        )
        EnforcementNode.objects.create(
            management_station=station, enforcement_point=point_b, appliance=appliance)
        point_a.in_scope = True
        point_a.save()

        merged = {"config": {
            "shared": {"address": {"entry": [
                {"@name": "shared-obj", "ip-netmask": "10.50.0.1/32"}]}},
            "devices": {"entry": [{"@name": "localhost.localdomain", "vsys": {"entry": [
                {"@name": "vsys1", "address": {"entry": [
                    {"@name": "vsys1-obj", "ip-netmask": "10.60.1.1/32"}]}},
                {"@name": "vsys2", "address": {"entry": [
                    {"@name": "vsys2-obj", "ip-netmask": "10.60.2.1/32"}]}},
            ]}}]}}}
        Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload=merged)
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"shared": {"address": {"entry": [
                {"@name": "pan-shared", "@loc": "shared", "ip-netmask": "10.51.0.1/32"}]}}})
        for point in (point_a, point_b):
            Snapshot.objects.create(
                management_station=station, enforcement_point=point,
                source_type="show_pushed_shared_policy_vsys",
                collected_at=timezone.now(), payload={"policy": {"panorama": {}}})
        return station, group, point_a, point_b

    def test_shared_objects_are_stored_once_on_the_group_not_per_point(self):
        station, group, point_a, point_b = self._station_with_two_points()
        normalize_appliance_group_shared_scope(group)
        normalize_enforcement_point_addresses(point_a)
        normalize_enforcement_point_addresses(point_b)

        self.assertEqual(
            sorted(group.address_objects.values_list("name", flat=True)),
            ["pan-shared", "shared-obj"],
            "both local-shared and Panorama-shared belong to the group",
        )
        # Each point holds only its own vsys scope plus the synthesized builtin.
        for point, own in ((point_a, "vsys1-obj"), (point_b, "vsys2-obj")):
            names = sorted(point.address_objects.values_list("name", flat=True))
            self.assertEqual(names, ["any", own], f"{point.vsys_name} holds only its own scope")

        # The duplication this removes: one row each, not one per point.
        self.assertEqual(AddressObject.objects.filter(name="shared-obj").count(), 1)
        self.assertEqual(AddressObject.objects.filter(name="pan-shared").count(), 1)

    def test_a_rule_resolves_across_both_owners(self):
        """The point sees the union of its own scope and the group's shared scope."""
        station, group, point_a, _ = self._station_with_two_points()
        normalize_appliance_group_shared_scope(group)
        normalize_enforcement_point_addresses(point_a)

        objects, groups, regions = build_address_lookup_maps(point_a)
        self.assertIn("vsys1-obj", objects, "own vsys scope")
        self.assertIn("shared-obj", objects, "group-owned local-shared")
        self.assertIn("pan-shared", objects, "group-owned Panorama-shared")
        self.assertNotIn("vsys2-obj", objects, "another vsys's scope must not leak in")

    def test_shared_objects_survive_a_second_point_being_normalized(self):
        """Order matters: the group pass is a delete-and-recreate, so re-running a point
        must not disturb rows that rule address refs already FK to."""
        station, group, point_a, point_b = self._station_with_two_points()
        normalize_appliance_group_shared_scope(group)
        original_ids = set(group.address_objects.values_list("pk", flat=True))

        normalize_enforcement_point_addresses(point_a)
        normalize_enforcement_point_addresses(point_b)

        self.assertEqual(set(group.address_objects.values_list("pk", flat=True)), original_ids)

    def test_owner_must_match_scope(self):
        station, group, point_a, _ = self._station_with_two_points()
        snapshot = Snapshot.objects.get(source_type="show_pushed_shared_policy")
        wrong = AddressObject(
            management_station=station, enforcement_point=point_a, source_snapshot=snapshot,
            config_source="pushed_pre", name="misfiled",
            namespace_type=PolicyObjectNamespace.PANORAMA_SHARED, namespace_value="shared",
            precedence_rank=precedence_for(PolicyObjectNamespace.PANORAMA_SHARED),
            address_type=AddressObject.TYPE_IP_NETMASK, value="10.0.0.1/32",
            last_synced_at=timezone.now(),
        )
        with self.assertRaisesMessage(ValidationError, "shared-scoped and must belong to an appliance group"):
            wrong.clean()


class PolicyObjectCensusTests(TestCase):
    """The census exists to validate that shared-scope rows collapsed to one per group.

    So the tests check it can tell the two states apart — not merely that it runs.
    """

    def _fixture(self):
        station, group, appliance, point_a = _create_grouped_enforcement_point(
            serial_number="8500", appliance_hostname="fw-census",
            station_hostname="panorama.local", group_name="grp-census",
            station_type=ManagementStation.StationType.PAN_PANORAMA, vsys_name="vsys1",
        )
        point_b = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, vsys_name="vsys2")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"shared": {}},
        )
        return station, group, point_a, point_b, snapshot

    def _shared_object(self, station, snapshot, name, *, owner):
        kwargs = {"enforcement_point": owner} if isinstance(owner, EnforcementPoint) else {"appliance_group": owner}
        return AddressObject.objects.create(
            management_station=station, source_snapshot=snapshot, config_source="pushed_pre",
            name=name, namespace_type=PolicyObjectNamespace.PANORAMA_SHARED,
            namespace_value="shared",
            precedence_rank=precedence_for(PolicyObjectNamespace.PANORAMA_SHARED),
            address_type=AddressObject.TYPE_IP_NETMASK, value="10.0.0.1/32",
            last_synced_at=timezone.now(), **kwargs,
        )

    def test_reports_one_row_per_object_when_shared_scope_is_group_owned(self):
        station, group, _, _, snapshot = self._fixture()
        for name in ("shr-a", "shr-b"):
            self._shared_object(station, snapshot, name, owner=group)

        census = capture_census(label="after")
        dup = census["models"]["AddressObject"]["duplication"]
        self.assertEqual(dup, {"shared_rows": 2, "distinct_shared": 2, "rows_per_object": 1.0})
        self.assertEqual(census["models"]["AddressObject"]["by_owner"]["appliance_group"], 2)
        self.assertEqual(census["models"]["AddressObject"]["by_owner"]["enforcement_point"], 0)

    def test_detects_the_duplication_the_split_removed(self):
        """The pre-change shape: the same shared object stored once per vsys."""
        station, group, point_a, point_b, snapshot = self._fixture()
        for point in (point_a, point_b):
            for name in ("shr-a", "shr-b"):
                self._shared_object(station, snapshot, name, owner=point)

        census = capture_census(label="before")
        dup = census["models"]["AddressObject"]["duplication"]
        self.assertEqual(dup["shared_rows"], 4)
        self.assertEqual(dup["distinct_shared"], 2)
        self.assertEqual(dup["rows_per_object"], 2.0, "two vsys, so two rows per object")

    def test_compare_flags_surviving_duplication_and_stays_quiet_when_clean(self):
        station, group, point_a, point_b, snapshot = self._fixture()
        for point in (point_a, point_b):
            self._shared_object(station, snapshot, "shr-a", owner=point)
        before = capture_census(label="before")

        AddressObject.objects.all().delete()
        self._shared_object(station, snapshot, "shr-a", owner=group)
        after = capture_census(label="after")

        clean = compare_censuses(before, after)
        self.assertEqual(clean["models"]["AddressObject"]["shared_rows"], {"before": 2, "after": 1, "delta": -1})
        self.assertEqual(clean["observations"], [
            "No anomalies: shared scope is stored once per appliance group and dependent "
            "rows were rebuilt."
        ])

        noisy = compare_censuses(before, before)
        self.assertTrue(any("still stored more than once" in o for o in noisy["observations"]))

    def test_compare_flags_a_renormalize_that_never_ran(self):
        station, group, point_a, _, snapshot = self._fixture()
        SecurityRule.objects.create(
            management_station=station, enforcement_point=point_a, source_snapshot=snapshot,
            config_source="local", effective_order=1, rule_position=1, name="r1",
            last_synced_at=timezone.now(),
        )
        before = capture_census(label="before")
        SecurityRule.objects.all().delete()          # what migration 0015 does
        after = capture_census(label="after")

        result = compare_censuses(before, after)
        self.assertTrue(
            any("renormalize did not run" in o for o in result["observations"]),
            result["observations"],
        )

    def test_the_same_name_in_different_groups_is_not_duplication(self):
        """Regression: namespace_value is the literal "shared" for every shared object, so
        keying duplication on (namespace_value, name) collapsed distinct groups together
        and reported 3.0 rows per object for a perfectly correct three-group deployment."""
        station, group_a, _, _, snapshot_a = self._fixture()
        group_b = ApplianceGroup.objects.create(management_station=station, name="grp-second")
        snapshot_b = Snapshot.objects.create(
            management_station=station, appliance_group=group_b,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(), payload={})

        self._shared_object(station, snapshot_a, "shr-a", owner=group_a)
        self._shared_object(station, snapshot_b, "shr-a", owner=group_b)

        dup = capture_census()["models"]["AddressObject"]["duplication"]
        self.assertEqual(dup["shared_rows"], 2)
        self.assertEqual(dup["distinct_shared"], 2, "one per group - not one overall")
        self.assertEqual(dup["rows_per_object"], 1.0, "each group holds exactly one copy")

    def test_compare_warns_when_the_snapshots_are_selected_backwards(self):
        self._fixture()
        first = capture_census(label="before-renormalize")
        second = capture_census(label="after-renormalize")
        second["captured_at"] = "2099-01-01T00:00:00+00:00"

        backwards = compare_censuses(second, first)
        self.assertTrue(
            any("inverted" in o for o in backwards["observations"]), backwards["observations"])
        forwards = compare_censuses(first, second)
        self.assertFalse(any("inverted" in o for o in forwards["observations"]))

    def test_write_and_load_round_trip(self):
        self._fixture()
        census = capture_census(label="round-trip")
        with tempfile.TemporaryDirectory() as tmp:
            path = write_census(census, Path(tmp) / "census.json")
            self.assertEqual(load_census(path), census)


class DeveloperPageTests(TestCase):
    """The hidden operations page: renders live counts, captures, and compares."""

    def setUp(self):
        self.census_dir = tempfile.TemporaryDirectory()
        patcher = patch(
            "optivedge_integrations.integrations.diagnostics.policy_object_census.DEFAULT_CENSUS_DIR",
            Path(self.census_dir.name),
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.census_dir.cleanup)

    def test_page_renders_live_counts_without_writing_anything(self):
        response = self.client.get(reverse("developer"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Policy object census")
        self.assertContains(response, "Rows / object")
        self.assertEqual(list(Path(self.census_dir.name).glob("*.json")), [],
                         "viewing the page must not write a snapshot")

    def test_page_is_not_advertised_in_the_sidebar(self):
        """It is reachable only by typing the URL; app_meta must not list it."""
        from optivedge_integrations.integrations import app_meta
        self.assertNotIn("developer", str(getattr(app_meta, "SIDEBAR_SECTION", "")))

    def test_capture_writes_a_snapshot_and_reports_it(self):
        response = self.client.post(
            reverse("policy_object_census_capture"), {"label": "before-renormalize"}, follow=True)
        self.assertEqual(response.status_code, 200)
        written = list(Path(self.census_dir.name).glob("*.json"))
        self.assertEqual(len(written), 1)
        self.assertIn("before-renormalize", written[0].name)
        self.assertContains(response, "Captured &quot;before-renormalize&quot;")

    def test_capture_warns_when_the_database_predates_the_migration(self):
        with patch(
            "optivedge_integrations.integrations.diagnostics.policy_object_census._has_owner_column",
            return_value=False,
        ):
            response = self.client.post(
                reverse("policy_object_census_capture"), {"label": "old-schema"}, follow=True)
        self.assertContains(response, "predates migration 0015")

    def test_comparing_two_snapshots_shows_the_drop(self):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="8700", appliance_hostname="fw-dev", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="grp-dev")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(), payload={})

        def shared(owner, name):
            kwargs = ({"enforcement_point": owner} if isinstance(owner, EnforcementPoint)
                      else {"appliance_group": owner})
            AddressObject.objects.create(
                management_station=station, source_snapshot=snapshot, config_source="pushed_pre",
                name=name, namespace_type=PolicyObjectNamespace.PANORAMA_SHARED,
                namespace_value="shared",
                precedence_rank=precedence_for(PolicyObjectNamespace.PANORAMA_SHARED),
                address_type=AddressObject.TYPE_IP_NETMASK, value="10.0.0.1/32",
                last_synced_at=timezone.now(), **kwargs)

        point_b = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, vsys_name="vsys2")
        for owner in (point, point_b):
            shared(owner, "shr-a")
        before = write_census(capture_census(label="before"))

        AddressObject.objects.all().delete()
        shared(group, "shr-a")
        after = write_census(capture_census(label="after"))

        response = self.client.get(
            reverse("developer"), {"before": str(before), "after": str(after)})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "before &rarr; after")
        self.assertContains(response, "No anomalies")

    def test_comparing_an_unreadable_snapshot_reports_instead_of_500ing(self):
        bad = Path(self.census_dir.name) / "corrupt.json"
        bad.write_text("{not json")
        response = self.client.get(reverse("developer"), {"before": str(bad), "after": str(bad)})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Could not compare")


class CensusVersioningTests(TestCase):
    """Derived values are frozen at capture time, so a later fix cannot repair a stored
    snapshot. Comparing across versions must say so rather than presenting stale numbers.
    """

    def test_a_snapshot_from_an_older_census_version_is_called_out(self):
        current = capture_census(label="after")
        legacy = dict(current, label="before")
        legacy.pop("census_version")          # version 1 files had no marker

        result = compare_censuses(legacy, current)
        self.assertEqual(result["census_versions"], {"before": 1, "after": CENSUS_VERSION})
        self.assertTrue(
            any("computed at capture time" in o for o in result["observations"]),
            result["observations"],
        )

    def test_two_current_snapshots_are_not_flagged(self):
        result = compare_censuses(capture_census(label="a"), capture_census(label="b"))
        self.assertFalse(any("census version" in o for o in result["observations"]))


class NameCollisionPrecheckTests(TestCase):
    """Stage B adds unique(owner, name). Surface violations as data first — a constraint
    added blind fails the migration partway through."""

    def _setup(self):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="8800", appliance_hostname="fw-coll", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="grp-coll")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(), payload={})
        return station, group, point, snapshot

    def _object(self, station, snapshot, name, *, owner, namespace_type):
        kwargs = ({"enforcement_point": owner} if isinstance(owner, EnforcementPoint)
                  else {"appliance_group": owner})
        return AddressObject.objects.create(
            management_station=station, source_snapshot=snapshot, config_source="local",
            name=name, namespace_type=namespace_type, namespace_value="vsys1",
            precedence_rank=precedence_for(namespace_type),
            address_type=AddressObject.TYPE_IP_NETMASK, value="10.0.0.1/32",
            last_synced_at=timezone.now(), **kwargs)

    def test_a_clean_deployment_reports_no_violations(self):
        station, group, point, snapshot = self._setup()
        self._object(station, snapshot, "web", owner=point,
                     namespace_type=PolicyObjectNamespace.LOCAL_VSYS)
        collisions = capture_census()["models"]["AddressObject"]["name_collisions"]
        self.assertEqual(collisions["enforcement_point_id"]["violating_pairs"], 0)
        self.assertEqual(collisions["appliance_group_id"]["violating_pairs"], 0)

    def test_a_vsys_object_colliding_with_a_vendor_object_is_reported(self):
        """rows_per_object covers only the shared side; this is the case it cannot see."""
        station, group, point, snapshot = self._setup()
        self._object(station, snapshot, "any", owner=point,
                     namespace_type=PolicyObjectNamespace.LOCAL_VSYS)
        self._object(station, snapshot, "any", owner=point,
                     namespace_type=PolicyObjectNamespace.BUILTIN)

        census = capture_census(label="after")
        collisions = census["models"]["AddressObject"]["name_collisions"]
        self.assertEqual(collisions["enforcement_point_id"]["violating_pairs"], 1)
        self.assertEqual(collisions["enforcement_point_id"]["examples"][0]["name"], "any")
        self.assertEqual(collisions["enforcement_point_id"]["examples"][0]["rows"], 2)

        observations = compare_censuses(capture_census(label="before"), census)["observations"]
        self.assertTrue(any("Stage B unique constraint would fail" in o for o in observations),
                        observations)


    def test_a_collision_says_which_rows_differ_and_how(self):
        """A count says a fault exists. The namespaces say which fault it is."""
        station, group, point, snapshot = self._setup()
        self._object(station, snapshot, "any", owner=point,
                     namespace_type=PolicyObjectNamespace.LOCAL_VSYS)
        self._object(station, snapshot, "any", owner=point,
                     namespace_type=PolicyObjectNamespace.BUILTIN)

        example = (capture_census()["models"]["AddressObject"]["name_collisions"]
                   ["enforcement_point_id"]["examples"][0])
        namespaces = {row["namespace_type"] for row in example["rows_detail"]}
        self.assertEqual(namespaces, {PolicyObjectNamespace.LOCAL_VSYS,
                                      PolicyObjectNamespace.BUILTIN})
        self.assertTrue(all("precedence_rank" in row for row in example["rows_detail"]))

    def test_a_synthetic_row_colliding_with_a_collected_one_is_named_as_ours(self):
        """The distinction that decides what Stage B should do.

        Two collected rows colliding would mean the device presented something PAN-OS
        rejects. A synthesized row colliding with a collected one means we manufactured the
        collision, and no constraint on collected data can be blamed for it.
        """
        station, group, point, snapshot = self._setup()
        self._object(station, snapshot, "172.200.255.254", owner=point,
                     namespace_type=PolicyObjectNamespace.LOCAL_VSYS)
        synthetic = self._object(station, snapshot, "172.200.255.254", owner=point,
                                 namespace_type=PolicyObjectNamespace.PANORAMA_DEVICE_GROUP)
        synthetic.is_synthetic = True
        synthetic.synthetic_kind = AddressObject.SYNTHETIC_KIND_RULE_LITERAL
        synthetic.save(update_fields=["is_synthetic", "synthetic_kind"])

        diagnoses = diagnose_collisions(capture_census())
        self.assertEqual(len(diagnoses), 1)
        line = diagnoses[0]["diagnoses"][0]
        self.assertIn("172.200.255.254", line)
        self.assertIn("SYNTHESIZED", line)
        self.assertIn("COLLECTED", line)
        self.assertIn(AddressObject.SYNTHETIC_KIND_RULE_LITERAL, line)

    def test_the_developer_page_renders_the_collision_detail(self):
        """Render it, do not just call it - the explainer's 500 was invisible to unit tests."""
        station, group, point, snapshot = self._setup()
        self._object(station, snapshot, "any", owner=point,
                     namespace_type=PolicyObjectNamespace.LOCAL_VSYS)
        self._object(station, snapshot, "any", owner=point,
                     namespace_type=PolicyObjectNamespace.BUILTIN)

        response = self.client.get(reverse("developer"))
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn("Stage B is blocked", body)
        self.assertIn(PolicyObjectNamespace.BUILTIN, body)


class SharedScopeAcrossPointsTests(TestCase):
    """Panorama does not push the same shared set to every vsys.

    Shared-object optimization pushes only what each device group references, so a
    Panorama-Shared object can appear in one vsys's per-vsys response and not another's.
    Deriving group-wide shared scope from a single representative point therefore left
    such objects owned by nobody - the group pass never saw them, and the owning point's
    pass discards shared scope by design - and every rule referencing one failed with
    "unresolved address reference".
    """

    def _fixture(self):
        station, group, appliance, point_a = _create_grouped_enforcement_point(
            serial_number="8900", appliance_hostname="fw-opt", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="grp-opt")
        point_a.in_scope = True
        point_a.save()
        point_b = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, vsys_name="vsys2", in_scope=True)
        EnforcementNode.objects.create(
            management_station=station, enforcement_point=point_b, appliance=appliance)

        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": "vsys1"}, {"@name": "vsys2"}]}}]}}})
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"shared": {"address": {"entry": [
                {"@name": "in-both", "@loc": "shared", "ip-netmask": "10.0.0.1/32"}]}}})

        def vsys_payload(entries, rules):
            return {"policy": {"panorama": {
                "address": {"entry": entries},
                "pre-rulebase": {"security": {"rules": {"entry": rules}}},
                "post-rulebase": {"security": {"rules": {"entry": []}},
                                  "default-security-rules": {"rules": {"entry": []}}}}}}

        Snapshot.objects.create(
            management_station=station, enforcement_point=point_a,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload=vsys_payload([], []))
        # Only vsys2 receives this shared object, and only vsys2 has a rule using it.
        Snapshot.objects.create(
            management_station=station, enforcement_point=point_b,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload=vsys_payload(
                [{"@name": "vsys2-only", "@loc": "shared", "ip-netmask": "172.25.84.0/24"}],
                [{"@name": "pushed-rule", "@loc": "dg1",
                  "from": {"member": ["trust"]}, "to": {"member": ["untrust"]},
                  "source": {"member": ["vsys2-only"]}, "destination": {"member": ["any"]},
                  "application": {"member": ["any"]},
                  "service": {"member": ["application-default"]}, "action": "allow"}]))
        return station, group, point_a, point_b

    def test_a_shared_object_seen_by_only_one_point_is_still_group_owned(self):
        _, group, _, _ = self._fixture()
        normalize_appliance_group_shared_scope(group)
        self.assertEqual(
            sorted(group.address_objects.values_list("name", flat=True)),
            ["in-both", "vsys2-only"],
            "shared scope must be the union across every in-scope point, not one sample",
        )

    def test_a_rule_using_that_object_normalizes_instead_of_failing(self):
        _, group, point_a, point_b = self._fixture()
        normalize_appliance_group_shared_scope(group)
        for point in (point_a, point_b):
            normalize_enforcement_point_addresses(point)

        result = normalize_enforcement_point_security_rules(point_b)
        self.assertEqual(len(result.security_rules), 1)
        self.assertEqual(list(result.security_rule_failures), [],
                         "an unresolved reference here means the object was owned by nobody")


class AddressReferenceExplainerTests(TestCase):
    """Diagnose "unresolved address reference" without guessing at the cause."""

    def _point(self, *, shared_entries=(), vsys_entries=(), merged_shared_entries=()):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="9300", appliance_hostname="fw-ref", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="grp-ref")
        point.in_scope = True
        point.save()
        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {
                "shared": {"address": {"entry": list(merged_shared_entries)}},
                "devices": {"entry": [{"@name": "localhost.localdomain", "vsys": {"entry": [
                    {"@name": point.vsys_name}]}}]}}})
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"shared": {"address": {"entry": list(shared_entries)}}})
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload={"policy": {"panorama": {"address": {"entry": list(vsys_entries)}}}})
        return station, group, point

    def test_reports_which_read_carried_it_and_which_owner_should_hold_it(self):
        _, group, point = self._point(shared_entries=[
            {"@name": "NET-A", "@loc": "shared", "ip-netmask": "10.1.0.0/24"}])
        normalize_appliance_group_shared_scope(group)

        result = explain_address_reference(point, "NET-A")
        self.assertTrue(result["persisted"]["resolvable"])
        self.assertEqual(result["persisted"]["rows"][0]["owner"], "appliance_group")
        self.assertTrue(any("@loc='shared'" in f and "appliance_group" in f
                            for f in result["findings"]), result["findings"])

    def test_flags_an_entry_with_no_loc_and_names_the_fallback(self):
        """Unmarked entries are kept at vsys scope rather than failing the build, but the
        fallback stays visible - it is an inference, and inferences should be reported."""
        _, _, point = self._point(shared_entries=[
            {"@name": "NET-B", "ip-netmask": "10.2.0.0/24"}])          # no @loc
        result = explain_address_reference(point, "NET-B")
        self.assertTrue(result["build_outcome"]["succeeded"],
                        "one unmarked entry must not fail the whole build")
        self.assertTrue(any("NO @loc marker" in f for f in result["findings"]), result["findings"])
        self.assertTrue(any("falls back to vsys scope" in f for f in result["findings"]),
                        result["findings"])

    def test_says_so_when_no_collected_source_mentions_the_name(self):
        _, _, point = self._point()
        result = explain_address_reference(point, "NET-GHOST")
        self.assertFalse(result["persisted"]["resolvable"])
        self.assertTrue(any("appears in NO collected source" in f
                            for f in result["findings"]), result["findings"])

    def test_distinguishes_a_normalization_gap_from_a_collection_gap(self):
        """Device reported it, nothing stored it - that is the interesting case."""
        _, _, point = self._point(shared_entries=[
            {"@name": "NET-C", "@loc": "shared", "ip-netmask": "10.3.0.0/24"}])
        # deliberately do NOT run the shared pass
        result = explain_address_reference(point, "NET-C")
        self.assertFalse(result["persisted"]["resolvable"])
        self.assertTrue(any("gap is in normalization, not collection" in f
                            for f in result["findings"]), result["findings"])


class MultiApplianceGroupDiagnosisTests(TestCase):
    """A group holding several appliances - a cloud NGFW presenting multiple instances,
    only one in scope - reads its two pushed responses from DIFFERENT scopes:

        per-vsys response   stored on the enforcement point
        non-vsys response   stored on the appliance GROUP

    While pushed objects were scoped by read position that asymmetry was invisible, since
    everything came from the point's own response. Once @loc routes shared objects to the
    non-vsys read, the group-scoped lookup decides which appliance's shared policy is used.
    """

    def _group_with_two_appliances(self):
        station, group, first, point = _create_grouped_enforcement_point(
            serial_number="AAA111", appliance_hostname="cloud-ngfw",
            station_hostname="pan.local", group_name="standalone-AAA111",
            station_type=ManagementStation.StationType.PAN_PANORAMA)
        point.in_scope = True
        point.save()
        # same hostname, different serial, not in scope
        second = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="BBB222", hostname="cloud-ngfw")
        Snapshot.objects.create(
            management_station=station, appliance=first, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": point.vsys_name}]}}]}}})
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload={"policy": {"panorama": {"address": {"entry": [
                {"@name": "NET-A", "@loc": "shared", "ip-netmask": "10.1.0.0/24"}]}}}})
        return station, group, first, second, point

    def test_reports_the_multi_appliance_group_and_duplicate_hostnames(self):
        station, group, first, second, point = self._group_with_two_appliances()
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"shared": {"address": {"entry": []}}})

        result = explain_address_reference(point, "NET-A")
        context = result["appliance_context"]
        self.assertEqual(len(context["appliances_in_group"]), 2)
        self.assertEqual(context["duplicate_hostnames_in_group"], ["cloud-ngfw"])
        self.assertTrue(any("stored on the GROUP" in f for f in result["findings"]),
                        result["findings"])
        self.assertTrue(any("cannot distinguish them" in f for f in result["findings"]),
                        result["findings"])

    def test_reports_competing_group_scoped_snapshots(self):
        station, group, first, second, point = self._group_with_two_appliances()
        for _ in range(2):
            Snapshot.objects.create(
                management_station=station, appliance_group=group,
                source_type="show_pushed_shared_policy", collected_at=timezone.now(),
                payload={"shared": {"address": {"entry": []}}})

        result = explain_address_reference(point, "NET-A")
        self.assertEqual(result["appliance_context"]["group_pushed_shared_snapshots"], 2)
        self.assertTrue(any("newest wins regardless of which appliance" in f
                            for f in result["findings"]), result["findings"])

    def test_names_the_object_as_reported_but_unstored(self):
        """The signature of the reported failure: the device sent it on the per-vsys read,
        but shared scope is built from the group-scoped read, and nothing persisted it."""
        station, group, first, second, point = self._group_with_two_appliances()
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"shared": {"address": {"entry": []}}})

        result = explain_address_reference(point, "NET-A")
        self.assertFalse(result["persisted"]["resolvable"])
        self.assertTrue(any("@loc='shared'" in f and "appliance_group" in f
                            for f in result["findings"]), result["findings"])
        self.assertTrue(any("gap is in normalization, not collection" in f
                            for f in result["findings"]), result["findings"])


class BuildFailureDiagnosisTests(TestCase):
    """A rule error naming one object is often downstream of the whole build failing.

    resolve_rule_address_refs() raises on the FIRST unresolved member and source comes
    before destination, so "every rule fails on a NET-* source" is indistinguishable from
    "this point has no objects at all" by reading the event log alone.
    """

    def _point(self, *, shared_payload):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="9400", appliance_hostname="cloud-ngfw", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="standalone-9400")
        point.in_scope = True
        point.save()
        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": point.vsys_name}]}}]}}})
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload=shared_payload)
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload={"policy": {"panorama": {"address": {"entry": [
                {"@name": "NET-A", "@loc": "shared", "ip-netmask": "10.1.0.0/24"}]}}}})
        return point

    def test_an_unfamiliar_payload_root_is_named_as_the_root_cause(self):
        """A cloud NGFW is a different product; nothing guarantees the VM-series roots."""
        point = self._point(shared_payload={"rulestack": {"address": {"entry": []}}})
        result = explain_address_reference(point, "NET-A")

        self.assertFalse(result["build_outcome"]["succeeded"])
        self.assertEqual(result["pushed_payload_roots"]["pushed_non_vsys"]["keys"], ["rulestack"])
        self.assertTrue(result["findings"][0].startswith("ADDRESS NORMALIZATION FAILS"),
                        result["findings"])
        self.assertTrue(any("neither 'shared' nor 'policy'" in f for f in result["findings"]),
                        result["findings"])
        self.assertTrue(any("returned {} silently" in f for f in result["findings"]),
                        result["findings"])

    def test_the_named_object_is_called_out_as_a_symptom_not_the_cause(self):
        point = self._point(shared_payload={"rulestack": {}})
        result = explain_address_reference(point, "NET-A")
        self.assertTrue(any("symptom, not the cause" in f for f in result["findings"]),
                        result["findings"])

    def test_a_healthy_point_reports_the_build_succeeding(self):
        point = self._point(shared_payload={"shared": {"address": {"entry": []}}})
        result = explain_address_reference(point, "NET-A")
        self.assertTrue(result["build_outcome"]["succeeded"])
        self.assertGreater(result["build_outcome"]["object_count"], 0)
        self.assertFalse(any("ADDRESS NORMALIZATION FAILS" in f for f in result["findings"]))


class OwnerTotalsDiagnosisTests(TestCase):
    """When shared references fail wholesale, the decisive number is how many objects the
    GROUP holds - not anything about the object named in the rule error."""

    def _fixture(self, *, in_scope=True):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="9500", appliance_hostname="cloud-ngfw", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            group_name="standalone-9500")
        point.in_scope = in_scope
        point.save()
        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": point.vsys_name}]}}]}}})
        body = {"policy": {"panorama": {"address": {"entry": [
            {"@loc": "shared", "@name": "NET-A",
             "ip-netmask": {"#text": "10.130.49.0/27", "@loc": "shared"}}]}}}}
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(), payload=body)
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(), payload=body)
        return station, group, point

    def test_an_empty_group_is_named_as_the_cause_when_the_build_is_fine(self):
        """The reported signature: build succeeds, shared objects exist in the payload,
        but nothing owns them because the shared pass did not run."""
        _, group, point = self._fixture()
        result = explain_address_reference(point, "NET-A")

        self.assertTrue(result["build_outcome"]["succeeded"])
        self.assertEqual(result["owner_totals"]["appliance_group"]["address_objects"], 0)
        self.assertTrue(result["findings"][0].startswith("The appliance group holds ZERO objects"),
                        result["findings"])
        self.assertIn("AddressNormalizationFailed", result["findings"][0])

    def test_a_group_with_no_in_scope_points_is_reported_as_never_selected(self):
        """Separates "ran and failed" from "was never selected" - the second leaves no
        failure event at all, so it is invisible in the log."""
        _, group, point = self._fixture(in_scope=False)
        result = explain_address_reference(point, "NET-A")

        self.assertIs(result["owner_totals"]["group_in_scope_for_shared_pass"], False)
        self.assertTrue(result["findings"][0].startswith("This appliance group is NOT selected"),
                        result["findings"])

    def test_a_healthy_group_reports_its_counts_and_no_ownership_finding(self):
        _, group, point = self._fixture()
        normalize_appliance_group_shared_scope(group)
        normalize_enforcement_point_addresses(point)

        result = explain_address_reference(point, "NET-A")
        self.assertIs(result["owner_totals"]["group_in_scope_for_shared_pass"], True)
        self.assertEqual(result["owner_totals"]["appliance_group"]["address_objects"], 1)
        self.assertTrue(result["persisted"]["resolvable"])
        self.assertFalse(any("ZERO objects" in f for f in result["findings"]))


class DeveloperPageExplanationRenderTests(TestCase):
    """The explainer's own tests all called the function directly, so the TEMPLATE was
    never exercised with an explanation present - and it 500'd in the field on the first
    real use. A diagnostic that fails during an incident is worse than none.

    The view's try/except cannot help here: a template error happens after the view
    returns. So these render the page.
    """

    def _point(self, *, payload):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="9600", appliance_hostname="cloud-ngfw", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="standalone-9600")
        point.in_scope = True
        point.save()
        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": point.vsys_name}]}}]}}})
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(), payload=payload)
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload=payload)
        return point

    def _explain(self, point, name):
        return self.client.get(
            reverse("developer"), {"reference_point": point.pk, "reference_name": name})

    def test_renders_a_dict_payload_without_erroring(self):
        """The reported 500: `{{ root.keys|default:root.value }}` resolved its default
        argument eagerly, so the absent key raised VariableDoesNotExist."""
        point = self._point(payload={"policy": {"panorama": {"address": {"entry": [
            {"@loc": "shared", "@name": "NET-A",
             "ip-netmask": {"#text": "10.130.49.0/27", "@loc": "shared"}}]}}}})
        response = self._explain(point, "NET-A")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Pushed payload roots")
        self.assertContains(response, "Owner totals")

    def test_renders_a_string_payload_without_erroring(self):
        """The other branch: a bare NO_PUSHED_POLICY_MESSAGE payload."""
        point = self._point(payload="No shared policy pushed to device")
        response = self._explain(point, "NET-A")
        self.assertEqual(response.status_code, 200)

    def test_renders_when_the_build_fails(self):
        point = self._point(payload={"rulestack": {"address": {"entry": []}}})
        response = self._explain(point, "NET-A")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ADDRESS NORMALIZATION FAILS")

    def test_renders_for_a_name_absent_everywhere(self):
        point = self._point(payload={"policy": {"panorama": {}}})
        response = self._explain(point, "NOTHING-BY-THIS-NAME")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "appears in NO collected source")

    def test_a_missing_enforcement_point_reports_instead_of_erroring(self):
        response = self.client.get(
            reverse("developer"), {"reference_point": 999999, "reference_name": "X"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "no longer exists")


class UnmarkedPushedEntryInventoryTests(TestCase):
    """What ARE the entries without @loc? The fallback is a guess, so it matters whether
    they are vendor-injected objects or firewall-local ones surfacing in the pushed read.

    If they are also in merged, the vsys fallback duplicates what local config yields -
    two candidates in one scope, which resolution rejects. That would trade one failure
    for another, so it has to be checkable rather than assumed.
    """

    def _point(self, *, merged_vsys_entries=(), pushed_entries=()):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="9700", appliance_hostname="cloud-ngfw", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="standalone-9700")
        point.in_scope = True
        point.save()
        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": point.vsys_name,
                                    "address": {"entry": list(merged_vsys_entries)}}]}}]}}})
        body = {"policy": {"panorama": {"address": {"entry": list(pushed_entries)}}}}
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(), payload=body)
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(), payload=body)
        return point

    def test_separates_pushed_only_names_from_names_that_are_also_local(self):
        point = self._point(
            merged_vsys_entries=[{"@name": "local-thing", "ip-netmask": "10.9.9.9/32"}],
            pushed_entries=[
                {"@name": "local-thing", "ip-netmask": "10.9.9.9/32"},        # no @loc, also local
                {"@name": "azure-healthcheck-address", "ip-netmask": "168.63.129.16/32"},
                {"@loc": "shared", "@name": "marked", "ip-netmask": "10.1.1.1/32"},
            ])
        inventory = unmarked_pushed_entries(point)

        self.assertEqual([r["name"] for r in inventory["also_local"]], ["local-thing"])
        self.assertEqual([r["name"] for r in inventory["pushed_only"]], ["azure-healthcheck-address"])
        self.assertEqual(inventory["reads"]["pushed_non_vsys"]["unmarked_count"], 2,
                         "the marked entry is not counted")

    def test_counts_every_unmarked_entry_not_just_the_first(self):
        """merge_pushed_entries() stopped at the first, so a build error names one entry
        whether there is one or a hundred."""
        point = self._point(pushed_entries=[
            {"@name": f"unmarked-{i}", "ip-netmask": f"10.0.0.{i}/32"} for i in range(1, 8)])
        inventory = unmarked_pushed_entries(point)
        self.assertEqual(inventory["reads"]["pushed_non_vsys"]["unmarked_count"], 7)
        self.assertEqual(len(inventory["pushed_only"]), 7)

    def test_the_explainer_reports_the_split_and_warns_about_duplication(self):
        point = self._point(
            merged_vsys_entries=[{"@name": "local-thing", "ip-netmask": "10.9.9.9/32"}],
            pushed_entries=[{"@name": "local-thing", "ip-netmask": "10.9.9.9/32"}])
        result = explain_address_reference(point, "local-thing")
        self.assertTrue(any("ALSO exist in merged local config" in f for f in result["findings"]),
                        result["findings"])
        self.assertTrue(any("two" in f and "candidates in one scope" in f
                            for f in result["findings"]), result["findings"])

    def test_a_deployment_with_no_unmarked_entries_says_nothing_about_them(self):
        point = self._point(pushed_entries=[
            {"@loc": "shared", "@name": "marked", "ip-netmask": "10.1.1.1/32"}])
        result = explain_address_reference(point, "marked")
        self.assertFalse(any("carry no @loc" in f for f in result["findings"]), result["findings"])


class TemplateCommentHygieneTests(TestCase):
    """Django's `{# #}` comment is SINGLE-LINE only.

    A multi-line one is not stripped - it renders as literal text on the page. Nothing
    errors, the page still returns 200, and it is only caught by looking at it. So it is
    asserted rather than reviewed.
    """

    def test_no_template_uses_a_multi_line_hash_comment(self):
        offenders = []
        for path in (Path(__file__).resolve().parent).rglob("*.html"):
            text = path.read_text()
            for match in re.finditer(r"\{#", text):
                tail = text[match.start():]
                close = tail.find("#}")
                if close == -1 or "\n" in tail[:close]:
                    offenders.append(f"{path.name}:{text[:match.start()].count(chr(10)) + 1}")
        self.assertEqual(
            offenders, [],
            "multi-line {# #} is not stripped by Django and renders as page text; "
            "use {% comment %}...{% endcomment %}",
        )

    def test_the_developer_page_renders_no_comment_delimiters(self):
        response = self.client.get(reverse("developer"))
        body = response.content.decode()
        self.assertNotIn("{#", body)
        self.assertNotIn("#}", body)
        self.assertNotIn("overflow-auto wrapper", body, "comment prose leaked into the page")


class PerObjectIndependenceTests(TestCase):
    """One bad entry must not discard the rest.

    Security rules have always failed independently; objects were the outlier, where a
    single unclassifiable entry took the whole enforcement point with it - and then every
    rule reported the fault against whatever it happened to reference first, so the cause
    was invisible among its own consequences.
    """

    def _point(self, *, vsys_entries=(), pushed_entries=()):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="9800", appliance_hostname="fw-ind", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="grp-ind")
        point.in_scope = True
        point.save()
        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": point.vsys_name,
                                    "address": {"entry": list(vsys_entries)}}]}}]}}})
        body = {"policy": {"panorama": {"address": {"entry": list(pushed_entries)}}}}
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(), payload=body)
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(), payload=body)
        return point

    def test_an_unnormalizable_entry_is_skipped_and_the_rest_survive(self):
        point = self._point(vsys_entries=[
            {"@name": "good-1", "ip-netmask": "10.1.1.1/32"},
            {"@name": "broken"},                                  # no recognised type node
            {"@name": "good-2", "ip-netmask": "10.1.1.2/32"},
        ])
        objects, _, issues = build_normalized_addresses(point)

        names = {o.name for o in objects}
        self.assertIn("good-1", names)
        self.assertIn("good-2", names)
        self.assertNotIn("broken", names)

        broken = [i for i in issues if i.name == "broken"]
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0].severity, "error")
        self.assertEqual(broken[0].kind, "address object")
        self.assertEqual(broken[0].raw_entry, {"@name": "broken"}, "raw entry kept for drill-through")

    def test_an_entry_with_no_name_is_reported_rather_than_failing_the_point(self):
        point = self._point(vsys_entries=[
            {"ip-netmask": "10.1.1.1/32"},                        # no @name
            {"@name": "good", "ip-netmask": "10.1.1.2/32"},
        ])
        objects, _, issues = build_normalized_addresses(point)
        self.assertIn("good", {o.name for o in objects})
        self.assertTrue(any(i.severity == "error" and "no @name" in i.reason for i in issues),
                        [i.reason for i in issues])

    def test_a_clean_point_reports_no_issues(self):
        point = self._point(vsys_entries=[{"@name": "fine", "ip-netmask": "10.1.1.1/32"}])
        objects, _, issues = build_normalized_addresses(point)
        self.assertIn("fine", {o.name for o in objects})
        self.assertEqual([i for i in issues if i.severity == "error"], [])

    def test_issues_reach_the_normalized_collection(self):
        point = self._point(vsys_entries=[
            {"@name": "broken"},
            {"@name": "good", "ip-netmask": "10.1.1.2/32"},
        ])
        result = normalize_enforcement_point_addresses(point)
        self.assertTrue(result.address_objects, "the good object still persisted")
        self.assertTrue(any(i.name == "broken" for i in result.policy_object_issues),
                        result.policy_object_issues)

    def test_point_level_problems_still_raise(self):
        """A missing snapshot is not one bad entry - there is nothing to iterate and no
        partial result worth keeping."""
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="9801", appliance_hostname="fw-nosnap", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="grp-nosnap")
        with self.assertRaisesMessage(ValueError, "missing merged config snapshot"):
            build_normalized_addresses(point)


class FailedObjectRuleInteractionTests(TestCase):
    """Where the two independence layers meet.

    An object that fails to normalize is absent, so rules referencing it fail. That is
    correct and visible - but it must stay confined: other rules on the same point, and
    other members of the same rule, must survive. This is the composition that was never
    tested, and it is exactly the path that misattributed 1,300 failures.
    """

    def _fixture(self):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="9900", appliance_hostname="fw-mix", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="grp-mix")
        point.in_scope = True
        point.save()
        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": point.vsys_name, "address": {"entry": [
                    {"@name": "good-src", "ip-netmask": "10.1.1.1/32"},
                    {"@name": "broken-src"},                       # unnormalizable
                ]}}]}}]}}})
        rules = [
            {"@name": "rule-uses-broken", "from": {"member": ["trust"]},
             "to": {"member": ["untrust"]}, "source": {"member": ["broken-src"]},
             "destination": {"member": ["any"]}, "application": {"member": ["any"]},
             "service": {"member": ["application-default"]}, "action": "allow"},
            {"@name": "rule-uses-good", "from": {"member": ["trust"]},
             "to": {"member": ["untrust"]}, "source": {"member": ["good-src"]},
             "destination": {"member": ["any"]}, "application": {"member": ["any"]},
             "service": {"member": ["application-default"]}, "action": "allow"},
        ]
        body = {"policy": {"panorama": {
            "pre-rulebase": {"security": {"rules": {"entry": rules}}},
            "post-rulebase": {"security": {"rules": {"entry": []}},
                              "default-security-rules": {"rules": {"entry": []}}}}}}
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"shared": {}})
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload=body)
        return group, point

    def test_only_the_rule_using_the_failed_object_fails(self):
        group, point = self._fixture()
        normalize_appliance_group_shared_scope(group)
        addresses = normalize_enforcement_point_addresses(point)
        rules = normalize_enforcement_point_security_rules(point)

        # the object failure is recorded once, against the object
        broken = [i for i in addresses.policy_object_issues if i.name == "broken-src"]
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0].severity, "error")
        self.assertEqual(broken[0].disposition, "skipped")

        # exactly one rule fails, and it is the one that referenced it
        failed = list(rules.security_rule_failures)
        self.assertEqual([f.name for f in failed], ["rule-uses-broken"])
        self.assertIn("broken-src", failed[0].error_text)

        # the other rule persists - the failure did not cascade
        self.assertEqual([r.name for r in rules.security_rules], ["rule-uses-good"])

    def test_the_object_failure_is_reported_once_not_once_per_referencing_rule(self):
        """The misattribution being removed: N rule errors naming one object should not be
        mistaken for N problems. The object is the cause and is counted once."""
        group, point = self._fixture()
        normalize_appliance_group_shared_scope(group)
        addresses = normalize_enforcement_point_addresses(point)
        rules = normalize_enforcement_point_security_rules(point)

        object_errors = [i for i in addresses.policy_object_issues if i.severity == "error"]
        self.assertEqual(len(object_errors), 1, "one root cause")
        self.assertGreaterEqual(len(rules.security_rule_failures), 1, "and its consequences")


class NormalizationIssuePersistenceTests(TestCase):
    """Issues are current state, not history: replaced per run, so a clean run clears them.

    That is the whole reason this is a model rather than IntegrationEvent. The event log
    is append-only and answers "what happened"; the health indicator needs "what is wrong
    right now", and has to become an EXISTS because it runs on every page load.
    """

    def _point(self, *, vsys_entries):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="9950", appliance_hostname="fw-persist", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="grp-persist")
        point.in_scope = True
        point.save()
        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": point.vsys_name,
                                    "address": {"entry": list(vsys_entries)}}]}}]}}})
        body = {"policy": {"panorama": {}}}
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"shared": {}})
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(), payload=body)
        return station, group, point, appliance

    def _remerge(self, station, appliance, point, entries):
        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": point.vsys_name,
                                    "address": {"entry": list(entries)}}]}}]}}})

    def test_an_issue_is_persisted_with_its_detail(self):
        station, group, point, _ = self._point(vsys_entries=[{"@name": "broken"}])
        normalize_enforcement_point_addresses(point)

        issue = NormalizationIssue.objects.get(enforcement_point=point)
        self.assertEqual(issue.name, "broken")
        self.assertEqual(issue.severity, NormalizationIssue.Severity.ERROR)
        self.assertEqual(issue.disposition, NormalizationIssue.Disposition.SKIPPED)
        self.assertEqual(issue.raw_entry, {"@name": "broken"}, "raw entry kept for drill-through")
        self.assertEqual(issue.management_station, station)

    def test_a_clean_run_clears_the_previous_issues(self):
        """The requirement the whole design rests on: it does not disappear until
        everything is normalized, and it DOES disappear when it is."""
        station, group, point, appliance = self._point(vsys_entries=[{"@name": "broken"}])
        normalize_enforcement_point_addresses(point)
        self.assertTrue(NormalizationIssue.objects.filter(enforcement_point=point).exists())

        self._remerge(station, appliance, point, [{"@name": "fixed", "ip-netmask": "10.0.0.1/32"}])
        normalize_enforcement_point_addresses(point)
        self.assertFalse(NormalizationIssue.objects.filter(enforcement_point=point).exists(),
                         "a clean run must leave nothing behind")

    def test_issues_do_not_accumulate_across_runs(self):
        station, group, point, appliance = self._point(vsys_entries=[{"@name": "broken"}])
        for _ in range(3):
            normalize_enforcement_point_addresses(point)
        self.assertEqual(NormalizationIssue.objects.filter(enforcement_point=point).count(), 1,
                         "replaced, not appended - this is state, not history")

    def test_shared_scope_issues_belong_to_the_appliance_group(self):
        station, group, point, appliance = self._point(vsys_entries=[])
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"shared": {"address": {"entry": [{"@loc": "shared", "@name": "bad-shared"}]}}})
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload={"policy": {"panorama": {}}})
        normalize_appliance_group_shared_scope(group)

        issue = NormalizationIssue.objects.get(appliance_group=group)
        self.assertEqual(issue.name, "bad-shared")
        self.assertIsNone(issue.enforcement_point)

    def test_an_issue_must_have_exactly_one_owner(self):
        station, group, point, _ = self._point(vsys_entries=[])
        orphan = NormalizationIssue(
            management_station=station, kind="address object", name="x",
            severity=NormalizationIssue.Severity.ERROR,
            disposition=NormalizationIssue.Disposition.SKIPPED, reason="r")
        with self.assertRaisesMessage(ValidationError, "exactly one owner"):
            orphan.clean()


class NormalizationHealthTests(TestCase):
    """Root causes separated from their consequences.

    One object that fails to normalize makes every rule referencing it fail. Counting
    those together reports 1,301 problems where there is one cause and 1,300 symptoms,
    and points at the symptoms - which is how a single unclassifiable object took several
    rounds to diagnose.
    """

    def _fixture(self, *, rule_count=3):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="9960", appliance_hostname="fw-health", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="grp-health")
        point.in_scope = True
        point.save()
        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": point.vsys_name, "address": {"entry": [
                    {"@name": "broken-obj"},                      # one root cause
                ]}}]}}]}}})
        rules = [
            {"@name": f"rule-{i}", "from": {"member": ["trust"]}, "to": {"member": ["untrust"]},
             "source": {"member": ["broken-obj"]}, "destination": {"member": ["any"]},
             "application": {"member": ["any"]}, "service": {"member": ["application-default"]},
             "action": "allow"}
            for i in range(rule_count)
        ]
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"shared": {}})
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload={"policy": {"panorama": {
                "pre-rulebase": {"security": {"rules": {"entry": rules}}},
                "post-rulebase": {"security": {"rules": {"entry": []}},
                                  "default-security-rules": {"rules": {"entry": []}}}}}})
        return station, group, point

    def test_one_bad_object_counts_as_one_root_and_its_rules_as_consequences(self):
        station, group, point = self._fixture(rule_count=3)
        normalize_appliance_group_shared_scope(group)
        normalize_enforcement_point_addresses(point)
        normalize_enforcement_point_security_rules(point)

        health = normalization_health(station)
        self.assertEqual(health["root_errors"], 1, "the object is the cause")
        self.assertEqual(health["consequent_errors"], 3, "the rules are symptoms")
        self.assertEqual(health["root_errors_by_kind"], {"address object": 1})
        self.assertTrue(health["has_errors"])

    def test_a_rule_failing_for_its_own_reasons_is_a_root(self):
        """Not every rule failure is downstream - one referencing a name that never
        existed anywhere is its own problem."""
        station, group, point = self._fixture(rule_count=0)
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload={"policy": {"panorama": {
                "pre-rulebase": {"security": {"rules": {"entry": [
                    {"@name": "rule-ghost", "from": {"member": ["trust"]},
                     "to": {"member": ["untrust"]}, "source": {"member": ["never-existed"]},
                     "destination": {"member": ["any"]}, "application": {"member": ["any"]},
                     "service": {"member": ["application-default"]}, "action": "allow"}]}}},
                "post-rulebase": {"security": {"rules": {"entry": []}},
                                  "default-security-rules": {"rules": {"entry": []}}}}}})
        normalize_appliance_group_shared_scope(group)
        normalize_enforcement_point_addresses(point)
        normalize_enforcement_point_security_rules(point)

        rule_issue = NormalizationIssue.objects.get(kind="security rule", name="rule-ghost")
        self.assertFalse(rule_issue.is_consequent, "nothing else failed to explain it")
        self.assertEqual(rule_issue.related_object_name, "never-existed")

    def test_the_indicator_is_binary_and_clears_on_a_clean_run(self):
        station, group, point = self._fixture(rule_count=1)
        normalize_appliance_group_shared_scope(group)
        normalize_enforcement_point_addresses(point)
        self.assertTrue(has_normalization_errors(station))

        NormalizationIssue.objects.all().delete()
        self.assertFalse(has_normalization_errors(station))

    def test_the_rule_pass_does_not_wipe_object_issues(self):
        """Both passes own rows for the same enforcement point, and each replaces only its
        own kinds - otherwise the later pass silently erases the earlier one's findings."""
        station, group, point = self._fixture(rule_count=1)
        normalize_appliance_group_shared_scope(group)
        normalize_enforcement_point_addresses(point)
        self.assertTrue(NormalizationIssue.objects.filter(kind="address object").exists())

        normalize_enforcement_point_security_rules(point)
        self.assertTrue(NormalizationIssue.objects.filter(kind="address object").exists(),
                        "the object issue must survive the rule pass")
        self.assertTrue(NormalizationIssue.objects.filter(kind="security rule").exists())


class NormalizationIndicatorAndReportTests(TestCase):
    """The shell indicator and the report it links to.

    The indicator is binary and absent when healthy - its presence is the signal. The
    report is where counts and severity live, and it leads with root causes so the cause
    is not buried among its own symptoms.
    """

    def _broken_point(self, *, rule_count=2):
        station, group, appliance, point = _create_grouped_enforcement_point(
            serial_number="9970", appliance_hostname="fw-ind", station_hostname="pan.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA, group_name="grp-ind")
        point.in_scope = True
        point.save()
        Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"shared": {}, "devices": {"entry": [{
                "@name": "localhost.localdomain",
                "vsys": {"entry": [{"@name": point.vsys_name, "address": {"entry": [
                    {"@name": "broken-obj"}]}}]}}]}}})
        rules = [{"@name": f"rule-{i}", "from": {"member": ["trust"]},
                  "to": {"member": ["untrust"]}, "source": {"member": ["broken-obj"]},
                  "destination": {"member": ["any"]}, "application": {"member": ["any"]},
                  "service": {"member": ["application-default"]}, "action": "allow"}
                 for i in range(rule_count)]
        Snapshot.objects.create(
            management_station=station, appliance_group=group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"shared": {}})
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload={"policy": {"panorama": {
                "pre-rulebase": {"security": {"rules": {"entry": rules}}},
                "post-rulebase": {"security": {"rules": {"entry": []}},
                                  "default-security-rules": {"rules": {"entry": []}}}}}})
        normalize_appliance_group_shared_scope(group)
        normalize_enforcement_point_addresses(point)
        normalize_enforcement_point_security_rules(point)
        return station, point

    def test_the_indicator_is_absent_when_nothing_is_wrong(self):
        self.assertIsNone(normalization_indicator())

    def test_the_indicator_appears_and_carries_no_count_in_the_chrome(self):
        self._broken_point()
        indicator = normalization_indicator()
        self.assertIsNotNone(indicator)
        self.assertIn("Normalization is incomplete", indicator["label"])
        self.assertEqual(indicator["url"], reverse("normalization_issue_list"))

    def test_the_shell_renders_the_icon_on_an_unrelated_page(self):
        """It must show everywhere, not only on pages that know about health."""
        self._broken_point()
        response = self.client.get(reverse("management_station_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Normalization is incomplete")
        self.assertContains(response, reverse("normalization_issue_list"))

    def test_the_shell_renders_nothing_when_healthy(self):
        response = self.client.get(reverse("management_station_list"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Normalization is incomplete")

    def test_a_broken_health_check_reports_itself_rather_than_hiding(self):
        """An indicator that fails silently is worse than none - its absence would read
        as all clear."""
        from optivedge.app_registry import health_indicators
        with patch(
            "optivedge_integrations.integrations.diagnostics.health.has_normalization_errors",
            side_effect=RuntimeError("boom"),
        ):
            indicators = health_indicators()
        self.assertTrue(any("Health check failed" in i["label"] for i in indicators), indicators)

    def test_the_report_leads_with_roots_and_groups_consequences(self):
        station, point = self._broken_point(rule_count=2)
        response = self.client.get(reverse("normalization_issue_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Root causes")
        self.assertContains(response, "broken-obj")
        self.assertContains(response, "Consequences")
        self.assertContains(response, "2 rules could not resolve it")
        self.assertContains(response, "1 root problem")

    def test_the_report_says_so_when_there_is_nothing_wrong(self):
        response = self.client.get(reverse("normalization_issue_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Nothing is unnormalized")

    def test_the_report_filters_by_management_station(self):
        station, point = self._broken_point()
        other = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="other.local")
        response = self.client.get(
            reverse("normalization_issue_list"), {"management_station": other.pk})
        self.assertContains(response, "Nothing is unnormalized")


class ManagementInterfaceNormalizationTests(TestCase):
    """Every management surface on one appliance, from one merged-config snapshot.

    The payload shapes here are the ones the payload contract records, including the two
    that bite: a leaf arriving as {'#text': ..., '@loc': ...} rather than a bare string, and
    vlan/loopback carrying the profile with NO layer3 node in the path.
    """

    def _appliance(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.mgmt-if",
        )
        return Appliance.objects.create(
            management_station=station, serial_number="SERIAL-MGMT-IF", hostname="fw-mgmt-if")

    def _snapshot(self, appliance, device_entry):
        return Snapshot.objects.create(
            management_station=appliance.management_station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": device_entry}}},
        )

    def test_every_surface_becomes_its_own_row(self):
        appliance = self._appliance()
        self._snapshot(appliance, {
            "deviceconfig": {"system": {
                "permitted-ip": {"entry": [
                    {"@name": "10.0.0.0/8", "description": "corp"},
                    {"@name": "2001:db8::/32"},
                ]},
                "aux-1": {"permitted-ip": {"entry": {"@name": "192.168.5.5"}}},
            }},
            "network": {
                "profiles": {"interface-management-profile": {"entry": [
                    {"@name": "mgmt-open"},
                    {"@name": "mgmt-tight", "permitted-ip": {"entry": {"@name": "172.16.0.0/12"}}},
                ]}},
                "interface": {
                    "ethernet": {"entry": [
                        {"@name": "ethernet1/1", "layer3": {
                            # a leaf carrying provenance rather than a bare string
                            "interface-management-profile": {"@loc": "tpl", "#text": "mgmt-tight"},
                            "units": {"entry": {"@name": "ethernet1/1.10",
                                                "interface-management-profile": "mgmt-open"}},
                        }},
                        {"@name": "ethernet1/2", "layer3": {}},
                    ]},
                    # the trap: no layer3 node in the path
                    "loopback": {"interface-management-profile": "mgmt-open"},
                },
            },
        })

        surfaces = normalize_management_interfaces(appliance)
        by_name = {(s.interface_name or s.plane): s for s in surfaces}
        self.assertEqual(
            sorted(by_name), ["aux-1", "ethernet1/1", "ethernet1/1.10", "loopback", "mgt"])

        # MGT: one v4 entry with an interval and a description, one v6 with neither
        mgt = list(by_name["mgt"].permitted_sources.all())
        self.assertEqual([s.value for s in mgt], ["10.0.0.0/8", "2001:db8::/32"])
        self.assertEqual(mgt[0].description, "corp")
        self.assertEqual(mgt[0].family, 4)
        self.assertEqual(mgt[0].ipv4_start_int, int(ipaddress.IPv4Address("10.0.0.0")))
        self.assertEqual(mgt[1].family, 6)
        self.assertIsNone(mgt[1].ipv4_start_int)

        # the provenance-wrapped leaf resolved to the profile name
        self.assertEqual(by_name["ethernet1/1"].profile_name, "mgmt-tight")
        self.assertEqual([s.value for s in by_name["ethernet1/1"].permitted_sources.all()],
                         ["172.16.0.0/12"])

        # a profile with no permitted-ip yields a surface with NO sources - unrestricted
        self.assertEqual(by_name["loopback"].permitted_sources.count(), 0)
        self.assertEqual(by_name["ethernet1/1.10"].permitted_sources.count(), 0)

    def test_an_empty_units_element_does_not_raise(self):
        """<units/> parses to None, so a default on .get() never applies. Real configs carry
        these; the fixtures above do not, which is how it reached the lab before it was caught."""
        appliance = self._appliance()
        self._snapshot(appliance, {
            "deviceconfig": {"system": {}},
            "network": {
                "profiles": {"interface-management-profile": {"entry": {"@name": "p"}}},
                "interface": {
                    "loopback": {"units": None, "interface-management-profile": "p"},
                    "ethernet": {"entry": {"@name": "ethernet1/3",
                                           "layer3": {"units": None,
                                                      "interface-management-profile": "p"}}},
                },
            },
        })
        surfaces = normalize_management_interfaces(appliance)
        self.assertEqual(sorted(s.interface_name or s.plane for s in surfaces),
                         ["ethernet1/3", "loopback", "mgt"])

    def test_an_interface_without_a_profile_is_not_a_surface(self):
        appliance = self._appliance()
        self._snapshot(appliance, {
            "deviceconfig": {"system": {}},
            "network": {"interface": {"ethernet": {"entry": {
                "@name": "ethernet1/9", "layer3": {"ip": {"entry": {"@name": "10.1.1.1/24"}}}}}}},
        })
        surfaces = normalize_management_interfaces(appliance)
        self.assertEqual([s.plane for s in surfaces], ["mgt"])

    def test_renormalizing_replaces_rather_than_accumulates(self):
        appliance = self._appliance()
        self._snapshot(appliance, {"deviceconfig": {"system": {
            "permitted-ip": {"entry": {"@name": "10.0.0.1"}}}}})
        normalize_management_interfaces(appliance)
        normalize_management_interfaces(appliance)
        self.assertEqual(ManagementInterface.objects.filter(appliance=appliance).count(), 1)
        self.assertEqual(PermittedSource.objects.count(), 1)

    def test_an_unparseable_source_is_kept_with_no_family(self):
        """Undetermined is a verdict, so the row must survive with its family null."""
        appliance = self._appliance()
        self._snapshot(appliance, {"deviceconfig": {"system": {
            "permitted-ip": {"entry": {"@name": "not-an-address"}}}}})
        surface = normalize_management_interfaces(appliance)[0]
        source = surface.permitted_sources.get()
        self.assertEqual(source.value, "not-an-address")
        self.assertIsNone(source.family)
        self.assertIsNone(source.ipv4_start_int)

    def test_provenance_is_captured_per_value_on_a_management_plane(self):
        """Measured on hardware: an override strips @ptpl from ONE leaf, not the entry.

        aux-2 on an HA pair showed disable-https and disable-ssh keeping their marker while
        the overridden disable-telnet lost it, so a plane's services genuinely differ from
        each other and a single provenance for the surface would be a lie.
        """
        appliance = self._appliance()
        self._snapshot(appliance, {"deviceconfig": {"system": {
            "@ptpl": "stack_fw-core-tpa",
            "aux-2": {
                "@ptpl": "stack_fw-core-tpa",
                "service": {
                    "@ptpl": "stack_fw-core-tpa",
                    "disable-https": {"@ptpl": "stack_fw-core-tpa", "#text": "no"},
                    "disable-telnet": "yes",
                },
                "permitted-ip": {"entry": [
                    {"@name": "10.0.0.0/8", "@ptpl": "stack_fw-core-tpa"},
                    {"@name": "192.168.1.1"},
                ]},
            },
        }}})
        normalize_management_interfaces(appliance)
        aux = ManagementInterface.objects.get(plane=ManagementInterface.PLANE_AUX2)

        def prov(instance):
            row = instance.field_provenance.filter(field_name="__entry__").first()
            return (row.provenance_type, row.raw_value) if row else None

        self.assertEqual(prov(aux), ("template", "stack_fw-core-tpa"))
        by_name = {s.name: s for s in aux.services.all()}
        self.assertEqual(prov(by_name["https"]), ("template", "stack_fw-core-tpa"))
        self.assertEqual(prov(by_name["telnet"]), ("local", ""),
                         "an overridden leaf is present-but-unmarked: local, not template")
        # Recorded since 2026-09-21 rather than skipped: nobody pushed or wrote it, and that
        # is a fact about the value worth keeping. The row's value is the EFFECTIVE one - snmp
        # off - not `disable-snmp: yes`, so it can be read beside the field it describes.
        self.assertEqual(prov(by_name["snmp"]), ("pan_os_default", "no"),
                         "an absent key is a PAN-OS default, and says so")
        sources = {s.value: prov(s) for s in aux.permitted_sources.all()}
        self.assertEqual(sources, {"10.0.0.0/8": ("template", "stack_fw-core-tpa"),
                                   "192.168.1.1": ("local", "")})

    def test_the_binding_carries_its_own_provenance(self):
        """Who attached the profile is a different fact from where the profile came from.

        Measured 2026-09-01: loopback.20's binding leaf carries @ptpl while ethernet1/1's is
        a bare string, on the same device. A locally created interface can bind a
        template-pushed profile, and the reverse.
        """
        appliance = self._appliance()
        self._snapshot(appliance, {"network": {
            "profiles": {"interface-management-profile": {"entry": [
                {"@name": "tpl-profile", "@ptpl": "ptpl_fw-core-tpa"},
                {"@name": "local-profile"},
            ]}},
            "interface": {
                # A template-pushed binding to a template-pushed profile.
                "loopback": {"units": {"entry": {
                    "@name": "loopback.20",
                    "interface-management-profile": {"@ptpl": "ptpl_fw-core-tpa",
                                                     "#text": "tpl-profile"}}}},
                # A local binding to a local profile.
                "ethernet": {"entry": {"@name": "ethernet1/1", "layer3": {
                    "interface-management-profile": "local-profile"}}},
            },
        }})
        normalize_management_interfaces(appliance)

        def binding(name):
            surface = ManagementInterface.objects.get(interface_name=name)
            row = surface.field_provenance.filter(field_name="profile_name").first()
            return (row.provenance_type, row.raw_value) if row else None

        self.assertEqual(binding("loopback.20"), ("template", "ptpl_fw-core-tpa"))
        self.assertEqual(binding("ethernet1/1"), ("local", ""))

    def test_a_management_plane_has_no_binding_row(self):
        """MGT and aux surfaces bind no profile, so profile_name has no provenance at all."""
        appliance = self._appliance()
        self._snapshot(appliance, {"deviceconfig": {"system": {}}})
        normalize_management_interfaces(appliance)
        mgt = ManagementInterface.objects.get(plane=ManagementInterface.PLANE_MGT)
        self.assertFalse(mgt.field_provenance.filter(field_name="profile_name").exists())

    def test_a_dataplane_surface_takes_provenance_from_its_profile(self):
        """A profile overrides at the entry, so its services share one source."""
        appliance = self._appliance()
        self._snapshot(appliance, {"network": {
            "profiles": {"interface-management-profile": {"entry": {
                "@name": "p", "@ptpl": "ptpl_fw-core-tpa",
                "https": {"@ptpl": "ptpl_fw-core-tpa", "#text": "yes"}}}},
            "interface": {"ethernet": {"entry": {"@name": "ethernet1/1", "layer3": {
                "interface-management-profile": "p"}}}},
        }})
        normalize_management_interfaces(appliance)
        surface = ManagementInterface.objects.get(plane=ManagementInterface.PLANE_DATAPLANE)
        row = surface.field_provenance.get(field_name="__entry__")
        self.assertEqual((row.provenance_type, row.raw_value), ("template", "ptpl_fw-core-tpa"))
        https = surface.services.get(name="https").field_provenance.get(field_name="__entry__")
        self.assertEqual(https.raw_value, "ptpl_fw-core-tpa")

    def test_a_local_value_and_a_defaulted_one_are_told_apart(self):
        appliance = self._appliance()
        self._snapshot(appliance, {"deviceconfig": {"system": {
            "service": {"disable-telnet": "yes"},
            "permitted-ip": {"entry": {"@name": "10.1.1.1"}},
        }}})
        normalize_management_interfaces(appliance)
        mgt = ManagementInterface.objects.get(plane=ManagementInterface.PLANE_MGT)
        # The surface exists, so it has an origin: locally defined.
        self.assertEqual(mgt.field_provenance.get().provenance_type, "local")
        # telnet was WRITTEN locally; the rest are PAN-OS defaults, and each says which it is.
        telnet = mgt.services.get(name="telnet").field_provenance.get()
        self.assertEqual((telnet.provenance_type, telnet.raw_value), ("local", ""))
        snmp = mgt.services.get(name="snmp").field_provenance.get()
        self.assertEqual((snmp.provenance_type, snmp.raw_value), ("pan_os_default", "no"),
                         "written locally and defaulted by the vendor are different facts")
        self.assertEqual(mgt.permitted_sources.get().field_provenance.get().provenance_type,
                         "local")

    def test_deviceconfig_polarity_is_inverted_and_defaults_applied(self):
        """`disable-telnet: yes` means OFF, and an absent key does NOT mean off.

        This is the assertion the whole child table exists to make safe. A consumer reading
        the raw key would report the exact opposite of the truth for the three services
        that run when nothing is written.
        """
        appliance = self._appliance()
        self._snapshot(appliance, {"deviceconfig": {"system": {
            "service": {"disable-telnet": "yes", "disable-https": "yes", "disable-http": "no"},
        }}})
        normalize_management_interfaces(appliance)
        surface = ManagementInterface.objects.get(plane=ManagementInterface.PLANE_MGT)
        state = dict(surface.services.values_list("name", "enabled"))

        self.assertFalse(state["telnet"], "disable-telnet: yes must store enabled=False")
        self.assertFalse(state["https"], "an explicit disable must beat the implicit default")
        self.assertTrue(state["http"], "disable-http: no must store enabled=True")
        # Absent keys: the measured defaults, not a blanket off.
        self.assertTrue(state["ssh"])
        self.assertTrue(state["icmp"])
        self.assertFalse(state["snmp"])
        self.assertFalse(state["http-ocsp"])
        self.assertFalse(state["userid-service"])

    def test_a_plane_with_no_service_node_gets_the_defaults(self):
        """tpa-a's real shape: no `service` element at all, and three services still on."""
        appliance = self._appliance()
        self._snapshot(appliance, {"deviceconfig": {"system": {}}})
        normalize_management_interfaces(appliance)
        surface = ManagementInterface.objects.get(plane=ManagementInterface.PLANE_MGT)
        on = set(surface.services.filter(enabled=True).values_list("name", flat=True))
        self.assertEqual(on, {"https", "ssh", "icmp"})
        self.assertEqual(surface.services.count(), 10)

    def test_an_aux_plane_reads_its_own_service_node(self):
        """aux-1 carries its own `service`; it must not inherit MGT's."""
        appliance = self._appliance()
        self._snapshot(appliance, {"deviceconfig": {"system": {
            "service": {"disable-ssh": "yes"},
            "aux-1": {"service": {"disable-telnet": "no"}},
        }}})
        normalize_management_interfaces(appliance)
        mgt = ManagementInterface.objects.get(plane=ManagementInterface.PLANE_MGT)
        aux = ManagementInterface.objects.get(plane=ManagementInterface.PLANE_AUX1)
        self.assertFalse(dict(mgt.services.values_list("name", "enabled"))["ssh"])
        self.assertTrue(dict(aux.services.values_list("name", "enabled"))["ssh"],
                        "aux-1 has no disable-ssh of its own, so ssh stays on there")
        self.assertTrue(dict(aux.services.values_list("name", "enabled"))["telnet"])

    def test_profile_polarity_is_positive_and_absent_means_off(self):
        """The opposite polarity: a bare profile entry exposes nothing."""
        appliance = self._appliance()
        self._snapshot(appliance, {"network": {
            "profiles": {"interface-management-profile": {"entry": [
                {"@name": "bare"},
                {"@name": "web", "https": "yes", "telnet": "yes", "ping": "no"},
            ]}},
            "interface": {"ethernet": {"entry": [
                {"@name": "ethernet1/1", "layer3": {"interface-management-profile": "bare"}},
                {"@name": "ethernet1/2", "layer3": {"interface-management-profile": "web"}},
            ]}},
        }})
        normalize_management_interfaces(appliance)
        bare = ManagementInterface.objects.get(interface_name="ethernet1/1")
        web = ManagementInterface.objects.get(interface_name="ethernet1/2")

        self.assertEqual(bare.services.filter(enabled=True).count(), 0,
                         "a bare profile enables nothing - absent is OFF here")
        self.assertEqual(bare.services.count(), 11)
        self.assertEqual(set(web.services.filter(enabled=True).values_list("name", flat=True)),
                         {"https", "telnet"})

    def test_the_planes_carry_different_service_sets(self):
        """icmp exists only on deviceconfig, ping/response-pages only on a profile.

        Absence of a row means the service does not exist on that plane, which is why this
        is a child table rather than a column per service.
        """
        appliance = self._appliance()
        self._snapshot(appliance, {
            "deviceconfig": {"system": {}},
            "network": {
                "profiles": {"interface-management-profile": {"entry": {"@name": "p"}}},
                "interface": {"ethernet": {"entry": {
                    "@name": "ethernet1/1", "layer3": {"interface-management-profile": "p"}}}},
            },
        })
        normalize_management_interfaces(appliance)
        mgt = set(ManagementInterface.objects.get(plane=ManagementInterface.PLANE_MGT)
                  .services.values_list("name", flat=True))
        prof = set(ManagementInterface.objects.get(plane=ManagementInterface.PLANE_DATAPLANE)
                   .services.values_list("name", flat=True))
        self.assertEqual(mgt - prof, {"icmp"})
        self.assertEqual(prof - mgt, {"ping", "response-pages"})
        self.assertEqual(len(mgt & prof), 9)


class InterfaceNormalizationTests(TestCase):
    """The interface as an object, and the anomalies that must not vanish.

    Containers are read from the payload rather than a fixed list: measured 2026-08-31, a
    PA-5220 offers `vlan` and a PA-VM does not, and both offer `sdwan`, which the two
    normalizers predating this one do not walk at all.
    """

    def _appliance(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.if")
        group = ApplianceGroup.objects.create(
            management_station=station, name="grp-if", group_type=ApplianceGroup.TYPE_STANDALONE)
        return Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="SERIAL-IF", hostname="fw-if")

    def _snapshot(self, appliance, network):
        return Snapshot.objects.create(
            management_station=appliance.management_station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": {"network": network}}}})

    def test_every_container_is_walked_including_ones_no_tuple_lists(self):
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {
            "ethernet": {"entry": {"@name": "ethernet1/1", "layer3": {
                "ip": {"entry": {"@name": "10.0.0.1/24"}}}}},
            "aggregate-ethernet": {"entry": {"@name": "ae1", "layer3": {}}},
            "vlan": {"units": {"entry": {"@name": "vlan.5"}}},
            "loopback": {"units": {"entry": {"@name": "loopback.1"}}},
            "tunnel": {"units": {"entry": {"@name": "tunnel.1"}}},
            # sdwan is the one the older normalizers miss entirely
            "sdwan": {"units": {"entry": {"@name": "sdwan.1"}}},
        }})
        result = normalize_interfaces(appliance)
        self.assertEqual(
            sorted(i.name for i in result.interfaces),
            ["ae1", "ethernet1/1", "loopback.1", "sdwan.1", "tunnel.1", "vlan.5"])
        self.assertEqual(result.issues, [])

    def test_type_is_the_present_key_not_a_truthy_one(self):
        """An empty type subtree serialises as null; truthiness reports it as typeless."""
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"ethernet": {"entry": [
            {"@name": "ethernet1/1", "tap": None},
            {"@name": "ethernet1/2", "layer2": None},
            {"@name": "ethernet1/3", "aggregate-group": "ae1"},
        ]}}})
        result = normalize_interfaces(appliance)
        by_name = {i.name: i for i in result.interfaces}
        self.assertEqual(by_name["ethernet1/1"].interface_type, Interface.TYPE_TAP)
        self.assertEqual(by_name["ethernet1/2"].interface_type, Interface.TYPE_LAYER2)
        self.assertEqual(by_name["ethernet1/3"].interface_type, Interface.TYPE_AGGREGATE_MEMBER)
        self.assertEqual(by_name["ethernet1/3"].aggregate_group, "ae1")
        self.assertEqual(result.issues, [])

    def test_an_aggregate_member_is_not_confused_with_a_unit(self):
        """Both look like 'has a parent' and they are different relationships."""
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"ethernet": {"entry": [
            {"@name": "ethernet1/1", "layer3": {"units": {"entry": {"@name": "ethernet1/1.10"}}}},
            {"@name": "ethernet1/3", "aggregate-group": "ae1"},
        ]}}})
        result = normalize_interfaces(appliance)
        by_name = {i.name: i for i in result.interfaces}
        self.assertEqual(by_name["ethernet1/1.10"].parent, by_name["ethernet1/1"])
        self.assertEqual(by_name["ethernet1/1.10"].aggregate_group, "")
        self.assertIsNone(by_name["ethernet1/3"].parent,
                          "a member is not a unit of its aggregate")

    def test_addressing_distinguishes_dhcp_from_no_address(self):
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"ethernet": {"entry": [
            {"@name": "ethernet1/1", "layer3": {"dhcp-client": {"enable": "yes"}}},
            {"@name": "ethernet1/2", "layer3": {}},
            {"@name": "ethernet1/4", "layer3": {"ipv6": {"address": {"entry": {"@name": "2001:db8::1/64"}}}}},
        ]}}})
        by_name = {i.name: i for i in normalize_interfaces(appliance).interfaces}
        self.assertEqual(by_name["ethernet1/1"].addressing, Interface.ADDRESSING_DHCP)
        self.assertEqual(by_name["ethernet1/1"].ipv4_addresses, [])
        self.assertEqual(by_name["ethernet1/2"].addressing, Interface.ADDRESSING_NONE)
        self.assertEqual(by_name["ethernet1/4"].ipv6_addresses, ["2001:db8::1/64"])

    def test_an_entry_with_no_name_is_reported_not_dropped_quietly(self):
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"ethernet": {"entry": [
            {"@name": "ethernet1/1", "layer3": {}},
            {"layer3": {}},
        ]}}})
        result = normalize_interfaces(appliance)
        self.assertEqual([i.name for i in result.interfaces], ["ethernet1/1"])
        self.assertEqual(len(result.issues), 1)
        self.assertEqual(result.issues[0].severity, NormalizationIssue.Severity.ERROR)
        self.assertEqual(result.issues[0].disposition, NormalizationIssue.Disposition.SKIPPED)
        self.assertEqual(NormalizationIssue.objects.filter(kind="interface").count(), 1)

    def test_a_declared_port_with_no_mode_is_ordinary_not_an_anomaly(self):
        """PAN-OS commits a bare `<entry name="ethernet1/9"/>` and stores exactly that.

        Warning on it fired on a real firewall's unconfigured port - noise on every device
        that declares ports it has not configured.
        """
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"ethernet": {"entry": [
            {"@name": "ethernet1/9"},
            {"@name": "ethernet1/8", "comment": "spare", "link-state": "auto"},
        ]}}})
        result = normalize_interfaces(appliance)
        self.assertEqual({i.name: i.interface_type for i in result.interfaces},
                         {"ethernet1/9": Interface.TYPE_UNCONFIGURED,
                          "ethernet1/8": Interface.TYPE_UNCONFIGURED})
        self.assertEqual(result.issues, [])

    def test_an_unrecognised_container_is_walked_and_reported(self):
        """Hard-coding the container set is what made sdwan invisible, so an unfamiliar one
        is still walked - but nothing here has been measured against its shape."""
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {
            "ethernet": {"entry": {"@name": "ethernet1/1", "layer3": {}}},
            "some-future-type": {"entry": {"@name": "sft.1"}},
        }})
        result = normalize_interfaces(appliance)
        self.assertIn("sft.1", [i.name for i in result.interfaces],
                      "an unfamiliar container is still normalized")
        container_issues = [i for i in result.issues if i.name == "some-future-type"]
        self.assertEqual(len(container_issues), 1)
        self.assertEqual(container_issues[0].severity, NormalizationIssue.Severity.WARNING)
        self.assertEqual(container_issues[0].disposition, NormalizationIssue.Disposition.KEPT)

    def test_an_unknown_type_is_kept_and_reported_rather_than_assumed_broken(self):
        """The type set is platform-dependent, so an unrecognised entry is news, not corruption."""
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"ethernet": {"entry": {
            "@name": "ethernet1/9", "decrypt-mirror": {"target": "x"}}}}})
        result = normalize_interfaces(appliance)
        self.assertEqual(result.interfaces[0].interface_type, Interface.TYPE_UNKNOWN)
        self.assertEqual(result.issues[0].severity, NormalizationIssue.Severity.WARNING)
        self.assertEqual(result.issues[0].disposition, NormalizationIssue.Disposition.KEPT)

    def test_two_type_keys_is_an_error_and_still_yields_a_row(self):
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"ethernet": {"entry": {
            "@name": "ethernet1/1", "layer3": {}, "layer2": {}}}}})
        result = normalize_interfaces(appliance)
        self.assertEqual(len(result.interfaces), 1)
        self.assertEqual(result.issues[0].severity, NormalizationIssue.Severity.ERROR)
        self.assertIn("2 type keys", result.issues[0].reason)

    def test_a_subinterface_inherits_its_parents_type(self):
        """A unit carries no type key of its own - the parent does.

        Type-discriminating a unit reported every subinterface on a real firewall as an
        unknown type: eighteen false warnings per device, from config that is entirely
        ordinary.
        """
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"ethernet": {"entry": {
            "@name": "ethernet1/1", "layer3": {"units": {"entry": [
                {"@name": "ethernet1/1.10", "ip": {"entry": {"@name": "10.1.1.1/24"}}},
                {"@name": "ethernet1/1.20"},
            ]}}}}}})
        result = normalize_interfaces(appliance)
        by_name = {i.name: i for i in result.interfaces}
        self.assertEqual(by_name["ethernet1/1.10"].interface_type, Interface.TYPE_LAYER3)
        self.assertEqual(by_name["ethernet1/1.20"].interface_type, Interface.TYPE_LAYER3)
        self.assertEqual(by_name["ethernet1/1.10"].ipv4_addresses, ["10.1.1.1/24"])
        self.assertEqual(result.issues, [], "an ordinary subinterface is not an anomaly")

    def test_an_empty_container_element_is_not_an_error(self):
        """`<aggregate-ethernet/>` parses to None. A device with no aggregates is normal."""
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {
            "ethernet": {"entry": {"@name": "ethernet1/1", "layer3": {}}},
            "aggregate-ethernet": None,
            "vlan": None,
        }})
        result = normalize_interfaces(appliance)
        self.assertEqual([i.name for i in result.interfaces], ["ethernet1/1"])
        self.assertEqual(result.issues, [])

    def test_a_container_of_the_wrong_type_is_still_an_error(self):
        """None is empty; a string is a payload we do not understand and must report."""
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"ethernet": "unexpected"}})
        result = normalize_interfaces(appliance)
        self.assertEqual(len(result.issues), 1)
        self.assertEqual(result.issues[0].severity, NormalizationIssue.Severity.ERROR)

    def test_two_appliances_in_one_group_keep_their_own_issues(self):
        """Both HA members normalize their own interfaces, so issues cannot be group-owned.

        A group-scoped replace had the second peer's run delete the first's issues with no
        trace, which is the one thing an issue record must never do.
        """
        first = self._appliance()
        second = Appliance.objects.create(
            management_station=first.management_station,
            appliance_group=first.appliance_group,
            serial_number="SERIAL-IF2", hostname="fw-if2")
        for appliance in (first, second):
            self._snapshot(appliance, {"interface": {"ethernet": {"entry": [{"layer3": {}}]}}})
            normalize_interfaces(appliance)

        self.assertEqual(NormalizationIssue.objects.filter(kind="interface").count(), 2)
        self.assertEqual(
            set(NormalizationIssue.objects.filter(kind="interface")
                .values_list("appliance__hostname", flat=True)),
            {"fw-if", "fw-if2"})

    def test_an_issue_belongs_to_exactly_one_owner(self):
        appliance = self._appliance()
        issue = NormalizationIssue(
            management_station=appliance.management_station,
            appliance=appliance, appliance_group=appliance.appliance_group,
            kind="interface", severity=NormalizationIssue.Severity.ERROR,
            disposition=NormalizationIssue.Disposition.SKIPPED, reason="x")
        with self.assertRaises(ValidationError):
            issue.clean()

    def test_issues_are_replaced_not_accumulated(self):
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"ethernet": {"entry": [{"layer3": {}}]}}})
        normalize_interfaces(appliance)
        normalize_interfaces(appliance)
        self.assertEqual(NormalizationIssue.objects.filter(kind="interface").count(), 1)

    def test_renormalizing_replaces_rather_than_accumulates(self):
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"ethernet": {"entry": {
            "@name": "ethernet1/1", "layer3": {}}}}})
        normalize_interfaces(appliance)
        normalize_interfaces(appliance)
        self.assertEqual(Interface.objects.filter(appliance=appliance).count(), 1)


class InterfaceManagementProfileNormalizationTests(TestCase):
    """Profiles as objects, so that an UNUSED one has somewhere to be."""

    def _appliance(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.imp")
        group = ApplianceGroup.objects.create(
            management_station=station, name="grp-imp", group_type=ApplianceGroup.TYPE_STANDALONE)
        return Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="SERIAL-IMP", hostname="fw-imp")

    def _snapshot(self, appliance, network):
        return Snapshot.objects.create(
            management_station=appliance.management_station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": {"network": network}}}})

    def test_an_unbound_profile_is_recorded_with_no_bindings(self):
        """The case that cannot be seen from ManagementInterface at all."""
        appliance = self._appliance()
        self._snapshot(appliance, {
            "profiles": {"interface-management-profile": {"entry": [
                {"@name": "bound-one", "https": "yes"},
                {"@name": "unused-one", "ssh": "yes"},
            ]}},
            "interface": {"ethernet": {"entry": {
                "@name": "ethernet1/1",
                "layer3": {"interface-management-profile": "bound-one"}}}},
        })
        normalize_interfaces(appliance)
        profiles = {p.name: p for p in normalize_interface_management_profiles(appliance)}
        self.assertEqual(profiles["bound-one"].bound_interface_names, ["ethernet1/1"])
        self.assertEqual(profiles["bound-one"].bound_interface_count, 1)
        self.assertEqual(profiles["unused-one"].bound_interface_names, [])
        self.assertEqual(profiles["unused-one"].bound_interface_count, 0)

    def test_a_profile_bound_to_an_sdwan_interface_is_not_reported_unused(self):
        """sdwan exists on a PA-5220 and a PA-VM, and the old hard-coded walks missed it.

        Getting this wrong produces a false finding: a profile that IS bound, reported as
        unused, on a container nobody thought to list.
        """
        appliance = self._appliance()
        self._snapshot(appliance, {
            "profiles": {"interface-management-profile": {"entry": {"@name": "p", "ssh": "yes"}}},
            "interface": {"sdwan": {"units": {"entry": {
                "@name": "sdwan.1", "interface-management-profile": "p"}}}},
        })
        normalize_interfaces(appliance)
        profile = normalize_interface_management_profiles(appliance)[0]
        self.assertEqual(profile.bound_interface_names, ["sdwan.1"])
        self.assertEqual(profile.bound_interface_count, 1)

    def test_bindings_are_found_at_every_depth(self):
        appliance = self._appliance()
        self._snapshot(appliance, {
            "profiles": {"interface-management-profile": {"entry": {"@name": "p"}}},
            "interface": {
                "ethernet": {"entry": {"@name": "ethernet1/1", "layer3": {
                    "interface-management-profile": "p",
                    "units": {"entry": {"@name": "ethernet1/1.10",
                                        "interface-management-profile": "p"}}}}},
                "loopback": {"units": {"entry": {"@name": "loopback.1",
                                                 "interface-management-profile": "p"}}},
            },
        })
        normalize_interfaces(appliance)
        profile = normalize_interface_management_profiles(appliance)[0]
        self.assertEqual(profile.bound_interface_names,
                         ["ethernet1/1", "ethernet1/1.10", "loopback.1"])

    def test_template_provenance_is_recorded_and_local_is_its_absence(self):
        """Measured on hardware: a pushed profile carries @ptpl, a local one carries nothing."""
        appliance = self._appliance()
        self._snapshot(appliance, {
            "profiles": {"interface-management-profile": {"entry": [
                {"@name": "from-template", "@ptpl": "ptpl_fw-core-tpa",
                 "https": {"@ptpl": "ptpl_fw-core-tpa", "#text": "yes"}},
                {"@name": "from-local", "ssh": "yes"},
            ]}},
            # An interface must exist for bindings to be countable at all - see the guard
            # in the profile normalizer.
            "interface": {"ethernet": {"entry": {"@name": "ethernet1/1", "layer3": {}}}},
        })
        normalize_interfaces(appliance)
        profiles = {p.name: p for p in normalize_interface_management_profiles(appliance)}
        ct = ContentType.objects.get_for_model(InterfaceManagementProfile)

        row = FieldProvenance.objects.get(
            content_type=ct, object_id=profiles["from-template"].pk, field_name=ENTRY_FIELD)
        self.assertEqual(row.provenance_type, FieldProvenance.ProvenanceType.TEMPLATE)
        self.assertEqual(row.raw_value, "ptpl_fw-core-tpa")
        # Local is now a ROW SAYING LOCAL, not the absence of one. Until 2026-10-05 this
        # asserted the absence, which is what made "defined on the device" and "nothing tracks
        # this" indistinguishable to every consumer.
        local_row = FieldProvenance.objects.get(
            content_type=ct, object_id=profiles["from-local"].pk, field_name=ENTRY_FIELD)
        self.assertEqual(local_row.provenance_type, FieldProvenance.ProvenanceType.LOCAL)
        self.assertEqual(local_row.raw_key, "", "no payload key said local; its absence did")

    def test_counting_without_interfaces_raises_rather_than_reporting_all_unused(self):
        """With no interface rows every profile counts zero bindings.

        Reporting that would be a page of false findings that look exactly like real ones,
        so the absence has to be an error rather than an answer.
        """
        appliance = self._appliance()
        self._snapshot(appliance, {"profiles": {"interface-management-profile": {
            "entry": {"@name": "p"}}}})
        with self.assertRaises(ValueError) as raised:
            normalize_interface_management_profiles(appliance)
        self.assertIn("no normalized interfaces", str(raised.exception))

    def test_a_locally_defined_profile_says_local_rather_than_saying_nothing(self):
        """LOCAL used to be the absence of a row, which made absence mean two things: defined on
        the device, and nothing tracks this. A consumer cannot tell those apart, so every
        locally defined profile was presented as unrecorded - four of the lab's eight.

        This is the same correction normalization made for FIELDS on 2026-09-21, applied to the
        entry. An override also leaves an entry unmarked and local is right there too: the
        override replaced the object, so the device copy is in force and is where a change has
        to be made."""
        appliance = self._appliance()
        self._snapshot(appliance, {
            "profiles": {"interface-management-profile": {"entry": [
                {"@name": "local-one", "https": "yes"},
                {"@name": "pushed-one", "@ptpl": "stack_x", "ssh": "yes"},
            ]}},
            "interface": {"ethernet": {"entry": {"@name": "ethernet1/1", "layer3": {}}}},
        })
        normalize_interfaces(appliance)
        normalize_interface_management_profiles(appliance)

        rows = {r.object_id: r for r in FieldProvenance.objects.filter(field_name="__entry__")}
        by_name = {p.name: p for p in InterfaceManagementProfile.objects.all()}
        self.assertEqual(rows[by_name["local-one"].pk].provenance_type, "local")
        self.assertEqual(rows[by_name["pushed-one"].pk].provenance_type, "template")
        self.assertEqual(rows[by_name["pushed-one"].pk].raw_value, "stack_x")

    def test_every_profile_gets_an_entry_row(self):
        """A profile is defined SOMEWHERE. Jason, 2026-10-05: "Everything should have
        provenance. A management profile is defined *somewhere*." So the count of entry rows
        equals the count of profiles, with no exceptions to remember."""
        appliance = self._appliance()
        self._snapshot(appliance, {
            "profiles": {"interface-management-profile": {"entry": [
                {"@name": f"p{i}"} for i in range(4)
            ]}},
            "interface": {"ethernet": {"entry": {"@name": "ethernet1/1", "layer3": {}}}},
        })
        normalize_interfaces(appliance)
        profiles = normalize_interface_management_profiles(appliance)

        self.assertEqual(
            FieldProvenance.objects.filter(field_name="__entry__").count(), len(profiles))

    def test_the_binding_is_read_from_the_interface_row_not_a_second_walk(self):
        appliance = self._appliance()
        self._snapshot(appliance, {
            "profiles": {"interface-management-profile": {"entry": {"@name": "p"}}},
            "interface": {"ethernet": {"entry": {"@name": "ethernet1/1", "layer3": {
                "interface-management-profile": "p"}}}},
        })
        interfaces = {i.name: i for i in normalize_interfaces(appliance).interfaces}
        self.assertEqual(interfaces["ethernet1/1"].management_profile_name, "p")
        profile = normalize_interface_management_profiles(appliance)[0]
        self.assertEqual(profile.bound_interface_names, ["ethernet1/1"])

    def test_an_aggregate_member_and_its_aggregate_are_both_typed(self):
        """Measured on hardware 2026-08-31 with a real ae1 and member.

        `aggregate-group` is a STRING where a type subtree would be, so code that finds the
        type key and reads its children returns nothing for a member - silently, per the
        vendor guide. The lab had no aggregates until this was built to check it.
        """
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {
            "aggregate-ethernet": {"entry": {"@name": "ae1", "layer3": None}},
            "ethernet": {"entry": {"@name": "ethernet1/9", "aggregate-group": "ae1"}},
        }})
        result = normalize_interfaces(appliance)
        by_name = {i.name: i for i in result.interfaces}
        self.assertEqual(by_name["ae1"].interface_type, Interface.TYPE_LAYER3)
        self.assertEqual(by_name["ethernet1/9"].interface_type, Interface.TYPE_AGGREGATE_MEMBER)
        self.assertEqual(by_name["ethernet1/9"].aggregate_group, "ae1")
        self.assertIsNone(by_name["ethernet1/9"].parent, "a member is not a unit")
        self.assertEqual(result.issues, [])

    def test_vlan_has_the_same_flat_shape_as_loopback(self):
        """Measured on hardware 2026-08-31, not inferred from action=complete.

        The flat shape was originally claimed from the schema, which reports what MAY be
        set rather than what an instance looks like. A configured vlan interface returns
        `units/entry` alongside container-level `comment` and `ip`, exactly as loopback
        does - so the bare `vlan` is an interface in its own right and its units are
        siblings of it, not children.
        """
        appliance = self._appliance()
        self._snapshot(appliance, {"interface": {"vlan": {
            "comment": "probe",
            "ip": {"entry": [{"@name": "10.254.0.1/32"}]},
            "units": {"entry": [
                {"@name": "vlan.5", "ip": {"entry": [{"@name": "10.254.5.1/24"}]}},
                {"@name": "vlan.6"},
            ]},
        }}})
        result = normalize_interfaces(appliance)
        by_name = {i.name: i for i in result.interfaces}
        self.assertEqual(sorted(by_name), ["vlan", "vlan.5", "vlan.6"])
        self.assertEqual(by_name["vlan"].ipv4_addresses, ["10.254.0.1/32"])
        self.assertEqual(by_name["vlan"].comment, "probe")
        self.assertEqual(by_name["vlan.5"].ipv4_addresses, ["10.254.5.1/24"])
        self.assertEqual(by_name["vlan.6"].addressing, Interface.ADDRESSING_NONE)
        # Units of a logical container have no parent row - the container is a sibling
        # interface, not their owner.
        self.assertIsNone(by_name["vlan.5"].parent)
        self.assertEqual(result.issues, [])

    def test_a_configured_logical_container_is_itself_an_interface(self):
        """vlan, loopback and tunnel accept ip/comment/profile directly - measured.

        A bare `loopback` carrying an address and a profile is a real interface, and
        without a row for it the binding it holds would be invisible and its profile
        reported unused.
        """
        appliance = self._appliance()
        self._snapshot(appliance, {
            "profiles": {"interface-management-profile": {"entry": {"@name": "p"}}},
            "interface": {"loopback": {
                "ip": {"entry": {"@name": "10.255.0.1/32"}},
                "interface-management-profile": "p",
                "units": {"entry": {"@name": "loopback.1"}}}},
        })
        interfaces = {i.name: i for i in normalize_interfaces(appliance).interfaces}
        self.assertEqual(sorted(interfaces), ["loopback", "loopback.1"])
        self.assertEqual(interfaces["loopback"].management_profile_name, "p")
        self.assertEqual(interfaces["loopback"].ipv4_addresses, ["10.255.0.1/32"])
        profile = normalize_interface_management_profiles(appliance)[0]
        self.assertEqual(profile.bound_interface_names, ["loopback"])

    def test_renormalizing_replaces_profiles_and_their_provenance(self):
        appliance = self._appliance()
        self._snapshot(appliance, {
            "profiles": {"interface-management-profile": {"entry": {"@name": "p", "@ptpl": "tpl"}}},
            "interface": {"ethernet": {"entry": {"@name": "ethernet1/1", "layer3": {}}}},
        })
        normalize_interfaces(appliance)
        normalize_interface_management_profiles(appliance)
        normalize_interface_management_profiles(appliance)
        self.assertEqual(InterfaceManagementProfile.objects.count(), 1)
        ct = ContentType.objects.get_for_model(InterfaceManagementProfile)
        self.assertEqual(FieldProvenance.objects.filter(content_type=ct).count(), 1,
                         "orphaned provenance rows would accumulate every run")


class AdminUserRoleShapeTests(SimpleTestCase):
    """`permissions/role-based` has THREE wire shapes and one enum column cannot hold them.

    Measured on fw-core-tpa-a with `action=complete`, 2026-09-08: `superuser`/`superreader`
    take yes/no; `deviceadmin`/`devicereader` take a member list of device names; and
    `vsysadmin`/`vsysreader` take an entry per device carrying a vsys member list. All three
    were present on the lab at once, and a parser written for any one of them reports the
    other two as "no role" - which reads as an account with no privilege at all.
    """

    def test_a_yes_no_leaf_resolves(self):
        self.assertEqual(
            resolve_role({"superuser": "yes"}),
            ("superuser", "", ""))

    def test_a_template_pushed_leaf_resolves_through_its_marker(self):
        # A pushed leaf arrives as a dict, not a string. A reader checking `== "yes"` sees
        # a dict and calls the account roleless.
        self.assertEqual(
            resolve_role({"superuser": {"@ptpl": "creds_tpl", "#text": "yes"}}),
            ("superuser", "", ""))

    def test_an_explicit_no_is_not_the_role(self):
        self.assertEqual(resolve_role({"superuser": "no"}), ("none", "", ""))

    def test_a_member_list_role_keeps_the_device_names(self):
        self.assertEqual(
            resolve_role({"deviceadmin": {"member": ["localhost.localdomain"]}}),
            ("deviceadmin", "localhost.localdomain", ""))

    def test_a_bare_member_list_role_is_still_the_role(self):
        # `<devicereader/>` parses to None. oep-authtest carries exactly this.
        self.assertEqual(resolve_role({"devicereader": None}), ("devicereader", "", ""))

    def test_a_vsys_role_keeps_the_device_and_its_vsys_list(self):
        self.assertEqual(
            resolve_role({"vsysadmin": {"entry": [
                {"@name": "localhost.localdomain", "vsys": {"member": ["vsys1", "vsys3"]}}]}}),
            ("vsysadmin", "localhost.localdomain: vsys1, vsys3", ""))

    def test_a_custom_role_keeps_its_profile_and_scope(self):
        self.assertEqual(
            resolve_role({"custom": {"vsys": {"member": ["vsys1"]}, "profile": "auditadmin"}}),
            ("custom", "vsys1", "auditadmin"))

    def test_two_roles_resolve_to_the_more_privileged(self):
        # Not expected from the UI, which offers one. A parser bug here must over-report
        # privilege rather than under-report it.
        role, _, _ = resolve_role({"devicereader": None, "superuser": "yes"})
        self.assertEqual(role, "superuser")

    def test_an_absent_permissions_node_is_no_role(self):
        self.assertEqual(resolve_role(None), ("none", "", ""))


class ManagementTlsBindingNormalizationTests(TestCase):
    """The last cluster out of the aggregate, and the one that had actually drifted.

    The binding now points at the `SslTlsServiceProfile` ROW and reads its floor and certificate
    through the key, so the thing to pin is the resolution rule applied to rows - predefined
    beats shared, vsys never - and that nothing is copied.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.mt")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-mt",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-MT", hostname="fw-mt")

    def _normalize(self, *, bound=None, shared=None, predefined=None, vsys=None,
                   shared_certs=None):
        system = {}
        if bound is not None:
            system["ssl-tls-service-profile"] = bound
        device = {"@name": "localhost.localdomain", "deviceconfig": {"system": system}}
        if vsys is not None:
            device["vsys"] = {"entry": [{"@name": "vsys1",
                                         "ssl-tls-service-profile": {"entry": vsys}}]}
        config = {"devices": {"entry": [device]}}
        if shared is not None:
            config.setdefault("shared", {})["ssl-tls-service-profile"] = {"entry": shared}
        if shared_certs is not None:
            config.setdefault("shared", {})["certificate"] = {"entry": shared_certs}
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": config})
        if predefined is not None:
            Snapshot.objects.create(
                management_station=self.station, appliance=self.appliance,
                source_type="config_predefined_ssl_tls_service_profiles",
                collected_at=timezone.now(),
                payload={"ssl-tls-service-profile": {"entry": predefined}})
        # The order APPLIANCE_OBJECT_NORMALIZERS enforces: rows first, then the binding.
        normalize_appliance_certificate_objects(self.appliance)
        normalize_appliance_management_tls(self.appliance)
        return ManagementTlsBinding.objects.get(appliance=self.appliance)

    @staticmethod
    def _profile(name, minimum, certificate="cert"):
        return [{"@name": name, "certificate": certificate,
                 "protocol-settings": {"min-version": minimum, "max-version": "tls1-3"}}]

    def test_the_binding_points_at_the_row_and_copies_nothing(self):
        binding = self._normalize(bound="hard", shared=self._profile("hard", "tls1-2"))
        row = SslTlsServiceProfile.objects.get(appliance=self.appliance, name="hard")
        self.assertEqual(binding.ssl_tls_service_profile, row)
        self.assertEqual(binding.min_version, "tls1-2")
        self.assertEqual(binding.certificate_name, "cert")
        # A change to the ROW is a change to what the binding reports - there is no second copy
        # to fall out of step, which is the defect this model exists to remove.
        row.min_version = "tls1-0"
        row.save()
        binding.refresh_from_db()
        self.assertEqual(binding.min_version, "tls1-0")

    def test_the_predefined_row_beats_a_same_named_shared_one(self):
        binding = self._normalize(
            bound="TLSv1.3_Default",
            shared=self._profile("TLSv1.3_Default", "tls1-2", certificate="mine"),
            predefined=self._profile("TLSv1.3_Default", "tls1-3",
                                     certificate="TLSv1.3_Default"))
        self.assertEqual(binding.profile_scope, ManagementTlsBinding.SCOPE_PREDEFINED)
        self.assertEqual(binding.ssl_tls_service_profile.scope, "predefined")
        self.assertEqual(binding.certificate_name, "TLSv1.3_Default")

    def test_a_vsys_profile_is_never_bound(self):
        """`deviceconfig/system` cannot reference a vsys profile at all - measured with
        `action=complete` on the binding field. A same-named vsys row must not satisfy it."""
        binding = self._normalize(bound="only-in-vsys", vsys=self._profile("only-in-vsys", "tls1-2"))
        self.assertEqual(binding.profile_scope, ManagementTlsBinding.SCOPE_UNRESOLVED)
        self.assertIsNone(binding.ssl_tls_service_profile)
        self.assertTrue(NormalizationIssue.objects.filter(
            appliance=self.appliance, kind="ssl_tls_service_profile_unresolved").exists())

    def test_nothing_bound_is_blank_not_unresolved(self):
        binding = self._normalize()
        self.assertEqual((binding.profile_name, binding.profile_scope), ("", ""))
        self.assertEqual(binding.certificate_trust, "")
        self.assertFalse(NormalizationIssue.objects.filter(
            appliance=self.appliance, kind="ssl_tls_service_profile_unresolved").exists())

    def test_the_trust_verdict_is_about_the_certificate_the_row_names(self):
        binding = self._normalize(
            bound="p", shared=self._profile("p", "tls1-2", certificate="corp"),
            shared_certs=[{"@name": "corp", "subject-hash": "1111", "issuer-hash": "2222",
                           "issuer": "/CN=Corp CA"}])
        self.assertEqual(binding.certificate_trust, ManagementTlsBinding.TRUST_CA_ISSUED)
        self.assertEqual(binding.certificate_issuer, "/CN=Corp CA")


class MasterKeyNormalizationTests(TestCase):
    """PAN-CRT-007's subject, and the only cluster whose values are not in the merged config."""

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.mk")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-mk",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-MK", hostname="fw-mk")
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": [{"@name": "localhost.localdomain"}]}}})

    def _normalize(self, properties=None):
        if properties is not None:
            Snapshot.objects.create(
                management_station=self.station, appliance=self.appliance,
                source_type="show_masterkey_properties", collected_at=timezone.now(),
                payload=properties)
        normalize_appliance_master_key(self.appliance)
        return MasterKey.objects.get(appliance=self.appliance)

    def test_a_row_exists_even_with_no_masterkey_snapshot(self):
        """No row would make PAN-CRT-007 report nothing for a device nobody asked, and "we
        never asked" must not look like "we asked and it was fine". The control fires on
        anything that is not `set`, so undetermined fires."""
        key = self._normalize()
        self.assertEqual(key.state, MasterKey.STATE_UNDETERMINED)

    def test_expire_at_zero_is_the_factory_key(self):
        key = self._normalize({"expire-at": "0"})
        self.assertEqual(key.state, MasterKey.STATE_DEFAULT)
        self.assertEqual(key.expires_at, "0")

    def test_a_real_expiry_is_a_configured_key(self):
        key = self._normalize({"expire-at": "2027/01/01 00:00:00", "auto-renew-mkey": "720",
                               "on-hsm": "yes"})
        self.assertEqual(key.state, MasterKey.STATE_SET)
        self.assertEqual(key.auto_renew_hours, 720)
        self.assertTrue(key.on_hsm)


class ServicesSettingsNormalizationTests(TestCase):
    """PAN-MGT-009 and 011 - two one-field clusters whose defaults are OPPOSITE.

    Absent `server-verification` is ENABLED and absent `enable-log-high-dp-load` is DISABLED, so
    an untouched device satisfies one control and fires the other. One shared assumption would
    have been wrong in both directions at once.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.ss")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-ss",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-SS", hostname="fw-ss")

    def _normalize(self, deviceconfig=None):
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": [
                {"@name": "localhost.localdomain",
                 "deviceconfig": deviceconfig if deviceconfig is not None else {}}]}}})
        normalize_appliance_services_settings(self.appliance)
        return (UpdateServerSettings.objects.get(appliance=self.appliance),
                LoggingSettings.objects.get(appliance=self.appliance))

    def test_the_two_defaults_point_opposite_ways(self):
        update, logging = self._normalize()
        self.assertTrue(update.verify_identity)
        self.assertFalse(logging.log_on_high_dp_load)

    def test_an_explicit_no_turns_verification_off(self):
        update, _ = self._normalize({"system": {"server-verification": "no"}})
        self.assertFalse(update.verify_identity)

    def test_the_logging_setting_lives_under_setting_management(self):
        _, logging = self._normalize(
            {"setting": {"management": {"enable-log-high-dp-load": "yes"}}})
        self.assertTrue(logging.log_on_high_dp_load)


class LoginBannerNormalizationTests(TestCase):
    """The third cluster out of the aggregate. PAN-MGT-007 and 008.

    Two fields that are one object: the acknowledgement checkbox is greyed out until a banner
    exists, so the pair has to be read together to be interpreted at all.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.lb")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-lb",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-LB", hostname="fw-lb")

    def _normalize(self, system=None):
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": [
                {"@name": "localhost.localdomain",
                 "deviceconfig": {"system": system if system is not None else {}}}]}}})
        normalize_appliance_login_banner(self.appliance)
        return LoginBanner.objects.get(appliance=self.appliance)

    def test_no_banner_is_empty_text_and_no_acknowledgement(self):
        """Empty is the FINDING, not missing data - PAN-MGT-007 asks whether there is one."""
        banner = self._normalize()
        self.assertEqual(banner.text, "")
        self.assertFalse(banner.acknowledgement_required)

    def test_the_banner_is_stored_whole(self):
        """A length or a boolean would answer PAN-MGT-007 and destroy the evidence: an assessor
        reading the finding needs to see what the banner actually says."""
        text = "Authorized use only.\nAll activity is monitored and recorded."
        banner = self._normalize({"login-banner": text, "ack-login-banner": "yes"})
        self.assertEqual(banner.text, text)
        self.assertTrue(banner.acknowledgement_required)

    def test_a_pushed_banner_is_read_through_its_marker(self):
        banner = self._normalize({"login-banner": {"@ptpl": "tpl-base", "#text": "Notice"}})
        self.assertEqual(banner.text, "Notice")
        rows = {p.field_name: p.raw_value for p in FieldProvenance.objects.filter(
            content_type=ContentType.objects.get_for_model(LoginBanner), object_id=banner.pk)}
        self.assertEqual(rows.get("text"), "tpl-base")
        # Defaulted, and recorded as such: mgmt-settings.ack-login-banner is implicit 'no'.
        self.assertEqual(rows["acknowledgement_required"], "no")


class AuthenticationSettingsNormalizationTests(TestCase):
    """The second cluster out of the aggregate. PAN-AUTH-014 to 017.

    The zeros are the whole subject: three of these four fields default to 0 and 0 means
    something different on each - unlimited attempts, locked until released, and a key that
    never expires. Idle timeout is the odd one, defaulting to the vendor's 60.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.as")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-as",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-AS", hostname="fw-as")

    def _normalize(self, management=None):
        entry = {"@name": "localhost.localdomain", "deviceconfig": {"system": {}}}
        if management is not None:
            entry["deviceconfig"]["setting"] = {"management": management}
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": [entry]}}})
        normalize_appliance_authentication_settings(self.appliance)
        return AuthenticationSettings.objects.get(appliance=self.appliance)

    def test_the_whole_management_node_can_be_absent(self):
        """Its normal state on a device nobody has configured - measured on both PA-5220s. The
        parser has to tolerate the PARENT missing, not just the key."""
        settings = self._normalize()
        self.assertEqual(settings.idle_timeout_minutes, 60)
        self.assertEqual(settings.lockout_failed_attempts, 0)
        self.assertEqual(settings.lockout_time_minutes, 0)
        self.assertEqual(settings.api_key_lifetime_minutes, 0)

    def test_admin_lockout_is_a_container(self):
        settings = self._normalize({
            "admin-lockout": {"failed-attempts": "3", "lockout-time": "30"},
            "idle-timeout": "10",
            "api": {"key": {"lifetime": "525600"}},
        })
        self.assertEqual(
            (settings.idle_timeout_minutes, settings.lockout_failed_attempts,
             settings.lockout_time_minutes, settings.api_key_lifetime_minutes),
            (10, 3, 30, 525600))

    def test_one_row_per_appliance_and_re_normalizing_updates_it(self):
        self._normalize({"idle-timeout": "10"})
        settings = self._normalize({"idle-timeout": "5"})
        self.assertEqual(
            AuthenticationSettings.objects.filter(appliance=self.appliance).count(), 1)
        self.assertEqual(settings.idle_timeout_minutes, 5)


class PasswordComplexityNormalizationTests(TestCase):
    """The first cluster cut out of `DeviceConfigurationProfile`. PAN-AUTH-001 to 013.

    Two things need guarding while both models exist: that the new row carries the SAME numbers
    the aggregate does - they share one parser precisely so they cannot drift - and that every
    absent key still resolves to the insecure default rather than to null.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.pc")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-pc",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-PC", hostname="fw-pc")

    def _normalize(self, complexity=None):
        config = {"devices": {"entry": [{"@name": "localhost.localdomain"}]}}
        if complexity is not None:
            config["mgt-config"] = {"password-complexity": complexity}
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": config})
        normalize_appliance_password_complexity(self.appliance)
        return PasswordComplexityPolicy.objects.get(appliance=self.appliance)

    def test_an_absent_node_is_the_insecure_default_not_null(self):
        """PAN-OS never writes these keys - the UI stores only the flag when complexity is
        enabled - so absent is the normal state and every default is the weak one."""
        policy = self._normalize()
        self.assertFalse(policy.enabled)
        self.assertEqual(policy.minimum_length, 0)
        self.assertEqual(policy.expiration_period, 0)

    def test_the_prefix_comes_off_and_the_values_do_not_change(self):
        """The shared parser names everything `password_*` because it was written for a model
        with 34 other fields. Renaming is a mapping, not a re-read: a typo in it would put a
        number on the wrong column and nothing else would notice."""
        policy = self._normalize({
            "enabled": "yes",
            "minimum-length": "12",
            "minimum-uppercase-letters": "1",
            "minimum-lowercase-letters": "2",
            "minimum-numeric-letters": "3",
            "minimum-special-characters": "4",
            "block-username-inclusion": "yes",
            "new-password-differs-by-characters": "5",
            "password-history-count": "6",
            "block-repeated-characters": "7",
            "password-change-on-first-login": "yes",
            "password-change-period-block": "8",
            "password-change": {
                "expiration-period": "90",
                "expiration-warning-period": "14",
                "post-expiration-admin-login-count": "2",
                "post-expiration-grace-period": "3",
            },
        })
        self.assertTrue(policy.enabled)
        self.assertEqual(
            (policy.minimum_length, policy.minimum_uppercase, policy.minimum_lowercase,
             policy.minimum_numeric, policy.minimum_special),
            (12, 1, 2, 3, 4))
        self.assertTrue(policy.block_username_inclusion)
        self.assertEqual((policy.new_differs_by_characters, policy.history_count), (5, 6))
        self.assertEqual((policy.block_repeated_characters, policy.change_period_block), (7, 8))
        self.assertTrue(policy.change_on_first_login)
        self.assertEqual(
            (policy.expiration_period, policy.expiration_warning_period,
             policy.post_expiration_admin_login_count, policy.post_expiration_grace_period),
            (90, 14, 2, 3))

    def test_one_row_per_appliance_and_re_normalizing_updates_it(self):
        self._normalize({"minimum-length": "8"})
        policy = self._normalize({"minimum-length": "16"})
        self.assertEqual(PasswordComplexityPolicy.objects.filter(
            appliance=self.appliance).count(), 1)
        self.assertEqual(policy.minimum_length, 16)

    def test_a_pushed_value_records_its_provenance(self):
        """mgt-config is template-managed; these values really can be pushed."""
        policy = self._normalize({"minimum-length": {"@ptpl": "tpl-base", "#text": "12"}})
        self.assertEqual(policy.minimum_length, 12)
        rows = {p.field_name: p for p in FieldProvenance.objects.filter(
            content_type=ContentType.objects.get_for_model(PasswordComplexityPolicy),
            object_id=policy.pk)}
        self.assertIn("minimum_length", rows)
        self.assertEqual(rows["minimum_length"].raw_value, "tpl-base")
        # An absent key produces NO row - that is what keeps "defaulted" and "written locally"
        # apart.
        # Every complexity key the device does not carry is a measured PAN-OS default - the
        # whole node absent means 0 and unticked, measured 2026-09-03 from the blank form.
        self.assertEqual(rows["minimum_special"].provenance_type, "pan_os_default")


class ServerProfileNormalizationTests(TestCase):
    """AAA server profiles - the shapes that would bite a normalizer written from one kind.

    Six kinds sit in six sibling containers and differ in ways `action=complete` cannot show:
    the server address key has three names, `protocol` has two wire forms, and two of the three
    measured implicit values invert what a checkbox suggests.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.sp")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-sp",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-SP", hostname="fw-sp")

    def _normalize(self, shared=None, vsys=None, extra_device=None):
        config = {"shared": {"server-profile": shared or {}},
                  "devices": {"entry": [{"@name": "localhost.localdomain",
                                         "vsys": {"entry": [
                                             {"@name": "vsys1",
                                              "server-profile": vsys or {}}]}}]}}
        if extra_device:
            config["devices"]["entry"][0].update(extra_device)
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": config})
        normalize_appliance_server_profiles(self.appliance)
        return {(p.kind, p.name): p
                for p in ServerProfile.objects.filter(appliance=self.appliance)}

    def test_the_address_key_has_three_names(self):
        """`address` on ldap and tacplus, `ip-address` on radius, `host` on kerberos. Reading
        one name records no servers for the other two, silently."""
        rows = self._normalize(shared={
            "ldap": {"entry": [{"@name": "l", "server": {"entry": [
                {"@name": "s", "address": "10.0.0.1"}]}}]},
            "radius": {"entry": [{"@name": "r", "protocol": {"PAP": None},
                                  "server": {"entry": [{"@name": "s", "ip-address": "10.0.0.2"}]}}]},
            "kerberos": {"entry": [{"@name": "k", "server": {"entry": [
                {"@name": "s", "host": "10.0.0.3"}]}}]},
        })
        self.assertEqual(rows[("ldap", "l")].server_addresses, ["10.0.0.1"])
        self.assertEqual(rows[("radius", "r")].server_addresses, ["10.0.0.2"])
        self.assertEqual(rows[("kerberos", "k")].server_addresses, ["10.0.0.3"])

    def test_protocol_has_two_wire_forms(self):
        """radius stores `{"PAP": null}` and tacplus stores `"PAP"`. Both complete to the same
        value list, so the schema oracle cannot tell them apart."""
        rows = self._normalize(shared={
            "radius": {"entry": [{"@name": "r", "protocol": {"PAP": None}}]},
            "tacplus": {"entry": [{"@name": "t", "protocol": "PAP"}]},
        })
        self.assertEqual(rows[("radius", "r")].protocol, "PAP")
        self.assertEqual(rows[("tacplus", "t")].protocol, "PAP")

    def test_the_implicit_values_that_invert(self):
        """Measured by writing key-less profiles and opening them in the UI. `ssl` and both SAML
        flags are implicit YES; only `verify-server-certificate` is implicit NO. Reading them as
        "absent means off" reports every unconfigured SAML profile as unvalidated and unsigned."""
        rows = self._normalize(shared={
            "ldap": {"entry": [{"@name": "bare"}]},
            "saml-idp": {"entry": [{"@name": "bare"}]},
        })
        self.assertTrue(rows[("ldap", "bare")].ldap_ssl)
        self.assertFalse(rows[("ldap", "bare")].ldap_verify_server_certificate)
        self.assertTrue(rows[("saml-idp", "bare")].saml_validate_idp_certificate)
        self.assertTrue(rows[("saml-idp", "bare")].saml_want_auth_requests_signed)

    def test_an_explicit_no_overrides_each_implicit_yes(self):
        rows = self._normalize(shared={
            "ldap": {"entry": [{"@name": "off", "ssl": "no"}]},
            "saml-idp": {"entry": [{"@name": "off", "validate-idp-certificate": "no",
                                    "want-auth-requests-signed": "no"}]},
        })
        self.assertFalse(rows[("ldap", "off")].ldap_ssl)
        self.assertFalse(rows[("saml-idp", "off")].saml_validate_idp_certificate)
        self.assertFalse(rows[("saml-idp", "off")].saml_want_auth_requests_signed)

    def test_a_pushed_value_is_read_through_its_marker(self):
        """A template-pushed leaf arrives as a dict. Both lab profiles that say `ssl: no` are
        pushed, so a reader comparing to the bare string would call them compliant."""
        rows = self._normalize(shared={"ldap": {"entry": [
            {"@name": "pushed", "ssl": {"@ptpl": "tpl", "#text": "no"}}]}})
        self.assertFalse(rows[("ldap", "pushed")].ldap_ssl)

    def test_one_name_can_exist_in_two_kinds(self):
        """`shared` is a saml-idp on the lab. Keying rows on the name alone would let a radius
        of the same name overwrite it and the count come out short."""
        rows = self._normalize(shared={
            "saml-idp": {"entry": [{"@name": "shared"}]},
            "radius": {"entry": [{"@name": "shared", "protocol": {"CHAP": None}}]},
        })
        self.assertEqual(ServerProfile.objects.filter(name="shared").count(), 2)
        self.assertEqual(rows[("radius", "shared")].protocol, "CHAP")

    def test_an_unrecognised_kind_is_kept_and_reported(self):
        """Hard-coding the container set is what made `sdwan` invisible on the interface side."""
        rows = self._normalize(shared={"quantum-auth": {"entry": [{"@name": "future"}]}})
        row = rows[("unknown", "future")]
        self.assertEqual(row.raw_kind, "quantum-auth")
        self.assertTrue(NormalizationIssue.objects.filter(
            appliance=self.appliance, kind="server profile").exists())

    def test_a_vsys_profile_is_scoped_to_its_vsys(self):
        rows = self._normalize(vsys={"ldap": {"entry": [{"@name": "in-vsys"}]}})
        self.assertEqual(rows[("ldap", "in-vsys")].scope, "vsys")
        self.assertEqual(rows[("ldap", "in-vsys")].vsys_name, "vsys1")

    def test_a_referenced_profile_counts_its_referrers(self):
        """PAN-AAA-013, the same walk PAN-AUTH-025 uses."""
        rows = self._normalize(
            shared={"ldap": {"entry": [{"@name": "used"}, {"@name": "orphan"}]}},
            extra_device={"vsys": {"entry": [{"@name": "vsys1", "authentication-profile": {
                "entry": [{"@name": "ap", "method": {"ldap": {"server-profile": "used"}}}]}}]}})
        self.assertEqual(rows[("ldap", "used")].referrer_count, 1)
        self.assertEqual(rows[("ldap", "orphan")].referrer_count, 0)

    def test_an_mfa_factor_counts_as_a_reference(self):
        """An authentication profile names its MFA server profiles as a member LIST under
        `multi-factor-auth/factors`, not as a `server-profile` leaf. The walk matched the key
        and `scalar_value` returned "" for the dict, so the reference vanished silently and
        PAN-AAA-013 reported the lab's one in-use MFA profile as an orphan to delete."""
        rows = self._normalize(
            shared={"mfa-server-profile": {"entry": [{"@name": "duo"}, {"@name": "unused"}]}},
            extra_device={"vsys": {"entry": [{"@name": "vsys1", "authentication-profile": {
                "entry": [{"@name": "ap", "multi-factor-auth": {
                    "mfa-enable": "yes",
                    "factors": {"member": ["duo"]}}}]}}]}})
        self.assertEqual(rows[("mfa-server-profile", "duo")].referrer_count, 1)
        self.assertTrue(rows[("mfa-server-profile", "duo")].referrer_paths[0].endswith(
            "/multi-factor-auth/factors/member"))
        self.assertEqual(rows[("mfa-server-profile", "unused")].referrer_count, 0)

    def test_every_member_of_a_factor_list_is_a_reference(self):
        """Up to three additional factors, says the guide. Taking only the first would leave the
        second and third profiles reporting unused while the firewall invokes them."""
        rows = self._normalize(
            shared={"mfa-server-profile": {"entry": [{"@name": "one"}, {"@name": "two"}]}},
            extra_device={"vsys": {"entry": [{"@name": "vsys1", "authentication-profile": {
                "entry": [{"@name": "ap", "multi-factor-auth": {
                    "factors": {"member": ["one", "two"]}}}]}}]}})
        self.assertEqual(rows[("mfa-server-profile", "one")].referrer_count, 1)
        self.assertEqual(rows[("mfa-server-profile", "two")].referrer_count, 1)


from optivedge_integrations.integrations.models import (  # noqa: E402
    AdminUser as _AdminUser, AuthenticationProfile as _AuthenticationProfile,
    AuthenticationSequence as _AuthenticationSequence)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication import (  # noqa: E402
    normalize_authentication_profiles as _normalize_profiles)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication_sequences import (  # noqa: E402
    normalize_authentication_sequences as _normalize_sequences)
from optivedge_integrations.integrations.platforms.pan_os.normalization.admin_users import (  # noqa: E402
    normalize_admin_users as _normalize_admins)


class AuthenticationSequenceNormalizationTests(TestCase):
    """PAN-AAA-012's subject, and the two defects sequences exposed in built controls.

    A sequence names its members as `authentication-profiles/member` - a member list under a
    key the profile referrer walk did not visit - and every administrative binding accepts a
    sequence, which the administrator resolution did not know. Measured 2026-09-11 on
    fw-core-tpa-b: an administrator bound to RADIUS-then-TACACS+ read as unresolved and not
    external, so PAN-AUTH-019 fired on it.
    """

    PROFILES = [
        {"@name": "radius-p", "method": {"radius": {"server-profile": "r"}}},
        {"@name": "tacacs-p", "method": {"tacplus": {"server-profile": "t"}}},
        {"@name": "local-p", "method": {"local-database": None}},
    ]

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.seq")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-seq",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-SEQ", hostname="fw-seq")

    def _normalize(self, sequences, users=(), device=None, vsys=None):
        config = {
            "shared": {"authentication-profile": {"entry": list(self.PROFILES)},
                       "authentication-sequence": {"entry": list(sequences)}},
            "devices": {"entry": [{"@name": "localhost.localdomain", **(device or {})}]},
        }
        if vsys:
            config["devices"]["entry"][0]["vsys"] = {"entry": [vsys]}
        if users:
            config["mgt-config"] = {"users": {"entry": list(users)}}
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": config})
        _normalize_profiles(self.appliance)
        _normalize_sequences(self.appliance)
        _normalize_admins(self.appliance)

    def test_an_admin_account_records_where_it_is_defined(self):
        """Validated against the lab 2026-10-05, 26 accounts across three devices: an entry is
        marked exactly when a template or STACK supplies it and has not been overridden, and
        unmarked otherwise. Jason expected admin users to behave like any other named object,
        and they do - the earlier doubt came from the CONTAINER marker, which says a template
        contributes to `mgt-config/users` and nothing about which entries came from it.

        So an unmarked entry means local, and now says so. Before this, 25 of the lab's 26
        accounts recorded nothing at all.

        `@ptpl` names a template OR a stack - `template_admin_user` on pan-fw-111 carries
        `temp-stck-jb-rg`, defined in the stack's own config layer. Stored as given and not
        disambiguated; Jason, 2026-10-05: "Treat stacks like templates... The engineer already
        understands stacks and templates."
        """
        self._normalize([], users=[
            {"@name": "local-admin",
             "permissions": {"role-based": {"superuser": "yes"}}},
            {"@name": "pushed-admin", "@ptpl": "temp-stck-jb-rg",
             "permissions": {"role-based": {"superuser": "yes"}}},
        ])

        ct = ContentType.objects.get_for_model(_AdminUser)
        by_name = {u.name: u for u in _AdminUser.objects.all()}
        rows = {r.object_id: r for r in FieldProvenance.objects.filter(
            content_type=ct, field_name="__entry__")}

        self.assertEqual(len(rows), 2, "every account is defined somewhere and must say where")
        self.assertEqual(rows[by_name["local-admin"].pk].provenance_type, "local")
        pushed = rows[by_name["pushed-admin"].pk]
        self.assertEqual(pushed.provenance_type, "template")
        self.assertEqual(pushed.raw_value, "temp-stck-jb-rg")

    def test_the_container_marker_is_not_read_as_the_entries_provenance(self):
        """Measured on three devices: `shared-multi-vsys` pushes an EMPTY users node, which is
        enough to mark the merged container over entries it contributed nothing to. Reading the
        container would report every local account as template-pushed - and on the PA-5220 pair
        that is all seventeen of them."""
        self._normalize([], users=[
            {"@name": "local-admin", "permissions": {"role-based": {"superuser": "yes"}}},
        ])
        # The container marker lives beside the entries, not on them.
        snapshot = Snapshot.objects.filter(appliance=self.appliance).latest("collected_at")
        self.assertNotIn("@ptpl", snapshot.payload["config"]["mgt-config"]["users"])

        row = FieldProvenance.objects.get(
            content_type=ContentType.objects.get_for_model(_AdminUser),
            object_id=_AdminUser.objects.get().pk, field_name="__entry__")
        self.assertEqual(row.provenance_type, "local")

    def _seq(self, name, *members, **flags):
        entry = {"@name": name, "authentication-profiles": {"member": list(members)}}
        entry.update(flags)
        return entry

    def _sequence(self, name):
        return _AuthenticationSequence.objects.get(appliance=self.appliance, name=name)

    def test_members_keep_their_order_and_resolve_their_methods(self):
        self._normalize([self._seq("s", "radius-p", "local-p")])
        s = self._sequence("s")
        self.assertEqual(s.member_names, ["radius-p", "local-p"])
        self.assertEqual(s.member_methods, ["radius", "local-database"])
        self.assertTrue(s.has_local_member)
        self.assertEqual(s.local_member_names, ["local-p"])
        self.assertFalse(s.all_members_external)

    def test_the_three_flags_take_their_measured_implicit_values(self):
        """None of the three is stored unless the form sets it; the form renders exit NO,
        domain YES, User-ID domain NO."""
        self._normalize([self._seq("s", "radius-p")])
        s = self._sequence("s")
        self.assertFalse(s.exit_sequence_on_failure)
        self.assertTrue(s.use_domain_find_profile)
        self.assertFalse(s.use_userid_domain)

    def test_explicit_flags_override_the_implicit_ones(self):
        self._normalize([self._seq("s", "radius-p", **{
            "exit-sequence-on-failure": "yes", "use-domain-find-profile": "no"})])
        s = self._sequence("s")
        self.assertTrue(s.exit_sequence_on_failure)
        self.assertFalse(s.use_domain_find_profile)

    def test_an_unresolvable_member_is_not_assumed_external(self):
        self._normalize([self._seq("s", "radius-p", "ghost")])
        s = self._sequence("s")
        self.assertEqual(s.unresolved_member_count, 1)
        self.assertEqual(s.member_methods, ["radius", ""])
        self.assertFalse(s.all_members_external)

    def test_a_sequence_an_administrator_names_is_administrative(self):
        self._normalize([self._seq("s", "radius-p", "local-p")],
                        users=[{"@name": "a", "authentication-profile": "s"}])
        self.assertTrue(self._sequence("s").is_administrative)
        self.assertEqual(self._sequence("s").referrer_count, 1)

    def test_the_device_wide_binding_also_makes_it_administrative(self):
        self._normalize([self._seq("s", "radius-p")], device={"deviceconfig": {"system": {
            "authentication-profile": "s"}}})
        self.assertTrue(self._sequence("s").is_administrative)

    def test_a_captive_portal_sequence_is_referenced_and_not_administrative(self):
        self._normalize([self._seq("s", "radius-p", "local-p")], vsys={
            "@name": "vsys1", "captive-portal": {"authentication-profile": "s"}})
        s = self._sequence("s")
        self.assertEqual(s.referrer_count, 1)
        self.assertFalse(s.is_administrative)

    def test_sequence_membership_counts_as_a_reference_to_the_profile(self):
        """PAN-AUTH-025's defect: `authentication-profiles/member` was not visited, so a
        profile used only through a sequence reported unused."""
        self._normalize([self._seq("s", "tacacs-p")])
        p = _AuthenticationProfile.objects.get(appliance=self.appliance, name="tacacs-p")
        self.assertEqual(p.referrer_count, 1)
        self.assertTrue(p.referrer_paths[0].endswith(
            "/authentication-sequence/entry[s]/authentication-profiles/member"))

    def test_a_profile_reached_through_an_administrative_sequence_is_administrative(self):
        self._normalize([self._seq("s", "tacacs-p")],
                        users=[{"@name": "a", "authentication-profile": "s"}])
        self.assertTrue(_AuthenticationProfile.objects.get(
            appliance=self.appliance, name="tacacs-p").is_administrative)

    def test_a_profile_in_a_non_administrative_sequence_is_not(self):
        self._normalize([self._seq("s", "tacacs-p")], vsys={
            "@name": "vsys1", "captive-portal": {"authentication-profile": "s"}})
        self.assertFalse(_AuthenticationProfile.objects.get(
            appliance=self.appliance, name="tacacs-p").is_administrative)

    def test_an_administrator_bound_to_an_all_external_sequence_is_external(self):
        """The PAN-AUTH-019 false positive: oep-seq-admin2, RADIUS then TACACS+."""
        self._normalize([self._seq("s", "radius-p", "tacacs-p")],
                        users=[{"@name": "a", "authentication-profile": "s"}])
        a = _AdminUser.objects.get(appliance=self.appliance, name="a")
        self.assertTrue(a.authentication_sequence)
        self.assertFalse(a.authentication_profile_unresolved)
        self.assertTrue(a.authentication_is_external)
        self.assertTrue(a.centrally_authenticated)

    def test_an_administrator_bound_to_a_sequence_with_a_local_member_is_not(self):
        self._normalize([self._seq("s", "radius-p", "local-p")],
                        users=[{"@name": "a", "authentication-profile": "s"}])
        a = _AdminUser.objects.get(appliance=self.appliance, name="a")
        self.assertTrue(a.authentication_sequence)
        self.assertFalse(a.authentication_is_external)
        self.assertFalse(a.centrally_authenticated)


from optivedge_integrations.integrations.models import ManagementSshSettings as _ManagementSshSettings  # noqa: E402
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_ssh import (  # noqa: E402
    DEFAULT_OFFER as _SSH_DEFAULT, normalize_management_ssh as _normalize_ssh)


class ManagementSshNormalizationTests(TestCase):
    """PAN-MCR-001 and 003's subject: the management SSH server's EFFECTIVE offer.

    Three measured rules (2026-09-11, 11.1 PA-5220 and 11.2 PA-VM): with nothing bound the device
    offers a built-in default that includes hmac-sha1 and group14-sha1; a profile that sets only
    some lists leaves the others at that default; a dangling binding is the default too.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.ssh")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-ssh", group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-SSH", hostname="fw-ssh", software_version="11.1.13-h3")

    def _normalize(self, ssh=None):
        system = {"ssh": ssh} if ssh is not None else {}
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": [{"@name": "localhost.localdomain",
                                                         "deviceconfig": {"system": system}}]}}})
        _normalize_ssh(self.appliance)
        return _ManagementSshSettings.objects.get(appliance=self.appliance)

    @staticmethod
    def _bound(name, **profile):
        return {"mgmt": {"server-profile": name},
                "profiles": {"mgmt-profiles": {"server-profiles": {"entry": [
                    {"@name": name, **profile}]}}}}

    def test_a_configured_host_key_and_rekey_carry_their_marker(self):
        """These three fields were stored with no provenance at all - read by raw dict access
        rather than through `scalar_value`, so the marker was discarded. A control firing on
        them could not say where to go and change them."""
        self._normalize(self._bound(
            "p",
            **{"default-hostkey": {"key-type": {"RSA": {"@ptpl": "stack_x", "#text": "4096"}}},
               "session-rekey": {"interval": {"@ptpl": "stack_x", "#text": "1800"}}}))
        row = _ManagementSshSettings.objects.get(appliance=self.appliance)
        rows = {r.field_name: r for r in FieldProvenance.objects.filter(
            content_type=ContentType.objects.get_for_model(_ManagementSshSettings),
            object_id=row.pk)}

        self.assertEqual(row.host_key_bits, 4096)
        self.assertEqual(row.rekey_interval_seconds, 1800)
        for field in ("host_key_type", "host_key_bits", "rekey_interval_seconds"):
            with self.subTest(field):
                self.assertEqual(rows[field].provenance_type, "template")
                self.assertEqual(rows[field].raw_value, "stack_x")

    def test_an_absent_host_key_stores_nothing_and_says_why(self):
        """`_host_key` used to fall back to RSA 2048, and discovery-log 2026-09-14 measured that
        false on a device ever set to `all`: the ECDSA keys it generated are still served after
        the setting is deleted. So absence means RSA 2048 on most devices and something else on
        an unknown subset, and only the live SSH offer can say which.

        Resolved 2026-10-06 the way Jason framed it - the lack of an explicit value is itself the
        finding, "an unknown risk, and likely weak" - so the field is null and the row says
        `not_configured`. `pan_os_default` would be the false vendor fact; `assumed_default`
        would still carry a value the device may not be serving."""
        self._normalize(self._bound("p", ciphers={"member": ["aes256-gcm"]}))
        row = _ManagementSshSettings.objects.get(appliance=self.appliance)
        rows = {r.field_name: r for r in FieldProvenance.objects.filter(
            content_type=ContentType.objects.get_for_model(_ManagementSshSettings),
            object_id=row.pk)}

        self.assertEqual(row.host_key_type, "")
        self.assertIsNone(row.host_key_bits)
        self.assertEqual(rows["host_key_type"].provenance_type, "not_configured")
        self.assertEqual(rows["host_key_bits"].provenance_type, "not_configured")
        # Still fires: PAN-MCR-004's baseline is "not ECDSA", and blank is not ECDSA.
        self.assertNotEqual(row.host_key_type.upper(), "ECDSA")

    def test_nothing_bound_offers_the_measured_default(self):
        row = self._normalize()
        self.assertEqual(row.profile_name, "")
        self.assertEqual(row.macs, _SSH_DEFAULT["11.1"]["macs"])
        self.assertTrue(row.ciphers_default and row.kex_default and row.macs_default)
        self.assertTrue(row.defaults_measured)
        self.assertTrue(row.offers_weak_mac)
        self.assertIn("hmac-sha1", row.weak_macs)
        self.assertTrue(row.offers_sha1_kex)
        self.assertFalse(row.offers_cbc_cipher)
        self.assertFalse(row.offers_weak_kex)
        # No profile bound, so no key type is configured - stored as absent rather than as the
        # RSA 2048 the vendor guide gives, which 2026-09-14 measured unreliable.
        self.assertEqual((row.host_key_type, row.host_key_bits), ("", None))

    def test_an_unset_list_in_a_bound_profile_is_the_default_not_empty(self):
        """tpa-a's ciphers-only profile narrowed the ciphers and left MACs at the default."""
        row = self._normalize(self._bound("p", ciphers={"member": ["aes256-gcm"]}))
        self.assertTrue(row.profile_found)
        self.assertEqual(row.ciphers, ["aes256-gcm"])
        self.assertFalse(row.ciphers_default)
        self.assertTrue(row.macs_default)
        self.assertTrue(row.offers_weak_mac)

    def test_a_strict_profile_clears_both_flags(self):
        row = self._normalize(self._bound(
            "strict", ciphers={"member": ["aes256-ctr", "aes256-gcm"]},
            kex={"member": ["ecdh-sha2-nistp256"]},
            mac={"member": ["hmac-sha2-256", "hmac-sha2-512"]},
            **{"default-hostkey": {"key-type": {"ECDSA": "256"}},
               "session-rekey": {"interval": "3600"}}))
        self.assertFalse(row.offers_weak_mac)
        self.assertFalse(row.offers_cbc_cipher)
        self.assertFalse(row.offers_sha1_kex)
        self.assertTrue(row.offers_sha2_256_mac)
        self.assertEqual((row.host_key_type, row.host_key_bits), ("ECDSA", 256))
        self.assertEqual(row.rekey_interval_seconds, 3600)

    def test_a_cbc_cipher_in_the_profile_is_flagged(self):
        row = self._normalize(self._bound("cbc", ciphers={"member": ["aes128-cbc", "aes256-gcm"]}))
        self.assertTrue(row.offers_cbc_cipher)

    def test_a_dangling_binding_offers_the_default(self):
        row = self._normalize({"mgmt": {"server-profile": "ghost"}})
        self.assertEqual(row.profile_name, "ghost")
        self.assertFalse(row.profile_found)
        self.assertTrue(row.macs_default)
        self.assertTrue(row.offers_weak_mac)

    def test_an_unmeasured_release_says_so(self):
        self.appliance.software_version = "12.1.0"
        self.appliance.save()
        row = self._normalize()
        self.assertFalse(row.defaults_measured)
        self.assertEqual(row.macs, _SSH_DEFAULT["11.1"]["macs"])

    def test_11_2_uses_its_own_measured_default(self):
        self.appliance.software_version = "11.2.3"
        self.appliance.save()
        self.assertTrue(self._normalize().defaults_measured)



class ImplicitDeclarationTests(TestCase):
    """Storing a value for an absent key is a claim about PAN-OS. This is what makes a site
    state whether it can back that claim, and what stops the three kinds being mixed again."""

    def test_a_measured_default_needs_a_citation_a_reader_can_check(self):
        from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
            Implicit)
        self.assertEqual(
            Implicit.measured(True, "payload contract, mgt-services.disable-ssh").provenance_type,
            "pan_os_default")
        with self.assertRaises(ValueError):
            Implicit.measured(True, "PAN-OS docs")

    def test_an_assumed_default_must_say_what_the_inference_rests_on(self):
        from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
            Implicit)
        self.assertEqual(
            Implicit.assumed(False, "neighbouring keys in this node default off").provenance_type,
            "assumed_default")
        with self.assertRaises(ValueError):
            Implicit.assumed(False, "")

    def test_the_bare_constructor_cannot_slip_past_either_guard(self):
        """`Implicit(x, "")` would otherwise reach a row as a measured default with no
        measurement behind it."""
        from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
            Implicit)
        with self.assertRaises(ValueError):
            Implicit(value=True, citation=None, reasoning="")
        with self.assertRaises(ValueError):
            Implicit(value=True, citation="short")

    def test_declining_to_guess_is_its_own_state(self):
        from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
            Implicit)
        declined = Implicit.not_assumed("the corpus records this default as unmeasured")
        self.assertEqual(declined.provenance_type, "not_configured")
        self.assertIsNone(declined.value)

    def test_was_absent_covers_both_ways_an_absent_key_arrives(self):
        """It used to be `raw_key is ABSENT` everywhere. An absent key now arrives as the
        declaration instead, and two lines asking the old question would have turned the
        security rule log flags from null into False."""
        from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
            ABSENT, Implicit, was_absent)
        self.assertTrue(was_absent(ABSENT))
        self.assertTrue(was_absent(Implicit.measured(True, "payload contract, some.node")))
        self.assertFalse(was_absent(None))
        self.assertFalse(was_absent("@ptpl"))

    #: Every default this pipeline INFERS rather than knows, by module. Adding one is meant to
    #: be a deliberate act with a reviewer, and this list is also the queue of what to measure
    #: next - each entry is a claim about a customer's firewall that nobody has checked.
    ASSUMED_DEFAULTS = {
        "authentication.py": 3,       # profile lockout pair, mfa-enable
        "certificates.py": 2,         # certificate-profile timeouts, certificate `ca`
        "device_configuration.py": 2, # master key auto-renew, on-hsm
        "device_services.py": 2,      # accept-dhcp-hostname, accept-dhcp-domain
        "management_ssh.py": 1,       # the built-in SSH offer of an UNMEASURED release
        "password_profiles.py": 1,    # password-change periods
        "server_profiles.py": 1,      # admin-use-only
        "zones.py": 1,                # user-identification and prenat flags
    }

    def test_every_assumed_default_is_accounted_for(self):
        """The inventory, enforced. A new assumption that nobody listed fails here rather than
        reaching an artifact as a vendor fact."""
        import re
        from pathlib import Path
        from optivedge_integrations.integrations.platforms.pan_os import normalization
        root = Path(normalization.__file__).parent
        found = {}
        for path in sorted(root.glob("*.py")):
            if path.name == "common.py":      # where the constructor itself is defined
                continue
            count = len(re.findall(r"Implicit\.assumed\(", path.read_text()))
            if count:
                found[path.name] = count
        self.assertEqual(found, self.ASSUMED_DEFAULTS)


class SecurityRuleLogFlagProvenanceTests(TestCase):
    """What PAN-OS does with an absent log flag - measured 2026-09-22, after a year of not being.

    The corpus recorded both defaults as unmeasured, so the normalizer stored NULL for an absent
    flag rather than guess, and PAN-POL-009 asserts log-end. Jason then said he believed the
    default was yes, and the Help turned out to say both things - p.134 "enabled by default" on
    the security rule screen, p.142 "cleared by default" on another.

    So it was measured the way the checklist's oracle table says to: a rule pushed with NEITHER
    key, absent in every config source including effective-running, opened in the device's own
    UI. `log-end` renders TICKED and `log-start` unticked. Both are `pan_os_default` now, and
    neither is null.

    These tests were the opposite assertion until that measurement, which is the point: they
    were right to hold the null while nobody knew, and the measurement is what changed it.
    """

    def _rules(self, *entries):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-LOGFLAGS", appliance_hostname="fw-logflags")
        Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": {"vsys": {"entry": {
                "@name": "vsys1",
                "rulebase": {"security": {"rules": {"entry": list(entries)}}},
            }}}}}})
        _create_empty_pushed_policy_snapshot(station=station,
                                             enforcement_point=enforcement_point)
        normalize_enforcement_point_addresses(enforcement_point)
        normalize_enforcement_point_security_rules(enforcement_point)
        return {rule.name: rule for rule in SecurityRule.objects.all()}

    @staticmethod
    def _entry(name, **extra):
        return {"@name": name, "from": {"member": "any"}, "to": {"member": "any"},
                "source": {"member": "any"}, "destination": {"member": "any"},
                "application": {"member": "any"}, "service": {"member": "application-default"},
                "action": "allow", **extra}

    def _provenance(self, rule, field):
        return rule.field_provenance.filter(field_name=field).first()

    def test_an_absent_log_flag_takes_its_measured_default(self):
        """log-end absent means the session IS logged at end; log-start absent means it is not.
        Stored, rather than left null, because the device was asked."""
        rules = self._rules(self._entry("quiet"))
        self.assertTrue(rules["quiet"].log_end)
        self.assertFalse(rules["quiet"].log_start)

    def test_and_the_row_says_pan_os_default_carrying_that_value(self):
        rules = self._rules(self._entry("quiet"))
        row = self._provenance(rules["quiet"], "log_end")
        self.assertIsNotNone(row, "an absent key is recorded; a missing row means untracked")
        self.assertEqual(row.provenance_type, "pan_os_default")
        self.assertEqual(row.raw_value, "yes",
                         "the row carries what the vendor supplies, so a reader need not "
                         "resolve the field to see it")
        start = self._provenance(rules["quiet"], "log_start")
        self.assertEqual((start.provenance_type, start.raw_value), ("pan_os_default", "no"))

    def test_a_written_flag_is_local_and_keeps_its_value(self):
        rules = self._rules(self._entry("logged", **{"log-end": "yes"}))
        self.assertTrue(rules["logged"].log_end)
        row = self._provenance(rules["logged"], "log_end")
        self.assertEqual((row.provenance_type, row.raw_value), ("local", ""))

    def test_a_measured_default_on_the_same_rule_does_claim_its_value(self):
        """`disabled` sits beside the log flags and IS documented - absent means no - so the
        two are told apart on one object rather than by which model they belong to."""
        rules = self._rules(self._entry("quiet"))
        row = self._provenance(rules["quiet"], "disabled")
        self.assertEqual((row.provenance_type, row.raw_value), ("pan_os_default", "no"))


class DerivedFieldDeclarationTests(TestCase):
    """`DERIVED_FIELDS` says which columns normalization WORKED OUT rather than read.

    It replaces a list the xlsx prototype kept per SHEET, a repository away from the fields it
    described. Declared on the model rather than written as rows because derived-ness belongs to
    the field and never varies by object - 885 security rules would otherwise carry 885 identical
    copies of a static fact.

    The danger is a wrong declaration: marking a field the device actually wrote would tell a
    reader "we computed this" about a value the firewall holds. `ca` on a certificate is the
    near-miss - it looks like a verdict, reads a real key, and has a provenance row.
    """

    def _models(self):
        from django.apps import apps
        from optivedge_integrations.integrations.models.provenance import ProvenancedMixin
        return [m for m in apps.get_models()
                if issubclass(m, ProvenancedMixin) and not m._meta.abstract]

    def test_every_declared_field_exists_on_its_model(self):
        """A typo would silently declare nothing, and the field would read as untracked."""
        for model in self._models():
            names = {f.name for f in model._meta.get_fields()}
            for field in model.DERIVED_FIELDS:
                with self.subTest(f"{model.__name__}.{field}"):
                    self.assertIn(field, names)

    def test_no_declared_field_is_one_normalization_records_provenance_for(self):
        """The contradiction that matters. If a normalizer writes a row for a field, that field
        came from the payload and is not derived - whichever way round the mistake was made.

        It can only catch what the database in front of it holds, so the authoritative run is
        against a normalized lab. That run found the one real clash:
        `SnmpSettings.community_is_default`, a verdict whose row is written deliberately because
        the community string's value is never stored and the row is the only record of who set
        it. The model says so where the declaration would have been.
        """
        from optivedge_integrations.integrations.models import FieldProvenance
        from django.contrib.contenttypes.models import ContentType
        clashes = []
        for model in self._models():
            if not model.DERIVED_FIELDS:
                continue
            recorded = set(FieldProvenance.objects.filter(
                content_type=ContentType.objects.get_for_model(model),
                field_name__in=model.DERIVED_FIELDS).values_list("field_name", flat=True))
            clashes += [f"{model.__name__}.{name}" for name in sorted(recorded)]
        self.assertEqual(clashes, [], "declared derived, but a row exists for it")

    def test_provenance_for_answers_all_three_ways(self):
        from optivedge_integrations.integrations.models import SystemIdentity
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.derived")
        appliance = Appliance.objects.create(
            management_station=station, serial_number="S-DERIVED", hostname="fw-derived")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(), payload={})
        identity = SystemIdentity.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            hostname="fw-derived", timezone="UTC")
        FieldProvenance.objects.create(
            content_type=ContentType.objects.get_for_model(SystemIdentity),
            object_id=identity.pk, field_name="timezone", provenance_type="local")

        self.assertEqual(identity.provenance_for("timezone").provenance_type, "local")
        self.assertEqual(identity.provenance_for("timezone_is_utc").provenance_type, "derived",
                         "a computed column answers, rather than reading as untracked")
        self.assertIsNone(identity.provenance_for("no_such_field"),
                          "and None now means only that nothing tracks it")

    def test_a_derived_answer_is_not_saved(self):
        """It is a description of the field, not a fact about this row - persisting one would put
        a static claim in as many copies as there are objects."""
        from optivedge_integrations.integrations.models import SystemIdentity
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.derived2")
        appliance = Appliance.objects.create(
            management_station=station, serial_number="S-DERIVED2", hostname="fw-derived2")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(), payload={})
        identity = SystemIdentity.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot)
        identity.provenance_for("timezone_is_utc")
        self.assertFalse(FieldProvenance.objects.filter(provenance_type="derived").exists())


# ---------------------------------------------------------------------------------------
# Device groups
# ---------------------------------------------------------------------------------------

#: The lab Panorama's own answer, measured 2026-09-22. Two top-level groups with no children,
#: one with five - which is the shape that matters, because `dg_fw-core-tpa-base-01` exists,
#: is parent to nothing, has no devices assigned, and therefore appears in no provenance row.
#: Derivation from provenance cannot see it; this is why the hierarchy is collected.
_DG_HIERARCHY_PAYLOAD = {
    "dg-hierarchy": {
        "dg": [
            {"@name": "prod-west-2", "@dg_id": "16"},
            {
                "@name": "dg_fw-core-tpa_base",
                "@dg_id": "137",
                "dg": [
                    {"@name": "dg_fw-core-tpa_edge", "@dg_id": "140"},
                    {"@name": "dg_fw-core-tpa_access", "@dg_id": "138"},
                ],
            },
            {"@name": "dg_fw-core-tpa-base-01", "@dg_id": "630"},
        ]
    }
}


def _collected_dg_hierarchy(payload):
    from optivedge_integrations.integrations.platforms.pan_os.collectors.device_groups import (
        DG_HIERARCHY_SOURCE_TYPE,
        SHOW_DG_HIERARCHY_COMMAND,
    )
    from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
        PANOSCollectedResponse,
        PANOSOperationRequest,
    )

    return PANOSCollectedResponse(
        source_type=DG_HIERARCHY_SOURCE_TYPE,
        request=PANOSOperationRequest(command_xml=SHOW_DG_HIERARCHY_COMMAND),
        response={"response": {"@status": "success", "result": payload}},
    )


class DeviceGroupHierarchyNormalizationTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )

    def _normalize(self, payload):
        from optivedge_integrations.integrations.platforms.pan_os.normalization.device_groups import (
            normalize_show_dg_hierarchy,
        )

        return normalize_show_dg_hierarchy(self.station, _collected_dg_hierarchy(payload))

    def test_shared_is_synthesized_as_the_root(self):
        """`show dg-hierarchy` does not emit Shared; Panorama shows it, so we create it."""
        result = self._normalize(_DG_HIERARCHY_PAYLOAD)

        shared = result.shared
        self.assertEqual(shared.name, "Shared")
        self.assertTrue(shared.is_shared)
        self.assertEqual(shared.discovered_from, DeviceGroup.DISCOVERED_SYNTHESIZED)
        self.assertIsNone(shared.parent)

        top_level = DeviceGroup.objects.get(management_station=self.station, name="prod-west-2")
        self.assertEqual(top_level.parent, shared)
        self.assertEqual(top_level.discovered_from, DeviceGroup.DISCOVERED_COLLECTED)

    def test_nesting_and_dg_id_come_from_the_payload(self):
        self._normalize(_DG_HIERARCHY_PAYLOAD)

        base = DeviceGroup.objects.get(management_station=self.station, name="dg_fw-core-tpa_base")
        edge = DeviceGroup.objects.get(management_station=self.station, name="dg_fw-core-tpa_edge")
        self.assertEqual(edge.parent, base)
        self.assertEqual(edge.dg_id, "140")
        self.assertEqual([group.name for group in edge.ancestors()],
                         ["dg_fw-core-tpa_base", "Shared"])

    def test_a_group_with_no_bindings_is_still_collected(self):
        """The case derivation from provenance cannot see."""
        self._normalize(_DG_HIERARCHY_PAYLOAD)

        empty = DeviceGroup.objects.get(
            management_station=self.station, name="dg_fw-core-tpa-base-01")
        self.assertEqual(empty.bindings.count(), 0)
        self.assertFalse(empty.is_missing)

    def test_a_single_child_arrives_as_a_dict_and_is_not_dropped(self):
        """xmltodict gives a lone child as a dict; reading it as a list loses the subtree."""
        payload = {"dg-hierarchy": {"dg": {"@name": "solo-parent", "@dg_id": "1",
                                           "dg": {"@name": "solo-child", "@dg_id": "2"}}}}
        self._normalize(payload)

        child = DeviceGroup.objects.get(management_station=self.station, name="solo-child")
        self.assertEqual(child.parent.name, "solo-parent")

    def test_a_group_that_stops_appearing_is_marked_missing(self):
        self._normalize(_DG_HIERARCHY_PAYLOAD)
        result = self._normalize({"dg-hierarchy": {"dg": [{"@name": "prod-west-2", "@dg_id": "16"}]}})

        self.assertIn("dg_fw-core-tpa_base", result.missing_names)
        gone = DeviceGroup.objects.get(
            management_station=self.station, name="dg_fw-core-tpa_base")
        self.assertTrue(gone.is_missing)
        self.assertIsNotNone(gone.missing_since)
        self.assertFalse(
            DeviceGroup.objects.get(management_station=self.station,
                                    name="prod-west-2").is_missing)

    def test_a_provenance_only_group_is_not_swept(self):
        """It was never in the hierarchy, so its absence from one says nothing."""
        seen_only_in_provenance = DeviceGroup.objects.create(
            management_station=self.station,
            name="dg-from-provenance",
            discovered_from=DeviceGroup.DISCOVERED_PROVENANCE,
        )
        self._normalize(_DG_HIERARCHY_PAYLOAD)

        seen_only_in_provenance.refresh_from_db()
        self.assertFalse(seen_only_in_provenance.is_missing)

    def test_an_empty_hierarchy_is_an_answer_not_an_error(self):
        result = self._normalize({})

        self.assertEqual(result.device_groups, [])
        self.assertEqual(
            list(DeviceGroup.objects.filter(management_station=self.station)
                 .values_list("name", flat=True)),
            ["Shared"],
        )

    def test_names_are_unique_per_station_not_globally(self):
        other = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-two.local",
        )
        self._normalize({"dg-hierarchy": {"dg": {"@name": "prod-west-2", "@dg_id": "16"}}})
        DeviceGroup.objects.create(management_station=other, name="prod-west-2")

        self.assertEqual(DeviceGroup.objects.filter(name="prod-west-2").count(), 2)

    def test_the_hierarchy_can_be_rebuilt_from_the_stored_snapshot(self):
        from optivedge_integrations.integrations.platforms.pan_os.collectors.device_groups import (
            DG_HIERARCHY_SOURCE_TYPE,
        )
        from optivedge_integrations.integrations.platforms.pan_os.normalization.device_groups import (
            renormalize_device_groups,
        )

        self.assertIsNone(renormalize_device_groups(self.station))
        Snapshot.objects.create(
            management_station=self.station,
            source_type=DG_HIERARCHY_SOURCE_TYPE,
            collected_at=timezone.now(),
            payload=_DG_HIERARCHY_PAYLOAD,
        )
        result = renormalize_device_groups(self.station)

        self.assertIsNotNone(result)
        self.assertEqual(
            DeviceGroup.objects.filter(management_station=self.station).count(), 6)


class DeviceGroupBindingTests(TestCase):
    """Bindings say which vsys a group HAS PUSHED TO, read from provenance."""

    def setUp(self):
        self.station, self.appliance, self.enforcement_point = (
            _create_panorama_enforcement_point(
                serial_number="0000000000001",
                appliance_hostname="fw-a",
            )
        )
        self.snapshot = Snapshot.objects.create(
            management_station=self.station,
            appliance=self.appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={},
        )

    def _address_object(self, name):
        return AddressObject.objects.create(
            management_station=self.station,
            enforcement_point=self.enforcement_point,
            source_snapshot=self.snapshot,
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name=name,
            namespace_type="pushed_vsys_effective",
            namespace_value="vsys1",
            precedence_rank=10,
            address_type=AddressObject.TYPE_IP_NETMASK,
            value="10.0.0.1/32",
            normalized_value="10.0.0.1/32",
        )

    def _provenance(self, obj, raw_value, field_name="__entry__"):
        return FieldProvenance.objects.create(
            content_type=ContentType.objects.get_for_model(type(obj)),
            object_id=obj.pk,
            field_name=field_name,
            provenance_type=FieldProvenance.ProvenanceType.DEVICE_GROUP,
            raw_value=raw_value,
        )

    def _rebuild(self):
        from optivedge_integrations.integrations.device_group_bindings import (
            rebuild_device_group_bindings,
        )

        return rebuild_device_group_bindings(self.station)

    def test_a_device_group_binds_to_the_vsys_it_pushed_to(self):
        self._provenance(self._address_object("addr-1"), "dg_fw-core-tpa_edge")
        result = self._rebuild()

        self.assertEqual(result.binding_count, 1)
        binding = DeviceGroupBinding.objects.get()
        self.assertEqual(binding.device_group.name, "dg_fw-core-tpa_edge")
        self.assertEqual(binding.enforcement_point, self.enforcement_point)

    def test_shared_binds_to_the_shared_container_rather_than_a_device_group(self):
        """1,140 of the lab's device-group rows say `shared`. It is a scope, and an operator
        still looks for it in the tree as a container."""
        self._provenance(self._address_object("addr-1"), "shared")
        self._rebuild()

        shared = DeviceGroup.objects.get(management_station=self.station, name="Shared")
        self.assertTrue(shared.is_shared)
        self.assertEqual(shared.discovered_from, DeviceGroup.DISCOVERED_SYNTHESIZED)
        self.assertEqual([b.enforcement_point for b in shared.bindings.all()],
                         [self.enforcement_point])
        self.assertFalse(
            DeviceGroup.objects.filter(management_station=self.station, name="shared").exists())

    def test_a_name_the_hierarchy_never_carried_is_flagged(self):
        self._provenance(self._address_object("addr-1"), "dg-never-collected")
        result = self._rebuild()

        self.assertEqual(result.provenance_only_names, ["dg-never-collected"])
        group = DeviceGroup.objects.get(
            management_station=self.station, name="dg-never-collected")
        self.assertEqual(group.discovered_from, DeviceGroup.DISCOVERED_PROVENANCE)

    def test_a_binding_that_no_longer_has_provenance_is_deleted(self):
        address_object = self._address_object("addr-1")
        row = self._provenance(address_object, "dg_fw-core-tpa_edge")
        self._rebuild()
        self.assertEqual(DeviceGroupBinding.objects.count(), 1)

        row.delete()
        result = self._rebuild()

        self.assertEqual(result.deleted_binding_count, 1)
        self.assertEqual(DeviceGroupBinding.objects.count(), 0)

    def test_a_content_type_whose_model_is_gone_is_skipped(self):
        """Generic relations do not cascade when a MODEL is dropped - DeviceConfigurationProfile
        left 28 such rows. Migration 0065 removes them; this must not raise on a later one."""
        FieldProvenance.objects.create(
            content_type=ContentType.objects.create(app_label="integrations", model="goneaway"),
            object_id=1,
            field_name="__entry__",
            provenance_type=FieldProvenance.ProvenanceType.DEVICE_GROUP,
            raw_value="dg_fw-core-tpa_edge",
        )
        self._provenance(self._address_object("addr-1"), "dg_fw-core-tpa_edge")
        result = self._rebuild()

        self.assertEqual(result.skipped_content_type_count, 1)
        self.assertEqual(result.binding_count, 1)

    def test_one_group_pushing_to_several_vsys_binds_to_each(self):
        second_point = EnforcementPoint.objects.create(
            management_station=self.station,
            appliance_group=self.appliance.appliance_group,
            vsys_name="vsys2",
        )
        first = self._address_object("addr-1")
        second = AddressObject.objects.create(
            management_station=self.station,
            enforcement_point=second_point,
            source_snapshot=self.snapshot,
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name="addr-2",
            namespace_type="pushed_vsys_effective",
            namespace_value="vsys2",
            precedence_rank=10,
            address_type=AddressObject.TYPE_IP_NETMASK,
            value="10.0.0.2/32",
            normalized_value="10.0.0.2/32",
        )
        self._provenance(first, "dg_fw-core-tpa_edge")
        self._provenance(second, "dg_fw-core-tpa_edge")
        self._rebuild()

        group = DeviceGroup.objects.get(
            management_station=self.station, name="dg_fw-core-tpa_edge")
        self.assertEqual(
            sorted(b.enforcement_point.vsys_name for b in group.bindings.all()),
            ["vsys1", "vsys2"],
        )

    def test_bindings_are_rebuilt_correctly_when_the_in_clause_has_to_be_chunked(self):
        """The crash that stopped a real refresh: `OperationalError: too many SQL variables`.

        `pk__in` carried every object of one type holding device-group provenance - tens of
        thousands on a real estate - and SQLite caps host parameters per statement at a limit
        set when SQLite was BUILT. The development build allows 250,000 and a Windows Python
        3.12 allows far fewer, so the query that worked everywhere it was written failed where
        it ran. Chunk size is forced to 1 here rather than creating 900 objects, because what
        needs proving is that chunking returns the same answer, not that a big list is big.
        """
        for index in range(5):
            self._provenance(self._address_object(f"addr-{index}"), "dg_edge")
        self._provenance(self._address_object("addr-other"), "dg_core")

        with patch.object(query_chunking, "CHUNK_SIZE", 1):
            result = self._rebuild()

        self.assertEqual(result.device_group_count, 2)
        self.assertEqual(
            set(DeviceGroupBinding.objects.values_list("device_group__name", flat=True)),
            {"dg_edge", "dg_core"},
        )
        self.assertEqual(result.unresolved_row_count, 0)

    def test_chunking_does_not_change_which_stale_bindings_are_deleted(self):
        self._provenance(self._address_object("addr-1"), "dg_edge")
        self._rebuild()
        self.assertEqual(DeviceGroupBinding.objects.count(), 1)

        # The provenance is gone, so the binding is now stale and must be removed - through
        # the chunked delete.
        FieldProvenance.objects.all().delete()
        with patch.object(query_chunking, "CHUNK_SIZE", 1):
            result = self._rebuild()

        self.assertEqual(DeviceGroupBinding.objects.count(), 0)
        self.assertEqual(result.binding_count, 0)


    def test_the_refresh_path_a_view_actually_calls_rebuilds_bindings(self):
        """The rebuild has to sit on a path a VIEW calls.

        It first went into `orchestration.refresh_panorama_in_scope_data`, which nothing but
        tests calls - so the lab came back from a full refresh with nine device groups and
        zero bindings. Both refresh paths go through this helper instead.
        """
        from optivedge_integrations.integrations.views import (
            _refresh_station_in_scope_with_tracking,
        )

        self._provenance(self._address_object("addr-1"), "dg_fw-core-tpa_edge")

        with patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_configuration_snapshots",
            return_value=_empty_in_scope_refresh_collection(),
        ):
            outcome = _refresh_station_in_scope_with_tracking(self.station)

        self.assertTrue(outcome.succeeded)
        self.assertEqual(DeviceGroupBinding.objects.count(), 1)
        self.assertTrue(
            IntegrationEvent.objects.filter(reason="DeviceGroupBindingsRebuilt").exists()
        )


class ScriptedCollectionScriptTests(SimpleTestCase):
    """The PowerShell collector must ask for exactly what the live collectors ask for.

    It is a separate implementation in a separate language, so nothing links the two: a
    command changed here would leave the script asking a device for something else, and the
    bundle would be wrong in a way that only shows up after a customer has run it.

    These are string comparisons against the collector constants, which is the whole point -
    the constants are the source, the script is the copy.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from pathlib import Path
        import optivedge_integrations.integrations as integrations_package

        root = Path(integrations_package.__file__).parent / "scripted_collection"
        cls.script_dir = root
        cls.script = (root / "Collect-OptivEdgeConfiguration.ps1").read_text(encoding="utf-8")
        # Comments name several of the things the code must not use, saying why - so the
        # forbidden-construct check reads the code with the commentary removed.
        code = re.sub(r"<#.*?#>", "", cls.script, flags=re.S)
        cls.code = re.sub(r"#.*$", "", code, flags=re.M)

    def test_the_shipped_files_are_all_present(self):
        for name in (
            "Collect-OptivEdgeConfiguration.ps1",
            "Collect-OptivEdgeConfiguration.cmd",
            "Instructions.txt",
            "README.md",
            "tests/Invoke-CollectorTests.ps1",
        ):
            self.assertTrue((self.script_dir / name).exists(), name)

    def test_every_op_command_matches_its_collector(self):
        from optivedge_integrations.integrations.platforms.pan_os.collectors.device_groups import (
            SHOW_DG_HIERARCHY_COMMAND,
        )
        from optivedge_integrations.integrations.platforms.pan_os.collectors.managed_devices import (
            SHOW_MANAGED_DEVICES_COMMAND,
        )
        from optivedge_integrations.integrations.platforms.pan_os.collectors.merged_config import (
            SHOW_MERGED_CONFIG_COMMAND,
        )
        from optivedge_integrations.integrations.platforms.pan_os.collectors.predefined import (
            SHOW_PREDEFINED_IP_BLOCK_LISTS_COMMAND,
            SHOW_PREDEFINED_URL_LISTS_COMMAND,
        )
        from optivedge_integrations.integrations.platforms.pan_os.collectors.pushed_shared_policy import (
            SHOW_PUSHED_SHARED_POLICY_COMMAND,
            build_show_pushed_shared_policy_vsys_command,
        )
        from optivedge_integrations.integrations.platforms.pan_os.collectors.system import (
            SHOW_MASTERKEY_PROPERTIES_COMMAND,
        )

        commands = [
            SHOW_MANAGED_DEVICES_COMMAND,
            SHOW_DG_HIERARCHY_COMMAND,
            SHOW_MERGED_CONFIG_COMMAND,
            SHOW_MASTERKEY_PROPERTIES_COMMAND,
            SHOW_PUSHED_SHARED_POLICY_COMMAND,
            SHOW_PREDEFINED_IP_BLOCK_LISTS_COMMAND,
            SHOW_PREDEFINED_URL_LISTS_COMMAND,
            # The script substitutes the vsys name with -f, so {0} stands where it goes.
            build_show_pushed_shared_policy_vsys_command("{0}"),
        ]
        for command in commands:
            self.assertIn(command, self.script, command)

    def test_every_config_xpath_matches_its_collector(self):
        from optivedge_integrations.integrations.platforms.pan_os.collectors.predefined import (
            PREDEFINED_CERTIFICATE_XPATH,
            PREDEFINED_SECURITY_PROFILES_XPATH,
            PREDEFINED_SSL_TLS_SERVICE_PROFILE_XPATH,
        )

        for xpath in (
            PREDEFINED_CERTIFICATE_XPATH,
            PREDEFINED_SECURITY_PROFILES_XPATH,
            PREDEFINED_SSL_TLS_SERVICE_PROFILE_XPATH,
        ):
            self.assertIn(xpath, self.script, xpath)

    def test_file_names_match_the_source_types_ingest_will_look_for(self):
        """The bundle names each file after the `source_type` of the snapshot it becomes.

        A substring check, because the script builds some names by concatenation and writes
        others as a literal path - what matters is that the token itself survives a rename.
        """
        for source_type in (
            "show_devices_all",
            "show_dg_hierarchy",
            "show_config_merged",
            "show_masterkey_properties",
            "show_pushed_shared_policy",
            "show_pushed_shared_policy_vsys",
            "show_predefined_ip_block_lists",
            "show_predefined_url_lists",
            "config_predefined_ssl_tls_service_profiles",
            "config_predefined_certificates",
            "config_predefined_security_profiles",
        ):
            self.assertIn(source_type, self.script, source_type)

    def test_it_stays_within_windows_powershell_5_1(self):
        """5.1 is what ships with Windows; 7 is an optional install a locked estate lacks."""
        for forbidden, why in (
            ("-SkipCertificateCheck", "PowerShell 7 only"),
            ("??", "null-coalescing is PowerShell 7 only"),
            ("AesGcm", "not in .NET Framework"),
            ("ImportSubjectPublicKeyInfo", "not in .NET Framework"),
            ("ConvertFrom-Json -AsHashtable", "PowerShell 6 only"),
        ):
            self.assertNotIn(forbidden, self.code, why)

    def test_the_tls_version_is_left_to_windows(self):
        """Measured 2026-09-23: a Panorama offering TLS 1.3 ONLY refuses a connection pinned
        to Tls12 -bor Tls11, which is the usual 5.1 incantation."""
        self.assertIn("SecurityProtocol = 0", self.code)
        self.assertNotIn("SecurityProtocolType]::Tls12 -bor", self.code)

    def test_it_is_read_only(self):
        """A collector performs reads. An action that mutates config must never appear."""
        for mutating in ("action=set", "action=edit", "action=delete", "'set'", "<commit"):
            self.assertNotIn(mutating, self.code, mutating)


class CollectionPackageTests(SimpleTestCase):
    """The .zip a consultant hands to a customer."""

    def _package(self, client_name="Contoso Manufacturing", generated_on=None):
        from datetime import date

        from optivedge_integrations.integrations.scripted_collection.generator import (
            build_collection_package,
        )

        return build_collection_package(
            client_name, generated_on=generated_on or date(2026, 9, 23)
        )

    def _members(self, package):
        import io
        import zipfile

        with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
            return {name: archive.read(name) for name in archive.namelist()}

    def test_it_contains_the_three_files_the_customer_needs(self):
        members = self._members(self._package())

        self.assertEqual(
            sorted(members),
            [
                "OptivEdge-Collection/Collect-OptivEdgeConfiguration.cmd",
                "OptivEdge-Collection/Collect-OptivEdgeConfiguration.ps1",
                "OptivEdge-Collection/Instructions.txt",
            ],
        )

    def test_the_client_name_reaches_the_script_and_the_instructions(self):
        members = self._members(self._package())
        script = members["OptivEdge-Collection/Collect-OptivEdgeConfiguration.ps1"].decode("utf-8")
        instructions = members["OptivEdge-Collection/Instructions.txt"].decode("utf-8")

        from optivedge_integrations.integrations.scripted_collection.generator import (
            CLIENT_NAME_TOKEN,
            GENERATED_ON_TOKEN,
        )

        self.assertIn("$script:ClientName = 'Contoso Manufacturing'", script)
        self.assertIn("$script:GeneratedOn = '2026-09-23'", script)
        self.assertNotIn(CLIENT_NAME_TOKEN, script)
        self.assertNotIn(GENERATED_ON_TOKEN, script)
        # `__OPTIVEDGE_*` still appears once, in the guard the script uses to decide whether
        # it was generated at all. That one must survive substitution.
        self.assertIn("-notlike '__OPTIVEDGE_*'", script)
        self.assertTrue(instructions.startswith("Prepared for Contoso Manufacturing"))

    def test_an_apostrophe_in_the_name_does_not_break_the_script(self):
        """A single quote would close the PowerShell string the name sits inside, and the
        customer would get a script that cannot parse."""
        members = self._members(self._package(client_name="O'Brien Industries"))
        script = members["OptivEdge-Collection/Collect-OptivEdgeConfiguration.ps1"].decode("utf-8")

        self.assertIn("$script:ClientName = 'O''Brien Industries'", script)

    def test_windows_line_endings_survive(self):
        """A .cmd with bare LF endings misbehaves under cmd.exe, and text mode would rewrite
        them silently."""
        members = self._members(self._package())

        for name, content in members.items():
            self.assertIn(b"\r\n", content, name)
            self.assertNotIn(b"\n\n", content.replace(b"\r\n", b"\r"), name)

    def test_the_download_is_named_for_the_client_and_the_day(self):
        self.assertEqual(
            self._package().file_name,
            "OptivEdge-Collection-Contoso-Manufacturing-2026-09-23.zip",
        )

    def test_a_name_of_punctuation_still_produces_a_usable_file_name(self):
        self.assertEqual(
            self._package(client_name="///").file_name,
            "OptivEdge-Collection-client-2026-09-23.zip",
        )

    def test_it_refuses_to_build_without_a_client_name(self):
        with self.assertRaises(ValueError):
            self._package(client_name="   ")

    def test_the_shipped_script_is_the_one_the_tests_check(self):
        """Not a copy, not a rendering - the same file the collector-drift test reads."""
        from pathlib import Path

        import optivedge_integrations.integrations as integrations_package
        from optivedge_integrations.integrations.scripted_collection.generator import (
            CLIENT_NAME_TOKEN,
            read_source,
            SCRIPT_NAME,
        )

        on_disk = (
            Path(integrations_package.__file__).parent / "scripted_collection" / SCRIPT_NAME
        ).read_bytes()
        self.assertEqual(read_source(SCRIPT_NAME), on_disk)
        self.assertIn(CLIENT_NAME_TOKEN.encode(), on_disk)


class CollectionScriptViewTests(TestCase):
    def test_the_page_suggests_the_configured_client(self):
        from optivedge.models import ApplicationEnvironment

        ApplicationEnvironment.objects.create(
            client_name="Contoso Manufacturing",
            client_short_name="Contoso",
            opportunity_number="OP-1234567",
        )

        response = self.client.get(reverse("collection_script"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Contoso Manufacturing")

    def test_the_page_says_so_when_no_environment_is_configured(self):
        response = self.client.get(reverse("collection_script"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No application environment is configured")

    def test_posting_a_client_name_downloads_the_package(self):
        response = self.client.post(
            reverse("collection_script"), {"client_name": "Contoso Manufacturing"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/zip")
        self.assertIn("Contoso-Manufacturing", response["Content-Disposition"])
        self.assertTrue(response.content.startswith(b"PK"))

    def test_an_empty_client_name_is_refused_rather_than_downloaded(self):
        response = self.client.post(reverse("collection_script"), {"client_name": "  "})

        self.assertRedirects(response, reverse("collection_script"))

    def test_it_is_in_the_sidebar(self):
        """A page nothing links to is a page nobody finds."""
        from optivedge_integrations.integrations import app_meta

        hrefs = {
            item["href"]
            for section in app_meta.SIDEBAR_SECTION
            for item in section["items"]
        }
        self.assertIn("/integrations/collection-script/", hrefs)


class NumHostsFromIntervalsTests(SimpleTestCase):
    def test_counts_both_ends_inclusively(self):
        self.assertEqual(num_hosts_from_intervals([(1, 1)]), 1)
        self.assertEqual(num_hosts_from_intervals([(0, 4294967295)]), 4294967296)

    def test_nothing_covers_nothing(self):
        self.assertEqual(num_hosts_from_intervals([]), 0)

    def test_overlapping_intervals_double_count_until_merged(self):
        """The reason merge_intervals is a separate call and not folded in: two EDL members
        covering the same host are one host, and this function cannot know that on its own."""
        overlapping = [(0, 10), (5, 15)]
        self.assertEqual(num_hosts_from_intervals(overlapping), 22)
        self.assertEqual(num_hosts_from_intervals(merge_intervals(overlapping)), 16)


class QueryChunkingTests(SimpleTestCase):
    def test_chunked_splits_and_keeps_order(self):
        self.assertEqual([list(c) for c in chunked(range(5), 2)], [[0, 1], [2, 3], [4]])

    def test_chunked_yields_nothing_for_an_empty_input(self):
        self.assertEqual(list(chunked([])), [])

    def test_chunked_rejects_a_useless_size(self):
        with self.assertRaises(ValueError):
            list(chunked([1, 2], 0))


class InScopeRefreshRunFinalizationTests(TestCase):
    """A run must be finished even when the refresh dies part way through it.

    Reported from a real estate: the bulk refresh raised in the binding rebuild, and the
    station showed "Refreshing..." for ever afterwards with a single InScopeRefreshStarted
    event to explain it. Only the collection call was guarded, so the run was never closed and
    the per-item events - gathered in memory and written in one go at the end - were all
    discarded by the exception.
    """

    def setUp(self):
        self.station, self.appliance, self.enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-RUN-001",
            appliance_hostname="fw-run-01",
        )

    def _collection_with_one_failure(self):
        collection = _empty_in_scope_refresh_collection()
        collection.configuration_snapshots.merged_config_failures.append(
            SimpleNamespace(appliance=self.appliance, error_text="device unreachable")
        )
        return collection

    def test_a_failure_after_collection_closes_the_run_and_keeps_the_events(self):
        from optivedge_integrations.integrations.views import (
            _refresh_station_in_scope_with_tracking,
        )

        with patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_configuration_snapshots",
            return_value=self._collection_with_one_failure(),
        ), patch(
            "optivedge_integrations.integrations.views.rebuild_device_group_bindings",
            side_effect=Exception("too many SQL variables"),
        ):
            outcome = _refresh_station_in_scope_with_tracking(self.station)

        self.assertFalse(outcome.succeeded)
        outcome.run.refresh_from_db()
        # The symptom: without this the run stays RUNNING and the UI never stops spinning.
        self.assertEqual(outcome.run.status, IntegrationRun.STATUS_FAILED)
        self.assertIsNotNone(outcome.run.completed_at)

        reasons = set(IntegrationEvent.objects.filter(run=outcome.run).values_list("reason", flat=True))
        self.assertIn("InScopeRefreshFailed", reasons)
        # The account of the run survives the failure rather than being thrown away with it.
        self.assertIn("MergedConfigCollectionFailed", reasons)
        self.assertIn(
            "too many SQL variables",
            IntegrationEvent.objects.get(run=outcome.run, reason="InScopeRefreshFailed").message,
        )

    def test_a_clean_run_still_succeeds_and_is_closed(self):
        from optivedge_integrations.integrations.views import (
            _refresh_station_in_scope_with_tracking,
        )

        with patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_configuration_snapshots",
            return_value=_empty_in_scope_refresh_collection(),
        ):
            outcome = _refresh_station_in_scope_with_tracking(self.station)

        self.assertTrue(outcome.succeeded)
        outcome.run.refresh_from_db()
        self.assertEqual(outcome.run.status, IntegrationRun.STATUS_SUCCEEDED)
        self.assertIsNotNone(outcome.run.completed_at)


class SideNumHostsTests(TestCase):
    """How many addresses one side of a rule permits - the column PAN-POL-002 scores.

    The arithmetic lives here and the severity bands live in OptivEdgeAssessments'
    `test_address_breadth_control`, so these tests are about the three ways the count can be
    wrong rather than about any threshold: counting a negated side's members instead of its
    complement, counting an overlapping union twice, and answering 0 where the truth is
    "could not be established".
    """

    def setUp(self):
        self.station, self.appliance, self.point = _create_panorama_enforcement_point(
            serial_number="SERIAL-BREADTH-001",
            appliance_hostname="fw-breadth-01",
        )
        self.snapshot = Snapshot.objects.create(
            management_station=self.station,
            appliance=self.appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={},
        )
        self.rank = 0

    def _netmask(self, name, cidr):
        network = ipaddress.IPv4Network(cidr)
        self.rank += 1
        return AddressObject.objects.create(
            management_station=self.station,
            enforcement_point=self.point,
            source_snapshot=self.snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name=name,
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=self.rank,
            address_type=AddressObject.TYPE_IP_NETMASK,
            value=cidr,
            normalized_value=cidr,
            ipv4_start_int=int(network.network_address),
            ipv4_end_int=int(network.broadcast_address),
        )

    def _unresolvable_edl(self, name):
        self.rank += 1
        return AddressObject.objects.create(
            management_station=self.station,
            enforcement_point=self.point,
            source_snapshot=self.snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name=name,
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=self.rank,
            address_type=AddressObject.TYPE_EDL,
            is_edl=True,
            edl_list_type="ip",
            value="ip",
            normalized_value="ip",
        )

    def _ref(self, address_object, *, position=0):
        return ResolvedAddressRef(
            raw_value=address_object.name,
            position=position,
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=address_object,
            address_group=None,
        )

    def test_one_member_is_its_own_size(self):
        refs = [self._ref(self._netmask("a-slash-24", "10.0.0.0/24"))]

        self.assertEqual(side_num_hosts(refs, negated=False, complement_ref=None), 256)

    def test_two_disjoint_members_add(self):
        refs = [
            self._ref(self._netmask("a-slash-24", "10.0.0.0/24")),
            self._ref(self._netmask("b-slash-24", "10.0.1.0/24"), position=1),
        ]

        self.assertEqual(side_num_hosts(refs, negated=False, complement_ref=None), 512)

    def test_overlapping_members_are_counted_once(self):
        """Two objects covering the same space are that space, not twice it. Without the merge
        a side naming the same /8 under two names reads as a /7 and crosses into critical."""
        refs = [
            self._ref(self._netmask("outer", "10.0.0.0/8")),
            self._ref(self._netmask("inner", "10.1.0.0/16"), position=1),
        ]

        self.assertEqual(side_num_hosts(refs, negated=False, complement_ref=None), 16_777_216)

    def test_a_negated_side_counts_the_complement_and_not_the_members(self):
        """The failure this guards: a rule negating ONE HOST permits everything but that host,
        and reading its member list would score it /32 - the narrowest rule on the device,
        where the truth is the broadest. The complement ref is what normalization materializes
        beside the members for exactly this.
        """
        members = [self._ref(self._netmask("one-host", "10.1.2.3/32"))]
        complement = self._ref(self._netmask("not-one-host-complement", "0.0.0.0/0"))

        self.assertEqual(
            side_num_hosts(members, negated=True, complement_ref=complement),
            4_294_967_296,
        )
        # And the un-negated reading of the same member list, for contrast.
        self.assertEqual(side_num_hosts(members, negated=False, complement_ref=None), 1)

    def test_a_negated_side_without_a_complement_is_indeterminate(self):
        """Normalization refuses to materialize a complement when any member is unresolvable,
        so its absence means the same thing here: not measured, not empty."""
        members = [self._ref(self._unresolvable_edl("no-content-edl"))]

        self.assertIsNone(side_num_hosts(members, negated=True, complement_ref=None))

    def test_one_unsizeable_member_makes_the_whole_side_indeterminate(self):
        """A partial union is an under-count, and an under-count on this control reads as a
        narrower rule than the configuration permits."""
        refs = [
            self._ref(self._netmask("known", "10.0.0.0/24")),
            self._ref(self._unresolvable_edl("unknown-edl"), position=1),
        ]

        self.assertIsNone(side_num_hosts(refs, negated=False, complement_ref=None))

    def test_a_truncated_edl_makes_the_side_indeterminate(self):
        """Collected content stopped at the ceiling is a known under-count, which is the same
        problem as no content at all for a question about size - and different from it for a
        question about membership, which is why the mark exists rather than discarding."""
        edl = self._unresolvable_edl("too-big-edl")
        AddressObjectResolvedEntry.objects.create(
            address_object=edl,
            ipv4_start_int=int(ipaddress.IPv4Address("1.2.3.4")),
            ipv4_end_int=int(ipaddress.IPv4Address("1.2.3.4")),
            source_snapshot=self.snapshot,
            collected_at=timezone.now(),
        )
        edl.resolved_content_truncated = True
        edl.save(update_fields=["resolved_content_truncated"])

        self.assertIsNone(
            side_num_hosts([self._ref(edl)], negated=False, complement_ref=None))

    def test_negating_the_whole_space_leaves_an_EMPTY_complement(self):
        """Reachable in committed config, which is not obvious.

        PAN-OS refuses `negate-source` beside the keyword `any` at COMMIT - "Negate cannot be
        enabled for security rule X with source address as 'any'" - so the obvious way to write
        this rule does not exist. It is a KEYWORD check though, not a space check: the same
        space as a 0.0.0.0/0 ip-netmask OBJECT negates and commits without complaint. Measured
        on pan-fw-111, 2026-10-05, and `oep002-g-neg-zero` is the lab subject for it.

        So the complement really can be empty, and empty must read as INDETERMINATE rather than
        0 - a rule permitting nothing is not the narrowest rule on the device, it is a rule
        whose breadth there is no point scoring.
        """
        whole_space = self._ref(self._netmask("everything", "0.0.0.0/0"))

        self.assertEqual(compute_negated_complement_intervals([whole_space]), [])
        self.assertIsNone(
            side_num_hosts([whole_space], negated=True, complement_ref=None))

    def test_no_members_is_indeterminate_rather_than_zero(self):
        """Zero is the narrowest value there is. A side with nothing resolvable on it must not
        read as the tightest side on the device."""
        self.assertIsNone(side_num_hosts([], negated=False, complement_ref=None))


class SupersededEnforcementPointTests(TestCase):
    """An HA pair that is still coming up reports no peer, and the group it lands in changes.

    Measured consequence, reported 2026-09-28 from a non-lab environment: two rows per vsys on
    the station's Enforcement Points tab. The duplicate is the visible half. The half that
    matters is that scope was recorded on the FIRST row and collection reads
    `enforcement_points.filter(in_scope=True)`, so an operator who chose scope before the pair
    came up has it applied to a row nothing collects through - and the estate reads as
    collected when nothing was.
    """

    SERIAL_A = "001111111111"
    SERIAL_B = "002222222222"

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.ha-flap",
        )

    def _collected(self, entries):
        from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
            PANOSCollectedResponse,
            PANOSOperationRequest,
        )

        return PANOSCollectedResponse(
            source_type="show_managed_devices",
            request=PANOSOperationRequest(command_xml="<show><devices><all/></devices></show>"),
            response={"response": {"@status": "success",
                                   "result": {"devices": {"entry": entries}}}},
        )

    @staticmethod
    def _entry(serial, *, peer=None, state=""):
        entry = {
            "@name": serial,
            "serial": serial,
            "hostname": f"fw-{serial[-2:]}",
            "vsys": {"entry": [{"@name": "vsys1", "display-name": "vsys1"}]},
        }
        if peer:
            entry["ha"] = {"state": state, "peer": {"serial": peer}}
        return entry

    def _sync(self, entries):
        from optivedge_integrations.integrations.platforms.pan_os.normalization.panorama import (
            normalize_show_managed_devices,
        )

        return normalize_show_managed_devices(self.station, self._collected(entries))

    def test_scope_follows_the_appliance_when_its_group_changes(self):
        """The bug, end to end: sync with no peer, choose scope, sync again with the peer."""
        self._sync([self._entry(self.SERIAL_A), self._entry(self.SERIAL_B)])
        standalone_points = EnforcementPoint.objects.all()
        self.assertEqual(standalone_points.count(), 2)
        standalone_points.update(in_scope=True)

        self._sync([
            self._entry(self.SERIAL_A, peer=self.SERIAL_B, state="active"),
            self._entry(self.SERIAL_B, peer=self.SERIAL_A, state="passive"),
        ])

        live = EnforcementPoint.objects.filter(is_missing=False)
        self.assertEqual(live.count(), 1, "the HA pair serves one vsys1, not one per node")
        self.assertEqual(live.get().appliance_group.group_type, ApplianceGroup.TYPE_HA_PAIR)
        self.assertTrue(live.get().in_scope, "scope has to travel with the appliance")

        retired = EnforcementPoint.objects.filter(is_missing=True)
        self.assertEqual(retired.count(), 2)
        self.assertFalse(any(p.in_scope for p in retired),
                         "collection follows in_scope, so a retired row must not keep it")
        self.assertTrue(all(p.missing_since for p in retired))

    def test_collection_targets_one_row_per_vsys_afterwards(self):
        """What the operator sees: the in-scope count stops double-counting, and the station's
        collection has one enforcement point to walk rather than three."""
        self._sync([self._entry(self.SERIAL_A), self._entry(self.SERIAL_B)])
        EnforcementPoint.objects.update(in_scope=True)
        self._sync([
            self._entry(self.SERIAL_A, peer=self.SERIAL_B, state="active"),
            self._entry(self.SERIAL_B, peer=self.SERIAL_A, state="passive"),
        ])

        self.assertEqual(
            self.station.enforcement_points.filter(in_scope=True).count(), 1)

    def test_the_station_page_marks_a_retired_point_rather_than_hiding_it(self):
        """Kept, not deleted - the collected configuration and the findings recorded against it
        hang off this row - so the tab has to say which of the two rows is history. Without the
        marker the duplicate reads as the retire having failed."""
        self._sync([self._entry(self.SERIAL_A), self._entry(self.SERIAL_B)])
        self._sync([self._entry(self.SERIAL_A, peer=self.SERIAL_B, state="active"),
                    self._entry(self.SERIAL_B, peer=self.SERIAL_A, state="passive")])

        response = self.client.get(
            reverse("management_station_detail", kwargs={"pk": self.station.pk}),
            {"tab": "enforcement-points", "scope": "all"})

        self.assertContains(response, "Retired")
        self.assertEqual(EnforcementPoint.objects.filter(is_missing=True).count(), 2)

    def test_a_point_still_served_where_it_says_it_is_survives(self):
        """The guard against over-retiring: syncing the same shape twice must retire nothing."""
        self._sync([self._entry(self.SERIAL_A, peer=self.SERIAL_B, state="active"),
                    self._entry(self.SERIAL_B, peer=self.SERIAL_A, state="passive")])
        EnforcementPoint.objects.update(in_scope=True)

        self._sync([self._entry(self.SERIAL_A, peer=self.SERIAL_B, state="active"),
                    self._entry(self.SERIAL_B, peer=self.SERIAL_A, state="passive")])

        self.assertEqual(EnforcementPoint.objects.filter(is_missing=True).count(), 0)
        self.assertEqual(EnforcementPoint.objects.filter(in_scope=True).count(), 1)

    def test_two_appliances_with_the_same_vsys_name_are_not_paired(self):
        """`vsys1` is on nearly every firewall, so matching on the name alone would retire one
        appliance's point in favour of an unrelated appliance's. The link is the enforcement
        NODE - which appliance actually reaches the point."""
        self._sync([self._entry(self.SERIAL_A), self._entry(self.SERIAL_B)])
        EnforcementPoint.objects.update(in_scope=True)

        # Same shape again: both still standalone, both still vsys1.
        self._sync([self._entry(self.SERIAL_A), self._entry(self.SERIAL_B)])

        self.assertEqual(EnforcementPoint.objects.filter(is_missing=True).count(), 0)
        self.assertEqual(EnforcementPoint.objects.filter(in_scope=True).count(), 2)


class ChooseLocalApplianceTests(TestCase):
    """Whose merged config speaks for an enforcement point on an HA pair.

    The active member, PROVIDED IT HAS ONE. The two differ after a failover and the difference
    used to fail the whole enforcement point: `active_appliance` is set during an inventory
    sync from `ha/state`, which contacts Panorama and no firewall, so a failover plus an
    inventory sync moves it to a node that has never been collected - and a renormalize, which
    contacts nothing either, then raised "missing merged config snapshot" for every vsys on the
    pair. The configuration was in the database the whole time, under the other serial.
    """

    def setUp(self):
        from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
            choose_local_appliance,
        )

        self.choose = choose_local_appliance
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.failover")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="ha-pair-A-B",
            group_type=ApplianceGroup.TYPE_HA_PAIR)
        self.a = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="SERIAL-A", hostname="fw-a")
        self.b = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="SERIAL-B", hostname="fw-b")
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.group, vsys_name="vsys1")
        for appliance in (self.a, self.b):
            EnforcementNode.objects.create(
                management_station=self.station, appliance=appliance,
                enforcement_point=self.point)

    def _collect(self, appliance):
        return Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})

    def _set_active(self, appliance):
        self.group.active_appliance = appliance
        self.group.save(update_fields=["active_appliance"])

    def test_the_active_member_wins_when_it_has_been_collected(self):
        """Unchanged for a collected estate, which is most of the point: this must not start
        preferring the peer."""
        self._collect(self.a)
        self._collect(self.b)
        self._set_active(self.a)

        self.assertEqual(self.choose(self.point), self.a)

    def test_a_failover_does_not_strand_the_collected_configuration(self):
        """The reported sequence. A collected while active; the pair fails over; an inventory
        sync moves `active_appliance` to B, which has never been collected."""
        self._collect(self.a)
        self._set_active(self.b)

        self.assertEqual(self.choose(self.point), self.a)

    def test_the_enforcement_point_normalizes_after_a_failover(self):
        """End of the chain, which is what actually broke: `latest_merged_snapshot` returning
        None is what `security_rules` raises on."""
        from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
            latest_merged_snapshot,
        )

        snapshot = self._collect(self.a)
        self._set_active(self.b)

        self.assertEqual(latest_merged_snapshot(self.point), snapshot)

    def test_a_pair_collected_nowhere_still_reports_it(self):
        """No invention. A pair that has never been collected is a different problem and has to
        keep saying so, or the failure this fixes is replaced by a silent empty normalization."""
        from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
            latest_merged_snapshot,
        )

        self._set_active(self.a)

        self.assertEqual(self.choose(self.point), self.a)
        self.assertIsNone(latest_merged_snapshot(self.point))

    def test_the_choice_is_stable_when_neither_is_active(self):
        """Ordered by hostname rather than row order, so two runs over the same data resolve
        the same way."""
        self._collect(self.b)
        self._collect(self.a)

        self.assertEqual(self.choose(self.point), self.a)

    def test_a_snapshot_of_another_type_does_not_count_as_collected(self):
        """`show_masterkey_properties` and the pushed-policy reads are attached to appliances
        too. Only a merged config answers this question."""
        Snapshot.objects.create(
            management_station=self.station, appliance=self.b,
            source_type="show_masterkey_properties", collected_at=timezone.now(), payload={})
        self._collect(self.a)
        self._set_active(self.b)

        self.assertEqual(self.choose(self.point), self.a)


class SecurityRuleProfileCoverageTests(TestCase):
    """Which threat profiles actually reach a rule - PAN-POL-008's subject.

    The case this exists for is the lab's own: 113 rules name a profile group called `default`,
    and that group NAMES NO PROFILES AT ALL. They look protected in every view that stops at
    "does the rule carry a profile group", and they inspect nothing. A control written against
    the reference rather than the resolved group would pass all 113.
    """

    def setUp(self):
        self.station, self.appliance, self.point = _create_panorama_enforcement_point(
            serial_number="SERIAL-PROF-001", appliance_hostname="fw-prof-01")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        self.rank = 0

    def _group(self, name, members, namespace_type="panorama_shared"):
        self.rank += 1
        return SecurityProfileGroup.objects.create(
            management_station=self.station, appliance_group=self.point.appliance_group,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name=name, namespace_type=namespace_type, namespace_value="shared",
            precedence_rank=self.rank, members=members)

    def _rule(self, name, *, group=None, profiles=()):
        self.rank += 1
        rule = SecurityRule.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            effective_order=self.rank, rule_position=self.rank, name=name, action="allow")
        if group is not None:
            SecurityRuleProfileGroup.objects.create(
                security_rule=rule, value=group, prov="test", position=0)
        for index, (profile_type, value) in enumerate(profiles):
            SecurityRuleProfile.objects.create(
                security_rule=rule, value=value, prov="test", position=index,
                profile_type=profile_type)
        return rule

    def _coverage(self, rule):
        normalize_security_rule_profile_coverage(self.point)
        rule.refresh_from_db()
        return (rule.has_antivirus_profile, rule.has_spyware_profile,
                rule.has_vulnerability_profile)

    def test_a_group_naming_nothing_protects_nothing(self):
        """The lab's `default` group, and the reason this is a resolved column rather than a
        query over the reference."""
        self._group("default", {})
        rule = self._rule("looks-protected", group="default")

        self.assertEqual(self._coverage(rule), (False, False, False))

    def test_a_group_naming_profiles_covers_those_types(self):
        self._group("real", {"virus": ["default"], "vulnerability": ["default"]})
        rule = self._rule("partly-protected", group="real")

        self.assertEqual(self._coverage(rule), (True, False, True))

    def test_profiles_named_directly_on_the_rule_count(self):
        """A rule names either individual profiles or a group. Both reach the same columns."""
        rule = self._rule("direct", profiles=(("virus", "av"), ("spyware", "as"),
                                              ("vulnerability", "vp")))

        self.assertEqual(self._coverage(rule), (True, True, True))

    def test_a_rule_naming_no_protection_at_all_is_uncovered(self):
        rule = self._rule("bare")

        self.assertEqual(self._coverage(rule), (False, False, False))

    def test_a_group_reference_that_resolves_to_nothing_is_uncovered(self):
        """A name no group defines. Nothing to read, so nothing is in force - and the rule must
        not inherit coverage from a group that is not there."""
        rule = self._rule("dangling", group="no-such-group")

        self.assertEqual(self._coverage(rule), (False, False, False))

    def test_the_pass_is_idempotent(self):
        self._group("real", {"virus": ["default"]})
        rule = self._rule("stable", group="real")

        first = self._coverage(rule)
        second = normalize_security_rule_profile_coverage(self.point)

        self.assertEqual(first, (True, False, False))
        self.assertEqual(second["updated"], 0, "a second pass should change nothing")


class SecurityProfileVerdictSatelliteTests(TestCase):
    """The verdicts are rows, so a profile kind that answers no severity question has none.

    That is the whole reason they moved off `SecurityProfile`. The columns could say only yes or
    no, so an antivirus profile - which has per-protocol decoders and no severity rules at all -
    would have had to say "critical is not blocked", a claim it never makes. With rows, the
    absence IS the answer.
    """

    def setUp(self):
        self.station, self.appliance, self.point = _create_panorama_enforcement_point(
            serial_number="SERIAL-VERDICT-1", appliance_hostname="fw-verdict-01")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="config_predefined_security_profiles", collected_at=timezone.now(),
            payload={})

    def _profile(self, name, kind):
        return SecurityProfile.objects.create(
            management_station=self.station, appliance_group=self.point.appliance_group,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_PUSHED_PRE,
            name=name, namespace_type="panorama_shared", namespace_value="shared",
            precedence_rank=10, kind=kind)

    def test_a_profile_that_answers_reports_its_verdict_and_reason(self):
        profile = self._profile("weak", SecurityProfile.KIND_SPYWARE)
        SecurityProfileSeverityVerdict.objects.create(
            security_profile=profile, severity="critical", blocked=False,
            detail="alert by rule a")
        SecurityProfileSeverityVerdict.objects.create(
            security_profile=profile, severity="high", blocked=True, detail="reset-both")

        self.assertIs(profile.critical_blocked, False)
        self.assertEqual(profile.critical_detail, "alert by rule a")
        self.assertIs(profile.high_blocked, True)

    def test_a_profile_with_no_verdict_row_says_NONE_rather_than_False(self):
        """An antivirus profile. `False` would read as "critical threats are not blocked"; None
        reads as "this profile does not answer that question", which is the truth."""
        profile = self._profile("default", SecurityProfile.KIND_SPYWARE)

        self.assertIsNone(profile.critical_blocked)
        self.assertIsNone(profile.high_blocked)
        self.assertIsNone(profile.medium_blocked)
        self.assertEqual(profile.critical_detail, "")

    def test_one_verdict_per_profile_per_severity(self):
        """Two verdicts for one severity would mean the normalizer ran twice or disagreed with
        itself, and a reader would get whichever row came back first."""
        profile = self._profile("dup", SecurityProfile.KIND_VULNERABILITY)
        SecurityProfileSeverityVerdict.objects.create(
            security_profile=profile, severity="critical", blocked=True, detail="")

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                SecurityProfileSeverityVerdict.objects.create(
                    security_profile=profile, severity="critical", blocked=False, detail="x")

    def test_the_verdicts_go_when_the_profile_does(self):
        profile = self._profile("gone", SecurityProfile.KIND_SPYWARE)
        SecurityProfileSeverityVerdict.objects.create(
            security_profile=profile, severity="high", blocked=True, detail="")

        profile.delete()

        self.assertEqual(SecurityProfileSeverityVerdict.objects.count(), 0)


class AntivirusProfileNormalizationTests(TestCase):
    """Antivirus profiles become rows, and write NO severity verdicts.

    `severity_verdict()` would happily return (False, "no catch-all rule") for one: the
    statement is true of its rule list, which does not exist, and reads to any consumer as
    "critical threats are not blocked". The gate is `SecurityProfile.THREAT_RULE_KINDS`.
    """

    #: The shape measured on Panorama 2026-10-07 from `antivirus_profile_defaults`, a profile
    #: created through the UI without touching a setting: seven decoders, all written, all at
    #: the literal `default`. No `rules` node anywhere.
    AV_ENTRY = {
        "@name": "default",
        "decoder": {"entry": [
            {"@name": name, "action": "default", "wildfire-action": "default"}
            for name in ("ftp", "http", "http2", "imap", "pop3", "smb", "smtp")]},
        "mlav-engine-filebased-enabled": {"entry": [
            {"@name": "Windows Executables", "mlav-policy-action": "enable"}]},
    }

    def _normalized(self, kind, entry):
        snapshot = Snapshot.objects.create(
            source_type="config_predefined_security_profiles",
            collected_at=timezone.now(), payload={})
        return normalize_security_profile(
            kind=kind, source_snapshot=snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            namespace_type="predefined", namespace_value="predefined", entry=entry)

    def test_an_antivirus_profile_writes_no_verdicts(self):
        normalized = self._normalized(SecurityProfile.KIND_VIRUS, self.AV_ENTRY)

        self.assertEqual(normalized.verdicts, {})
        self.assertEqual(normalized.name, "default")

    def test_it_counts_no_threat_rules_which_is_TRUE_of_it(self):
        """A count of zero threat rules is a true statement about an antivirus profile, where a
        verdict of "not blocked" is a claim it never makes. That is why rule_count stayed on the
        profile and the verdicts did not."""
        normalized = self._normalized(SecurityProfile.KIND_VIRUS, self.AV_ENTRY)

        self.assertEqual(normalized.rule_count, 0)
        self.assertEqual(normalized.threat_exception_count, 0)

    def test_a_threat_rule_kind_still_writes_all_three(self):
        entry = {"@name": "weak", "rules": {"entry": [
            {"@name": "alert-all", "severity": {"member": ["any"]}, "action": {"alert": None}}]}}

        normalized = self._normalized(SecurityProfile.KIND_SPYWARE, entry)

        self.assertEqual(set(normalized.verdicts), {"critical", "high", "medium"})

    def test_virus_is_collected_but_is_not_a_threat_rule_kind(self):
        self.assertIn(SecurityProfile.KIND_VIRUS, PROFILE_KINDS)
        self.assertNotIn(SecurityProfile.KIND_VIRUS, SecurityProfile.THREAT_RULE_KINDS)


class AntivirusDecoderResolutionTests(SimpleTestCase):
    """`default` is a pointer, and what it points at differs per protocol.

    Measured 2026-10-07, two profiles side by side in the Panorama UI - the predefined `default`
    and one created without touching a setting. Both render http/http2/ftp/smb as reset-both and
    smtp/imap/pop3 as alert. controls.json independently says the shipped profile "only alerts
    on several decoders", and three is several.
    """

    def test_default_resolves_to_reset_both_on_the_file_transfer_decoders(self):
        for protocol in ("http", "http2", "ftp", "smb"):
            with self.subTest(protocol=protocol):
                self.assertEqual(resolve_decoder_action(protocol, "default"), "reset-both")

    def test_default_resolves_to_ALERT_on_the_mail_decoders(self):
        """The whole reason this control exists: the shipped profile detects mail-borne malware
        and does not stop it."""
        for protocol in ("smtp", "imap", "pop3"):
            with self.subTest(protocol=protocol):
                self.assertEqual(resolve_decoder_action(protocol, "alert"), "alert")
                self.assertEqual(resolve_decoder_action(protocol, "default"), "alert")

    def test_an_explicit_action_is_taken_as_written(self):
        self.assertEqual(resolve_decoder_action("smtp", "reset-both"), "reset-both")
        self.assertEqual(resolve_decoder_action("http", "alert"), "alert")

    def test_an_absent_action_is_ALLOW_and_not_default(self):
        """The correction of 2026-10-08, and it was wrong in the dangerous direction.

        Measured by exporting the UI's own view of three profiles: one with no decoder node,
        one with a decoder carrying no action, and one naming `default` on http alone. All
        render `allow` on every protocol the config does not give a value for - including the
        six the third never mentions. Reading absence as `default` reported a profile that
        allows malware on http as one that resets both ends of the connection.
        """
        self.assertEqual(resolve_decoder_action("http", ""), "allow")
        self.assertEqual(resolve_decoder_action("smtp", ""), "allow")
        self.assertNotEqual(resolve_decoder_action("http", ""),
                            resolve_decoder_action("http", "default"))

    def test_an_unknown_protocol_resolves_to_nothing_rather_than_guessing(self):
        """A decoder PAN-OS adds in a later release. Better an empty effective action, which
        reads as unestablished, than a guess that a control would score."""
        self.assertEqual(resolve_decoder_action("quic", "default"), "")


class AntivirusDecoderParsingTests(SimpleTestCase):
    """The shape measured on the predefined `default` profile, 2026-10-07."""

    PREDEFINED = {"@name": "default", "decoder": {"entry": [
        {"@name": p, "action": "default", "wildfire-action": "default"}
        for p in ("http", "http2", "smtp", "imap", "pop3", "ftp", "smb")]}}

    def test_the_shipped_profile_leaves_three_decoders_not_blocking(self):
        rows = {r[0]: r for r in profile_decoders(self.PREDEFINED)}

        self.assertEqual(len(rows), 7)
        not_blocking = sorted(p for p, r in rows.items() if not r[3])
        self.assertEqual(not_blocking, ["imap", "pop3", "smtp"])

    def test_it_keeps_the_configured_literal_beside_what_it_means(self):
        """An engineer looking for the line to change needs `default`; a control needs
        `alert`."""
        smtp = next(r for r in profile_decoders(self.PREDEFINED) if r[0] == "smtp")

        self.assertEqual(smtp[1], "default")
        self.assertEqual(smtp[2], "alert")

    def test_a_hardened_profile_blocks_on_every_decoder(self):
        entry = {"@name": "hard", "decoder": {"entry": [
            {"@name": p, "action": "reset-both", "wildfire-action": "reset-both"}
            for p in ("http", "http2", "smtp", "imap", "pop3", "ftp", "smb")]}}

        rows = profile_decoders(entry)

        self.assertTrue(all(r[3] for r in rows))
        self.assertTrue(all(r[6] for r in rows))

    def test_drop_counts_as_blocking_though_the_corpus_names_reset_both(self):
        """Same deviation PAN-SPY-001 makes: a profile that drops malware has not failed to
        block it."""
        entry = {"@name": "drops", "decoder": {"entry": [
            {"@name": "smtp", "action": "drop"}]}}

        # By protocol, not by position: the rows are in PAN-OS's own decoder order now, so the
        # one the config names is not necessarily first.
        smtp = next(r for r in profile_decoders(entry) if r[0] == "smtp")

        self.assertTrue(smtp[3])

    def test_a_profile_with_no_decoder_node_still_has_SEVEN_decoders(self):
        """PAN-OS evaluates every protocol whether or not the config names it, and allows on
        the ones it does not. Yielding nothing here made such a profile invisible to
        PAN-AVW-001 - no rows, so no gap to report, so a profile inspecting nothing passed."""
        rows = profile_decoders({"@name": "bare"})

        self.assertEqual(len(rows), 7)
        self.assertTrue(all(r[2] == "allow" for r in rows))
        self.assertTrue(all(not r[3] for r in rows), "none of them block")

    def test_the_protocols_the_config_omits_are_allow(self):
        """`oep-avp-xdefault` on the lab: `default` on http alone. The UI renders
        `default (reset-both)` for http and `allow` for the other six."""
        rows = {r[0]: r for r in profile_decoders(
            {"@name": "one", "decoder": {"entry": [{"@name": "http", "action": "default"}]}})}

        self.assertEqual(rows["http"][2], "reset-both")
        self.assertTrue(rows["http"][3])
        for protocol in ("http2", "smtp", "imap", "pop3", "ftp", "smb"):
            self.assertEqual(rows[protocol][2], "allow", protocol)
            self.assertFalse(rows[protocol][3], protocol)

    def test_a_decoder_entry_with_no_action_allows(self):
        rows = {r[0]: r for r in profile_decoders(
            {"@name": "empty", "decoder": {"entry": [{"@name": "http"}]}})}

        self.assertEqual(rows["http"][1], "")
        self.assertEqual(rows["http"][2], "allow")
        self.assertFalse(rows["http"][3])

    def test_a_protocol_PAN_OS_adds_later_is_carried_rather_than_dropped(self):
        rows = {r[0]: r for r in profile_decoders(
            {"@name": "future", "decoder": {"entry": [{"@name": "quic", "action": "drop"}]}})}

        self.assertEqual(len(rows), 8)
        self.assertEqual(rows["quic"][2], "drop")


class AntivirusApplicationOverrideTests(SimpleTestCase):
    """The per-application action override, measured on pan-fw-111 2026-10-08.

    Found by enumerating the profile's key set with `action=complete` rather than reading a
    sample: the node was in the config all along and PAN-AVW-001 walked only the decoders, so a
    profile with `reset-both` everywhere and one `allow` override reported as hardened.

    Each shape below was written to a device and either accepted or refused, so none of these
    inputs is invented.
    """

    def test_no_application_node_yields_no_rows(self):
        """The normal case. UNLIKE the decoders, nothing is synthesized - an override is an
        operator-added exception, so the absence of one is the absence of an override and not a
        silent default. Synthesizing 1454 rows per profile would be the same bug inverted."""
        self.assertEqual(profile_application_overrides({"@name": "plain"}), [])

    def test_an_allow_override_does_not_block(self):
        self.assertEqual(
            profile_application_overrides({"@name": "p", "application": {"entry": [
                {"@name": "gmail-base", "action": "allow"}]}}),
            [("gmail-base", "allow", False)])

    def test_a_blocking_override_blocks(self):
        """An override may TIGHTEN an action, so this must not read as a gap."""
        self.assertEqual(
            profile_application_overrides({"@name": "p", "application": {"entry": [
                {"@name": "gmail-base", "action": "reset-both"}]}}),
            [("gmail-base", "reset-both", True)])

    def test_an_override_with_no_action_allows(self):
        """The device ACCEPTS an entry with no action and stores it absent - and refuses one
        with an empty action element. So absence is reachable and is the permissive end, the
        same rule as an absent decoder action."""
        self.assertEqual(
            profile_application_overrides({"@name": "p", "application": {"entry": [
                {"@name": "ftp"}]}}),
            [("ftp", "", False)])

    def test_default_is_UNESTABLISHED_rather_than_resolved(self):
        """`default` is accepted on an override. A decoder's `default` resolves per protocol
        and that was measured; an override is not per-protocol, so that table cannot answer it
        and no device oracle was found that does. None, not False - which the control reports
        rather than passes."""
        self.assertEqual(
            profile_application_overrides({"@name": "p", "application": {"entry": [
                {"@name": "web-browsing", "action": "default"}]}}),
            [("web-browsing", "default", None)])

    def test_alert_is_detection_without_prevention(self):
        self.assertEqual(
            profile_application_overrides({"@name": "p", "application": {"entry": [
                {"@name": "dropbox-base", "action": "alert"}]}})[0][2],
            False)

    def test_a_single_entry_arriving_unwrapped_is_still_read(self):
        """PAN-OS returns a lone entry as a dict rather than a one-item list."""
        self.assertEqual(
            profile_application_overrides({"@name": "p", "application": {"entry": {
                "@name": "ftp", "action": "allow"}}}),
            [("ftp", "allow", False)])

    def test_a_pushed_override_carries_provenance_attributes(self):
        """What a read actually returns: the action is a dict with the value under `#text`."""
        self.assertEqual(
            profile_application_overrides({"@name": "p", "application": {"entry": [
                {"@name": "ftp", "@loc": "shared",
                 "action": {"@admin": "admin", "#text": "allow"}}]}}),
            [("ftp", "allow", False)])

    def test_an_entry_with_no_name_is_skipped_rather_than_crashing(self):
        self.assertEqual(
            profile_application_overrides({"@name": "p", "application": {"entry": [
                {"action": "allow"}, {"@name": "ftp", "action": "allow"}]}}),
            [("ftp", "allow", False)])


class AntivirusMlModelTests(SimpleTestCase):
    """The WildFire Inline ML models, whose names come from the CONTENT release.

    controls.json says so and says to enumerate them on the target version before automating,
    so nothing here hardcodes them - the catalogue comes from the predefined profile, which
    carries every model the device knows about.
    """

    #: As the predefined profile carries them on the lab, 2026-10-07.
    EIGHT = ("Windows Executables", "PowerShell Script 1", "PowerShell Script 2",
             "Executable Linked Format", "MSOffice", "Shell", "OOXML", "MachO")

    def _entry(self, name, actions):
        return {"@name": name, "mlav-engine-filebased-enabled": {"entry": [
            {"@name": model, "mlav-policy-action": action}
            for model, action in actions.items()]}}

    def test_it_reads_what_the_config_names(self):
        entry = self._entry("p", {m: "enable" for m in self.EIGHT})

        self.assertEqual(profile_ml_models(entry), {m: "enable" for m in self.EIGHT})

    def test_a_profile_with_no_ml_node_names_nothing(self):
        """And that is the finding, not an absence of one: the UI renders every model as
        `disable` for such a profile. The catalogue puts the rows back at persist time."""
        self.assertEqual(profile_ml_models({"@name": "bare"}), {})

    def test_the_catalogue_comes_from_the_profiles_themselves(self):
        """A content update that adds a ninth model adds it here with no code change, because
        the predefined profile is read for the list rather than a constant."""
        class N:
            def __init__(self, kind, models):
                self.kind = kind
                self.ml_models = models

        predefined = N("virus", {m: "enable" for m in self.EIGHT})
        custom = N("virus", {"Windows Executables": "disable"})
        spyware = N("spyware", {})

        catalogue = ml_model_catalogue([predefined, custom, spyware])

        self.assertEqual(set(catalogue), set(self.EIGHT))
        self.assertEqual(catalogue, sorted(catalogue), "stable order, so rows do not churn")

    def test_a_model_only_a_custom_profile_names_is_still_catalogued(self):
        """Rather than dropped because the predefined profile has not heard of it."""
        class N:
            def __init__(self, kind, models):
                self.kind, self.ml_models = kind, models

        catalogue = ml_model_catalogue([
            N("virus", {"Windows Executables": "enable"}),
            N("virus", {"Some New Engine": "enable"})])

        self.assertIn("Some New Engine", catalogue)

    def test_a_non_virus_kind_contributes_nothing_to_the_catalogue(self):
        class N:
            def __init__(self, kind, models):
                self.kind, self.ml_models = kind, models

        self.assertEqual(ml_model_catalogue([N("spyware", {"Nonsense": "enable"})]), [])
