import ipaddress
from pathlib import Path
import tempfile
import re
from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressObject,
    AddressObjectResolvedEntry,
    Appliance,
    ApplianceGroup,
    EnforcementNode,
    EnforcementPoint,
    DeviceConfigurationProfile,
    IntegrationEvent,
    IntegrationRun,
    ManagementStation,
    Note,
    PolicyObjectNamespace,
    PolicyObjectPrecedence,
    PolicyObjectScope,
    Region,
    precedence_for,
    scope_for,
    SecurityRule,
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
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
    ISO_3166_1_ALPHA2_REGIONS,
    NormalizedSecurityRuleMember,
    build_normalized_security_rules,
    build_address_lookup_maps,
    first_effective_object,
    literal_namespace,
    resolve_rule_address_refs,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    pushed_shared,
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
    CENSUS_VERSION,
    compare_censuses,
    load_census,
    write_census,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_device_configuration,
    normalize_appliance_group_shared_scope,
    normalize_enforcement_point_addresses,
    normalize_enforcement_point_dynamic_address_content,
    normalize_enforcement_point_security_rules,
    normalize_enforcement_point_zones,
)
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
            device_configuration_normalizations=[],
            device_configuration_failures=[],
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
        device_configuration_normalizations=[],
        device_configuration_failures=[],
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
            name="www.example.com",
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=10,
            address_type=AddressObject.TYPE_FQDN,
            value="www.example.com",
            normalized_value="www.example.com",
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
            payload={"entry": [{"member": "1.2.3.4"}, {"member": "1.2.3.5"}]},
        )
        Snapshot.objects.create(
            appliance=appliance,
            source_type="show_dns_proxy_fqdn_all",
            collected_at=timezone.now(),
            payload={
                "entry": [
                    {"fqdn": "www.example.com", "ip": "5.6.7.8"},
                    {"fqdn": "other.example.com", "ip": "9.9.9.9"},
                ]
            },
        )

        result = normalize_enforcement_point_dynamic_address_content(enforcement_point)

        self.assertEqual(result.total_resolved_entries, 2)
        self.assertEqual(
            {obj.name for obj in result.updated_address_objects},
            {"my-edl", "www.example.com"},
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

        fqdn_entries = list(fqdn_object.resolved_entries.all())
        self.assertEqual(len(fqdn_entries), 1)
        expected_ip = int(ipaddress.IPv4Address("5.6.7.8"))
        self.assertEqual(fqdn_entries[0].ipv4_start_int, expected_ip)
        self.assertEqual(fqdn_entries[0].ipv4_end_int, expected_ip)

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
            payload={"entry": [{"member": "10.0.0.0/24"}]},
        )

        normalize_enforcement_point_dynamic_address_content(enforcement_point)

        entries = list(edl_object.resolved_entries.all())
        self.assertEqual(len(entries), 1)
        self.assertNotEqual(entries[0].ipv4_start_int, 1)


class NegatedComplementNormalizationTests(TestCase):
    def _build_enforcement_point(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-NEG-001",
            appliance_hostname="fw-neg-01",
        )
        return station, appliance, enforcement_point

    def _build_pushed_snapshot(self, *, station, enforcement_point):
        _create_empty_pushed_policy_snapshot(station=station, enforcement_point=enforcement_point)

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

    def test_get_renders_bulk_refresh_button(self):
        response = self.client.get(reverse("management_station_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Refresh All In Scope")


class DeviceConfigurationNormalizationTests(TestCase):
    def test_normalize_appliance_device_configuration_populates_effective_fields(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        appliance_group = ApplianceGroup.objects.create(
            management_station=station,
            name="ha-pair-a",
            group_type=ApplianceGroup.TYPE_HA_PAIR,
        )
        appliance = Appliance.objects.create(
            management_station=station,
            appliance_group=appliance_group,
            serial_number="SERIAL-010",
            hostname="fw-10",
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
                            "deviceconfig": {
                                "high-availability": {
                                    "enabled": "yes",
                                    "group": {
                                        "state-synchronization": {"enabled": "no"},
                                        "monitoring": {
                                            "link-monitoring": {
                                                "enabled": "yes",
                                            }
                                        },
                                    },
                                },
                                "system": {
                                    "ntp-servers": {
                                        "primary-ntp-server": {
                                            "ntp-server-address": "time1.example.com",
                                        },
                                        "secondary-ntp-server": {
                                            "ntp-server-address": "time2.example.com",
                                        },
                                    },
                                    "service": {
                                        "disable-http": "yes",
                                        "disable-telnet": "yes",
                                    },
                                    "permitted-ip": {
                                        "entry": [
                                            {"@name": "10.10.10.0/24"},
                                        ]
                                    },
                                    "login-banner": "Authorized users only.",
                                },
                                "setting": {
                                    "management": {
                                        "idle-timeout": "10",
                                    }
                                },
                            }
                        }
                    }
                }
            },
        )

        normalized = normalize_appliance_device_configuration(appliance)

        self.assertEqual(len(normalized.device_configuration_profiles), 1)
        profile = normalized.device_configuration_profiles[0]
        self.assertTrue(profile.ha_required)
        self.assertTrue(profile.ha_enabled)
        self.assertFalse(profile.ha_state_sync_enabled)
        self.assertTrue(profile.ha_link_monitoring_enabled)
        self.assertEqual(profile.ntp_primary_server, "time1.example.com")
        self.assertEqual(profile.ntp_secondary_server, "time2.example.com")
        self.assertTrue(profile.http_disabled)
        self.assertFalse(profile.https_disabled)
        self.assertTrue(profile.telnet_disabled)
        self.assertFalse(profile.ssh_disabled)
        self.assertEqual(profile.permitted_ip_values, ["10.10.10.0/24"])
        self.assertTrue(profile.has_permitted_ip_restrictions)
        self.assertFalse(profile.has_unrestricted_permitted_ips)
        self.assertEqual(profile.login_banner, "Authorized users only.")
        self.assertEqual(profile.idle_timeout_minutes, 10)

    def test_normalize_appliance_device_configuration_applies_intrinsic_defaults(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        appliance_group = ApplianceGroup.objects.create(
            management_station=station,
            name="standalone-a",
            group_type=ApplianceGroup.TYPE_STANDALONE,
        )
        appliance = Appliance.objects.create(
            management_station=station,
            appliance_group=appliance_group,
            serial_number="SERIAL-011",
            hostname="fw-11",
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
                            "deviceconfig": {
                                "system": {
                                    "service": {
                                        "disable-http": {"#text": "no", "@ptpl": "template-a"},
                                    },
                                    "permitted-ip": {
                                        "entry": [{"@name": "0.0.0.0/0"}],
                                    },
                                    "login-banner": "",
                                }
                            }
                        }
                    }
                }
            },
        )

        normalize_appliance_device_configuration(appliance)
        profile = DeviceConfigurationProfile.objects.get(appliance=appliance)

        self.assertFalse(profile.ha_required)
        self.assertFalse(profile.ha_enabled)
        self.assertFalse(profile.ha_state_sync_enabled)
        self.assertFalse(profile.ha_link_monitoring_enabled)
        from django.contrib.contenttypes.models import ContentType
        from optivedge_integrations.integrations.models import FieldProvenance
        ct = ContentType.objects.get_for_model(DeviceConfigurationProfile)
        self.assertTrue(
            FieldProvenance.objects.filter(
                content_type=ct,
                object_id=profile.pk,
                field_name="http_disabled",
            ).exists()
        )
        self.assertFalse(profile.http_disabled)
        self.assertFalse(profile.https_disabled)
        self.assertFalse(profile.ssh_disabled)
        self.assertTrue(profile.snmp_disabled)
        self.assertTrue(profile.has_permitted_ip_restrictions)
        self.assertTrue(profile.has_unrestricted_permitted_ips)
        self.assertEqual(profile.idle_timeout_minutes, 60)

    def test_normalize_enforcement_point_security_rules_persists_rules_with_edl_objects(self):
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
                                    "rulebase": {
                                        "security": {
                                            "rules": {
                                                "entry": [
                                                    {
                                                        "@name": "rule-plain",
                                                        "from": {"member": ["trust"]},
                                                        "to": {"member": ["untrust"]},
                                                        "source": {"member": ["any"]},
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
        Snapshot.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_type="show_pushed_shared_policy_vsys",
            collected_at=timezone.now(),
            payload={
                "policy": {
                    "panorama": {
                        "external-list": {
                            "entry": [
                                {
                                    "@name": "prod_west_edl",
                                    # Every pushed entry on both lab devices carries @loc
                                    # (398 checked, none missing); scope is derived from it.
                                    "@loc": "prod-west",
                                    "type": {"ip": {"url": "http://192.0.2.10/edl.txt"}},
                                }
                            ]
                        },
                        "pre-rulebase": {
                            "security": {
                                "rules": {
                                    "entry": [
                                        {
                                            "@name": "rule-edl",
                                            "from": {"member": ["trust"]},
                                            "to": {"member": ["untrust"]},
                                            "source": {"member": ["prod_west_edl"]},
                                            "destination": {"member": ["prod_west_edl"]},
                                            "application": {"member": ["ssl"]},
                                            "service": {"member": ["application-default"]},
                                            "action": "allow",
                                        }
                                    ]
                                }
                            }
                        },
                        "post-rulebase": {
                            "security": {"rules": {"entry": []}},
                            "default-security-rules": {"rules": {"entry": []}},
                        },
                    }
                }
            },
        )

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        edl_object = enforcement_point.address_objects.get(name="prod_west_edl")
        self.assertTrue(edl_object.is_edl)
        self.assertEqual(edl_object.address_type, edl_object.TYPE_EDL)
        self.assertEqual(edl_object.namespace_type, "pushed_vsys_effective")

        # Rules referencing an EDL must still be persisted, not silently dropped - only IP
        # semantic matching is unsupported for EDL address objects (same as FQDNs), not
        # existence in the list/search/findings/export pipeline.
        self.assertEqual(
            {rule.name for rule in normalized.security_rules},
            {"rule-plain", "rule-edl"},
        )

        edl_rule = SecurityRule.objects.get(enforcement_point=enforcement_point, name="rule-edl")
        source_ref = edl_rule.source_address_refs.get()
        destination_ref = edl_rule.destination_address_refs.get()
        self.assertEqual(source_ref.ref_type, SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT)
        self.assertEqual(source_ref.address_object, edl_object)
        self.assertEqual(destination_ref.ref_type, SecurityRuleDestinationAddressRef.RefType.ADDRESS_OBJECT)
        self.assertEqual(destination_ref.address_object, edl_object)

    def test_normalization_tolerates_string_pushed_policy_payload(self):
        station, appliance, enforcement_point = _create_panorama_enforcement_point(
            serial_number="SERIAL-003",
            appliance_hostname="fw-03",
            vsys_name="vsys6",
            vsys_display_name="vsys1",
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
                                    "@name": "vsys6",
                                    "address": {"entry": []},
                                    "address-group": {"entry": []},
                                    "rulebase": {
                                        "security": {"rules": {"entry": []}},
                                        "default-security-rules": {"rules": {"entry": []}},
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
            payload="No shared policy pushed to device",
            metadata={"vsys_name": "vsys6"},
        )

        address_normalized = normalize_enforcement_point_addresses(enforcement_point)
        rule_normalized = normalize_enforcement_point_security_rules(enforcement_point)

        self.assertEqual(len(address_normalized.address_groups), 0)
        self.assertEqual(len(rule_normalized.security_rules), 0)
        self.assertEqual(
            [address.name for address in address_normalized.address_objects],
            ["any"],
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

        for tab in ("details", "appliance-groups", "enforcement-points", "events"):
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
        ) as mocked_collect:
            response = self.client.post(
                reverse("management_station_sync", kwargs={"pk": station.pk})
            )

        mocked_collect.assert_called_once()
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

    def test_in_scope_sync_view_succeeds_for_panorama_station(self):
        station = self._create_panorama_station("panorama-in-scope.local")

        with patch(
            "optivedge_integrations.integrations.views.refresh_in_scope_configuration_snapshots",
            return_value=_empty_in_scope_refresh_collection(),
        ):
            response = self.client.post(
                reverse("management_station_in_scope_sync", kwargs={"pk": station.pk})
            )

        self.assertRedirects(
            response,
            reverse("management_station_detail", kwargs={"pk": station.pk}),
        )
        run = IntegrationRun.objects.get(management_station=station)
        self.assertEqual(run.status, IntegrationRun.STATUS_SUCCEEDED)
        messages = list(response.wsgi_request._messages)
        self.assertIn("In-scope configuration refresh completed", messages[0].message)

    def test_renormalize_view_succeeds(self):
        station = self._create_panorama_station("panorama-renorm.local")

        with patch(
            "optivedge_integrations.integrations.views.renormalize_in_scope_configuration",
            return_value=_empty_renormalization_result(),
        ):
            response = self.client.post(
                reverse("management_station_renormalize", kwargs={"pk": station.pk})
            )

        self.assertRedirects(response, reverse("management_station_list"))
        run = IntegrationRun.objects.get(management_station=station)
        self.assertEqual(run.status, IntegrationRun.STATUS_SUCCEEDED)

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
                                        "packet-buffer-protection": "yes",
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
        """Not reported and reported-as-no are different facts; don't collapse them."""
        zones = {zone.name: zone for zone in build_normalized_zones(ZONE_MERGED_CONFIG_PAYLOAD, "vsys1")}

        self.assertIsNone(zones["dmz"].packet_buffer_protection)
        self.assertFalse(zones["dmz"].enable_user_identification)

    def test_single_member_is_read_as_one_interface_not_characters(self):
        """xmltodict collapses a one-element member list to a bare string."""
        zones = {zone.name: zone for zone in build_normalized_zones(ZONE_MERGED_CONFIG_PAYLOAD, "vsys1")}

        self.assertEqual([i.name for i in zones["dmz"].interfaces], ["loopback.1"])

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


class EnforcementPointListViewTests(TestCase):
    def setUp(self):
        _, _, _, self.in_scope = _create_grouped_enforcement_point(
            serial_number="0001",
            appliance_hostname="fw-a",
            station_hostname="panorama-a.local",
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            group_name="grp-a",
            vsys_name="vsys1",
        )
        self.in_scope.in_scope = True
        self.in_scope.save()

        _, _, _, self.out_of_scope = _create_grouped_enforcement_point(
            serial_number="0002",
            appliance_hostname="fw-b",
            station_hostname="firewall-b.local",
            station_type=ManagementStation.StationType.PAN_FIREWALL,
            group_name="grp-b",
            vsys_name="vsys2",
        )

    def listed_pks(self, query=None):
        response = self.client.get(reverse("enforcement_point_list"), query or {})
        self.assertEqual(response.status_code, 200)
        return response, [point.pk for point in response.context["enforcement_points"]]

    def test_list_view_shows_only_in_scope_points_by_default(self):
        """in_scope gates collection, so an out-of-scope point carries no rules or objects."""
        response, pks = self.listed_pks()

        self.assertEqual(pks, [self.in_scope.pk])
        self.assertEqual(response.context["scope_filter"], "in")

    def test_scope_filter_selects_out_of_scope_points(self):
        _, pks = self.listed_pks({"scope": "out"})

        self.assertEqual(pks, [self.out_of_scope.pk])

    def test_scope_filter_all_shows_both(self):
        _, pks = self.listed_pks({"scope": "all"})

        self.assertEqual(sorted(pks), sorted([self.in_scope.pk, self.out_of_scope.pk]))

    def test_unknown_scope_filter_falls_back_to_in_scope(self):
        response, pks = self.listed_pks({"scope": "not-a-scope"})

        self.assertEqual(pks, [self.in_scope.pk])
        self.assertEqual(response.context["scope_filter"], "in")

    def test_list_view_shows_points_from_every_management_station(self):
        response, pks = self.listed_pks({"scope": "all"})

        self.assertContains(response, "panorama-a.local")
        self.assertContains(response, "firewall-b.local")
        self.assertContains(response, reverse("enforcement_point_detail", kwargs={"pk": self.in_scope.pk}))
        self.assertContains(response, reverse("enforcement_point_detail", kwargs={"pk": self.out_of_scope.pk}))

    def test_columns_lead_with_appliance_names_and_omit_owner_type(self):
        response = self.client.get(reverse("enforcement_point_list"))

        headers = re.findall(r"<th[^>]*>\s*(.*?)\s*</th>", response.content.decode())
        self.assertEqual(
            headers,
            [
                "Appliance Names",
                "VSYS",
                "Management Station",
                "Appliance Group",
                "Last Synced",
                "In Scope",
            ],
        )

    def test_empty_state_names_the_active_filter(self):
        EnforcementPoint.objects.all().delete()

        self.assertContains(self.client.get(reverse("enforcement_point_list")), "No in-scope enforcement points")
        self.assertContains(
            self.client.get(reverse("enforcement_point_list"), {"scope": "out"}),
            "No out-of-scope enforcement points",
        )
        self.assertContains(
            self.client.get(reverse("enforcement_point_list"), {"scope": "all"}),
            "No enforcement points discovered",
        )


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
    def test_sidebar_lists_enforcement_points_below_management_stations(self):
        from optivedge.app_registry import sidebar_sections

        sections = [s for s in sidebar_sections() if s["label"] == "Firewall Integrations"]
        self.assertEqual(len(sections), 1)

        labels = [item["label"] for item in sections[0]["items"]]
        self.assertEqual(labels, ["Management Stations", "Enforcement Points"])

    def test_sidebar_active_names_cover_every_enforcement_point_route(self):
        """A route missing from active_names silently stops highlighting its own page."""
        from optivedge_integrations.integrations import app_meta

        item = next(
            item
            for section in app_meta.SIDEBAR_SECTION
            for item in section["items"]
            if item["label"] == "Enforcement Points"
        )
        self.assertEqual(
            item["active_names"],
            {"enforcement_point_list", "enforcement_point_detail", "enforcement_point_zone_detail"},
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
            f"{reverse('management_station_detail', kwargs={'pk': station.pk})}?tab=enforcement-points",
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

        objects, groups = build_normalized_addresses(point)
        # Only the synthesized builtin "any" survives - nothing Panorama-derived, because
        # there is no Panorama. Previously this call raised instead of returning.
        self.assertEqual(
            [(obj.name, obj.namespace_type) for obj in objects],
            [("any", "builtin")],
        )
        self.assertEqual(groups, [])
        self.assertEqual(build_normalized_regions(point), [])
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

        objects, _ = build_normalized_addresses(point)
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
        objects, _ = build_normalized_addresses(point)
        ovr = sorted((o for o in objects if o.name == "ovr"), key=lambda o: o.namespace_type)
        self.assertEqual(
            [(o.namespace_type, o.value) for o in ovr],
            [(PolicyObjectNamespace.PANORAMA_SHARED, "10.213.1.1"),
             (PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE, "10.214.1.1")],
        )

    def test_same_key_with_conflicting_definitions_raises(self):
        station, point = self._point()
        self._pushed(
            station, point,
            group_payload={"shared": {"address": {"entry": [
                self._addr("clash", "shared", "10.0.0.1")]}}},
            vsys_payload={"policy": {"panorama": {"address": {"entry": [
                self._addr("clash", "shared", "10.0.0.99")]}}}},
        )
        with self.assertRaisesMessage(ValueError, "conflicting pushed address definitions"):
            build_normalized_addresses(point)

    def test_pushed_entry_without_loc_raises_rather_than_guessing(self):
        station, point = self._point()
        self._pushed(
            station, point,
            group_payload={"shared": {"address": {"entry": [
                {"@name": "no-loc", "ip-netmask": "10.0.0.1"}]}}},
            vsys_payload={"policy": {"panorama": {}}},
        )
        with self.assertRaisesMessage(ValueError, "has no @loc marker"):
            build_normalized_addresses(point)


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

        objects, _ = build_normalized_addresses(point)
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
