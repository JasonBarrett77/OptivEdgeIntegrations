import ipaddress
from unittest.mock import patch

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
    EnforcementPoint,
    DeviceConfigurationProfile,
    IntegrationEvent,
    IntegrationRun,
    ManagementStation,
    SecurityRule,
    SecurityRuleApplication,
    SecurityRuleSearchVocabularyEntry,
    SecurityRuleService,
    SecurityRuleDestinationAddressRef,
    SecurityRuleSourceAddressRef,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os import (
    PANOSInScopeConfigCollection,
    PANOSInScopeRefreshCollection,
    PANOSInScopeRenormalizationResult,
    PANOSDynamicContentRefreshResult,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_device_configuration,
    normalize_enforcement_point_addresses,
    normalize_enforcement_point_dynamic_address_content,
    normalize_enforcement_point_security_rules,
)
from optivedge_integrations.integrations.orchestration import refresh_panorama_in_scope_data
from optivedge_integrations.integrations.search_vocabulary import (
    rebuild_all_security_rule_search_vocabulary,
    rebuild_security_rule_search_vocabulary,
)


def _create_panorama_enforcement_point(
    *,
    serial_number,
    appliance_hostname,
    station_hostname="panorama.local",
    vsys_name="vsys1",
    vsys_display_name=None,
):
    """Build a ManagementStation/Appliance/EnforcementPoint chain shared by normalization tests."""
    station = ManagementStation.objects.create(
        station_type=ManagementStation.StationType.PAN_PANORAMA,
        hostname=station_hostname,
    )
    appliance = Appliance.objects.create(
        management_station=station,
        serial_number=serial_number,
        hostname=appliance_hostname,
    )
    enforcement_point_kwargs = {"vsys_name": vsys_name}
    if vsys_display_name is not None:
        enforcement_point_kwargs["vsys_display_name"] = vsys_display_name
    enforcement_point = EnforcementPoint.objects.create(
        management_station=station,
        appliance=appliance,
        **enforcement_point_kwargs,
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
    )


def _empty_dynamic_content_refresh_result():
    return PANOSDynamicContentRefreshResult(
        appliances=[],
        enforcement_points=[],
        fqdn_cache_collections=[],
        fqdn_cache_failures=[],
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

    def test_normalize_enforcement_point_security_rules_raises_on_circular_static_address_group(self):
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
        with self.assertRaises(ValueError):
            normalize_enforcement_point_security_rules(enforcement_point)

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

    def test_normalize_enforcement_point_security_rules_raises_on_unresolved_two_letter_value(self):
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
        with self.assertRaises(ValueError):
            normalize_enforcement_point_security_rules(enforcement_point)

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

        response = self.client.get(
            reverse(
                "appliance_group_snapshots",
                kwargs={"pk": station.pk, "appliance_group_pk": appliance_group.pk},
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Merged Config")

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
