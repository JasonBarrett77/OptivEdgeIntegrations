from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressObject,
    Appliance,
    ApplianceGroup,
    EnforcementPoint,
    DeviceConfigurationProfile,
    ManagementStation,
    SecurityRule,
    SecurityRuleApplication,
    SecurityRuleSearchVocabularyEntry,
    SecurityRuleService,
    SecurityRuleDestinationAddressRef,
    SecurityRuleSourceAddressRef,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_device_configuration,
    normalize_enforcement_point_addresses,
    normalize_enforcement_point_security_rules,
)
from optivedge_integrations.integrations.orchestration import refresh_panorama_in_scope_data
from optivedge_integrations.integrations.orchestration.pan_os import refresh_all_panorama_in_scope_data
from optivedge_integrations.integrations.search_vocabulary import (
    rebuild_all_security_rule_search_vocabulary,
    rebuild_security_rule_search_vocabulary,
)


class AddressNormalizationTests(TestCase):
    def test_normalize_enforcement_point_addresses_populates_derived_fields_and_builtin_any(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        appliance = Appliance.objects.create(
            management_station=station,
            serial_number="SERIAL-001",
            hostname="fw-01",
        )
        enforcement_point = EnforcementPoint.objects.create(
            management_station=station,
            appliance=appliance,
            vsys_name="vsys1",
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
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        appliance = Appliance.objects.create(
            management_station=station,
            serial_number="SERIAL-002",
            hostname="fw-02",
        )
        enforcement_point = EnforcementPoint.objects.create(
            management_station=station,
            appliance=appliance,
            vsys_name="vsys1",
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
        Snapshot.objects.create(
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
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname=hostname,
        )
        appliance = Appliance.objects.create(
            management_station=station,
            serial_number=serial_number,
            hostname=appliance_hostname,
        )
        enforcement_point = EnforcementPoint.objects.create(
            management_station=station,
            appliance=appliance,
            vsys_name="vsys1",
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
            "integrations.orchestration.pan_os.refresh_in_scope_configuration_snapshots",
            side_effect=fake_platform_refresh,
        ), patch(
            "integrations.orchestration.pan_os.rebuild_security_rule_search_vocabulary",
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

    def test_refresh_all_panorama_in_scope_data_runs_all_platform_refreshes_then_bulk_vocabulary_rebuild(self):
        first_station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-a.local",
        )
        second_station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-b.local",
        )
        ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_FIREWALL,
            hostname="firewall.local",
        )
        call_order: list[tuple[str, object]] = []

        def fake_platform_refresh(management_station, **kwargs):
            call_order.append(("platform", management_station))
            return f"refresh:{management_station.hostname}"

        def fake_bulk_vocab_rebuild():
            call_order.append(("vocab", "all"))
            return ["vocab-result-a", "vocab-result-b"]

        with patch(
            "integrations.orchestration.pan_os.refresh_in_scope_configuration_snapshots",
            side_effect=fake_platform_refresh,
        ), patch(
            "integrations.orchestration.pan_os.rebuild_all_security_rule_search_vocabulary",
            side_effect=fake_bulk_vocab_rebuild,
        ):
            result = refresh_all_panorama_in_scope_data()

        self.assertEqual(
            result.platform_refreshes,
            [
                (first_station, "refresh:panorama-a.local"),
                (second_station, "refresh:panorama-b.local"),
            ],
        )
        self.assertEqual(result.security_rule_search_vocabulary, ["vocab-result-a", "vocab-result-b"])
        self.assertEqual(
            call_order,
            [
                ("platform", first_station),
                ("platform", second_station),
                ("vocab", "all"),
            ],
        )


class ManagementStationBulkInScopeSyncViewTests(TestCase):
    def test_post_starts_background_refresh_and_redirects_immediately(self):
        ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama-view.local",
        )

        with (
            patch("optivedge_integrations.integrations.views.threading.Thread") as mocked_thread_cls,
            patch("optivedge_integrations.integrations.views.refresh_all_panorama_in_scope_data") as mocked_refresh,
        ):
            response = self.client.post(reverse("management_station_bulk_in_scope_sync"))

            # The view starts a background thread instead of running the refresh inline.
            mocked_thread_cls.assert_called_once()
            _, kwargs = mocked_thread_cls.call_args
            self.assertTrue(kwargs["daemon"])
            mocked_thread_cls.return_value.start.assert_called_once()
            mocked_refresh.assert_not_called()

            # Invoking the thread's target directly simulates the background thread running,
            # while the patches above are still active.
            kwargs["target"]()
            mocked_refresh.assert_called_once_with()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("management_station_list"))

        messages = list(response.wsgi_request._messages)
        self.assertEqual(len(messages), 1)
        self.assertIn("started in the background", messages[0].message)

    def test_get_renders_bulk_refresh_button(self):
        response = self.client.get(reverse("management_station_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Refresh All In Scope")

    def test_normalize_enforcement_point_security_rules_realizes_literal_address_objects(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        appliance = Appliance.objects.create(
            management_station=station,
            serial_number="SERIAL-003",
            hostname="fw-03",
        )
        enforcement_point = EnforcementPoint.objects.create(
            management_station=station,
            appliance=appliance,
            vsys_name="vsys1",
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
        Snapshot.objects.create(
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

        normalize_enforcement_point_addresses(enforcement_point)
        normalized = normalize_enforcement_point_security_rules(enforcement_point)

        self.assertEqual(len(normalized.security_rules), 1)
        literal_object = enforcement_point.address_objects.get(name="10.0.0.0/8")
        self.assertFalse(literal_object.field_provenance.filter(field_name="__entry__").exists())
        self.assertEqual(literal_object.address_type, literal_object.TYPE_IP_NETMASK)
        self.assertEqual(literal_object.normalized_value, "10.0.0.0/8")
        self.assertEqual(literal_object.namespace_type, "local_vsys")
        self.assertEqual(literal_object.namespace_value, "vsys1")


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

    def test_normalize_enforcement_point_security_rules_skips_rules_with_edl_objects(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        appliance = Appliance.objects.create(
            management_station=station,
            serial_number="SERIAL-004",
            hostname="fw-04",
        )
        enforcement_point = EnforcementPoint.objects.create(
            management_station=station,
            appliance=appliance,
            vsys_name="vsys1",
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

        self.assertEqual(len(normalized.security_rules), 1)
        self.assertEqual(normalized.security_rules[0].name, "rule-plain")

    def test_normalization_tolerates_string_pushed_policy_payload(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        appliance = Appliance.objects.create(
            management_station=station,
            serial_number="SERIAL-003",
            hostname="fw-03",
        )
        enforcement_point = EnforcementPoint.objects.create(
            management_station=station,
            appliance=appliance,
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
