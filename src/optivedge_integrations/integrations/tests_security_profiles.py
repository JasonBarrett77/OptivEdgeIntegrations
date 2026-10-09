"""Anti-spyware and vulnerability profile normalization - PAN-SPY-001 and PAN-VLN-001's subjects.

Every rule shape below is what the lab STORED, read back after commit on 2026-09-11 (fw-core-tpa-b
vsys1, pan-fw-111 shared, Panorama shared) or what /config/predefined/profiles returns - not a
shape reconstructed from documentation. The verdict is order-independent (Jason, 2026-09-11); the
cases pin both of its edges: a non-blocking rule ABOVE a broad blocking one fails, and so does
the same rule BELOW it, which is the accepted cost.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from optivedge_integrations.integrations.models import PolicyObjectNamespace, SecurityProfile
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_profiles import (
    NormalizedSecurityProfile,
    ProfileReference,
    attribute_references,
    collect_references,
    profile_rules,
    rule_action,
    severity_verdict,
)

SPY = SecurityProfile.KIND_SPYWARE
VLN = SecurityProfile.KIND_VULNERABILITY


def spy_rule(name, severities, action, category="any"):
    return {"@name": name, "threat-name": "any", "category": category,
            "severity": {"member": severities}, "action": {action: None}}


def vln_rule(name, severities, action, host="any"):
    return {"@name": name, "threat-name": "any", "category": "any", "host": host,
            "cve": {"member": ["any"]}, "vendor-id": {"member": ["any"]},
            "severity": {"member": severities}, "action": {action: None}}


ADWARE_ALERT = spy_rule("adware-alert", ["critical"], "alert", category="adware")
BROAD_BLOCK = spy_rule("broad-block", ["critical", "high"], "reset-both")


def verdicts(kind, rules):
    return {s: severity_verdict(kind, rules, s) for s in ("critical", "high")}


class SeverityVerdictTests(SimpleTestCase):
    def test_a_broad_reset_both_rule_blocks(self):
        self.assertEqual(verdicts(SPY, [spy_rule("block-chm", ["critical", "high", "medium"], "reset-both")]),
                         {"critical": (True, "reset-both"), "high": (True, "reset-both")})

    def test_drop_counts_as_blocking(self):
        # Any blocking action passes (Jason, 2026-09-11), not only the corpus's reset-both.
        self.assertEqual(verdicts(SPY, [spy_rule("drop-ch", ["critical", "high"], "drop")])["high"], (True, "drop"))

    def test_an_alert_rule_fails_only_its_own_severity(self):
        result = verdicts(SPY, [spy_rule("block-critical", ["critical"], "reset-both"),
                                spy_rule("alert-high", ["high"], "alert")])
        self.assertEqual(result, {"critical": (True, "reset-both"), "high": (False, "alert by rule alert-high")})

    def test_a_narrow_alert_rule_above_a_broad_block_fails(self):
        self.assertEqual(verdicts(SPY, [ADWARE_ALERT, BROAD_BLOCK])["critical"],
                         (False, "alert by rule adware-alert"))

    def test_the_same_rules_in_the_other_order_also_fail(self):
        # First-match would never reach the alert rule here. The order-independent verdict still
        # fails it - the cost Jason accepted for not depending on an undocumented ordering.
        self.assertEqual(verdicts(SPY, [BROAD_BLOCK, ADWARE_ALERT])["critical"],
                         (False, "alert by rule adware-alert"))
        self.assertEqual(verdicts(SPY, [BROAD_BLOCK, ADWARE_ALERT])["high"], (True, "reset-both"))

    def test_a_narrow_rule_alone_does_not_cover_a_severity(self):
        only_adware = [spy_rule("adware-block", ["critical"], "reset-both", category="adware")]
        self.assertEqual(verdicts(SPY, only_adware)["critical"], (False, "no catch-all rule"))

    def test_a_profile_with_no_rules_blocks_nothing(self):
        self.assertEqual(profile_rules({"@name": "oep-spy-empty", "description": "x"}), [])
        self.assertEqual(verdicts(SPY, []), {"critical": (False, "no catch-all rule"),
                                             "high": (False, "no catch-all rule")})

    def test_severity_any_covers_every_severity(self):
        self.assertEqual(verdicts(SPY, [spy_rule("all", ["any"], "reset-both")])["high"], (True, "reset-both"))

    def test_default_is_not_a_blocking_action(self):
        # The shipped `default` profile, as /config/predefined/profiles returns it.
        predefined_default = [spy_rule(f"simple-{s}", [s], "default") for s in ("critical", "high", "medium", "low")]
        self.assertEqual(verdicts(SPY, predefined_default)["critical"], (False, "default by rule simple-critical"))

    def test_a_client_only_vulnerability_rule_leaves_the_server_side_uncovered(self):
        rules = [vln_rule("block-ch-client", ["critical", "high"], "reset-both", host="client")]
        self.assertEqual(verdicts(VLN, rules)["critical"], (False, "server side: no catch-all rule"))

    def test_one_host_any_rule_failing_both_sides_is_reported_once(self):
        rules = [vln_rule("default-ch", ["critical", "high"], "default")]
        self.assertEqual(verdicts(VLN, rules)["high"], (False, "default by rule default-ch"))

    def test_host_any_covers_client_and_server(self):
        self.assertEqual(verdicts(VLN, [vln_rule("block-ch", ["critical", "high"], "reset-both")])["critical"],
                         (True, "reset-both"))

    def test_a_cve_narrowed_rule_is_not_a_catch_all(self):
        narrowed = vln_rule("cve-only", ["critical"], "reset-both")
        narrowed["cve"] = {"member": ["CVE-2021-44228"]}
        self.assertEqual(verdicts(VLN, [narrowed])["critical"], (False, "no catch-all rule"))

    def test_a_pushed_action_carries_loc_beside_the_choice(self):
        self.assertEqual(rule_action({"action": {"@loc": "shared", "reset-both": {"@loc": "shared"}}}), "reset-both")


def profile(name, namespace_type, kind=SPY):
    return NormalizedSecurityProfile(
        source_snapshot=None, config_source="local", kind=kind, name=name, namespace_type=namespace_type,
        namespace_value="x", precedence_rank=0, description="", rule_count=0, threat_exception_count=0,
        verdicts={}, decoders=[], ml_models={}, application_overrides=[], wildfire_rules=[],
        raw_profile={},
        field_provenance_data=[])


class ReferenceTests(SimpleTestCase):
    def test_rules_and_groups_are_referrers_and_definitions_are_not(self):
        vsys = {
            "profiles": {"spyware": {"entry": [{"@name": "oep-spy-pass", "rules": {"entry": []}}]}},
            "profile-group": {"entry": [{"@name": "oep-pg-predefined", "spyware": {"member": ["strict"]},
                                         "vulnerability": {"member": ["oep-vln-pass"]}}]},
            "rulebase": {"security": {"rules": {"entry": [{"@name": "allow-web", "profile-setting": {
                "profiles": {"spyware": {"member": ["oep-spy-pass"]}}}}]}}},
        }
        found = collect_references(vsys, where="vsys1 ", shared_root=False, pushed=False)
        self.assertEqual(sorted((r.kind, r.name, r.referrer) for r in found), [
            ("spyware", "oep-spy-pass", "vsys1 rulebase/security/rules/allow-web"),
            ("spyware", "strict", "vsys1 profile-group/oep-pg-predefined"),
            ("vulnerability", "oep-vln-pass", "vsys1 profile-group/oep-pg-predefined"),
        ])
        self.assertFalse(any(r.shared_scope for r in found))

    def test_a_pushed_referrer_takes_its_scope_from_loc(self):
        pushed = {"profile-group": {"entry": [
            {"@name": "OutBound-Block", "@loc": "shared",
             "vulnerability": {"@loc": "shared", "member": [{"@loc": "shared", "#text": "default"}]}},
            {"@name": "dg-group", "@loc": "dg_fw-core-tpa_application",
             "spyware": {"member": [{"@loc": "dg_fw-core-tpa_application", "#text": "strict"}]}},
        ]}}
        found = {r.name: r for r in collect_references(pushed, where="pushed ", shared_root=False, pushed=True)}
        self.assertTrue(found["default"].shared_scope)
        self.assertFalse(found["strict"].shared_scope)

    def test_a_vsys_reference_resolves_vsys_then_shared_then_predefined(self):
        profiles = [profile("p", PolicyObjectNamespace.LOCAL_VSYS), profile("p", PolicyObjectNamespace.LOCAL_SHARED),
                    profile("strict", PolicyObjectNamespace.PREDEFINED)]
        refs = [ProfileReference(SPY, "p", "vsys rule", False), ProfileReference(SPY, "p", "shared group", True),
                ProfileReference(SPY, "strict", "vsys rule", False), ProfileReference(SPY, "missing", "vsys rule", False)]
        attributed, unresolved = attribute_references(refs, profiles)
        self.assertEqual(attributed[profiles[0].key], ["vsys rule"])
        # A shared referrer cannot see a vsys definition, so it lands on the shared one.
        self.assertEqual(attributed[profiles[1].key], ["shared group"])
        self.assertEqual(attributed[profiles[2].key], ["vsys rule"])
        self.assertEqual([r.name for r in unresolved], ["missing"])

    def test_one_referrer_seen_through_two_reads_counts_once(self):
        # On a single-vsys firewall the two pushed reads are byte-identical.
        refs = [ProfileReference(SPY, "strict", "pushed profile-group/g", False)] * 2
        attributed, _ = attribute_references(refs, [profile("strict", PolicyObjectNamespace.PREDEFINED)])
        self.assertEqual(list(attributed.values()), [["pushed profile-group/g"]])
