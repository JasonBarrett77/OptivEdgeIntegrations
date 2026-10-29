"""Anti-spyware and vulnerability profile normalization - PAN-SPY-001 and PAN-VLN-001's subjects.

Every rule shape below is what the lab STORED, read back after commit on 2026-09-11 (fw-core-tpa-b
vsys1, pan-fw-111 shared, Panorama shared) or what /config/predefined/profiles returns - not a
shape reconstructed from documentation. The verdict is order-independent (Jason, 2026-09-11); the
cases pin both of its edges: a non-blocking rule ABOVE a broad blocking one fails, and so does
the same rule BELOW it, which is the accepted cost.
"""

from __future__ import annotations

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    Certificate,
    DataFilteringPosture,
    DecryptionSettings,
    EnforcementNode,
    EnforcementPoint,
    FieldProvenance,
    ManagementStation,
    PolicyObjectNamespace,
    SecurityProfile,
    SecurityProfileInlineDetector,
    SecurityProfileThreatException,
    SecurityRule,
    SecurityRuleProfileVerdict,
    Snapshot,
    SslTlsServiceProfile,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_profiles import (
    DECRYPTION_ALGORITHM_SWITCHES,
    DECRYPTION_BLOCK_SWITCHES,
    NormalizedSecurityProfile,
    ProfileReference,
    attribute_references,
    collect_profile_and_group_references,
    collect_references,
    data_filtering_rule_pattern_names,
    data_filtering_verdicts,
    decryption_profile_values,
    decryption_rule_facts,
    decryption_rule_references,
    decryption_version_rank,
    data_pattern_defines_a_pattern,
    file_blocking_verdicts,
    reference_reach_by_key,
    GroupReference,
    NormalizedSecurityProfileGroup,
    VIA_GROUP,
    VIA_RULE,
    inline_detector_action,
    profile_inline_detector_ldl,
    profile_rules,
    profile_threat_exceptions,
    normalize_security_profile,
    normalize_security_rule_profile_coverage,
    rule_action,
    category_verdict,
    dns_security_categories,
    dns_signature_sources,
    dns_sinkhole_address,
    severity_verdict,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_group_security_profiles,
    normalize_security_profiles,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.decryption import (
    normalize_decryption_settings,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
    normalize_security_rules,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors import (
    build_pushed_vsys_profiles_xpath,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    pushed_vsys_profiles,
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
        exception_surfaces={},
        inline_detectors={},
        inline_detector_ldl={},
        threat_exceptions=[],
        cloud_inline_analysis=False,
        category_verdicts={},
        dns_signature_sources=[], dns_categories=[],
        dns_sinkhole_ipv4='', dns_sinkhole_ipv6='',
        has_rules=False, file_blocking={}, data_filtering={}, pattern_names=[],
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


def bf_rule(name, severities, action, *, category="brute-force", host="any",
            track_by="source", duration=300, threat_name="any", cve=("any",)):
    """A vulnerability rule, with `block-ip`'s children when the action is block-ip."""
    if action == "block-ip":
        inner = {}
        if track_by:
            inner["track-by"] = track_by
        if duration is not None:
            inner["duration"] = str(duration)
        node = {"block-ip": inner or None}
    else:
        node = {action: None}
    return {"@name": name, "threat-name": threat_name, "category": category, "host": host,
            "cve": {"member": list(cve)}, "vendor-id": {"member": ["any"]},
            "severity": {"member": severities}, "action": node}


ALL_SEV = ["critical", "high", "medium"]


class CategoryVerdictTests(SimpleTestCase):
    """PAN-VLN-002: is the SOURCE of a brute-force attempt blocked?"""

    def verdict(self, rules):
        return category_verdict(VLN, rules, "brute-force")

    def test_a_block_ip_rule_on_the_category_blocks_the_source(self):
        blocks, weakest, track_by, duration, detail = self.verdict(
            [bf_rule("bf", ALL_SEV, "block-ip")])
        self.assertTrue(blocks)
        self.assertEqual((weakest, track_by, duration, detail),
                         ("block-ip", "source", 300, ""))

    def test_a_category_any_rule_also_covers_brute_force(self):
        # A rule not narrowing by category covers every category, including this one.
        self.assertTrue(self.verdict([bf_rule("all", ALL_SEV, "block-ip", category="any")])[0])

    def test_reset_both_blocks_the_threat_and_not_the_source(self):
        # The distinction the whole control rests on: this rule PASSES PAN-VLN-001.
        blocks, weakest, _, _, detail = self.verdict([bf_rule("rb", ALL_SEV, "reset-both")])
        self.assertFalse(blocks)
        self.assertEqual(weakest, "reset-both")
        self.assertIn("reset-both by rule rb", detail)

    def test_no_rule_covering_the_category_at_all(self):
        blocks, weakest, _, _, detail = self.verdict([])
        self.assertFalse(blocks)
        self.assertEqual(weakest, "")
        self.assertIn("no rule covers brute-force", detail)

    def test_block_ip_without_track_by_is_not_credited(self):
        # `track-by` is required at COMMIT, so such a rule cannot be running - but it can sit
        # in a candidate, and a profile read from one is not blocking anything yet.
        blocks, _, _, _, detail = self.verdict(
            [bf_rule("bf", ALL_SEV, "block-ip", track_by="")])
        self.assertFalse(blocks)
        self.assertIn("block-ip by rule bf", detail)

    def test_covering_only_critical_does_not_cover_the_category(self):
        blocks, _, _, _, detail = self.verdict([bf_rule("bf", ["critical"], "block-ip")])
        self.assertFalse(blocks)
        self.assertIn("high", detail)

    def test_a_client_only_rule_leaves_the_server_side_open(self):
        blocks, _, _, _, detail = self.verdict(
            [bf_rule("bf", ALL_SEV, "block-ip", host="client")])
        self.assertFalse(blocks)
        self.assertIn("server side", detail)

    def test_a_signature_narrowed_rule_does_not_cover_the_category(self):
        # It can only open a hole, never establish coverage - the same reading `is_catch_all`
        # applies to a severity.
        blocks, _, _, _, detail = self.verdict(
            [bf_rule("one", ALL_SEV, "block-ip", threat_name="RDP")])
        self.assertFalse(blocks)
        self.assertIn("no rule covers", detail)

    def test_a_weak_rule_fails_whichever_order_it_sits_in(self):
        strong = bf_rule("strong", ALL_SEV, "block-ip")
        weak = bf_rule("weak", ALL_SEV, "alert")
        self.assertFalse(self.verdict([strong, weak])[0])
        self.assertFalse(self.verdict([weak, strong])[0])

    def test_duration_absent_reads_as_None_not_zero(self):
        # The implicit value was NOT established, so None means the config is silent.
        blocks, _, track_by, duration, _ = self.verdict(
            [bf_rule("bf", ALL_SEV, "block-ip", duration=None)])
        self.assertTrue(blocks)
        self.assertEqual((track_by, duration), ("source", None))

    def test_source_and_destination_tracking_also_blocks(self):
        blocks, _, track_by, _, _ = self.verdict(
            [bf_rule("bf", ALL_SEV, "block-ip", track_by="source-and-destination")])
        self.assertTrue(blocks)
        self.assertEqual(track_by, "source-and-destination")

    def test_a_spyware_profile_is_judged_on_one_side_only(self):
        # Spyware rules carry no `host`, so there is no client/server split to fail on.
        self.assertTrue(category_verdict(
            SPY, [bf_rule("bf", ALL_SEV, "block-ip")], "brute-force")[0])


class CategoryCoverageAsymmetryTests(SimpleTestCase):
    """A rule NAMING the category governs; a `category any` rule can only ADD coverage.

    Every case here was reachable on the lab, and the first one was a real false positive:
    a profile written exactly as PAN-VLN-002's own remediation describes reported as failing,
    because the catch-all rule PAN-VLN-001 requires also matches brute-force signatures.
    """

    def verdict(self, rules):
        return category_verdict(VLN, rules, "brute-force")

    def test_a_dedicated_rule_survives_a_weaker_catch_all(self):
        # The lab's oep-vln-bf-blocked, and the configuration the corpus tells engineers to
        # build. Weakest-wins judged this as not blocking.
        blocks, weakest, track_by, duration, detail = self.verdict([
            bf_rule("block-severity", ALL_SEV, "reset-both", category="any"),
            bf_rule("bf", ALL_SEV, "block-ip"),
        ])
        self.assertTrue(blocks, detail)
        self.assertEqual((weakest, track_by, duration), ("block-ip", "source", 300))

    def test_the_catch_all_cannot_be_credited_when_it_does_not_block_the_source(self):
        blocks, weakest, _, _, detail = self.verdict(
            [bf_rule("block-severity", ALL_SEV, "reset-both", category="any")])
        self.assertFalse(blocks)
        self.assertEqual(weakest, "reset-both")
        self.assertIn("reset-both by rule block-severity", detail)

    def test_a_catch_all_that_does_block_the_source_is_enough_on_its_own(self):
        # It genuinely blocks the source of every category, brute force among them.
        blocks, _, track_by, _, detail = self.verdict(
            [bf_rule("all-block", ALL_SEV, "block-ip", category="any")])
        self.assertTrue(blocks, detail)
        self.assertEqual(track_by, "source")

    def test_a_weak_rule_NAMING_the_category_is_not_rescued_by_a_strong_catch_all(self):
        # The direction that must stay strict: an explicit brute-force exception to an
        # otherwise source-blocking profile is exactly what this control should report.
        blocks, weakest, _, _, detail = self.verdict([
            bf_rule("all-block", ALL_SEV, "block-ip", category="any"),
            bf_rule("bf-alert", ALL_SEV, "alert"),
        ])
        self.assertFalse(blocks)
        self.assertEqual(weakest, "alert")
        self.assertIn("alert by rule bf-alert", detail)

    def test_a_dedicated_rule_covering_one_severity_does_not_cover_the_rest(self):
        # The lab's oep-vln-bf-critical: high and medium fall through to the catch-all, and a
        # catch-all that does not block the source cannot cover them.
        blocks, _, _, _, detail = self.verdict([
            bf_rule("block-severity", ALL_SEV, "reset-both", category="any"),
            bf_rule("bf", ["critical"], "block-ip"),
        ])
        self.assertFalse(blocks)
        self.assertIn("reset-both by rule block-severity", detail)
        self.assertIn("high", detail)

    def test_a_dedicated_rule_on_one_host_side_leaves_the_other_to_the_catch_all(self):
        # The lab's oep-vln-bf-client.
        blocks, _, _, _, detail = self.verdict([
            bf_rule("block-severity", ALL_SEV, "reset-both", category="any"),
            bf_rule("bf", ALL_SEV, "block-ip", host="client"),
        ])
        self.assertFalse(blocks)
        self.assertIn("server side", detail)


def spy_profile_entry(name, *, lists=None, sinkhole=None):
    """An anti-spyware profile entry as `show config` returns it."""
    entry = {"@name": name}
    botnet = {}
    if lists is not None:
        botnet["lists"] = {"entry": [
            {"@name": n, "action": {a: None}} for n, a in lists]}
    if sinkhole is not None:
        botnet["sinkhole"] = {k: v for k, v in sinkhole.items()}
    if botnet:
        entry["botnet-domains"] = botnet
    return entry


class DnsSignatureSourceTests(SimpleTestCase):
    """PAN-SPY-002: which DNS source sinkholes, and what absence means."""

    def test_the_predefined_strict_shape_sinkholes(self):
        rows = dns_signature_sources(spy_profile_entry(
            "strict", lists=[("default-paloalto-dns", "sinkhole")],
            sinkhole={"ipv4-address": "pan-sinkhole-default-ip", "ipv6-address": "::1"}))
        self.assertEqual(rows, [("default-paloalto-dns", True, "paloalto-content",
                                 "sinkhole", "sinkhole", True, True, False)])

    def test_the_predefined_default_shape_does_NOT_sinkhole(self):
        # Measured 2026-10-11: `default` ships with ALERT, not sinkhole. The payload contract
        # said both predefined profiles sinkholed, from reading `strict` and generalising.
        rows = dns_signature_sources(spy_profile_entry(
            "default", lists=[("default-paloalto-dns", "alert")]))
        self.assertEqual(rows[0][3:], ("alert", "alert", False, False, False))

    def test_an_absent_source_is_synthesized_and_flagged_implicit(self):
        rows = dns_signature_sources(spy_profile_entry("bare"))
        self.assertEqual(rows, [("default-paloalto-dns", True, "paloalto-content", "",
                                 "sinkhole", True, True, True)])

    def test_block_does_not_count_as_sinkholing(self):
        # It breaks C2 resolution and loses the infected client, which is half the control.
        rows = dns_signature_sources(spy_profile_entry(
            "blocked", lists=[("default-paloalto-dns", "block")]))
        self.assertFalse(rows[0][5])

    def test_an_edl_gets_a_row_and_is_not_the_asserted_source(self):
        rows = dns_signature_sources(spy_profile_entry(
            "edl", lists=[("corp-dns-allow", "allow"),
                          ("default-paloalto-dns", "sinkhole")]))
        by_name = {r[0]: r for r in rows}
        self.assertFalse(by_name["corp-dns-allow"][1])
        self.assertTrue(by_name["default-paloalto-dns"][1])

    def test_an_edl_only_profile_still_gets_the_synthesized_content_row(self):
        rows = dns_signature_sources(spy_profile_entry(
            "edl-only", lists=[("corp-dns-allow", "alert")]))
        self.assertEqual(len(rows), 2)
        content = [r for r in rows if r[1]][0]
        self.assertEqual(content[3:], ("", "sinkhole", True, True, True))

    def test_the_sinkhole_address_is_read_and_ipv4_is_the_one_that_matters(self):
        self.assertEqual(
            dns_sinkhole_address(spy_profile_entry(
                "s", sinkhole={"ipv4-address": "10.9.9.9", "ipv6-address": "::1"})),
            ("10.9.9.9", "::1"))

    def test_no_sinkhole_node_reads_as_two_blanks(self):
        self.assertEqual(dns_sinkhole_address(spy_profile_entry("none")), ("", ""))

    def test_an_ipv6_only_address_leaves_ipv4_blank(self):
        # Measured: ipv6 alone does NOT satisfy the device's constraint, so the blank ipv4 is
        # the field that tells a reader the prerequisite is unmet.
        self.assertEqual(
            dns_sinkhole_address(spy_profile_entry("v6", sinkhole={"ipv6-address": "::1"})),
            ("", "::1"))


def spy_categories_entry(name, *, categories=None, advanced=None):
    """An anti-spyware profile carrying DNS Security category entries."""
    botnet = {}
    if categories is not None:
        botnet["dns-security-categories"] = {"entry": [
            {"@name": n, "action": a} for n, a in categories]}
    if advanced is not None:
        botnet["advanced-dns-security-categories"] = {"entry": [
            {"@name": n, "action": a} for n, a in advanced]}
    entry = {"@name": name}
    if botnet:
        entry["botnet-domains"] = botnet
    return entry


CC = "pan-dns-sec-cc"
MALWARE = "pan-dns-sec-malware"
PHISHING = "pan-dns-sec-phishing"
ASSERTED = (CC, MALWARE, PHISHING)


class DnsSecurityCategoryTests(SimpleTestCase):
    """PAN-SPY-003. Absence FIRES here and PASSES for the list on the same screen."""

    def rows(self, entry):
        return {r[0]: r for r in dns_security_categories(entry)}

    def test_the_predefined_shape_leaves_every_category_at_default(self):
        rows = self.rows(spy_categories_entry(
            "strict", categories=[(n, "default") for n in
                                  ("pan-dns-sec-benign", CC, MALWARE, PHISHING)]))
        for name in ASSERTED:
            # enforces False, sinkholes False - `default` is a pointer, not an action.
            self.assertEqual(rows[name][5:7], (False, False), name)

    def test_sinkhole_enforces_and_sinkholes(self):
        rows = self.rows(spy_categories_entry("s", categories=[(CC, "sinkhole")]))
        self.assertEqual(rows[CC][5:7], (True, True))

    def test_block_enforces_without_sinkholing(self):
        # controls.json for PAN-SPY-003 says "must sinkhole/block", so block passes HERE -
        # unlike PAN-SPY-002, whose corpus entry asks for sinkhole alone.
        rows = self.rows(spy_categories_entry("b", categories=[(CC, "block")]))
        self.assertEqual(rows[CC][5:7], (False, True))

    def test_allow_does_neither(self):
        rows = self.rows(spy_categories_entry("a", categories=[(CC, "allow")]))
        self.assertEqual(rows[CC][5:7], (False, False))

    def test_an_unconfigured_profile_gets_the_asserted_rows_synthesized(self):
        # The whole reason absence can report: Help p.284 says DNS Security defaults to allow.
        rows = self.rows(spy_categories_entry("bare"))
        self.assertEqual(sorted(rows), sorted(ASSERTED))
        for name in ASSERTED:
            self.assertEqual(rows[name][3:], ("", "default", False, False, True), name)

    def test_a_partially_configured_profile_synthesizes_only_what_is_missing(self):
        rows = self.rows(spy_categories_entry("part", categories=[(CC, "sinkhole")]))
        self.assertFalse(rows[CC][7], "cc is configured, so not implicit")
        self.assertTrue(rows[MALWARE][7], "malware is absent, so synthesized")

    def test_categories_the_corpus_leaves_to_risk_tolerance_are_not_synthesized(self):
        # `recent` and `parked` are "sinkhole or alert per risk tolerance" in controls.json,
        # and benign must never be asserted at all.
        rows = self.rows(spy_categories_entry("bare"))
        for name in ("pan-dns-sec-recent", "pan-dns-sec-parked", "pan-dns-sec-benign"):
            self.assertNotIn(name, rows)

    def test_a_configured_non_asserted_category_still_gets_a_row(self):
        # Visible in the tab, just not asserted.
        rows = self.rows(spy_categories_entry(
            "x", categories=[("pan-dns-sec-recent", "alert")]))
        self.assertIn("pan-dns-sec-recent", rows)

    def test_the_advanced_categories_are_recorded_and_marked_as_their_own_source(self):
        rows = self.rows(spy_categories_entry(
            "adv", advanced=[("pan-adns-sec-hijacking", "default")]))
        self.assertEqual(rows["pan-adns-sec-hijacking"][2],
                         "advanced-dns-security-category")

    def test_category_rows_are_never_the_paloalto_content_list(self):
        # PAN-SPY-002's query filters on that flag, so a category leaking into it would make
        # one control answer the other's question.
        for row in dns_security_categories(spy_categories_entry("bare")).__iter__():
            self.assertFalse(row[1])


# ============================================================================================
# FILE BLOCKING AND DATA FILTERING - PAN-FIL-001 to PAN-FIL-004's subjects.
#
# Every rule shape below is what the lab STORED, read back out of the RUNNING config on
# 2026-10-29 (pan-fw-201 / serial 691665AC334B458 vsys1 and shared, pan-fw-111 / serial
# 6A9C0A9904E7D6E, Panorama shared, and /config/predefined/profiles on both) - not a shape
# reconstructed from documentation. The file-type SPELLINGS are the device's own: the lower-case
# `pe` and `multi-level-encoding` are refused at the write with code=12, so a test written in the
# asserted spelling would pass against a verdict that matches no stored row anywhere.
# ============================================================================================

FB = SecurityProfile.KIND_FILE_BLOCKING
DF = SecurityProfile.KIND_DATA_FILTERING

#: The ten the floor names, device spelling. `PE` upper case is not a typo.
FLOOR = ["PE", "dll", "bat", "vbe", "hta", "pif", "scr", "chm", "hlp", "torrent"]
MLE = "Multi-Level-Encoding"


def fb_rule(name, file_types, action=None, direction=None, applications=("any",)):
    rule = {"@name": name, "file-type": {"member": list(file_types)}}
    if applications is not None:
        rule["application"] = {"member": list(applications)}
    if direction is not None:
        rule["direction"] = direction
    if action is not None:
        rule["action"] = action
    return rule


def fb_profile(*rules):
    return {"@name": "p", "rules": {"entry": list(rules)}} if rules else {"@name": "p"}


def df_rule(name, data_object="d1", alert=None, block=None):
    rule = {"@name": name, "data-object": data_object,
            "application": {"member": ["any"]}, "file-type": {"member": ["any"]}}
    if alert is not None:
        rule["alert-threshold"] = alert
    if block is not None:
        rule["block-threshold"] = block
    return rule


def df_profile(*rules):
    return {"@name": "f", "rules": {"entry": list(rules)}} if rules else {"@name": "f"}


class PushedProfilesReadTests(SimpleTestCase):
    def test_the_xpath_is_the_one_measured_on_the_device(self):
        # Measured with that exact string on both lab PA-VMs on 2026-10-29: it answers with
        # every pushed profile collection under it, file-blocking and data-filtering included,
        # while the op read `show config pushed-shared-policy` omits them on the PA-5220 pair.
        self.assertEqual(
            build_pushed_vsys_profiles_xpath("vsys1"),
            "/config/panorama/vsys/entry[@name='vsys1']/profiles")

    def test_the_payload_is_shaped_like_the_other_pushed_roots(self):
        self.assertEqual(
            pushed_vsys_profiles({"@total-count": "1", "@count": "1",
                                  "profiles": {"file-blocking": {"entry": [{"@name": "z"}]}}}),
            {"profiles": {"file-blocking": {"entry": [{"@name": "z"}]}}})

    def test_an_absent_collection_and_an_empty_envelope_both_answer_nothing(self):
        # The three answers a container read can give are not interchangeable, and `if result:`
        # cannot tell an absent collection from a committed empty one.
        for payload in (None, {}, {"@total-count": "0", "@count": "0", "profiles": None}):
            self.assertEqual(pushed_vsys_profiles(payload), {})


class FileBlockingVerdictTests(SimpleTestCase):
    """oep-fdf7-01 to oep-fdf7-06 and the two vendor profiles, as they stand on the lab."""

    def test_the_floor_is_stopped_only_by_block_in_both_directions(self):
        # oep-fdf7-01 r1, read back from the running config.
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", FLOOR + [MLE], action="block", direction="both")))
        self.assertTrue(v["stops_floor_file_types"])
        self.assertEqual(v["floor_file_type_action"], "block")

    def test_one_direction_is_not_both(self):
        # oep-fdf7-06: the ACTION is the value the grading calls acceptable and the DIRECTION is
        # not, so the verdict is false while the graded column sits on its best value. Keeping
        # those two apart is the whole reason there are two columns.
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", FLOOR + [MLE], action="block", direction="upload")))
        self.assertFalse(v["stops_floor_file_types"])
        self.assertEqual(v["floor_file_type_action"], "block")

    def test_nine_of_the_ten_members_is_not_the_floor(self):
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", FLOOR[1:], action="block", direction="both")))
        self.assertFalse(v["stops_floor_file_types"])
        self.assertEqual(v["floor_file_type_action"], "",
                         "no rule names the floor, so no action is in force on it")

    def test_the_asserted_lower_case_spelling_matches_nothing(self):
        # The control asserts `pe` and `multi-level-encoding`; the device refuses both at the
        # write. A verdict computed against the asserted spelling passes nothing, ever.
        lower = [t.lower() for t in FLOOR] + ["multi-level-encoding"]
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", lower, action="block", direction="both")))
        self.assertFalse(v["stops_floor_file_types"])
        self.assertFalse(v["stops_nested_encoding"])

    def test_two_rules_naming_the_floor_store_the_weakest_action(self):
        # Rule ORDER is not stored and first-match-wins has never been measured, so the weakest
        # action is what is kept. The error that leaves can only under-state protection.
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", FLOOR, action="block", direction="both"),
            fb_rule("r2", FLOOR, action="alert", direction="both")))
        self.assertEqual(v["floor_file_type_action"], "alert")
        self.assertTrue(v["stops_floor_file_types"],
                        "one rule DOES block them in both directions, which the verdict reports")

    def test_an_absent_action_stops_nothing_and_grades_nothing(self):
        # oep-fdf7-05: neither a direction nor an action, both optional at commit validation.
        # Stage 4 measured no implicit for either, so an absent action is UNKNOWN - and an
        # unknown fires. The action column then matches none of the three placements, so the
        # baseline finding reports at its own severity rather than a calibrated one.
        v = file_blocking_verdicts(fb_profile(fb_rule("r1", FLOOR + [MLE])))
        self.assertFalse(v["stops_floor_file_types"])
        self.assertFalse(v["stops_nested_encoding"])
        self.assertEqual(v["floor_file_type_action"], "")
        self.assertEqual(v["nested_encoding_action"], "")

    def test_the_nested_encoding_member_is_judged_on_its_own(self):
        # oep-fdf7-04's shape: one encrypted member and nothing else. The nested-encoding
        # columns must not borrow the floor's answer.
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", [MLE], action="block", direction="both")))
        self.assertTrue(v["stops_nested_encoding"])
        self.assertFalse(v["stops_floor_file_types"])

    def test_an_encrypted_member_expresses_the_unopenable_decision_whatever_the_action(self):
        # The assertion is that a decision is EXPRESSED, not which way it went.
        for action in ("block", "alert", "continue"):
            v = file_blocking_verdicts(fb_profile(
                fb_rule("r1", ["encrypted-zip"], action=action, direction="both")))
            self.assertTrue(v["expresses_unopenable_file_decision"], action)

    def test_a_profile_naming_no_encrypted_member_expresses_no_decision(self):
        # oep-fdf7-02's shape.
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", FLOOR + [MLE], action="alert", direction="both")))
        self.assertFalse(v["expresses_unopenable_file_decision"])

    def test_continue_on_web_browsing_alone_is_the_vendors_one_permitted_case(self):
        # oep-fdf7-04, and the only configuration in the lab that passes this half.
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", ["encrypted-zip"], action="continue", direction="both",
                    applications=["web-browsing"])))
        self.assertFalse(v["confirm_rule_beyond_web_browsing"])

    def test_continue_on_any_application_is_the_finding(self):
        # oep-fdf7-03, and the vendor's own `basic file blocking` ships this combination:
        # `any` is a MEMBER of the application list, not an absence.
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", FLOOR, action="continue", direction="both", applications=["any"])))
        self.assertTrue(v["confirm_rule_beyond_web_browsing"])

    def test_a_continue_rule_with_no_application_list_fires(self):
        # An absent application list is a key nobody measured, and an unmeasured precondition
        # must not read as the vendor's one permitted case.
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", FLOOR, action="continue", direction="both", applications=None)))
        self.assertTrue(v["confirm_rule_beyond_web_browsing"])

    def test_a_block_rule_on_any_application_does_not_fire_the_continue_column(self):
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", FLOOR, action="block", direction="both", applications=["any"])))
        self.assertFalse(v["confirm_rule_beyond_web_browsing"])

    def test_the_pushed_profile_is_judged_per_rule_and_not_per_profile(self):
        # zz_fileblock_shared: its two rules name every floor member BETWEEN them except the
        # executable one, and the question is existential over single rules. A union would read
        # this profile as very nearly compliant; it stops none of the floor as one transfer.
        v = file_blocking_verdicts(fb_profile(
            fb_rule("r1", ["exe", "dll", "jar"], action="block", direction="both"),
            fb_rule("r2", [t for t in FLOOR if t != "PE"], action="block", direction="both")))
        self.assertFalse(v["stops_floor_file_types"])

    def test_a_profile_with_no_rules_stops_nothing(self):
        v = file_blocking_verdicts(fb_profile())
        self.assertFalse(v["stops_floor_file_types"])
        self.assertFalse(v["stops_nested_encoding"])
        self.assertFalse(v["expresses_unopenable_file_decision"])
        self.assertFalse(v["confirm_rule_beyond_web_browsing"],
                         "the one column whose firing side is TRUE stays false here")

    def test_a_pushed_action_carries_loc_beside_the_choice(self):
        # Every element of the pushed profile arrives decorated @loc, action included.
        v = file_blocking_verdicts(fb_profile(
            {"@name": "r1", "@loc": "shared",
             "file-type": {"@loc": "shared", "member": FLOOR},
             "direction": {"@loc": "shared", "#text": "both"},
             "action": {"@loc": "shared", "block": {"@loc": "shared"}}}))
        self.assertTrue(v["stops_floor_file_types"])


class DataFilteringVerdictTests(SimpleTestCase):
    def test_both_counts_on_the_one_rule_passes(self):
        # oep-fdf7-f1 as committed: alert 100, block 10.
        v = data_filtering_verdicts(df_profile(df_rule("r1", alert="100", block="10")))
        self.assertTrue(v["every_rule_carries_both_counts"])
        self.assertEqual(v["lowest_block_threshold"], 10)

    def test_a_second_rule_carrying_neither_count_fails_the_quantifier(self):
        # oep-fdf7-f2, and the shape stage 3 warned a per-profile answer would pass.
        v = data_filtering_verdicts(df_profile(
            df_rule("r1", alert="100", block="10"), df_rule("r2", data_object="d2")))
        self.assertFalse(v["every_rule_carries_both_counts"])
        self.assertEqual(v["lowest_block_threshold"], 10,
                         "the number is still the smallest any rule carries")

    def test_a_stored_zero_is_present_and_passes(self):
        # oep-fdf7-f3. What 0 MEANS is unsettled - inside the writable range at both ends, and
        # the value the dialog's OK writes by default - so this test pins the mechanism and not
        # the meaning.
        v = data_filtering_verdicts(df_profile(df_rule("r1", alert="0", block="0")))
        self.assertTrue(v["every_rule_carries_both_counts"])
        self.assertEqual(v["lowest_block_threshold"], 0,
                         "0 is distinct from 'no rule carries one', which is None")

    def test_a_profile_with_no_rules_is_false_and_not_vacuously_true(self):
        # oep-fdf7-f4 and the pushed test_dlp_prof: legal, committed, scanning nothing. A bare
        # entry with no child element at all was accepted at the write.
        v = data_filtering_verdicts({"@name": "f"})
        self.assertFalse(v["every_rule_carries_both_counts"])
        self.assertIsNone(v["lowest_block_threshold"])

    def test_one_count_alone_fails(self):
        for alert, block in (("100", None), (None, "10")):
            v = data_filtering_verdicts(df_profile(df_rule("r1", alert=alert, block=block)))
            self.assertFalse(v["every_rule_carries_both_counts"], (alert, block))

    def test_the_lowest_block_count_is_the_minimum_across_rules(self):
        v = data_filtering_verdicts(df_profile(
            df_rule("r1", alert="100", block="50"), df_rule("r2", alert="1", block="3")))
        self.assertEqual(v["lowest_block_threshold"], 3)

    def test_the_rules_pattern_objects_are_read_in_order_without_duplicates(self):
        names = data_filtering_rule_pattern_names(df_profile(
            df_rule("r1", data_object="d1"), df_rule("r2", data_object="d2"),
            df_rule("r3", data_object="d1")))
        self.assertEqual(names, ["d1", "d2"])


class DataPatternObjectTests(SimpleTestCase):
    """oep-fdf7-d1, d2 and d3 - the three branches `pattern-type` can take."""

    def test_the_predefined_branch_defines_a_pattern(self):
        entry = {"@name": "d1", "pattern-type": {"predefined": {"pattern": {"entry": [
            {"@name": "credit-card-numbers", "file-type": {"member": ["any"]}}]}}}}
        self.assertEqual(data_pattern_defines_a_pattern(entry), (True, "predefined"))

    def test_the_regex_branch_defines_a_pattern(self):
        entry = {"@name": "d2", "pattern-type": {"regex": {"pattern": {"entry": [
            {"@name": "p1", "regex": "OEP-FDF7-000000",
             "file-type": {"member": ["any"]}}]}}}}
        self.assertEqual(data_pattern_defines_a_pattern(entry), (True, "regex"))

    def test_the_file_properties_branch_defines_a_pattern(self):
        entry = {"@name": "d3", "pattern-type": {"file-properties": {"pattern": {"entry": [
            {"@name": "p1", "file-type": "docx",
             "file-property": "panav-rsp-office-dlp-author",
             "property-value": "oep-fdf7"}]}}}}
        self.assertEqual(data_pattern_defines_a_pattern(entry), (True, "file-properties"))

    def test_a_branch_with_no_pattern_entry_defines_nothing(self):
        # The device makes a pattern entry mandatory at commit, so this is the state a
        # collection gap or a future release could produce - not one an operator can commit. It
        # must not read as a defined pattern.
        entry = {"@name": "d4", "pattern-type": {"regex": {"pattern": None}}}
        self.assertEqual(data_pattern_defines_a_pattern(entry), (False, ""))

    def test_no_pattern_type_at_all_defines_nothing(self):
        self.assertEqual(data_pattern_defines_a_pattern({"@name": "d5"}), (False, ""))


def fb_group(name, namespace_type=PolicyObjectNamespace.LOCAL_VSYS, members=("p",),
             member_kind=None):
    return NormalizedSecurityProfileGroup(
        source_snapshot=None, config_source="local", name=name,
        namespace_type=namespace_type, namespace_value="vsys1", precedence_rank=0,
        members={member_kind or FB: list(members)}, raw_group={}, field_provenance_data=[])


class ReferenceReachTests(SimpleTestCase):
    """The two-hop walk: oep-fdf7-01 through -06, and the one rule in the estate that reaches."""

    def reach(self, profiles, references, group_references=(), groups=()):
        return reference_reach_by_key(list(references), list(group_references),
                                      list(profiles), list(groups))

    def test_a_rule_naming_the_profile_directly_is_named_by_a_rule(self):
        p = profile("p", PolicyObjectNamespace.LOCAL_VSYS, FB)
        ref = ProfileReference(kind=FB, name="p", referrer="vsys1 rulebase/.../r1",
                               shared_scope=False, via=VIA_RULE)
        self.assertEqual(self.reach([p], [ref])[p.key], SecurityProfile.REACH_BY_RULE)

    def test_a_group_a_rule_names_carries_the_profile_the_second_hop(self):
        # oep-fdf7-01: group oep-fdf7-g1 names it and rule oep-fdf7-r1 names that group. The
        # ONLY two-hop path in the lab estate, and a boolean referrer flag cannot tell it from
        # the case below.
        p = profile("p", PolicyObjectNamespace.LOCAL_VSYS, FB)
        g = fb_group("g1")
        reach = self.reach(
            [p],
            [ProfileReference(kind=FB, name="p", referrer="vsys1 profile-group/g1",
                              shared_scope=False, via=VIA_GROUP, owner_group="g1")],
            [GroupReference(name="g1", referrer="vsys1 rulebase/.../r1", shared_scope=False)],
            [g])
        self.assertEqual(reach[p.key], SecurityProfile.REACH_BY_RULE)

    def test_a_group_no_rule_names_leaves_the_profile_named_by_a_group_only(self):
        # oep-fdf7-02 through -06: five profiles a group names and nothing enforces. The shipped
        # one-hop `is_used` passes every one of them.
        p = profile("p", PolicyObjectNamespace.LOCAL_VSYS, FB)
        reach = self.reach(
            [p],
            [ProfileReference(kind=FB, name="p", referrer="vsys1 profile-group/g2",
                              shared_scope=False, via=VIA_GROUP, owner_group="g2")],
            [], [fb_group("g2")])
        self.assertEqual(reach[p.key], SecurityProfile.REACH_BY_GROUP_ONLY)

    def test_a_rule_naming_a_group_that_resolves_to_nothing_reaches_no_profile(self):
        # Resolved and not assumed: the lab's `default` group is named by 113 rules and names
        # no profile at all.
        p = profile("p", PolicyObjectNamespace.LOCAL_VSYS, FB)
        reach = self.reach(
            [p],
            [ProfileReference(kind=FB, name="p", referrer="vsys1 profile-group/g2",
                              shared_scope=False, via=VIA_GROUP, owner_group="g2")],
            [GroupReference(name="absent", referrer="vsys1 rulebase/.../r1",
                            shared_scope=False)],
            [fb_group("g2")])
        self.assertEqual(reach[p.key], SecurityProfile.REACH_BY_GROUP_ONLY)

    def test_a_profile_nothing_names_is_unreferenced(self):
        # oep-fdf7-04, and PAN-FIL-004's whole subject.
        p = profile("p", PolicyObjectNamespace.LOCAL_VSYS, FB)
        self.assertEqual(self.reach([p], [])[p.key], SecurityProfile.REACH_UNREFERENCED)

    def test_a_rule_beats_a_group_for_one_profile(self):
        p = profile("p", PolicyObjectNamespace.LOCAL_VSYS, FB)
        reach = self.reach(
            [p],
            [ProfileReference(kind=FB, name="p", referrer="g", shared_scope=False,
                              via=VIA_GROUP, owner_group="g2"),
             ProfileReference(kind=FB, name="p", referrer="r", shared_scope=False,
                              via=VIA_RULE)],
            [], [fb_group("g2")])
        self.assertEqual(reach[p.key], SecurityProfile.REACH_BY_RULE)

    def test_a_vsys_group_naming_a_shared_profile_reaches_it(self):
        # oep-fdf7-g5 is at vsys scope and its member oep-fdf7-06 is at SHARED scope: the pool
        # merges vsys, shared, predefined and pushed-shared and returns one winner per name.
        shared = profile("p", PolicyObjectNamespace.LOCAL_SHARED, FB)
        reach = self.reach(
            [shared],
            [ProfileReference(kind=FB, name="p", referrer="vsys1 profile-group/g5",
                              shared_scope=False, via=VIA_GROUP, owner_group="g5")],
            [], [fb_group("g5")])
        self.assertEqual(reach[shared.key], SecurityProfile.REACH_BY_GROUP_ONLY)


class ReferenceWalkPathTests(SimpleTestCase):
    """Which payload path a member list was found at is what decides `via`."""

    def test_a_local_rules_profile_setting_is_a_rule_and_its_group_arm_is_collected(self):
        vsys = {"rulebase": {"security": {"rules": {"entry": [
            {"@name": "r1", "profile-setting": {"profiles": {FB: {"member": ["p"]}}}},
            {"@name": "r2", "profile-setting": {"group": {"member": ["g1"]}}},
        ]}}}}
        refs, groups = collect_profile_and_group_references(
            vsys, where="vsys1 ", shared_root=False, pushed=False)
        self.assertEqual([(r.name, r.via) for r in refs], [("p", VIA_RULE)])
        self.assertEqual([(g.name, g.referrer) for g in groups],
                         [("g1", "vsys1 rulebase/security/rules/r2")])

    def test_a_profile_group_member_is_a_group_and_carries_the_groups_name(self):
        vsys = {"profile-group": {"entry": [{"@name": "g1", FB: {"member": ["p"]}}]}}
        refs, groups = collect_profile_and_group_references(
            vsys, where="vsys1 ", shared_root=False, pushed=False)
        self.assertEqual([(r.name, r.via, r.owner_group) for r in refs],
                         [("p", VIA_GROUP, "g1")])
        self.assertEqual(groups, [])

    def test_a_pushed_pre_rulebase_is_still_a_rule(self):
        # THE BUG THIS PINS: the rulebase key is `rulebase` locally and `pre-rulebase` in the
        # pushed tree, so a path test naming the rulebase matches the local arm and silently
        # misses every pushed rule - which is the half that decides whether a pushed group is in
        # the enforcement path.
        pushed = {"pre-rulebase": {"security": {"rules": {"entry": [
            {"@name": "r1", "@loc": "shared",
             "profile-setting": {"group": {"member": ["OutBound-Block"]}}},
        ]}}}}
        refs, groups = collect_profile_and_group_references(
            pushed, where="pushed ", shared_root=False, pushed=True)
        self.assertEqual([g.name for g in groups], ["OutBound-Block"])
        self.assertTrue(all(g.shared_scope for g in groups),
                        "@loc=shared makes the referrer a Panorama-Shared one")
        self.assertEqual(refs, [])

    def test_a_definition_is_not_a_referrer(self):
        vsys = {"profiles": {FB: {"entry": [{"@name": "p", "rules": {"entry": []}}]}}}
        refs, groups = collect_profile_and_group_references(
            vsys, where="vsys1 ", shared_root=False, pushed=False)
        self.assertEqual((refs, groups), ([], []))


class FileDataFilteringNormalizationTests(TestCase):
    """End to end, over payloads shaped like the ones read off pan-fw-201 on 2026-10-29."""

    def _point(self, *, serial="FDF7", merged, pushed_profiles=None, predefined=True):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname=f"pano-{serial}")
        group = ApplianceGroup.objects.create(
            management_station=station, name=f"grp-{serial}",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number=serial, hostname=f"host-{serial}")
        group.active_appliance = appliance
        group.save()
        point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, vsys_name="vsys1", in_scope=True)
        EnforcementNode.objects.create(
            management_station=station, enforcement_point=point, appliance=appliance)
        now = timezone.now()
        Snapshot.objects.create(management_station=station, appliance=appliance,
                                source_type="show_merged_config", collected_at=now,
                                payload=merged)
        if predefined:
            Snapshot.objects.create(
                management_station=station, appliance=appliance,
                source_type="config_predefined_security_profiles", collected_at=now,
                payload={"profiles": {}})
        Snapshot.objects.create(management_station=station, appliance_group=group,
                                source_type="show_pushed_shared_policy", collected_at=now,
                                payload={"policy": {"panorama": {}}})
        Snapshot.objects.create(management_station=station, enforcement_point=point,
                                source_type="show_pushed_shared_policy_vsys", scope_name="vsys1",
                                collected_at=now, payload={"policy": {"panorama": {}}})
        if pushed_profiles is not None:
            Snapshot.objects.create(
                management_station=station, enforcement_point=point,
                source_type="config_pushed_vsys_profiles", scope_name="vsys1",
                collected_at=now, payload=pushed_profiles)
        return station, group, point

    @staticmethod
    def _merged(vsys_content=None, shared_content=None):
        return {"config": {
            "shared": shared_content or {},
            "devices": {"entry": [{"@name": "localhost.localdomain", "vsys": {"entry": [
                dict({"@name": "vsys1"}, **(vsys_content or {}))]}}]}}}

    def _normalize(self, group, point):
        normalize_appliance_group_security_profiles(group)
        return normalize_security_profiles(point)

    def test_a_point_with_no_data_filtering_anywhere_still_gets_a_posture_row(self):
        # THE WHOLE REASON THE SUBJECT EXISTS. Three of the four lab appliances are in this
        # state, and a profile-keyed row cannot report something that does not exist.
        station, group, point = self._point(merged=self._merged(), pushed_profiles={})
        counts = self._normalize(group, point)
        self.assertEqual(counts["data_filtering_postures"], 1)
        row = DataFilteringPosture.objects.get(enforcement_point=point)
        self.assertFalse(row.outward_data_filtering_effective)
        self.assertFalse(row.data_filtering_in_force)
        self.assertFalse(row.named_patterns_defined)
        self.assertEqual(row.profiles_in_force, [],
                         "an empty evidence list beside a firing verdict is the honest pair")

    def test_a_profile_a_rule_reaches_through_a_group_makes_the_posture_effective(self):
        # oep-fdf7-f1 + oep-fdf7-g1 + oep-fdf7-r1 + oep-fdf7-d1, which is the only
        # configuration in the lab estate that a two-hop walk reaches from a rule.
        station, group, point = self._point(pushed_profiles={}, merged=self._merged({
            "profiles": {
                DF: {"entry": [df_profile(df_rule("r1", data_object="d1",
                                                  alert="100", block="10")) | {"@name": "f1"}]},
                "data-objects": {"entry": [
                    {"@name": "d1", "pattern-type": {"predefined": {"pattern": {"entry": [
                        {"@name": "credit-card-numbers",
                         "file-type": {"member": ["any"]}}]}}}}]},
            },
            "profile-group": {"entry": [{"@name": "g1", DF: {"member": ["f1"]}}]},
            "rulebase": {"security": {"rules": {"entry": [
                {"@name": "r1", "profile-setting": {"group": {"member": ["g1"]}}}]}}},
        }))
        self._normalize(group, point)
        row = DataFilteringPosture.objects.get(enforcement_point=point)
        self.assertTrue(row.data_filtering_in_force)
        self.assertTrue(row.named_patterns_defined)
        self.assertTrue(row.outward_data_filtering_effective)
        self.assertEqual([p["reference_reach"] for p in row.profiles_in_force],
                         [SecurityProfile.REACH_BY_RULE])

    def test_a_referenced_profile_with_no_rules_is_not_in_force(self):
        # THE PUSHED test_dlp_prof: the only data-filtering profile anything in the estate
        # references, and it carries no rules. A bare "is it referenced" predicate finds it and
        # reports the estate as watched.
        station, group, point = self._point(pushed_profiles={}, merged=self._merged({
            "profiles": {DF: {"entry": [{"@name": "f1"}]}},
            "profile-group": {"entry": [{"@name": "g1", DF: {"member": ["f1"]}}]},
            "rulebase": {"security": {"rules": {"entry": [
                {"@name": "r1", "profile-setting": {"group": {"member": ["g1"]}}}]}}},
        }))
        self._normalize(group, point)
        row = DataFilteringPosture.objects.get(enforcement_point=point)
        self.assertFalse(row.data_filtering_in_force)
        self.assertFalse(row.outward_data_filtering_effective)
        self.assertEqual(row.profiles_in_force[0]["reference_reach"],
                         SecurityProfile.REACH_BY_RULE,
                         "it IS reached; what it is not is watching anything")
        self.assertFalse(row.profiles_in_force[0]["has_rules"])

    def test_an_in_force_profile_naming_a_pattern_that_defines_nothing_fails_the_verdict(self):
        station, group, point = self._point(pushed_profiles={}, merged=self._merged({
            "profiles": {
                DF: {"entry": [df_profile(df_rule("r1", data_object="d1",
                                                  alert="1", block="1")) | {"@name": "f1"}]},
                "data-objects": {"entry": [
                    {"@name": "d1", "pattern-type": {"regex": {"pattern": None}}}]},
            },
            "profile-group": {"entry": [{"@name": "g1", DF: {"member": ["f1"]}}]},
            "rulebase": {"security": {"rules": {"entry": [
                {"@name": "r1", "profile-setting": {"group": {"member": ["g1"]}}}]}}},
        }))
        self._normalize(group, point)
        row = DataFilteringPosture.objects.get(enforcement_point=point)
        self.assertTrue(row.data_filtering_in_force)
        self.assertFalse(row.named_patterns_defined)
        self.assertFalse(row.outward_data_filtering_effective)

    def test_has_rules_agrees_with_rule_count_on_every_row(self):
        # The two are the same reading in two forms and are written from one `profile_rules()`
        # call. Nothing calls `full_clean` anywhere in this package - measured, zero hits - so
        # this test is the gate and a `clean()` would not be.
        station, group, point = self._point(pushed_profiles={}, merged=self._merged({
            "profiles": {
                FB: {"entry": [fb_profile(fb_rule("r1", FLOOR, action="block", direction="both"))
                               | {"@name": "p1"},
                               {"@name": "p2"}]},
                DF: {"entry": [{"@name": "f1"}]},
            }}))
        self._normalize(group, point)
        rows = SecurityProfile.objects.filter(management_station=station)
        self.assertTrue(rows.exists())
        for row in rows:
            self.assertEqual(row.has_rules, row.rule_count > 0, row.name)

    def test_a_data_filtering_row_is_never_reference_reach_resolved(self):
        # Four of the ten fields that can point at the data-filtering collection are AI-security
        # profile `data-leak-detection` member lists and nothing in this package reads
        # `profiles/ai-security`. False FIRES, and the finding it raises - "we could not
        # establish whether anything points at this profile" - replaces a false one.
        station, group, point = self._point(pushed_profiles={}, merged=self._merged({
            "profiles": {DF: {"entry": [{"@name": "f1"}]},
                         FB: {"entry": [{"@name": "p1"}]}}}))
        self._normalize(group, point)
        self.assertFalse(SecurityProfile.objects.get(kind=DF).reference_reach_resolved)
        self.assertTrue(SecurityProfile.objects.get(kind=FB).reference_reach_resolved,
                        "the file-blocking walk HAS every read it needs")

    def test_an_unreferenced_data_filtering_profile_reads_undetermined_and_not_unreferenced(self):
        # PAN-FIL-004's second restatement cannot report today, and this is where that is
        # visible: the clause is `equals unreferenced` and the column never holds it while the
        # AI-security read is missing. Stage 5 predicted it; the expectation it breaks is stage
        # 6's, which read the column as `unreferenced` for oep-fdf7-f4.
        station, group, point = self._point(pushed_profiles={}, merged=self._merged({
            "profiles": {DF: {"entry": [{"@name": "f1"}]}}}))
        self._normalize(group, point)
        self.assertEqual(SecurityProfile.objects.get(kind=DF).reference_reach,
                         SecurityProfile.REACH_UNDETERMINED)

    def test_an_unissued_pushed_profiles_read_leaves_the_walk_unresolved(self):
        # The read is the only source for the pushed profiles on one of the two lab platforms,
        # so a point without it has not established what Panorama put in the enforcement path.
        station, group, point = self._point(pushed_profiles=None, merged=self._merged({
            "profiles": {FB: {"entry": [{"@name": "p1"}]}}}))
        self._normalize(group, point)
        row = SecurityProfile.objects.get(kind=FB)
        self.assertFalse(row.reference_reach_resolved)
        self.assertEqual(row.reference_reach, SecurityProfile.REACH_UNDETERMINED,
                         "nothing named it AND the reads were short, so the answer is unknown")

    def test_an_incomplete_read_set_does_not_downgrade_a_rule_that_was_found(self):
        # Positive evidence stays positive: a read nobody issued can only hide a REFERRER.
        station, group, point = self._point(pushed_profiles=None, merged=self._merged({
            "profiles": {FB: {"entry": [{"@name": "p1"}]}},
            "rulebase": {"security": {"rules": {"entry": [
                {"@name": "r1", "profile-setting": {"profiles": {FB: {"member": ["p1"]}}}}]}}},
        }))
        self._normalize(group, point)
        row = SecurityProfile.objects.get(kind=FB)
        self.assertEqual(row.reference_reach, SecurityProfile.REACH_BY_RULE)
        self.assertFalse(row.reference_reach_resolved)

    def test_a_fresh_row_holds_the_firing_side_on_every_column_but_one(self):
        # The migration window. A row nobody has renormalised must raise rather than pass.
        row = SecurityProfile(kind=FB, name="x")
        for column in ("has_rules", "stops_floor_file_types", "stops_nested_encoding",
                       "expresses_unopenable_file_decision", "every_rule_carries_both_counts",
                       "reference_reach_resolved"):
            self.assertFalse(getattr(row, column), column)
        self.assertEqual(row.reference_reach, SecurityProfile.REACH_UNDETERMINED)
        self.assertFalse(row.confirm_rule_beyond_web_browsing,
                         "THE EXCEPTION: this column names a configuration that is PRESENT, so "
                         "its firing side is True and its migration window is silent")


# --------------------------------------------------------------------------- anti-spyware,
# PAN-SPY-001 to PAN-SPY-005. Every payload shape below was read off serial 691665AC334B458
# (PA-VM 11.2.5, hostname PA-VM, labelled pan-fw-201 in the probe inventory) on 2026-10-29 with
# `type=config&action=get`, from the thirteen vsys profiles, the one shared profile, the two
# predefined profiles and the twenty-three rules stage 6 and earlier runs left standing - not a
# shape reconstructed from documentation.


def spy_engine(name, action=None, ldl=None):
    entry = {"@name": name}
    if action is not None:
        entry["inline-policy-action"] = action
    if ldl is not None:
        entry["local-deep-learning"] = ldl
    return entry


class CloudInlineAnalysisTests(SimpleTestCase):
    """The Inline Cloud Analysis tab's own enable. PAN-SPY-004's prerequisite."""

    @staticmethod
    def _normalize(entry, kind=SPY):
        return normalize_security_profile(
            kind=kind, source_snapshot=None, config_source="local",
            namespace_type=PolicyObjectNamespace.LOCAL_VSYS, namespace_value="vsys1",
            entry=entry)

    def test_an_absent_key_is_false_and_carries_a_measured_provenance(self):
        # oep-spy6-13, the committed keyless profile, and BOTH predefined profiles are in this
        # state - so every estate binding `default` or `strict` reads false here.
        normalized = self._normalize({"@name": "p"})
        self.assertFalse(normalized.cloud_inline_analysis)
        recorded = dict((name, rk) for name, rk, _ in normalized.field_provenance_data)
        self.assertEqual(recorded["cloud_inline_analysis"].value, False)
        self.assertIn("691665AC334B458", recorded["cloud_inline_analysis"].citation)

    def test_yes_and_no_are_both_read_and_neither_is_the_implicit(self):
        # `yes` on all twelve configured standing profiles. `no` is not in the lab and is the
        # value that must not be confused with absence - the provenance row is what separates
        # them, and the stored boolean is the same either way.
        for wire, expected in (("yes", True), ("no", False)):
            normalized = self._normalize({"@name": "p", "cloud-inline-analysis": wire})
            self.assertIs(normalized.cloud_inline_analysis, expected)
            # raw_key None means PRESENT AND LOCALLY CONFIGURED - not absent, which is the
            # `Implicit` object, and not pushed, which is one of the marker keys. `no` and
            # absent store the same False and are separated by exactly this.
            recorded = dict((n, rk) for n, rk, _ in normalized.field_provenance_data)
            self.assertIsNone(recorded["cloud_inline_analysis"])

    def test_no_other_kind_carries_the_column(self):
        # The key exists on no other profile kind, so the model default stands for them - which
        # is the firing side, kept off the wrong rows by the `kind` clause on every query.
        normalized = self._normalize({"@name": "p", "cloud-inline-analysis": "yes"}, kind=VLN)
        self.assertFalse(normalized.cloud_inline_analysis)
        self.assertNotIn("cloud_inline_analysis",
                         [name for name, _, _ in normalized.field_provenance_data])


class InlineDetectorLocalDeepLearningTests(SimpleTestCase):
    """`local-deep-learning`, which NOTHING ASSERTS and which no row in the lab holds."""

    def test_only_what_the_config_stores_reaches_the_mapping(self):
        entry = {"@name": "p", "mica-engine-spyware-enabled": {"entry": [
            spy_engine("HTTP Command and Control detector", "reset-both", "enable"),
            spy_engine("SSL Command and Control detector", "reset-both"),
        ]}}
        self.assertEqual(profile_inline_detector_ldl(SPY, entry),
                         {"HTTP Command and Control detector": "enable"})

    def test_an_11_1_appliance_and_an_unwritten_key_are_indistinguishable_here(self):
        # On 11.1.13-h3 the key does not exist at all - completing it answers code=6 `Invalid
        # sequence` - and on 11.2 an engine that stores nothing answers the same way. Both are
        # blank, and the column's own comment is where that is recorded; nothing is materialised,
        # so no clause may be written over it.
        entry = {"@name": "p", "mica-engine-spyware-enabled": {"entry": [
            spy_engine("HTTP Command and Control detector", "alert")]}}
        self.assertEqual(profile_inline_detector_ldl(SPY, entry), {})

    def test_a_vulnerability_profile_is_not_asked(self):
        self.assertEqual(profile_inline_detector_ldl(VLN, {"@name": "p"}), {})


class InlineDetectorWeakestActionTests(SimpleTestCase):
    """PAN-SPY-004's graded value. The order is the control's grading, not an invention."""

    def test_a_blank_action_sorts_weakest_and_is_not_given_an_implicit_here(self):
        # A blank reaches this only on a VULNERABILITY engine the profile omits, whose implicit
        # nothing has read - so it sorts weakest, which is the safe direction, and no value is
        # claimed for it. The SPYWARE implicit is materialised on the way in instead, by
        # `inline_detector_action`, where its citation is.
        self.assertEqual(SecurityProfileInlineDetector.weakest_action(["reset-both", ""]), "")

    def test_the_spyware_implicit_is_materialised_on_the_way_in(self):
        # Both predefined profiles carry no engine node at all, and every one of their engine
        # rows therefore stores `alert` rather than an empty string - which is what the device
        # renders and the baseline failing state of PAN-SPY-004.
        self.assertEqual(inline_detector_action(SPY, {}, "SSL Command and Control detector"),
                         "alert")
        self.assertEqual(inline_detector_action(SPY, {"SSL Command and Control detector": "drop"},
                                                "SSL Command and Control detector"), "drop")
        self.assertEqual(inline_detector_action(VLN, {}, "SQL Injection"), "",
                         "the vulnerability engine's implicit is not measured and not borrowed")

    def test_drop_is_the_weakest_of_the_four_stopping_actions(self):
        # oep-spy6-11: drop on HTTP, reset-client on HTTP2, reset-server on SSL, reset-both on
        # the other two. stage6-anti-spyware.json records the graded column reading `drop` there.
        self.assertEqual(SecurityProfileInlineDetector.weakest_action(
            ["drop", "reset-client", "reset-server", "reset-both", "reset-both"]), "drop")

    def test_allow_beats_alert_to_the_bottom(self):
        self.assertEqual(
            SecurityProfileInlineDetector.weakest_action(["reset-both", "alert", "allow"]),
            "allow")

    def test_an_action_the_table_does_not_know_sorts_weakest(self):
        # The same rule `_weakest_action` follows: a value nobody has measured must not be read
        # as protection. A content release adding a seventh action lands here.
        self.assertEqual(SecurityProfileInlineDetector.weakest_action(
            ["reset-both", "oep-not-an-action"]), "oep-not-an-action")

    def test_no_rows_at_all_is_empty_rather_than_a_value(self):
        self.assertEqual(SecurityProfileInlineDetector.weakest_action([]), "")


class ThreatExceptionTests(SimpleTestCase):
    """The per-signature override - PAN-SPY-005's own row, and what can undo PAN-SPY-001."""

    def test_nothing_is_synthesized_for_a_profile_with_no_exception(self):
        # The OPPOSITE of the engine and category collections on the same object. An exception
        # that does not exist is not an exception at any action, and the Signature Exceptions
        # GRID rendering thirty catalogue rows at this state is the trap that reading says no to.
        self.assertEqual(profile_threat_exceptions({"@name": "p"}), [])
        self.assertEqual(profile_threat_exceptions({"@name": "p", "threat-exception": {}}), [])

    def test_the_action_is_a_choice_element_and_an_absent_one_is_the_pointer(self):
        # oep-spy6-12 and oep-spy6-20 both hold exactly this shape on threat 10001.
        self.assertEqual(
            profile_threat_exceptions({"@name": "p", "threat-exception": {"entry": [
                {"@name": "10001", "action": {"default": None}},
                {"@name": "10002", "action": {"reset-both": None}},
                {"@name": "10003"},
            ]}}),
            [("10001", "default", 0), ("10002", "reset-both", 0), ("10003", "default", 0)])

    def test_exempt_ip_is_entry_keyed_and_zero_is_the_widest_form(self):
        # Settled by refusal: <member> is rejected at this position and <entry name=...> is
        # accepted. A member list here would count ZERO, which is the widest and worst value.
        rows = profile_threat_exceptions({"@name": "p", "threat-exception": {"entry": [
            {"@name": "10001", "action": {"allow": None},
             "exempt-ip": {"entry": [{"@name": "10.1.1.1"}, {"@name": "10.1.1.2"}]}},
            {"@name": "10002", "action": {"allow": None},
             "exempt-ip": {"member": ["10.1.1.3"]}},
        ]}})
        self.assertEqual(rows, [("10001", "allow", 2), ("10002", "allow", 0)])

    def test_the_pointer_is_undecided_rather_than_harmless(self):
        default_row = SecurityProfileThreatException(threat_id="1", action="default")
        alert_row = SecurityProfileThreatException(threat_id="2", action="alert")
        drop_row = SecurityProfileThreatException(threat_id="3", action="drop")
        self.assertFalse(default_row.hands_signature_back)
        self.assertTrue(default_row.undecided_without_resolution)
        self.assertTrue(alert_row.hands_signature_back)
        self.assertFalse(alert_row.undecided_without_resolution)
        self.assertFalse(drop_row.hands_signature_back)
        self.assertFalse(drop_row.undecided_without_resolution)

    def test_both_threat_rule_kinds_are_parsed_and_no_other_is(self):
        entry = {"@name": "p", "threat-exception": {"entry": [{"@name": "10001"}]}}
        for kind, expected in ((SPY, 1), (VLN, 1), (SecurityProfile.KIND_VIRUS, 0)):
            normalized = normalize_security_profile(
                kind=kind, source_snapshot=None, config_source="local",
                namespace_type=PolicyObjectNamespace.LOCAL_VSYS, namespace_value="vsys1",
                entry=entry)
            self.assertEqual(len(normalized.threat_exceptions), expected, kind)


class AntiSpywarePerRuleTests(TestCase):
    """End to end over the shapes serial 691665AC334B458 holds: thirteen vsys profiles, one
    shared profile, two predefined profiles and sixteen rules binding them.

    What this pins that the offline cases above cannot: the THIRD ATTACHMENT STATE, the three
    graded values, and the one place an exception reaches back into a severity verdict.
    """

    def _point(self, *, vsys, shared=None, predefined=None):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano-spy")
        group = ApplianceGroup.objects.create(
            management_station=station, name="grp-spy",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="691665AC334B458", hostname="PA-VM")
        group.active_appliance = appliance
        group.save()
        point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, vsys_name="vsys1", in_scope=True)
        EnforcementNode.objects.create(
            management_station=station, enforcement_point=point, appliance=appliance)
        now = timezone.now()
        Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=now,
            payload={"config": {
                "shared": shared or {},
                "devices": {"entry": [{"@name": "localhost.localdomain", "vsys": {"entry": [
                    dict({"@name": "vsys1"}, **vsys)]}}]}}})
        if predefined is not None:
            Snapshot.objects.create(
                management_station=station, appliance=appliance,
                source_type="config_predefined_security_profiles", collected_at=now,
                payload={"profiles": predefined})
        Snapshot.objects.create(management_station=station, appliance_group=group,
                                source_type="show_pushed_shared_policy", collected_at=now,
                                payload={"policy": {"panorama": {}}})
        Snapshot.objects.create(management_station=station, enforcement_point=point,
                                source_type="show_pushed_shared_policy_vsys", scope_name="vsys1",
                                collected_at=now, payload={"policy": {"panorama": {}}})
        Snapshot.objects.create(management_station=station, enforcement_point=point,
                                source_type="config_pushed_vsys_profiles", scope_name="vsys1",
                                collected_at=now, payload={})
        normalize_security_rules(point)
        normalize_appliance_group_security_profiles(group)
        normalize_security_profiles(point)
        return point, normalize_security_rule_profile_coverage(point)

    @staticmethod
    def _rule(name, *, octet, spyware=None, group=None, action="allow"):
        # The lab's own shape: both addresses inside TEST-NET-2, so no traffic matches the rule.
        entry = {"@name": name,
                 "from": {"member": ["any"]}, "to": {"member": ["any"]},
                 "source": {"member": ["198.18.251.1/32"]},
                 "destination": {"member": [f"198.18.251.{octet}/32"]},
                 "application": {"member": ["any"]}, "service": {"member": ["any"]},
                 "action": action}
        if spyware is not None:
            entry["profile-setting"] = {"profiles": {"spyware": {"member": [spyware]}}}
        if group is not None:
            entry["profile-setting"] = {"group": {"member": [group]}}
        return entry

    @staticmethod
    def _strong_profile(name, **overrides):
        # oep-spy6-01: one catch-all rule on all three bands at reset-both, the content list
        # sinkholed with an address pair, the three asserted categories sinkholed, every engine
        # at reset-both, inline analysis on, and no exception anywhere.
        entry = {
            "@name": name,
            "rules": {"entry": [spy_rule("p1", ["critical", "high", "medium"], "reset-both")]},
            "botnet-domains": {
                "lists": {"entry": [{"@name": "default-paloalto-dns",
                                     "action": {"sinkhole": None}}]},
                "dns-security-categories": {"entry": [
                    {"@name": "pan-dns-sec-cc", "action": "sinkhole"},
                    {"@name": "pan-dns-sec-malware", "action": "sinkhole"},
                    {"@name": "pan-dns-sec-phishing", "action": "sinkhole"}]},
                "sinkhole": {"ipv4-address": "pan-sinkhole-default-ip", "ipv6-address": "::1"}},
            "mica-engine-spyware-enabled": {"entry": [
                spy_engine(n, "reset-both")
                for n in SecurityProfileInlineDetector.SPYWARE_DETECTORS]},
            "cloud-inline-analysis": "yes",
        }
        entry.update(overrides)
        return entry

    def test_the_three_attachment_states_are_three_different_pairs_of_columns(self):
        # THE WHOLE POINT OF spyware_profile_resolved. All three shapes stand on the lab:
        # oep-spy6-r01 binds a profile that exists; intrazone_rule_test binds the group `default`
        # which resolves to nothing at any scope (measured: /config/predefined/profile-group
        # answers null on both PA-VMs); oep-spy6-r16 binds nothing at all.
        point, counts = self._point(vsys={
            "profiles": {SPY: {"entry": [self._strong_profile("p1")]}},
            "profile-group": {"entry": [{"@name": "g-empty", SPY: {"member": []}},
                                        {"@name": "g-missing", SPY: {"member": ["p-gone"]}}]},
            "rulebase": {"security": {"rules": {"entry": [
                self._rule("r-bound", octet=11, spyware="p1"),
                self._rule("r-unresolvable-name", octet=12, spyware="p-gone"),
                self._rule("r-group-names-nothing", octet=13, group="g-empty"),
                self._rule("r-group-names-a-ghost", octet=14, group="g-missing"),
                self._rule("r-nothing", octet=15),
            ]}}}})
        state = {r.name: (r.has_spyware_profile, r.spyware_profile_resolved)
                 for r in SecurityRule.objects.all()}
        self.assertEqual(state["r-bound"], (True, True))
        self.assertEqual(state["r-unresolvable-name"], (True, False),
                         "a name is bound and resolves to nothing: repair the profile")
        self.assertEqual(state["r-group-names-a-ghost"], (True, False),
                         "the group exists and names a profile that does not: repair the group")
        self.assertEqual(state["r-nothing"], (False, False), "attach a profile")
        # THE FOURTH SHAPE, and the one the pair cannot separate: a group whose spyware key
        # exists and is EMPTY. `has_spyware_profile` reads the KEY and answers True; nothing
        # resolves. That is the lab's `default` group exactly, and it is reported here rather
        # than smoothed over - the verdict's NULL still fires, so the finding is raised.
        self.assertEqual(state["r-group-names-nothing"], (True, False))
        self.assertEqual(counts["spyware_profile_unresolved"], 4)

    def test_each_graded_value_lands_on_its_own_assertion_and_nowhere_else(self):
        # oep-spy6-02 (critical uncovered), -05 (content list at alert) and -09 (engines at
        # alert) are the three single-respect variants stage 6 built for exactly this.
        point, _ = self._point(vsys={
            "profiles": {SPY: {"entry": [
                self._strong_profile("p-band", rules={"entry": [
                    spy_rule("p1", ["high", "medium"], "reset-both")]}),
                self._strong_profile("p-dns", **{"botnet-domains": {
                    "lists": {"entry": [{"@name": "default-paloalto-dns",
                                         "action": {"alert": None}}]}}}),
                self._strong_profile("p-engine", **{"mica-engine-spyware-enabled": {"entry": [
                    spy_engine(n, "alert")
                    for n in SecurityProfileInlineDetector.SPYWARE_DETECTORS]}}),
            ]}},
            "rulebase": {"security": {"rules": {"entry": [
                self._rule("r-band", octet=21, spyware="p-band"),
                self._rule("r-dns", octet=22, spyware="p-dns"),
                self._rule("r-engine", octet=23, spyware="p-engine"),
            ]}}}})
        graded = {(v.security_rule.name, v.assertion): (v.satisfied, v.grading_value)
                  for v in SecurityRuleProfileVerdict.objects.select_related("security_rule")}
        self.assertEqual(graded[("r-band", "spyware_blocks_critical_high")], (False, "critical"))
        self.assertEqual(graded[("r-dns", "spyware_dns_sinkholes")], (False, "alert"))
        self.assertEqual(graded[("r-engine", "spyware_inline_analysis_blocks")], (False, "alert"))
        # NO GRADED VALUE on the assertions that have no grading, and none on the OTHER rules'
        # copy of a graded assertion when the profile satisfies it in a way that names no band.
        self.assertEqual(graded[("r-band", "spyware_exceptions_minimal")], (True, ""))
        self.assertEqual(graded[("r-dns", "spyware_blocks_critical_high")], (True, ""))
        # The rule whose DNS action is fine still carries the VALUE, because a grading reads the
        # value whether or not the verdict failed - oep-spy6-r01 reads `sinkhole` on the lab.
        self.assertEqual(graded[("r-band", "spyware_dns_sinkholes")], (True, "sinkhole"))

    def test_a_verdict_with_no_profile_carries_no_graded_value(self):
        point, _ = self._point(vsys={
            "rulebase": {"security": {"rules": {"entry": [
                self._rule("r-nothing", octet=31)]}}}})
        verdict = SecurityRule.objects.get(name="r-nothing").profile_verdict(
            "spyware_blocks_critical_high")
        self.assertIsNone(verdict.satisfied, "a NULL verdict fires, which is the finding")
        self.assertEqual(verdict.grading_value, "",
                         "naming a band here would hand the grading a severity it has not earned")

    def test_an_exception_at_alert_undoes_a_severity_verdict_the_rule_set_satisfied(self):
        # STAGE 5 ASKS FOR THIS and the lab cannot show it: the only exception standing on the
        # estate is at the pointer `default`, on oep-spy6-12 and oep-spy6-20. Both halves are
        # here so the difference between them is pinned rather than argued.
        point, _ = self._point(vsys={
            "profiles": {SPY: {"entry": [
                self._strong_profile("p-exc-alert", **{"threat-exception": {"entry": [
                    {"@name": "10001", "action": {"alert": None}}]}}),
                self._strong_profile("p-exc-default", **{"threat-exception": {"entry": [
                    {"@name": "10001", "action": {"default": None}}]}}),
            ]}},
            "rulebase": {"security": {"rules": {"entry": [
                self._rule("r-alert", octet=41, spyware="p-exc-alert"),
                self._rule("r-default", octet=42, spyware="p-exc-default"),
            ]}}}})
        alert = SecurityRule.objects.get(name="r-alert").profile_verdict(
            "spyware_blocks_critical_high")
        self.assertFalse(alert.satisfied)
        self.assertIn("10001", alert.detail)
        # THE POINTER DOES NOT FAIL IT. `default` resolves per signature from the content
        # release and the resolution is in no column, so failing on it would assert something
        # nothing read - and stage6-anti-spyware.json requires oep-spy6-12, which holds exactly
        # this, to keep PAN-SPY-001 satisfied while making only PAN-SPY-005 false.
        pointer = SecurityRule.objects.get(name="r-default").profile_verdict(
            "spyware_blocks_critical_high")
        self.assertTrue(pointer.satisfied)
        self.assertFalse(SecurityRule.objects.get(name="r-default").profile_verdict(
            "spyware_exceptions_minimal").satisfied)
        profile = SecurityProfile.objects.get(name="p-exc-default")
        self.assertEqual(profile.exceptions_undecided_without_resolution, ["10001"])
        self.assertEqual(profile.exceptions_handing_signatures_back, [])
        self.assertEqual(profile.widest_exempt_ip_count, 0,
                         "zero is the widest form, not the narrowest")

    def test_a_predefined_profile_reads_false_on_inline_analysis_and_fails_four_controls(self):
        # Read off /config/predefined/profiles/spyware on BOTH PA-VMs on 2026-10-29: neither
        # shipped profile carries `cloud-inline-analysis` or any engine node, `default` has the
        # content list at alert and no sinkhole node, and both leave every DNS category at the
        # literal `default`.
        predefined = {SPY: {"entry": [
            {"@name": "default",
             "rules": {"entry": [
                 {"@name": "simple-critical", "threat-name": "any", "category": "any",
                  "severity": {"member": ["critical"]}, "action": {"default": None}}]},
             "botnet-domains": {
                 "lists": {"entry": [{"@name": "default-paloalto-dns",
                                      "packet-capture": "disable",
                                      "action": {"alert": None}}]},
                 "dns-security-categories": {"entry": [
                     {"@name": n, "action": "default"} for n in
                     ("pan-dns-sec-cc", "pan-dns-sec-malware", "pan-dns-sec-phishing")]}}},
        ]}}
        point, _ = self._point(predefined=predefined, vsys={
            "rulebase": {"security": {"rules": {"entry": [
                self._rule("r-default", octet=90, spyware="default")]}}}})
        profile = SecurityProfile.objects.get(name="default", kind=SPY)
        self.assertTrue(profile.is_predefined)
        self.assertFalse(profile.cloud_inline_analysis,
                         "the vendor's own profile reads false, which is the firing side")
        self.assertEqual(profile.inline_detectors.count(), 5)
        self.assertEqual(profile.worst_inline_detector_action, "alert")
        rule = SecurityRule.objects.get(name="r-default")
        self.assertTrue(rule.spyware_profile_resolved,
                        "the predefined read is what makes the commonest binding resolve at all")
        self.assertEqual(rule.spyware_worst_engine_action, "alert")
        self.assertEqual(rule.spyware_dns_content_list_action, "alert")
        self.assertEqual(rule.spyware_worst_unstopped_severity, "critical")
        self.assertFalse(rule.spyware_inline_analysis_blocks)
        self.assertFalse(rule.spyware_dns_sinkholes)
        self.assertFalse(rule.spyware_dns_categories_enforced)
        self.assertFalse(rule.spyware_blocks_critical_high)

    def test_a_profile_that_stores_no_dns_branch_passes_the_action_half_and_not_the_rest(self):
        # oep-spy6-13, the committed keyless profile: THE ONE PLACE IN THIS DOMAIN WHERE AN
        # ABSENCE PASSES. The content list's implicit is sinkhole, measured on two appliances
        # and two content releases, so the action half of PAN-SPY-002 is satisfied by a profile
        # that configures nothing - while the categories, the engines and the rule set all fail.
        point, _ = self._point(vsys={
            "profiles": {SPY: {"entry": [{"@name": "p-bare"}]}},
            "rulebase": {"security": {"rules": {"entry": [
                self._rule("r-bare", octet=23, spyware="p-bare")]}}}})
        profile = SecurityProfile.objects.get(name="p-bare")
        self.assertFalse(profile.cloud_inline_analysis)
        self.assertEqual(profile.rule_count, 0)
        self.assertEqual(profile.threat_exceptions.count(), 0)
        self.assertEqual(profile.dns_content_list_action, "sinkhole")
        self.assertTrue(profile.dns_sinkhole_action_is_implicit)
        self.assertEqual(profile.dns_sinkhole_ipv4, "",
                         "and it holds NO address, which the action half does not test")
        rule = SecurityRule.objects.get(name="r-bare")
        self.assertTrue(rule.spyware_dns_sinkholes)
        self.assertEqual(rule.spyware_dns_content_list_action, "sinkhole")
        self.assertFalse(rule.spyware_blocks_critical_high)
        self.assertEqual(rule.spyware_worst_unstopped_severity, "critical")
        self.assertFalse(rule.spyware_dns_categories_enforced)
        self.assertFalse(rule.spyware_inline_analysis_blocks)
        self.assertEqual(rule.spyware_worst_engine_action, "alert")

    def test_every_engine_row_carries_a_blank_local_deep_learning_on_this_estate(self):
        # A COLUMN NOBODY POPULATED, said out loud. No standing profile on the lab writes
        # `local-deep-learning`, so every row of it is blank - which is what stage 5 declared
        # and is the answer this stage owes rather than a defect to hunt.
        point, _ = self._point(vsys={
            "profiles": {SPY: {"entry": [
                self._strong_profile("p1"),
                self._strong_profile("p2", **{"mica-engine-spyware-enabled": {"entry": [
                    spy_engine("HTTP Command and Control detector", "reset-both",
                               ldl="enable")]}}),
            ]}},
            "rulebase": {"security": {"rules": {"entry": [
                self._rule("r1", octet=51, spyware="p1")]}}}})
        p1 = SecurityProfile.objects.get(name="p1")
        self.assertEqual({d.local_deep_learning for d in p1.inline_detectors.all()}, {""})
        p2 = SecurityProfile.objects.get(name="p2")
        self.assertEqual(
            p2.inline_detectors.get(name="HTTP Command and Control detector")
            .local_deep_learning, "enable")
        self.assertEqual(
            {d.local_deep_learning for d in p2.inline_detectors.exclude(
                name="HTTP Command and Control detector")}, {""},
            "a synthesized row stores nothing here, and nothing is materialised")

    def test_the_provenance_row_for_the_new_profile_column_is_written(self):
        point, _ = self._point(vsys={
            "profiles": {SPY: {"entry": [self._strong_profile("p1"), {"@name": "p-bare"}]}},
            "rulebase": {"security": {"rules": {"entry": [
                self._rule("r1", octet=61, spyware="p1")]}}}})
        rows = {p.name: FieldProvenance.objects.get(
            object_id=p.pk, field_name="cloud_inline_analysis").provenance_type
            for p in SecurityProfile.objects.filter(kind=SPY)}
        self.assertEqual(rows["p1"], "local")
        self.assertEqual(rows["p-bare"], "pan_os_default",
                         "the measured implicit, not an assumption")


# ------------------------------------------------------------------------------------------
# Decryption profiles - PAN-DCP-001, 002 and 007's subject
# ------------------------------------------------------------------------------------------
#
# EVERY ENTRY SHAPE BELOW IS WHAT THE LAB STORED, read back off pan-fw-201 (PA-VM 11.2.5) and
# fw-core-tpa-a (PA-5220 11.1.13-h3) on 2026-10-29 through Panorama's `target=` proxy - not a
# shape reconstructed from the specification. That distinction has already cost this repo once:
# a pushed-rulebase walk used the merged view's spelling and a fixture built from the spec would
# have agreed with the bug.

DCP = SecurityProfile.KIND_DECRYPTION


def dcp_entry(name, *, protocol=None, forward=None, inbound=None, bare=False):
    """One `profiles/decryption` entry. `bare=True` is the 19-key-less lab subject."""
    entry = {"@name": name}
    if bare:
        return entry
    if protocol is not None:
        entry["ssl-protocol-settings"] = protocol
    if forward is not None:
        entry["ssl-forward-proxy"] = forward
    if inbound is not None:
        entry["ssl-inbound-proxy"] = inbound
    return entry


def dcp_values(entry, sw="11.2.5"):
    return decryption_profile_values(entry, software_version=sw)[0]


class DecryptionProfileImplicitTests(SimpleTestCase):
    """What an ABSENT key asserts, which on this node is per key and not per family."""

    def test_a_profile_with_no_key_at_all_reports_rather_than_passing(self):
        # `oep-dcp6-01`, and the vendor's predefined `default`, whose whole stored content is an
        # EMPTY `ssl-protocol-settings` container. So "nobody configured it" and "nobody
        # collected it" are the same configuration on this node, measured.
        v = dcp_values(dcp_entry("oep-dcp6-01", bare=True))
        self.assertEqual(v["ssl_min_version"], "tls1-0")
        self.assertEqual(v["ssl_max_version"], "tls1-2")
        self.assertTrue(v["ssl_min_version_below_tls12"])
        self.assertTrue(v["ssl_max_version_restrictive"])
        self.assertEqual(v["weakest_broken_primitive_permitted"], "rc4")
        self.assertEqual(v["weakest_non_pfs_or_unauthenticated_permitted"], "rsa")

    def test_md5_is_the_one_key_of_its_family_that_absence_disables(self):
        # THE MEASURED EXCEPTION. Twelve algorithm keys of this node assert ENABLED when absent
        # and two assert DISABLED; MD5 is the only one of the two a control asserts. A uniform
        # family default reports MD5 as permitted on every unconfigured profile in the estate.
        v = dcp_values(dcp_entry("p", bare=True))
        self.assertTrue(v["enc_algo_rc4"])
        self.assertTrue(v["enc_algo_3des"])
        self.assertTrue(v["auth_algo_sha1"])
        self.assertTrue(v["keyxchg_algo_rsa"])
        self.assertFalse(v["auth_algo_md5"], "absent MD5 is DISABLED, unlike its siblings")

    def test_an_empty_container_reads_the_same_as_an_absent_one(self):
        # `oep-dcp6-10` writes three EMPTY containers. The container keys carry no value of
        # their own - their absence asserts each child's implicit and nothing else - so the two
        # states must produce identical columns, and a reader that treated an empty container as
        # a different answer would split one configuration into two.
        empty = dcp_values({"@name": "p", "ssl-forward-proxy": None,
                            "ssl-inbound-proxy": None, "ssl-protocol-settings": None})
        self.assertEqual(empty, dcp_values(dcp_entry("p", bare=True)))

    def test_all_twelve_block_switches_read_absence_as_not_blocking(self):
        v = dcp_values(dcp_entry("p", bare=True))
        for column, _, _ in DECRYPTION_BLOCK_SWITCHES:
            self.assertFalse(v[column], column)


class DecryptionVersionOrderTests(SimpleTestCase):
    """The ordering, and why it is not `SslTlsServiceProfile.VERSION_ORDER`."""

    def test_sslv3_is_placed_and_sorts_below_every_tls_generation(self):
        # The shipped four-member tuple on the SSL/TLS service profile has no `sslv3`, and
        # ranking this leaf against it would make `oep-dcp6-04`'s floor unrecognised.
        self.assertEqual(decryption_version_rank("sslv3"), 0)
        self.assertLess(decryption_version_rank("sslv3"), decryption_version_rank("tls1-0"))
        self.assertEqual(decryption_version_rank("sslv3"), SslTlsServiceProfile.RANK_UNRECOGNISED + 1)

    def test_an_unrecognised_token_sorts_below_everything_so_the_verdict_fires(self):
        self.assertEqual(decryption_version_rank("TLSv1.2"), -1)
        v = dcp_values(dcp_entry("p", protocol={"min-version": "TLSv1.2"}))
        self.assertTrue(v["ssl_min_version_below_tls12"],
                        "the catalogue's spelling is not the device's, and it must not pass")

    def test_the_floor_verdict_fires_on_sslv3_tls10_and_tls11_and_not_on_tls12_or_tls13(self):
        for token, fires in (("sslv3", True), ("tls1-0", True), ("tls1-1", True),
                             ("tls1-2", False), ("tls1-3", False)):
            v = dcp_values(dcp_entry("p", protocol={"min-version": token}))
            self.assertEqual(v["ssl_min_version_below_tls12"], fires, token)

    def test_max_resolves_against_the_build_and_the_token_is_stored_unchanged(self):
        # `oep-dcp6-02` stores `max`. The literal is a POINTER, so three columns and not one.
        v = dcp_values(dcp_entry("p", protocol={"max-version": "max"}), sw="11.2.5")
        self.assertEqual(v["ssl_max_version"], "max", "the configured literal, unchanged")
        self.assertEqual(v["ssl_max_version_resolved"], "tls1-3")
        self.assertFalse(v["ssl_max_version_restrictive"])

    def test_an_unknown_build_leaves_the_ceiling_unresolved_and_the_verdict_firing(self):
        # Guessing upward would make an appliance whose ceiling nobody could place read as
        # COMPLIANT, which is the one direction that must not happen.
        v = dcp_values(dcp_entry("p", protocol={"max-version": "max"}), sw="99.9.9")
        self.assertEqual(v["ssl_max_version_resolved"], "")
        self.assertTrue(v["ssl_max_version_restrictive"])

    def test_a_ceiling_of_tls12_is_restrictive_on_every_lab_build(self):
        for sw in ("11.1.13-h3", "11.2.3-h3", "11.2.5"):
            v = dcp_values(dcp_entry("p", protocol={"max-version": "tls1-2"}), sw=sw)
            self.assertTrue(v["ssl_max_version_restrictive"], sw)


class DecryptionWeakestPrimitiveTests(SimpleTestCase):
    """The two collapsed verdicts, and every member of each value set."""

    def test_each_member_of_the_broken_order_is_reachable(self):
        # The four lab subjects that discriminate this column, by what they switch OFF.
        off = {"enc-algo-rc4": "no", "enc-algo-3des": "no",
               "auth-algo-sha1": "no", "auth-algo-md5": "no"}
        cases = [
            ({}, "rc4"),                                                  # oep-dcp6-01
            ({"enc-algo-rc4": "no"}, "3des"),                             # oep-dcp6-07
            ({"enc-algo-rc4": "no", "enc-algo-3des": "no"}, "sha1"),       # oep-dcp6-08
            ({"enc-algo-rc4": "no", "enc-algo-3des": "no",
              "auth-algo-md5": "yes"}, "md5"),                            # oep-dcp6-09
            (off, "none"),                                                 # oep-dcp6-02
        ]
        for protocol, expected in cases:
            v = dcp_values(dcp_entry("p", protocol=protocol))
            self.assertEqual(v["weakest_broken_primitive_permitted"], expected, protocol)

    def test_md5_ranks_above_sha1_so_a_profile_switching_md5_on_reports_md5(self):
        # SHA-1 is the one member stage 3 ranks below the others, for the vendor's own reason -
        # its row is CONDITIONAL where its neighbours are unconditional.
        v = dcp_values(dcp_entry("p", protocol={
            "enc-algo-rc4": "no", "enc-algo-3des": "no", "auth-algo-md5": "yes"}))
        self.assertEqual(v["weakest_broken_primitive_permitted"], "md5")
        self.assertTrue(v["auth_algo_sha1"], "sha1 is still permitted and is still reportable")

    def test_each_member_of_the_non_pfs_order_is_reachable(self):
        cases = [
            ({}, "rsa"),
            ({"keyxchg-algo-rsa": "no"}, "aes-128-cbc"),
            ({"keyxchg-algo-rsa": "no", "enc-algo-aes-128-cbc": "no"}, "aes-256-cbc"),
            ({"keyxchg-algo-rsa": "no", "enc-algo-aes-128-cbc": "no",
              "enc-algo-aes-256-cbc": "no"}, "none"),
        ]
        for protocol, expected in cases:
            v = dcp_values(dcp_entry("p", protocol=protocol))
            self.assertEqual(v["weakest_non_pfs_or_unauthenticated_permitted"], expected,
                             protocol)

    def test_collapsing_keeps_only_the_worse_and_the_booleans_stay_readable(self):
        # The named cost of one column rather than four: a report naming RC4 is silent about
        # SHA-1 on the same profile, which is why the four booleans are all presented.
        v = dcp_values(dcp_entry("p", protocol={}))
        self.assertEqual(v["weakest_broken_primitive_permitted"], "rc4")
        self.assertTrue(v["auth_algo_sha1"])
        self.assertTrue(v["enc_algo_3des"])


class DecryptionReferrerWalkTests(SimpleTestCase):
    """The walk the shipped one cannot do, and the companion that tells zero from unknown."""

    def test_a_decryption_rule_names_its_profile_at_profile_and_not_profile_setting(self):
        # `oep-dec6-r08` on fw-core-tpa-a vsys2 - the only rule in the estate that names a
        # decryption profile. The shipped two-hop walk reads `profile-setting`, which a
        # decryption rule does not carry, so it finds nothing here.
        rules = [{"@name": "r08", "profile": "default",
                  "destination": {"member": ["any"]}}]
        self.assertEqual(decryption_rule_references(rules), [("default", False)])

    def test_a_rule_naming_no_profile_contributes_nothing(self):
        # Eleven of the thirteen rules on that vsys, and all four on pan-fw-201.
        rules = [{"@name": "r01", "destination": {"member": ["any"]}}]
        self.assertEqual(decryption_rule_references(rules), [])

    def test_a_destination_of_any_is_not_a_narrowing(self):
        # `any` is a MEMBER of the list and not an absence, so the test is on the values.
        facts = decryption_rule_facts(
            decryption_rule_references([{"@name": "r", "profile": "p",
                                         "destination": {"member": ["any"]}}]),
            collected=True)
        self.assertTrue(facts["p"]["rule_destination_unrestricted"])

    def test_an_absent_destination_is_not_a_narrowing_either(self):
        # An unmeasured precondition must not read as the vendor's recommended exception.
        facts = decryption_rule_facts(
            decryption_rule_references([{"@name": "r", "profile": "p"}]), collected=True)
        self.assertTrue(facts["p"]["rule_destination_unrestricted"])

    def test_a_named_destination_set_narrows_and_clears_the_applicability_clause(self):
        # THE BRANCH THE LAB CANNOT DISCRIMINATE: `oep-dec6-r12` narrows its destination to
        # `ao-analytics-ingestion-services-01-loc` and names NO profile, so no stored row in
        # this estate has this column false. It is pinned here instead.
        facts = decryption_rule_facts(
            decryption_rule_references([
                {"@name": "r", "profile": "p",
                 "destination": {"member": ["ao-analytics-ingestion-services-01-loc"]}}]),
            collected=True)
        self.assertFalse(facts["p"]["rule_destination_unrestricted"])

    def test_one_narrowing_rule_among_several_suppresses_the_control_as_declared(self):
        # THE QUANTIFIER IS STAGE 5's AND THIS RUN BELIEVES IT IS THE WRONG WAY ROUND. Its
        # `computes` is explicit - "whether ANY decryption rule naming this profile restricts
        # its destination ... negated" - and its `stores` agrees: true only "where EVERY rule
        # naming it leaves the destination open". So one narrowed rule among ten wide-open ones
        # SUPPRESSES the control on a profile nine rules still expose, which is the suppressing
        # form rules.md warns about, on a column stage 5 itself documents as an applicability
        # clause. Implemented as declared and reported in the stage 7 artifact's `spec_gaps`;
        # the other quantifier - any rule leaving it open keeps the control applying - is what
        # this run would have written, and changing it is a person's call and not this stage's.
        #
        # This test asserts the DECLARED behaviour, so it fails if somebody flips it quietly.
        facts = decryption_rule_facts(
            decryption_rule_references([
                {"@name": "r1", "profile": "p", "destination": {"member": ["net-a"]}},
                {"@name": "r2", "profile": "p", "destination": {"member": ["any"]}}]),
            collected=True)
        self.assertFalse(facts["p"]["rule_destination_unrestricted"])
        self.assertEqual(facts["p"]["referrer_count"], 2)

    def test_the_collected_flag_is_carried_through_and_is_what_separates_zero_from_unknown(self):
        # THE OTHER BRANCH THE LAB CANNOT DISCRIMINATE: no pushed rulebase on any lab appliance
        # is unreadable, so `False` never occurs in a stored row today.
        facts = decryption_rule_facts(
            decryption_rule_references([{"@name": "r", "profile": "p"}]), collected=False)
        self.assertFalse(facts["p"]["decryption_rulebase_collected"])


class DecryptionProfileNormalizationTests(TestCase):
    """End to end, over payloads shaped like the ones read off the lab on 2026-10-29."""

    def _point(self, *, merged, pushed_profiles=None, serial="DCP7", sw="11.2.5"):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname=f"pano-{serial}")
        group = ApplianceGroup.objects.create(
            management_station=station, name=f"grp-{serial}",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number=serial, hostname=f"host-{serial}", software_version=sw)
        group.active_appliance = appliance
        group.save()
        point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, vsys_name="vsys1", in_scope=True)
        EnforcementNode.objects.create(
            management_station=station, enforcement_point=point, appliance=appliance)
        now = timezone.now()
        Snapshot.objects.create(management_station=station, appliance=appliance,
                                source_type="show_merged_config", collected_at=now,
                                payload=merged)
        Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="config_predefined_security_profiles", collected_at=now,
            payload={"profiles": {DCP: {"entry": [{"@name": "default",
                                                   "ssl-protocol-settings": None}]}}})
        Snapshot.objects.create(management_station=station, appliance_group=group,
                                source_type="show_pushed_shared_policy", collected_at=now,
                                payload={"policy": {"panorama": {}}})
        Snapshot.objects.create(management_station=station, enforcement_point=point,
                                source_type="show_pushed_shared_policy_vsys", scope_name="vsys1",
                                collected_at=now, payload={"policy": {"panorama": {}}})
        Snapshot.objects.create(
            management_station=station, enforcement_point=point,
            source_type="config_pushed_vsys_profiles", scope_name="vsys1",
            collected_at=now, payload=pushed_profiles if pushed_profiles is not None else {})
        return station, group, point

    @staticmethod
    def _merged(vsys_content=None, shared_content=None):
        return {"config": {
            "shared": shared_content or {},
            "devices": {"entry": [{"@name": "localhost.localdomain", "vsys": {"entry": [
                dict({"@name": "vsys1"}, **(vsys_content or {}))]}}]}}}

    def _normalize(self, group, point):
        normalize_appliance_group_security_profiles(group)
        return normalize_security_profiles(point)

    def test_the_vendor_predefined_profile_lands_as_a_row_that_fires(self):
        # IT EXISTS ON ALL FOUR LAB APPLIANCES AND IS THE COMMONEST FAILING STATE: it stores an
        # empty `ssl-protocol-settings` and nothing else, and it is in force on every appliance
        # whose rules name it.
        station, group, point = self._point(merged=self._merged())
        self._normalize(group, point)
        row = SecurityProfile.objects.get(kind=DCP, name="default")
        self.assertTrue(row.is_predefined)
        self.assertEqual(row.ssl_min_version, "tls1-0")
        self.assertTrue(row.ssl_min_version_below_tls12)
        self.assertEqual(row.weakest_broken_primitive_permitted, "rc4")

    def test_a_vsys_scoped_profile_is_owned_by_the_point_and_a_shared_one_by_the_group(self):
        station, group, point = self._point(
            merged=self._merged(
                {"profiles": {DCP: {"entry": [dcp_entry("oep-dcp6-01", bare=True)]}}},
                {"profiles": {DCP: {"entry": [dcp_entry(
                    "oep-dcp6-02", protocol={"min-version": "tls1-2",
                                             "max-version": "max"})]}}}))
        self._normalize(group, point)
        vsys_row = SecurityProfile.objects.get(kind=DCP, name="oep-dcp6-01")
        shared_row = SecurityProfile.objects.get(kind=DCP, name="oep-dcp6-02")
        self.assertEqual(vsys_row.enforcement_point_id, point.pk)
        self.assertIsNone(vsys_row.appliance_group_id)
        self.assertEqual(shared_row.appliance_group_id, group.pk)
        self.assertIsNone(shared_row.enforcement_point_id)
        self.assertEqual(shared_row.ssl_max_version_resolved, "tls1-3")
        self.assertFalse(shared_row.ssl_min_version_below_tls12)

    def test_the_referrer_columns_come_from_the_decryption_rulebase_and_not_from_security_rules(self):
        # A SECURITY rule naming a `decryption` profile is not a thing the device has, and the
        # shipped walk would find nothing either way. What matters is that the DECRYPTION rule
        # is found: without this the column reads zero for every profile in the estate, with a
        # deletion remediation attached.
        station, group, point = self._point(merged=self._merged({
            "profiles": {DCP: {"entry": [dcp_entry("p1", bare=True),
                                         dcp_entry("p2", bare=True)]}},
            "rulebase": {"decryption": {"rules": {"entry": [
                {"@name": "d1", "profile": "p1", "destination": {"member": ["any"]}}]}}},
        }))
        self._normalize(group, point)
        p1 = SecurityProfile.objects.get(kind=DCP, name="p1")
        p2 = SecurityProfile.objects.get(kind=DCP, name="p2")
        self.assertEqual(p1.referrer_count, 1)
        self.assertTrue(p1.is_used)
        self.assertEqual(p2.referrer_count, 0)
        self.assertFalse(p2.is_used, "a profile no rule names, which is the firing side")
        self.assertTrue(p1.decryption_rulebase_collected)
        self.assertTrue(p2.decryption_rulebase_collected,
                        "the rulebase WAS read; p2 simply is not in it")

    def test_a_narrowing_rule_clears_the_applicability_clause_on_the_profile_it_names(self):
        station, group, point = self._point(merged=self._merged({
            "profiles": {DCP: {"entry": [dcp_entry("p1", bare=True)]}},
            "rulebase": {"decryption": {"rules": {"entry": [
                {"@name": "d1", "profile": "p1",
                 "destination": {"member": ["pinned-apps"]}}]}}},
        }))
        self._normalize(group, point)
        row = SecurityProfile.objects.get(kind=DCP, name="p1")
        self.assertFalse(row.rule_destination_unrestricted)

    def test_every_measured_decryption_column_carries_a_provenance_row(self):
        # An absent key asserts a value on all 21, so a reader is owed the difference between a
        # value read and a value inferred on every one of them.
        station, group, point = self._point(merged=self._merged({
            "profiles": {DCP: {"entry": [
                dcp_entry("p-bare", bare=True),
                dcp_entry("p-set", protocol={"min-version": "tls1-2", "enc-algo-rc4": "no"},
                          forward={"block-expired-certificate": "yes"})]}}}))
        self._normalize(group, point)
        rows = {}
        for name in ("p-bare", "p-set"):
            row = SecurityProfile.objects.get(kind=DCP, name=name)
            rows[name] = {p.field_name: p.provenance_type for p in
                          FieldProvenance.objects.filter(object_id=row.pk)}
        measured = ([c for c, _, _ in DECRYPTION_ALGORITHM_SWITCHES]
                    + [c for c, _, _ in DECRYPTION_BLOCK_SWITCHES]
                    + ["ssl_min_version", "ssl_max_version"])
        self.assertEqual(len(measured), 21)
        for column in measured:
            self.assertIn(column, rows["p-bare"], column)
            self.assertEqual(rows["p-bare"][column], "pan_os_default",
                             f"{column}: a MEASURED implicit, not an assumption")
        for column in ("ssl_min_version", "enc_algo_rc4", "fwd_block_expired_certificate"):
            self.assertEqual(rows["p-set"][column], "local", column)

    def test_no_derived_decryption_column_carries_a_provenance_row(self):
        # `DerivedFieldDeclarationTests` enforces this repo-wide; this pins it for the seven
        # this domain added, because a derived column with a row would claim a device said
        # something it never says.
        station, group, point = self._point(merged=self._merged({
            "profiles": {DCP: {"entry": [dcp_entry("p", bare=True)]}}}))
        self._normalize(group, point)
        row = SecurityProfile.objects.get(kind=DCP, name="p")
        written = {p.field_name for p in FieldProvenance.objects.filter(object_id=row.pk)}
        for column in ("ssl_max_version_resolved", "ssl_min_version_below_tls12",
                       "ssl_max_version_restrictive", "rule_destination_unrestricted",
                       "weakest_broken_primitive_permitted",
                       "weakest_non_pfs_or_unauthenticated_permitted",
                       "decryption_rulebase_collected"):
            self.assertNotIn(column, written, column)

    def test_a_non_decryption_kind_keeps_the_firing_defaults_and_the_kind_clause_matters(self):
        # THE LOUD CONSEQUENCE OF A SHARED MODEL. An antivirus row holds `enc_algo_rc4 = True`,
        # so a clause written without `kind eq decryption` fires on every antivirus profile in
        # the estate. Nothing downstream enforces that clause, which is why it is pinned here.
        station, group, point = self._point(merged=self._merged({
            "profiles": {SecurityProfile.KIND_VIRUS: {"entry": [{"@name": "av1"}]}}}))
        self._normalize(group, point)
        row = SecurityProfile.objects.get(kind=SecurityProfile.KIND_VIRUS, name="av1")
        self.assertTrue(row.enc_algo_rc4)
        self.assertEqual(row.weakest_broken_primitive_permitted, "rc4")
        written = {p.field_name for p in FieldProvenance.objects.filter(object_id=row.pk)}
        self.assertNotIn("enc_algo_rc4", written,
                         "no decryption key was read, so nothing claims one was")


class DecryptionSettingsTests(TestCase):
    """The forward-proxy signing designation. PAN-DCP-003, 004 and 006's subject."""

    def _appliance(self, *, shared, certificates=None, sw="11.2.5"):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano-ds")
        group = ApplianceGroup.objects.create(
            management_station=station, name="grp-ds",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="DS7", hostname="host-ds", software_version=sw)
        Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"shared": shared, "devices": {"entry": [
                {"@name": "localhost.localdomain",
                 "vsys": {"entry": [{"@name": "vsys1"}]}}]}}})
        for name, is_ca, self_signed in (certificates or []):
            Certificate.objects.create(
                management_station=station, appliance=appliance, appliance_group=group,
                source_snapshot=Snapshot.objects.filter(appliance=appliance).first(),
                scope=Certificate.SCOPE_SHARED, name=name, is_ca=is_ca,
                is_self_signed=self_signed)
        return appliance

    def test_an_appliance_with_no_ssl_decrypt_node_still_gets_a_row_that_fires(self):
        # THE STATE ALL FOUR LAB APPLIANCES WERE IN before stage 6 built a designation on one,
        # and the state the other three are still in. A per-slot grain has NO ROW here, so it
        # could not report PAN-DCP-006 at all - which is the control this subject exists for.
        appliance = self._appliance(shared={})
        counts = normalize_decryption_settings(appliance)
        self.assertEqual(counts["decryption_settings"], 1)
        self.assertFalse(counts["node_present"])
        row = DecryptionSettings.objects.get(appliance=appliance)
        self.assertEqual(row.forward_trust_cert_rsa, "")
        self.assertFalse(row.forward_trust_is_designated_local_ca)
        self.assertFalse(row.untrust_distinct_from_trust)

    def test_the_designation_is_a_nested_dict_and_not_a_certificate_name(self):
        # `{"forward-trust-certificate": {"rsa": "oep-p1-cert"}}` - measured. A consumer reading
        # the container as a name stores the repr of a dict, which looks like a name.
        appliance = self._appliance(
            shared={"ssl-decrypt": {"forward-trust-certificate": {"rsa": "oep-p1-cert"}}},
            certificates=[("oep-p1-cert", True, True)])
        normalize_decryption_settings(appliance)
        row = DecryptionSettings.objects.get(appliance=appliance)
        self.assertEqual(row.forward_trust_cert_rsa, "oep-p1-cert")
        self.assertEqual(row.forward_trust_cert_ecdsa, "")
        self.assertTrue(row.forward_trust_is_designated_local_ca)

    def test_an_empty_untrust_container_is_not_a_designation(self):
        # pan-fw-201 stores `"forward-untrust-certificate": null` - the element exists and holds
        # nothing. Reading the container's presence rather than its children would report a
        # separate untrusted-site authority that does not exist.
        appliance = self._appliance(
            shared={"ssl-decrypt": {"forward-trust-certificate": {"rsa": "oep-p1-cert"},
                                    "forward-untrust-certificate": None}},
            certificates=[("oep-p1-cert", True, True)])
        normalize_decryption_settings(appliance)
        row = DecryptionSettings.objects.get(appliance=appliance)
        self.assertEqual(row.forward_untrust_cert_rsa, "")
        self.assertFalse(row.untrust_distinct_from_trust)

    def test_a_designation_naming_a_certificate_that_is_not_a_local_ca_does_not_pass(self):
        # THE BRANCH THE LAB CANNOT DISCRIMINATE: the one designation standing on the estate
        # names a self-signed CA, so no stored row has a filled trust slot and a false verdict.
        for certs in ([("c1", False, True)], [("c1", True, False)], []):
            with self.subTest(certs=certs):
                appliance = self._appliance(
                    shared={"ssl-decrypt": {"forward-trust-certificate": {"rsa": "c1"}}},
                    certificates=certs)
                normalize_decryption_settings(appliance)
                row = DecryptionSettings.objects.get(appliance=appliance)
                self.assertFalse(row.forward_trust_is_designated_local_ca)
                Certificate.objects.all().delete()
                DecryptionSettings.objects.all().delete()
                Snapshot.objects.all().delete()
                Appliance.objects.all().delete()
                ApplianceGroup.objects.all().delete()
                ManagementStation.objects.all().delete()

    def test_both_filled_trust_slots_must_qualify_and_not_just_one(self):
        # The weaker of the two is what a session can end up negotiating, and nothing in the
        # configuration says which it will be.
        appliance = self._appliance(
            shared={"ssl-decrypt": {"forward-trust-certificate": {
                "rsa": "good", "ecdsa": "third-party"}}},
            certificates=[("good", True, True), ("third-party", True, False)])
        normalize_decryption_settings(appliance)
        row = DecryptionSettings.objects.get(appliance=appliance)
        self.assertFalse(row.forward_trust_is_designated_local_ca)

    def test_untrust_naming_the_same_certificate_as_trust_is_not_distinct(self):
        # A firewall using one certificate for both gives a user no way to tell a trustworthy
        # site from an untrustworthy one.
        appliance = self._appliance(
            shared={"ssl-decrypt": {"forward-trust-certificate": {"rsa": "c1"},
                                    "forward-untrust-certificate": {"rsa": "c1"}}},
            certificates=[("c1", True, True)])
        normalize_decryption_settings(appliance)
        row = DecryptionSettings.objects.get(appliance=appliance)
        self.assertFalse(row.untrust_distinct_from_trust)

    def test_a_distinct_untrust_authority_passes(self):
        appliance = self._appliance(
            shared={"ssl-decrypt": {"forward-trust-certificate": {"rsa": "c1"},
                                    "forward-untrust-certificate": {"rsa": "c2"}}},
            certificates=[("c1", True, True), ("c2", True, True)])
        normalize_decryption_settings(appliance)
        row = DecryptionSettings.objects.get(appliance=appliance)
        self.assertTrue(row.untrust_distinct_from_trust)

    def test_the_four_designation_columns_carry_provenance_and_the_verdicts_do_not(self):
        appliance = self._appliance(
            shared={"ssl-decrypt": {"forward-trust-certificate": {"rsa": "c1"}}},
            certificates=[("c1", True, True)])
        normalize_decryption_settings(appliance)
        row = DecryptionSettings.objects.get(appliance=appliance)
        written = {p.field_name: p.provenance_type
                   for p in FieldProvenance.objects.filter(object_id=row.pk)}
        self.assertEqual(written.get("forward_trust_cert_rsa"), "local")
        # not_assumed: there is no value to materialise and `may_materialise` is false.
        self.assertEqual(written.get("forward_trust_cert_ecdsa"), "not_configured")
        self.assertNotIn("forward_trust_is_designated_local_ca", written)
        self.assertNotIn("untrust_distinct_from_trust", written)


class CertificateHsmCustodyTests(TestCase):
    """`private-key-on-hsm`, which NO certificate on this estate carries."""

    def test_an_absent_key_is_stored_as_an_assumption_and_fires(self):
        # Every certificate on all three lab appliances lacks this key, so the stored value is
        # the assumption on every row in the estate - and FALSE is the direction that RAISES
        # PAN-DCP-006 rather than passing it.
        from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
            PRIVATE_KEY_ON_HSM_ABSENT)
        self.assertIs(PRIVATE_KEY_ON_HSM_ABSENT.value, False)
        self.assertEqual(PRIVATE_KEY_ON_HSM_ABSENT.provenance_type, "assumed_default",
                         "assumed and not measured - stage 4's own disposition")
