"""Objects > Security Profiles (Anti-Spyware, Vulnerability Protection, Antivirus) and Groups.

Subjects of PAN-SPY-001 and PAN-VLN-001. Both are policy objects in the PAN-OS sense - they live
under `vsys/entry/profiles` or `shared/profiles`, arrive from Panorama through the pushed reads,
and a rule names them - so they scope exactly like address objects: vsys scope on the
enforcement point, shared scope on the appliance group, vendor scope synthesized per point. See
`ScopedPolicyObject`.

ONE MODEL FOR EVERY PROFILE KIND, with `kind`. This used to hold two kinds and said so, on the
grounds that they are one shape - an ordered rule list whose entries match on severity. The
vulnerability rule adds `host`, `cve` and `vendor-id`, which only change which rules can match,
and that is decided in normalization rather than stored as columns.

ANTIVIRUS IS NOT THAT SHAPE, and it is here anyway. It has per-protocol decoders - ftp, http,
http2, imap, pop3, smb, smtp - not severity rules. What made room for it was moving the severity
verdict off this model onto `SecurityProfileSeverityVerdict`: what remains here is what every
kind genuinely shares, which is a name, a scope, a precedence, whether it is predefined, and who
references it. A kind that answers no severity question simply writes no verdict rows.

That is the line to hold as the remaining kinds arrive - URL filtering, file blocking, WildFire
analysis, decryption, SCTP, SD-WAN path quality, all of which the predefined collector already
downloads. Shared identity belongs here; anything true of only one kind belongs beside it.

THE VERDICT IS ORDER-INDEPENDENT (Jason, 2026-09-11). A severity is blocked only when a
catch-all rule covers it - client AND server, for vulnerability - and every rule that can match
it takes a blocking action. No document says whether profile rules are first-match, and this
reading does not need to know: it cannot pass a weak profile. Its cost is that a non-blocking rule
sitting BELOW a broad blocking one still fails the severity, where first-match would never reach
it. `blocking` is drop, reset-client, reset-server, reset-both and block-ip - a deviation from the
corpus minimum, which names reset-both alone.

PREDEFINED PROFILES ARE ROWS TOO. `default` and `strict` ship with the device, live under
`/config/predefined/profiles` rather than in the merged config, and are what a rule uses when
nobody built a custom profile. They are assessed only when something USES them - a rule or a
profile group names them - which is what `is_used` records. An unused `default` is not a finding
about the estate; a rule protected by it is.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from ..collected import ApplianceGroup, EnforcementPoint, ManagementStation
from .objects import ScopedPolicyObject


class SecurityProfile(ScopedPolicyObject):

    #: Computed here: severity verdicts over the rule list, and the referrer walk. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "is_predefined",
        "rule_count",
        "threat_exception_count",
        "referrer_count",
        "is_used",
        "has_rules",
        "stops_floor_file_types",
        "floor_file_type_action",
        "stops_nested_encoding",
        "nested_encoding_action",
        "expresses_unopenable_file_decision",
        "confirm_rule_beyond_web_browsing",
        "every_rule_carries_both_counts",
        "lowest_block_threshold",
        "reference_reach",
        "reference_reach_resolved",
        # ANTIVIRUS and WILDFIRE-ANALYSIS aggregates over the satellite rows, added for
        # PAN-AVW-001/002/003. Aggregates over related rows, so they have no payload key of
        # their own and can never carry a provenance row.
        "weakest_decoder_action",
        "weakest_application_override_action",
        "weakest_ml_model_state",
        "submits_all_file_types",
        "covers_all_applications",
        "direction_coverage",
        # DECRYPTION, added for PAN-DCP-001/002/007. The two version verdicts and the two
        # weakest-primitive tokens are computed from this row's own measured columns; the two
        # rule-facing ones come from the decryption rulebase in the same payload the profile was
        # read from. None of them has a payload key, so none can carry a provenance row.
        #
        # THE 21 MEASURED DECRYPTION COLUMNS ARE DELIBERATELY NOT HERE. Each has a key under
        # `ssl-protocol-settings/`, `ssl-forward-proxy/` or `ssl-inbound-proxy/` and writes a
        # `FieldProvenance` row, because for every one of them an absent key asserts a value and
        # a reader is owed the difference between a value read and a value inferred.
        "ssl_max_version_resolved",
        "ssl_min_version_below_tls12",
        "ssl_max_version_restrictive",
        "rule_destination_unrestricted",
        "weakest_broken_primitive_permitted",
        "weakest_non_pfs_or_unauthenticated_permitted",
        "decryption_rulebase_collected",
        # URL FILTERING, added for PAN-URL-001 to PAN-URL-006. Twenty-seven verdicts, counts,
        # inventories and position facts over this row's own measured columns, the device's own
        # category catalogue and the custom-URL-category rows. None of them has a payload key,
        # so none can carry a provenance row.
        #
        # THE EIGHTEEN MEASURED URL-FILTERING COLUMNS ARE DELIBERATELY NOT HERE, for the same
        # reason the twenty-one decryption ones are not: each has a key under the entry or
        # under `credential-enforcement/`, each writes a `FieldProvenance` row, and for every
        # one of them a reader is owed the difference between a value read and a value
        # inferred - two of the three request-header booleans rest on an ASSUMED default and
        # the report has to say so.
        "category_catalogue_size",
        "category_catalogue_collected",
        "all_hostile_categories_blocked",
        "weakest_hostile_category_action",
        "unblocked_hostile_categories",
        "all_reachable_categories_logged",
        "reachable_unlogged_category_count",
        "reachable_unlogged_categories",
        "worst_reachable_unlogged_category",
        "credential_submission_blocked_for_every_category",
        "all_reachable_categories_credential_restricted",
        "credential_permissive_category_count",
        "credential_permissive_categories",
        "worst_credential_permissive_category",
        "records_all_request_headers",
        "unrecorded_request_header_count",
        "unrecorded_request_headers",
        "worst_unrecorded_request_header",
        "local_inline_categorization_on",
        "local_inline_categorization_undetermined",
        "any_inline_analysis_engine_on",
        "inline_analysis_exemption_count",
        "inline_analysis_exemptions_computed",
        "broadest_inline_analysis_exemption_type",
        "permitted_custom_category_count",
        "permitted_custom_categories",
        "weakest_permitted_custom_category_action",
        # VULNERABILITY PROTECTION, added for PAN-VLN-004. A classification over three unrelated
        # subtrees and over whether a CHILD of an exception entry exists, so no payload key
        # carries it and it can never hold a provenance row.
        #
        # `inline_cloud_analysis_enabled` IS DELIBERATELY NOT HERE. It reads the entry's own
        # `cloud-inline-analysis` key and writes a `FieldProvenance` row, and on a vulnerability
        # profile that row is the only thing separating the value the device holds from the one
        # this project INFERS for an absent key - stage4-vulnerability-protection.json declined
        # to call that implicit measured.
        "widest_exemption_surface",
        # DOS PROTECTION, added for PAN-ZON-007. A keyed summary of the flood and resource
        # subtrees rather than a read of any one leaf, so it has no payload key of its own and
        # can never carry a provenance row.
        #
        # `profile_type` IS DELIBERATELY NOT HERE. It reads the entry's own mandatory `type`
        # leaf and writes a `FieldProvenance` row - and on this object that row is what tells a
        # reader the difference between a key the device holds and a candidate-only entry that
        # never passed commit validation, which is the only way the key can be absent.
        "flood_and_resource_settings",
    )
    KIND_SPYWARE = "spyware"
    KIND_VULNERABILITY = "vulnerability"
    KIND_VIRUS = "virus"
    KIND_WILDFIRE_ANALYSIS = "wildfire-analysis"
    KIND_FILE_BLOCKING = "file-blocking"
    KIND_DATA_FILTERING = "data-filtering"
    KIND_DECRYPTION = "decryption"
    KIND_URL_FILTERING = "url-filtering"
    #: PAN-ZON-007 and PAN-ZON-008's DoS half. THE CHEAPEST KIND ON THIS MODEL and the
    #: reason is a measured scope match rather than a resemblance: stage 4 measured a DoS
    #: protection profile at `vsys/entry/profiles/dos-protection` AND at
    #: `/config/shared/profiles/dos-protection` - the shared write was ACCEPTED, which is the
    #: measured contrast with the ZONE protection profile beside it, whose shared spelling is
    #: refused code=13 "Could not find schema node for xpath" - with a device-group scope
    #: derived from the grammar, and a DoS POLICY RULE is what names it. That is
    #: `ScopedPolicyObject`'s shape exactly, and it is why this is a kind and not a model.
    #:
    #: ADDING A KIND MAKES EVERY CONTROL ALREADY ON THIS MODEL SEE THE NEW ROWS, and nothing
    #: downstream enforces the `kind` clause that keeps them off - no catalog schema check, no
    #: compiler check, no lint, no generic test. A control on one of the eight existing kinds
    #: that does not clause on `kind` begins firing on DoS protection profiles the day this
    #: ships, and its columns hold their defaults on those rows. Stage 5 named that as the cost
    #: of the proposal and this comment is the only place in the code it can be named.
    #:
    #: The class docstring enumerates the kinds it expected next and DoS protection is not
    #: among them. The line it says to hold is held: nothing true of only this kind is on this
    #: model beyond the two columns below, and the flood thresholds, the block durations and
    #: the concurrent-session ceiling are in ONE json column rather than twenty.
    KIND_DOS_PROTECTION = "dos-protection"
    KIND_CHOICES = [
        (KIND_SPYWARE, "Anti-Spyware"),
        (KIND_VULNERABILITY, "Vulnerability Protection"),
        (KIND_VIRUS, "Antivirus"),
        (KIND_WILDFIRE_ANALYSIS, "WildFire Analysis"),
        (KIND_FILE_BLOCKING, "File Blocking"),
        (KIND_DATA_FILTERING, "Data Filtering"),
        (KIND_DECRYPTION, "Decryption"),
        (KIND_URL_FILTERING, "URL Filtering"),
        (KIND_DOS_PROTECTION, "DoS Protection"),
    ]

    #: How far the reference walk behind `reference_reach` got. FOUR values, not a boolean,
    #: because `unreferenced` and `undetermined` have opposite consequences for a reader and a
    #: boolean collapses them - which is the measured failure the column exists for.
    REACH_BY_RULE = "named_by_a_rule"
    REACH_BY_GROUP_ONLY = "named_by_a_group_only"
    REACH_UNREFERENCED = "unreferenced"
    REACH_UNDETERMINED = "undetermined"
    REACH_CHOICES = [
        (REACH_BY_RULE, "Named by a security rule"),
        (REACH_BY_GROUP_ONLY, "Named only by a profile group no rule names"),
        (REACH_UNREFERENCED, "Nothing on this firewall names it"),
        (REACH_UNDETERMINED, "The reference walk could not be completed"),
    ]
    #: Which kinds answer the file-blocking questions, and which answer the data-filtering
    #: ones. A kind that answers neither keeps the column default, which is the firing side -
    #: the same rule the severity verdicts follow, except that these are COLUMNS and so cannot
    #: be absent the way a verdict ROW can. The `kind` clause on every query is what keeps a
    #: file-blocking assertion off an antivirus row; nothing downstream enforces that.
    FILE_BLOCKING_KINDS = (KIND_FILE_BLOCKING,)
    DATA_FILTERING_KINDS = (KIND_DATA_FILTERING,)
    #: Which kinds answer the decryption questions. The same rule as the two above, and this
    #: family is the LOUDEST case of it: the permitted-primitive columns default TRUE, so a
    #: `virus` row reads as permitting RC4 and a clause written without `kind eq decryption`
    #: fires on every antivirus profile in the estate. Nothing downstream enforces the clause.
    DECRYPTION_KINDS = (KIND_DECRYPTION,)
    #: Which kinds answer the URL-filtering questions. The same rule as the three above, and
    #: the same hazard as the decryption family: `local_inline_categorization_undetermined`
    #: defaults TRUE and `category_catalogue_collected` defaults FALSE, so every spyware,
    #: antivirus and decryption row in the estate reads as "the URL category catalogue was
    #: never collected" - which is true of them and means nothing, because they have no
    #: catalogue. A clause written without `kind eq url-filtering` fires on all of them.
    URL_FILTERING_KINDS = (KIND_URL_FILTERING,)
    #: Which kinds answer the DoS-protection questions. The same rule as the four above:
    #: `profile_type` is blank and `flood_and_resource_settings` is null on every other kind,
    #: and the `kind eq dos-protection` clause every query over them carries is what keeps a
    #: DoS assertion off an antivirus row. Nothing downstream enforces that clause.
    DOS_PROTECTION_KINDS = (KIND_DOS_PROTECTION,)

    #: The three categories PAN-URL-001 asserts must be refused outright. THE VENDOR NAMES
    #: ELEVEN (Help p.297, URL guide p.133) and stage 3 asserts these three; widening the set
    #: is stage 3's decision and not this model's. All three were confirmed present in the
    #: device's own catalogue on all four lab appliances, 2026-10-29.
    HOSTILE_URL_CATEGORIES = ("command-and-control", "malware", "phishing")

    #: The six site-access actions, WEAKEST FIRST, which is the order `_weakest` wants.
    #:
    #: `isolate` IS PLACED HERE AND STAGE 5 DECLINED TO PLACE IT, saying only that it sits
    #: "outside that order". It is ranked immediately above `allow` for two reasons that have
    #: to hold together: the verdicts treat an isolated category as reachable-and-unlogged,
    #: because the interface renders it as `allow` and no screen shows otherwise - so it must
    #: not rank as a restriction - while remote browser isolation does something, so calling it
    #: weaker than a bare permit would overstate. With `allow` left weakest, a profile whose
    #: only weakness is an isolated category reports `isolate` and is distinguishable.
    #:
    #: `none` IS NOT HERE. The device accepts it on a custom category only and refuses it as a
    #: member of any site-access list, which is what says `none` is the ABSENCE of membership
    #: rather than an action.
    URL_ACTION_WEAKEST_FIRST = ("allow", "isolate", "alert", "continue", "override", "block")
    URL_ACTION_BLOCK = "block"
    URL_ACTION_ALLOW = "allow"
    URL_ACTION_ISOLATE = "isolate"
    #: What a CUSTOM category named in no list is: inert, matching nothing. Measured - a
    #: key-less profile renders every custom category at `none` and every predefined one at
    #: `allow` - and it is the state a category must be put into in every profile before it can
    #: be deleted, so a category here is mid-retirement rather than carved out.
    URL_ACTION_NONE = "none"
    #: The actions that leave a category REACHABLE. `none` is absent because an inert category
    #: matches nothing, and `block` because it refuses.
    URL_REACHABLE_ACTIONS = ("allow", "isolate", "alert", "continue", "override")
    #: Reachable AND invisible: no log entry is written. This is the set PAN-URL-002 tests for
    #: emptiness, and `isolate` is in it for the reason given above.
    URL_UNLOGGED_ACTIONS = ("allow", "isolate")

    #: The four credential-detection methods, as `action=complete` enumerates them identically
    #: on all four appliances. The arms are ELEMENT PRESENCE and only `group-mapping` takes a
    #: value; the chosen arm is a CHILD ELEMENT and a text value is refused.
    CREDENTIAL_MODES = ("disabled", "ip-user", "group-mapping", "domain-credentials")
    CREDENTIAL_MODE_DISABLED = "disabled"
    #: The credential actions, weakest first. There is no `isolate` arm under
    #: credential-enforcement and no `override`.
    CREDENTIAL_ACTION_WEAKEST_FIRST = ("allow", "alert", "continue", "block")

    #: Stage 3's own risk placement for the two "worst category" gradings, WORST FIRST. The
    #: remaining 80-odd categories the device offers take the assertion's baseline, which this
    #: tuple expresses by not naming them - `_weakest` returns an unplaced member as the device
    #: gave it, and no calibration query matches it.
    URL_CATEGORY_RISK_WORST_FIRST = (
        "high-risk", "unknown", "medium-risk", "newly-registered-domain", "not-resolved",
        "low-risk")

    #: The three request headers, by the vendor's own label, WORST-MISSING FIRST. All three are
    #: placed and the set is whole: the device offers these three and no more at this object on
    #: all four appliances. The 12.2 screen replaces them with a different field set, which is
    #: why this column's derivation is not established there.
    REQUEST_HEADER_LABELS = (
        ("log_http_header_xff", "X-Forwarded-For"),
        ("log_http_header_user_agent", "User-Agent"),
        ("log_http_header_referer", "Referer"),
    )

    #: A custom category's two stored types, BROADEST FIRST. An external dynamic list is the
    #: third kind the vendor documents at the exemption field and the device offered no such
    #: name at that position on any of the three builds read, so it has no placement here
    #: rather than a guessed one.
    URL_CATEGORY_TYPE_BROADEST_FIRST = ("Category Match", "URL List")
    #: Kinds built from an ordered rule list matching on SEVERITY, and so the only kinds for
    #: which a severity verdict means anything. Antivirus is deliberately not here: it has
    #: per-protocol decoders instead, and writes no verdict rows.
    THREAT_RULE_KINDS = (KIND_SPYWARE, KIND_VULNERABILITY)

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE, related_name="security_profiles")
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE, related_name="security_profiles",
        null=True, blank=True)
    appliance_group = models.ForeignKey(
        ApplianceGroup, on_delete=models.CASCADE, related_name="security_profiles",
        null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="security_profiles")

    kind = models.CharField(max_length=32, choices=KIND_CHOICES)
    description = models.TextField(blank=True)
    is_predefined = models.BooleanField(default=False)
    rule_count = models.PositiveIntegerField(default=0)
    threat_exception_count = models.PositiveIntegerField(default=0)

    #: Rules and profile groups that name this definition, resolved within their own scope
    #: first (vsys, then shared, then predefined). A count and a flag rather than the list,
    #: because a finding rests on a column; `referrers` is for the tab.
    referrer_count = models.PositiveIntegerField(default=0)
    is_used = models.BooleanField(default=False)
    referrers = models.JSONField(default=list, blank=True)

    #: ANTI-SPYWARE ONLY, and blank on every other kind. The sinkhole destination is a
    #: PROFILE-level prerequisite rather than a property of a signature source: measured
    #: 2026-10-11, a `sinkhole` action is refused with `sinkhole IPv4 information is missing`
    #: (code=12) until `botnet-domains/sinkhole/ipv4-address` exists, and AN IPv6 ADDRESS ALONE
    #: DOES NOT SATISFY IT - the refusal is unchanged with ipv6 set.
    #:
    #: `pan-sinkhole-default-ip` is the vendor's symbolic default and what predefined `strict`
    #: carries; the node also accepts an FQDN or any IPv4 address. Blank means the config does
    #: not say, which for a profile whose action is `sinkhole` should be impossible - the device
    #: refuses that combination - and is the normal state everywhere else.
    #:
    #: WHICH address is not assertable. controls.json's preferred value wants "an internal
    #: sinkhole address inside a monitored zone", and no configuration states which zone is
    #: monitored - so the column is detail for the tab, not a control's subject.
    dns_sinkhole_ipv4 = models.CharField(max_length=128, blank=True)
    dns_sinkhole_ipv6 = models.CharField(max_length=128, blank=True)

    #: ANTI-SPYWARE ONLY, and the Inline Cloud Analysis tab's own enable - the profile's
    #: `cloud-inline-analysis` key, POSITIVE polarity, so the column says what a reader wants it
    #: to say. FALSE is the firing side and the default.
    #:
    #: **controls.json points at a child that does not exist.** Its set command and xpath both end
    #: `/enabled`; the PARENT is a real bare boolean and the child is refused with the MISLEADING
    #: code=13 `set failed, may need to override template object first`, which taken at face value
    #: sends a reader to Panorama to override a template for a node no appliance has.
    #:
    #: Measured 2026-10-25 on serial 691665AC334B458 (PA-VM 11.2.5): on a committed profile
    #: storing no such key the tab's `Enable cloud inline analysis` box renders UNTICKED, with the
    #: positive control paid (writing `yes` is accepted and reads back) and the sibling move paid
    #: (moving the five engine entries underneath it left the box unticked, so the tab's enable is
    #: not derived from the engines). Re-read 2026-10-29 off the same serial: `yes` on all twelve
    #: configured standing profiles, the key ABSENT on the keyless one, and ABSENT on BOTH
    #: predefined profiles - so every estate binding `default` or `strict` reads false here.
    cloud_inline_analysis = models.BooleanField(default=False)

    #: VULNERABILITY ONLY, and the SAME DEVICE KEY `cloud-inline-analysis` the column directly
    #: above reads. Two columns over one node is a hazard and is recorded as one: OEP stage 7,
    #: vulnerability-protection, 2026-10-30. Read this before clausing on either.
    #:
    #:   `cloud_inline_analysis`           written for `kind=spyware` ONLY and HARDCODED False
    #:                                     on every other kind, by the normalizer's own `kind`
    #:                                     gate. On a vulnerability profile it is NOT a reading.
    #:   `inline_cloud_analysis_enabled`   written for `kind=vulnerability` ONLY and hardcoded
    #:                                     False on every other kind, the mirror image.
    #:
    #: So a vulnerability profile whose key is `yes` carries True here and False above, and the
    #: two say opposite things about one device key on ONE ROW. Nothing merges them because
    #: merging means widening a column another domain measured and tested for its own kind -
    #: `tests_security_profiles.py` asserts the vulnerability case stores False above - and
    #: because stage5-vulnerability-protection.json declares this column by name. WHICH OF THE
    #: TWO SURVIVES IS A PRODUCT DECISION and is in that run's handback, not taken here.
    #:
    #: POSITIVE polarity: yes means the real-time analysis runs, so the per-detector actions
    #: underneath it are in effect rather than merely stored. FALSE is the firing side and the
    #: default, and a profile with every detector at reset-both and this switch off inspects
    #: nothing in real time - which is the gap PAN-VLN-003's first half asserts and which the
    #: detector rows alone cannot see.
    #:
    #: ITS IMPLICIT IS AN INFERENCE AND NOT A MEASUREMENT, which is why it is absent from
    #: DERIVED_FIELDS and writes `assumed_default` rather than `pan_os_default`.
    #: stage4-vulnerability-protection.json records `unmeasured` with `consumer_disposition:
    #: assumed`: three readings agree that an absent key renders the `Enable cloud inline
    #: analysis` box unticked - the DOM, the screenshot, and all nine pre-existing lab profiles
    #: omitting the key while two of them carry detector entries at reset-both - and the POSITIVE
    #: CONTROL WAS NOT PAID on this kind, so "renders the implicit value" cannot be told from
    #: "renders an unticked box whatever the config says". The spyware measurement above is of a
    #: different kind's entry and is not borrowed.
    inline_cloud_analysis_enabled = models.BooleanField(default=False)

    #: {surface: count} for every exception surface that holds any. The COUNT is in
    #: `threat_exception_count`; this says WHERE, which is what a hygiene finding names and
    #: what an engineer needs to find them. Detail only - a control rests on the count.
    #:
    #: Four surfaces exist on an anti-spyware profile and controls.json names one. See
    #: `exception_surfaces` in the normalizer.
    exception_surfaces = models.JSONField(default=dict, blank=True)

    #: THE WIDEST EXEMPTION THIS PROFILE CARRIES, AS A SHAPE RATHER THAN A COUNT. PAN-VLN-004's
    #: grading axis, and VULNERABILITY ONLY: the three shapes below are the three surfaces that
    #: kind has, and an anti-spyware profile has five - two of them in the botnet tree, which no
    #: member here could describe. Blank on every other kind, so the `kind` clause every query
    #: over this model carries is what keeps the reading off the wrong rows.
    #:
    #: One exemption nobody can justify is the finding and twenty documented ones
    #: are not worse in any way the configuration can show, so the severity turns on HOW WIDE the
    #: widest one is and not on how many there are - `threat_exception_count` is the count and
    #: `exception_surfaces` is the map, and a finding may never rest on the map.
    #:
    #: THE THREE SHAPES ARE THIS ASSESSMENT'S VOCABULARY AND NOT THE DEVICE'S. No key of any
    #: object holds a value set these are members of; they are read off the PRESENCE of
    #: `exempt-ip` on an exception entry and off which surface holds the entry.
    #:
    #: EMPTY means no exemption on any surface, which is the PASSING state on this axis - so
    #: nothing may rest an assertion here. What raises PAN-VLN-004 is the rule-grain verdict
    #: `vulnerability_exceptions_minimal`, and what catches a rule nobody assessed is
    #: `SecurityRule.vulnerability_verdict_written`. This column can only ever soften the
    #: severity of a finding another column has already raised.
    EXEMPTION_NONE = ""
    #: A per-signature exception narrowed to named addresses - the narrowest real exemption.
    EXEMPTION_SIGNATURE_SCOPED = "signature-scoped"
    #: A per-signature exception with NO address scope, so it applies to everything the profile
    #: inspects. Measured: an exemption is WIDEST WHEN ITS `exempt-ip` IS ABSENT, and zero
    #: entries is the same state as no node - see `widest_exempt_ip_count`, whose name carries
    #: the same inverted polarity for the same reason.
    EXEMPTION_SIGNATURE_UNSCOPED = "signature-unscoped"
    #: An entry on either real-time-analysis exclusion list, which lifts EVERY detector on the
    #: profile for the whole population the list resolves to. The surfaces take a REFERENCE to an
    #: external dynamic list or an address group and refuse a literal, so one entry can be any
    #: number of hosts and the configuration never says how many.
    EXEMPTION_INLINE_POPULATION = "inline-analysis-population"
    #: WIDEST LAST, so `[-1]` is the answer and the order reads the way the grading reads.
    EXEMPTION_WIDTH_ORDER = (EXEMPTION_NONE, EXEMPTION_SIGNATURE_SCOPED,
                             EXEMPTION_SIGNATURE_UNSCOPED, EXEMPTION_INLINE_POPULATION)
    widest_exemption_surface = models.CharField(max_length=64, blank=True)

    #: Whether this profile carries any rule at all. FALSE means it matches nothing and takes no
    #: action, whatever its name suggests - legal, committable and measured on two of the lab's
    #: six data-filtering profiles, including the only one anything in the estate references.
    #:
    #: THE SIBLING OF `rule_count` AND DELIBERATELY NOT THE SAME CLAIM. `rule_count` is an
    #: arithmetic reading; this is the vendor fact the absence of the `rules` key licenses. The
    #: two are written from one `profile_rules()` call and `test_has_rules_agrees_with_rule_count`
    #: fails if they ever disagree.
    has_rules = models.BooleanField(default=False)

    # --- file blocking. Blank/false on every other kind; see FILE_BLOCKING_KINDS. ---

    #: Whether at least one rule blocks EVERY floor file type, in BOTH directions. The floor is
    #: spelled as the device's own catalogue spells it - `PE` upper case, the rest lower - because
    #: the lower-case spellings are REFUSED at the write (code=12, "file-type 'pe' is not an
    #: allowed keyword"), so a verdict computed against the asserted spelling matches no stored
    #: row anywhere. `inbound` is refused too: the leaf's value set is upload|download|both, so
    #: `both` is the only reading that satisfies a floor of "at minimum inbound".
    #:
    #: FALSE IS THE FIRING SIDE and the default, so a row nobody has recomputed raises rather
    #: than passes. Computed over the rule SET and not the rule SEQUENCE - see
    #: `file_blocking_verdicts`.
    stops_floor_file_types = models.BooleanField(default=False)

    #: The WEAKEST action in force on the floor file types across this profile's rules, ordered
    #: block, continue, alert. BLANK where no rule names any of them, which matches none of the
    #: severity placements - so the baseline finding reports at its own severity instead of a
    #: calibrated one. Blank rather than null deliberately: the search layer has no is-null
    #: operator, so a nullable column passes every clause written over it.
    floor_file_type_action = models.CharField(max_length=32, blank=True)

    #: The same conjunction as `stops_floor_file_types` over the single nested-encoding member,
    #: `Multi-Level-Encoding`, spelled as /config/predefined/tdb/file-type spells it. The
    #: lower-case spelling the control asserts is refused at the write.
    stops_nested_encoding = models.BooleanField(default=False)

    #: The weakest action in force on the nested-encoding member, same order and same blank rule
    #: as `floor_file_type_action`.
    nested_encoding_action = models.CharField(max_length=32, blank=True)

    #: Whether any rule names at least one file type the firewall cannot look inside - a
    #: password-protected archive or a protected office document - with ANY action. TRUE means a
    #: decision about those files is expressed in the configuration; it says nothing about which
    #: way the decision went, which is the whole of what the assertion asks.
    expresses_unopenable_file_decision = models.BooleanField(default=False)

    #: Whether this profile carries a rule whose action is `continue` over anything but
    #: web-browsing alone. TRUE IS THE FINDING: the vendor says such a rule stops the traffic the
    #: security policy permits, and neither the write gate nor the commit gate enforces it - the
    #: vendor's own predefined `basic file blocking` ships the combination.
    #:
    #: THE ONE COLUMN HERE WHOSE FIRING SIDE IS TRUE, so its migration window is silent. That is
    #: deliberate: inverting it would mean storing the negation of what the device says.
    confirm_rule_beyond_web_browsing = models.BooleanField(default=False)

    # --- data filtering. False/null on every other kind; see DATA_FILTERING_KINDS. ---

    #: Whether EVERY rule carries both the alert count and the block count. FALSE is the finding:
    #: at least one rule detects without stopping, or stops without warning. A profile with no
    #: rules is FALSE and not vacuously true - the assertion is about a profile that is watching.
    #:
    #: A STORED 0 PASSES THIS COLUMN, because the key is present. What 0 MEANS is unsettled: it is
    #: inside the device's writable range at both ends, and `alert > block` is accepted, so the
    #: pair is not validated as ordered either.
    every_rule_carries_both_counts = models.BooleanField(default=False)

    #: The smallest block count any rule carries, or NULL where no rule carries one. NULL here is
    #: safe where it would not be elsewhere: nothing clauses on this column, it is the number an
    #: assessor reads beside the verdict, and 0 is a real and distinct stored value that an
    #: empty-string sentinel could not hold.
    lowest_block_threshold = models.PositiveIntegerField(null=True, blank=True)

    # --- the reference walk, both kinds (and every other kind once its walk is trusted) ---

    #: How far the two-hop reference walk reaches this profile. `undetermined` IS THE DEFAULT and
    #: not null, on this column's own instruction: a null never matches `is not unreferenced`, so
    #: an applicability clause over a null SUPPRESSES the control on exactly the appliances whose
    #: walk could not be completed, and a suppressed control reads in the report as a profile that
    #: was examined and found fine.
    reference_reach = models.CharField(
        max_length=32, choices=REACH_CHOICES, default=REACH_UNDETERMINED)

    #: Whether the walk behind `reference_reach` actually completed on this appliance. FALSE means
    #: the question "is this profile in force" was not answered, which is a finding in its own
    #: right and not a pass. Non-nullable and false by default, which is the firing side - that is
    #: what makes the column safe to ship before the walk is complete everywhere.
    reference_reach_resolved = models.BooleanField(default=False)

    #: ANTIVIRUS ONLY. The WEAKEST state any row of each satellite collection is left in, as one
    #: token, so that a SEVERITY can vary with it. The booleans beside them - the
    #: `has_non_blocking_*` properties above - are what a clause rests on; these exist because a
    #: grading places VALUES and a boolean has only two.
    #:
    #: THEY SUMMARISE ROWS NOBODY CAN REACH. `SecurityProfileDecoder`,
    #: `SecurityProfileApplicationOverride` and `SecurityProfileMlModel` are in no search
    #: registry, so no clause can name a column of theirs and no finding can rest on one; an
    #: aggregate written onto this row at normalization is the only way the detail becomes
    #: reportable at all.
    #:
    #: Each default is the WEAKEST token of its own collection, which is the firing side: a row
    #: nobody has normalized is graded as though every entry were at its absent state, and the
    #: measured implicit says an untouched profile really is there - an absent decoder action is
    #: `allow` and an absent ML model is `disable`. A null would be worse than the weakest token,
    #: because a grading places values and a null matches no placement.
    #:
    #: BLANK MEANS THE COLLECTION HAS NO ROWS, which is NOT the same as the weakest token, and
    #: the two cases that produce it are opposite in meaning: a non-antivirus kind (nothing is
    #: claimed, and the `kind` clause every query carries keeps the assertion off the row) and an
    #: antivirus profile naming no application exception at all (measured, and the COMPLIANT
    #: state - a profile with no exceptions has nothing overriding its decoders). Writing `allow`
    #: for the second would grade every clean profile at the worst severity on the strength of
    #: rows that do not exist. A blank matches no placement, so such a row is reported at the
    #: baseline, which is the same mechanism `direction_coverage`'s null uses below.
    weakest_decoder_action = models.CharField(max_length=32, blank=True, default="allow")
    weakest_application_override_action = models.CharField(
        max_length=32, blank=True, default="allow")
    #: The ML order is NOT the order a reader would guess: `disable` is weakest, then
    #: `enable(alert-only)`, then `enable` - a model that is off produces nothing, while one on
    #: the middle setting at least produces a record of the delivery.
    weakest_ml_model_state = models.CharField(max_length=32, blank=True, default="disable")

    #: WILDFIRE-ANALYSIS ONLY, and all three are a UNION OVER THE PROFILE'S RULES rather than a
    #: property of any one rule: a profile can reach `any` file type through one rule and both
    #: directions through another, and the commonest failing state - a profile with no rules node
    #: at all - has no row to carry anything.
    #:
    #: `submits_all_file_types` and `covers_all_applications` answer `some rule names any`. They
    #: CANNOT answer the wider question of whether a list of named types or applications adds up
    #: to the release's whole set: the accepted file-type set moves with the content release and
    #: the application set is a content catalogue of ~1400 entries, and neither is in any
    #: configuration read or in this store. A profile naming every type individually therefore
    #: reads as not covering them all, which is almost certainly right and is a different claim.
    #:
    #: False is the migration default on both and is the side that FIRES: a profile nobody has
    #: normalized has not been shown to cover anything.
    submits_all_file_types = models.BooleanField(default=False)
    covers_all_applications = models.BooleanField(default=False)
    #: `both` where some rule covers both or two rules cover one each, `download` where only
    #: inbound is reached, `upload` where only outbound, and NULL where no rule reaches either.
    #: INBOUND IS DELIVERY: `upload` alone leaves every delivered file unanalysed.
    #:
    #: THE NULL DOES TWO JOBS THAT AGREE: it is what a profile with no rules holds and what a row
    #: nobody has normalized holds, and both must be reported at the baseline severity. It is
    #: also the honest answer to an unsettled measurement - what an absent `direction` on a rule
    #: means was never established, so a rule's own direction can be null too and the union of
    #: nulls is a null rather than a guess.
    direction_coverage = models.CharField(max_length=16, null=True, blank=True, default=None)

    # --- DECRYPTION ONLY. PAN-DCP-001, 002 and 007. ---
    #
    # EVERY DEFAULT HERE IS THE FIRING SIDE AND ON THIS KIND THE FIRING SIDE IS THE MEASURED
    # ONE, which is what makes the family unusual: the vendor's predefined `default` profile
    # stores an EMPTY `ssl-protocol-settings` container and no other key, so "nobody configured
    # it" and "nobody collected it" really are the same configuration, measured 2026-10-25 on
    # pan-fw-201 across four key-less committed objects and rendered in the grid and the dialog.
    #
    # THE POLARITIES RUN BOTH WAYS WITHIN ONE NODE. The nine `ssl-protocol-settings` algorithm
    # keys are ALLOW switches - true means the primitive is permitted, which is the weak
    # direction - while the twelve `block-*` keys are BLOCK switches, where false is weak. A
    # query author reading this list top to bottom meets both polarities with nothing in the
    # column names announcing the change, which is why each block below says which it is.

    #: ALLOW SWITCHES. The floor and the ceiling as the administrator typed them, in the
    #: DEVICE's spelling (`sslv3`, `tls1-0` ... `tls1-3`, plus `max` on the ceiling alone) and
    #: never the catalogue's `TLSvN.M`. DO NOT COMPARE EITHER TOKEN IN A CLAUSE: the two leaves
    #: do not share a value set - the device refuses `max` at `min-version` with code=12 - and
    #: lexicographic order is right for the floor by coincidence and INVERTED for the ceiling,
    #: where `max` sorts first while meaning the strongest setting available. The three verdict
    #: columns below are what an assertion rests on.
    #:
    #: The defaults are the MEASURED absent values and both fire: an absent floor asserts
    #: TLS 1.0 (deprecated by RFC 8996, the second-worst value the leaf can hold) and an absent
    #: ceiling asserts TLS 1.2, which is NOT the `max` a reader would expect of a ceiling - the
    #: newest protocol version is unreachable on every session an unconfigured profile governs.
    ssl_min_version = models.CharField(max_length=16, blank=True, default="tls1-0")
    ssl_max_version = models.CharField(max_length=16, blank=True, default="tls1-2")

    #: The ceiling as the appliance would actually negotiate it, with the literal `max` replaced
    #: by the highest version that build implements. BLANK where the literal could not be
    #: resolved, which is the honest answer rather than a guess at an unknown build - and the
    #: verdict beside it then stays TRUE, so an unresolvable ceiling reports rather than passing.
    #:
    #: Three columns and not one, because the stored literal is a POINTER: two appliances
    #: storing `max` can negotiate different ceilings, and an appliance upgraded between two
    #: collections changes what the literal means without the stored value moving.
    ssl_max_version_resolved = models.CharField(max_length=16, blank=True, default="")

    #: THE VERDICTS, both in the firing direction, both defaulting TRUE so an uncollected or
    #: unrecomputed row reports itself. `below_tls12` is the ordering `sslv3 < tls1-0 < tls1-1 <
    #: tls1-2 < tls1-3` applied to the floor; `restrictive` asks whether the RESOLVED ceiling
    #: excludes a version the appliance implements, which the vendor recommends in exactly one
    #: named circumstance - certificate-pinned mobile applications - and which nothing on the
    #: firewall records, so that exception lives in the grading and not in a clause.
    ssl_min_version_below_tls12 = models.BooleanField(default=True)
    ssl_max_version_restrictive = models.BooleanField(default=True)

    #: Whether NO decryption rule naming this profile narrows its destination to a named set.
    #: TRUE where every rule naming it leaves the destination open, TRUE where no rule names it,
    #: and TRUE where the rulebase was not collected - the direction is deliberate, because this
    #: is used as an APPLICABILITY clause and the suppressing form would let a profile with a
    #: TLS 1.0 floor pass on the strength of a rule nobody looked at.
    #:
    #: The off-box half of the exception - WHICH destinations the business actually requires -
    #: is not here and cannot be: nothing in the configuration records which sites were meant
    #: to be in it.
    rule_destination_unrestricted = models.BooleanField(default=True)

    #: ALLOW SWITCHES, one per primitive, with the VENDOR's polarity kept: TRUE MEANS PERMITTED,
    #: which is the weak direction. Seven of the node's nine algorithm keys - the two this
    #: domain's controls do not assert are left unread rather than stored at a guessed default.
    #:
    #: SIX DEFAULT TRUE AND `auth_algo_md5` DEFAULTS FALSE, and that is not a slip. Measured
    #: 2026-10-25: twelve algorithm keys of this node assert ENABLED when absent and two assert
    #: DISABLED, and MD5 is the only one of the two a control asserts - on three key-less
    #: objects the grid does not list it and the dialog checkbox is unticked, while every other
    #: member of its family reads enabled on the same objects in the same second. A normaliser
    #: that materialises one implicit value per family reports MD5 as permitted on every
    #: unconfigured profile in the estate, which is a false finding at high severity.
    enc_algo_rc4 = models.BooleanField(default=True)
    enc_algo_3des = models.BooleanField(default=True)
    auth_algo_sha1 = models.BooleanField(default=True)
    auth_algo_md5 = models.BooleanField(default=False)
    keyxchg_algo_rsa = models.BooleanField(default=True)
    enc_algo_aes_128_cbc = models.BooleanField(default=True)
    enc_algo_aes_256_cbc = models.BooleanField(default=True)

    #: The worst primitive each class still leaves negotiable, as ONE token, because the
    #: SEVERITY varies with which one it is and a grading places the values of one column.
    #: `none` is the compliant member of each.
    #:
    #: COLLAPSING COSTS SOMETHING AND IT IS NAMED: where two broken primitives are permitted
    #: this holds only the worse, so a report naming RC4 is silent about SHA-1 on the same
    #: profile. The seven booleans above are all presented for exactly that reason.
    #:
    #: Both defaults are the measured reading of a key-less profile rather than a pessimistic
    #: guess: rc4, 3des and sha1 each assert ENABLED when absent, so an unconfigured profile
    #: really does permit RC4, and all three key exchanges are enabled by default.
    BROKEN_PRIMITIVE_ORDER = ("rc4", "3des", "md5", "sha1")
    NON_PFS_OR_UNAUTHENTICATED_ORDER = ("rsa", "aes-128-cbc", "aes-256-cbc")
    PRIMITIVE_NONE = "none"
    weakest_broken_primitive_permitted = models.CharField(
        max_length=16, blank=True, default="rc4")
    weakest_non_pfs_or_unauthenticated_permitted = models.CharField(
        max_length=16, blank=True, default="rsa")

    #: BLOCK SWITCHES - the opposite polarity from the seven above. FALSE means the profile does
    #: NOT perform the check, which is the weak direction, and false is what an absent key
    #: asserts on all twelve (measured: the dialog's checkboxes are unticked on a profile that
    #: stores no forward- or inbound-proxy key). So the materialised default, the measured
    #: absent value and the firing side are the same answer here.
    #:
    #: `fwd_` is `ssl-forward-proxy`, `inb_` is `ssl-inbound-proxy`. The two containers are NOT
    #: symmetric: `block-expired-certificate` and `block-untrusted-issuer` exist on the forward
    #: container only, because an inbound-proxy session presents the organisation's own
    #: certificate and there is no issuer to distrust.
    fwd_block_expired_certificate = models.BooleanField(default=False)
    fwd_block_untrusted_issuer = models.BooleanField(default=False)
    fwd_block_unsupported_version = models.BooleanField(default=False)
    fwd_block_unsupported_cipher = models.BooleanField(default=False)
    inb_block_unsupported_version = models.BooleanField(default=False)
    inb_block_unsupported_cipher = models.BooleanField(default=False)
    fwd_block_if_no_resource = models.BooleanField(default=False)
    fwd_block_tls13_downgrade_no_resource = models.BooleanField(default=False)
    inb_block_if_no_resource = models.BooleanField(default=False)
    inb_block_tls13_downgrade_no_resource = models.BooleanField(default=False)
    fwd_block_if_hsm_unavailable = models.BooleanField(default=False)
    inb_block_if_hsm_unavailable = models.BooleanField(default=False)

    #: THE COMPANION THAT TELLS A REFERRER COUNT OF ZERO FROM A COUNT NOBODY TOOK, and the
    #: mechanism rules.md prescribes for a reading that cannot tell ZERO from UNKNOWN. There is
    #: no is-null operator in the query language, so "is this unknown" cannot be asked of
    #: `is_used` or `referrer_count` directly; this column is that unknown, made askable.
    #:
    #: FALSE routes the row into the UNDETERMINED group rather than into the assertion, which is
    #: the only direction that cannot produce a wrong deletion remediation: without the pair,
    #: `is_used` false reports every profile on an uncollected appliance as unused.
    #:
    #: An APPLICABILITY clause on this column SUPPRESSES the control when the answer is no, and
    #: the suppressing form reads as careful - so the suppressed rows must be picked up by a
    #: second group that fires on its own. That pairing is stage 8's to write; this column only
    #: makes it possible.
    decryption_rulebase_collected = models.BooleanField(default=False)

    # ----------------------------------------------------------------- URL FILTERING
    #
    # PAN-URL-001 to PAN-URL-006. Eighteen measured columns off `profiles/url-filtering/entry`
    # and twenty-seven derived over them; blank/default on every other kind, which is the
    # firing side, kept off the wrong rows by the `kind eq url-filtering` clause every query
    # over this model carries. See URL_FILTERING_KINDS.
    #
    # THE SIX SITE-ACCESS LISTS ARE MUTUALLY EXCLUSIVE, measured: adding `gambling` to
    # `continue` while it sat in `isolate` on the same entry is refused code=12 "'gambling' is
    # already in use". So a category's action is single-valued by construction and the
    # effective action of one name is "which of these six holds it, and the per-kind default if
    # none does".
    #
    # AN EMPTY LIST AND AN ABSENT KEY ARE ONE STATE ON THE WIRE - the device drops an empty
    # container - so `[]` versus `null` here is NOT empty-versus-absent. It is what stage 4
    # could establish about the absence: `[]` where a positive control was paid, `null` where
    # none was, and `Implicit.not_assumed` is what writes the second.
    #
    # NOTHING CLAUSES ON ANY OF THE SIX. An empty `block` list means nothing is refused and an
    # empty `allow` list means every predefined category is permitted anyway, so both sit on
    # the reassuring side if read directly. The verdict columns below compute the device's own
    # catalogue MINUS these lists, and the empty list is what makes that computation fire.
    block_categories = models.JSONField(default=list, blank=True)
    alert_categories = models.JSONField(null=True, blank=True, default=None)
    #: EXPLICITLY permitted, which on a PREDEFINED category never happens: `allow` is what the
    #: device omits, so the only names that ever appear here are custom categories, whose own
    #: default is the inert action rather than the permit.
    allow_categories = models.JSONField(default=list, blank=True)
    continue_categories = models.JSONField(null=True, blank=True, default=None)
    override_categories = models.JSONField(null=True, blank=True, default=None)
    #: 11.2 ONLY and WORSE THAN OUT OF SCOPE: the key is absent from both PA-5220s' 17-key set
    #: and a write of it there is refused code=13. A category put here renders as `allow` in
    #: the Site Access column on a PA-VM and no screen shows otherwise, so a reading taken from
    #: the screen reports it as permitted-and-unlogged. The column exists so the verdicts can
    #: tell an isolated category from a permitted one.
    isolate_categories = models.JSONField(default=list, blank=True)

    #: Which corporate-credential detection method the profile has switched on. The stored
    #: shape is A CHOICE NODE AND NOT A STRING - `{"mode": {"group-mapping": "any"}}` on the
    #: wire, `{"mode": {"disabled": null}}` for the empty arm - and a text value is REFUSED:
    #: `<mode>disabled</mode>` answers code=12 "credential-enforcement -> mode is unexpected".
    #: So the normalizer reads the single non-@ child key's NAME.
    #:
    #: `disabled` is the measured absent value and the FIRING side of PAN-URL-003's first half,
    #: so materialising it is what makes a profile nobody has edited produce the finding rather
    #: than disappear from the result set.
    credential_detection_mode = models.CharField(max_length=32, blank=True, default="disabled")

    #: THE FOUR CREDENTIAL LISTS, and an empty `credential_block_categories` DOES NOT MEAN NO
    #: CATEGORY REFUSES CREDENTIALS. Measured on the predefined `default`, which carries no
    #: credential-enforcement node at all and whose dialog grid reads 13 credential blocks on
    #: pan-fw-111, 12 on pan-fw-201 and 13 on fw-core-tpa-a - each set equal to its own
    #: site-access `block` set - while the LIST grid's credential cell reads
    #: `Allow Categories (90)` / `Block Categories (0)` in the same minute on the same entry.
    #: The dialog is right: the device DERIVES `block` for every category the site-access
    #: `block` list names, without anything being written here. A query joining on membership
    #: of these four reports every estate's credential posture as fully permissive.
    credential_block_categories = models.JSONField(default=list, blank=True)
    credential_alert_categories = models.JSONField(null=True, blank=True, default=None)
    credential_allow_categories = models.JSONField(null=True, blank=True, default=None)
    credential_continue_categories = models.JSONField(null=True, blank=True, default=None)

    #: THE THREE REQUEST HEADERS. POSITIVE polarity, so false is the firing side and false is
    #: what an absent key stores. Only `log-http-hdr-user-agent` carries a MEASURED absent
    #: value; the other two are `Implicit.assumed` - four of the method's five points paid and
    #: the positive control on the key itself not paid - so the sheet renders them as "assumed,
    #: not measured" and one write per key would close it.
    #:
    #: WHAT `log_http_header_xff` RECORDS IS NOT ONLY ABOUT THIS OBJECT. Two device-wide
    #: settings on Device > Setup > Content-ID - `strip-x-fwd-for` and the x-forwarded-for
    #: parsing mode - decide whether the header reaches the firewall at all, so `true` here on
    #: a firewall that strips it logs nothing while the column reads true.
    log_http_header_user_agent = models.BooleanField(default=False)
    log_http_header_referer = models.BooleanField(default=False)
    log_http_header_xff = models.BooleanField(default=False)

    #: THE VENDOR'S CLOUD-SIDE REAL-TIME PAGE ANALYSIS. SWITCHED ON IS NOT WORKING: the engine
    #: is subscription-gated and device-certificate-gated and this column says nothing about
    #: either. No appliance in this lab has both - `Advanced URL Filtering` is licensed on
    #: serial 691665AC334B458 alone and that serial has NO device certificate, while serial
    #: 6A9C0A9904E7D6E holds the lab's only device certificate, which expired on 2026/01/12,
    #: and carries no URL filtering licence at all. A report must not read true as analysis
    #: happening.
    cloud_inline_categorization = models.BooleanField(default=False)

    #: THE ON-BOX ENGINE, AND THE ONE KEY ON THIS OBJECT WHOSE IMPLICIT IS A RELATION RATHER
    #: THAN A CONSTANT. Nullable and NOTHING IS MATERIALISED: on a committed key-less profile
    #: the box renders TICKED on serials 691665AC334B458 (PA-VM 11.2.5) and 6A9C0A9904E7D6E
    #: (PA-VM 11.2.3-h3) and UNTICKED on 013201001475 (PA-5220 11.1.13-h3), with the positive
    #: control paid on both sides. Materialising `yes` from a PA-VM reading onto a PA-5220
    #: would report an on-box analysis engine the device's own interface says is off.
    #:
    #: Null means THE KEY WAS ABSENT, which is the common case and does not mean off. Nothing
    #: clauses on this column - `local_inline_categorization_on` and
    #: `local_inline_categorization_undetermined` are what a query reads.
    local_inline_categorization = models.BooleanField(null=True, blank=True, default=None)

    #: Every custom URL category exempted from BOTH real-time page analysis engines. One list
    #: serves both engines, so one entry can empty the whole assertion rather than half of it.
    #: NEGATED KEY: its presence weakens the control and its absence satisfies it, which is why
    #: the materialised `[]` here is the one default in this family that legitimately reassures.
    #:
    #: It can only name a CUSTOM category: `action=complete` at this position offers 22
    #: candidates on all four appliances, every one @type `Panorama pushed
    #: custom-url-category`, and not one predefined category. So a profile can only exempt URLs
    #: somebody has gathered into a custom category.
    inline_analysis_exemptions = models.JSONField(default=list, blank=True)

    #: THE ONLY KEY ON THIS OBJECT WHOSE IMPLICIT IS `yes` ON EVERY APPLIANCE, and its security
    #: direction is INVERTED: true means LESS is logged - one entry for the container page and
    #: none for the resources inside it. Vendor Help p.299 documents it as default enabled and
    #: the device agrees.
    #:
    #: CARRIED WITHOUT AN ASSERTION ON PURPOSE. No control in the corpus names it, so nothing
    #: fires on it; it exists so a finding about log richness cannot say "headers are recorded"
    #: about a profile logging one entry per page.
    log_container_page_only = models.BooleanField(default=True)

    #: ----- the derived half. See DERIVED_FIELDS: no payload key, so no provenance row.
    #:
    #: THE DENOMINATOR EVERY PER-CATEGORY VERDICT IS COMPUTED AGAINST, and it is not one
    #: number: 90 on both PA-VMs and 88 on both PA-5220s, measured, with the difference
    #: confounded between platform, major version and the url-filtering content release. It is
    #: also a property of the PROFILE'S SCOPE and not of the appliance: a vsys-scoped
    #: key-less profile's grid has 113 rows on serial 691665AC334B458 - 90 predefined plus the
    #: custom categories - and a SHARED-scoped one on the same appliance in the same session
    #: has 90 and no custom category at all.
    #:
    #: NULL RATHER THAN 0, and the reason is the whole point: the device reports 88 or 90, so a
    #: stored 0 would make every verdict read "no category is unlogged" - the most permissive
    #: profile in an estate passing every control here.
    category_catalogue_size = models.PositiveIntegerField(null=True, blank=True, default=None)

    #: THE SANCTIONED COMPANION, and the mechanism rules.md prescribes for a reading that
    #: cannot tell ZERO from UNKNOWN. There is no is-null operator in the query language, so
    #: "is `category_catalogue_size` unknown" cannot be asked of it directly; this inverted
    #: boolean is that question, written at normalization time.
    #:
    #: FALSE means every per-category verdict on this row is resting on nothing. It is the
    #: default, so between the migration that adds this model and the pass that issues the
    #: catalogue read every row says so, and every assertion's undetermined query reports those
    #: rows rather than letting them look clean.
    category_catalogue_collected = models.BooleanField(default=False)

    #: PAN-URL-001. The three confirmed-hostile categories, read as the EFFECTIVE action rather
    #: than as membership of a list. FALSE means "not all three are refused" - the failing side
    #: - so an uncomputed row, a row whose catalogue was never read and a row that genuinely
    #: permits a hostile category all report alike; `category_catalogue_collected` and
    #: `unblocked_hostile_categories` are what tell them apart on the sheet.
    all_hostile_categories_blocked = models.BooleanField(default=False)
    #: The weakest action any of the three holds, for the grading. NULL rather than `allow`:
    #: `allow` is a real and critical configuration, and a column defaulting to it would make
    #: every unrecomputed row produce a critical finding on a profile nobody has read.
    weakest_hostile_category_action = models.CharField(
        max_length=32, null=True, blank=True, default=None)
    #: Which of the three are not refused, and what each one's effective action is instead -
    #: the list an engineer reads to know which line to change. Empty is indistinguishable from
    #: the compliant state, which is why nothing clauses on it.
    unblocked_hostile_categories = models.JSONField(default=list, blank=True)

    #: PAN-URL-002. Whether EVERY category this profile does not refuse is nonetheless held to
    #: an action that writes a log entry. THE PROFILE'S PERMIT SET IS NOT IN THE PROFILE -
    #: every permitted predefined category is absent from every list, because `allow` is what
    #: the device omits - so the answer is the catalogue minus the restricting lists, which is
    #: why this is a column and not a clause. FALSE is the failing side AND the default: a
    #: default of true would make every unrecomputed profile report that no category is
    #: unlogged, which is exactly the reading stage 3 inverted.
    all_reachable_categories_logged = models.BooleanField(default=False)
    #: The size of the finding, for the sheet and the grading. NULLABLE deliberately: a stored
    #: 0 is the compliant reading, so `reachable_unlogged_category_count gt 0` passes a row
    #: nobody computed - which is why PAN-URL-002 clauses on the boolean above instead.
    reachable_unlogged_category_count = models.PositiveIntegerField(
        null=True, blank=True, default=None)
    reachable_unlogged_categories = models.JSONField(default=list, blank=True)
    #: The highest-risk member, by the ranking stage 3 placed. Null matches no placement, so
    #: the finding reports at the assertion's own baseline severity rather than at one derived
    #: from a value nobody computed.
    worst_reachable_unlogged_category = models.CharField(
        max_length=64, null=True, blank=True, default=None)

    #: PAN-URL-003's EXCEPTION, and the one column in this family whose direction is an
    #: APPLICABILITY decision rather than an assertion. FALSE means the exception does not
    #: apply and the control RUNS. A default of true would suppress PAN-URL-003's first half on
    #: every unrecomputed profile - a clause that reads as careful and silences a control that
    #: should fire - which is why the column is phrased as "blocked for every category" rather
    #: than as its negation.
    credential_submission_blocked_for_every_category = models.BooleanField(default=False)
    #: PAN-URL-003. Whether every category the profile still lets users reach carries SOME
    #: decision about corporate credential submission. The coupling is what makes this a
    #: column: a category in the site-access `block` list is credential-refused without
    #: anything being written in the credential lists at all, so no predicate can express
    #: "this category is credential-refused because a DIFFERENT list names it".
    all_reachable_categories_credential_restricted = models.BooleanField(default=False)
    credential_permissive_category_count = models.PositiveIntegerField(
        null=True, blank=True, default=None)
    credential_permissive_categories = models.JSONField(default=list, blank=True)
    #: A CATEGORY WHOSE SITE ACCESS IS REFUSED IS NOT IN THIS SET AT ALL - the device refuses
    #: its credentials automatically - so its membership of the restricted set is
    #: PAN-URL-001's outcome and not evidence about this control.
    worst_credential_permissive_category = models.CharField(
        max_length=64, null=True, blank=True, default=None)

    #: PAN-URL-004. The conjunction over the three header booleans, promoted into a column
    #: because the DOWNSTREAM query encodes the failing condition - "any of the three is not
    #: yes" - which is a disjunction stage 5's clause grammar has no way to write.
    #:
    #: All three sources materialise false on an absent key, so a correctly-computed row and an
    #: uncomputed row agree here, and both report. TWO OF THE THREE REST ON AN ASSUMED DEFAULT,
    #: so this finding is partly resting on an inference - which the sheet shows on those two
    #: fields and which one write per key would close.
    records_all_request_headers = models.BooleanField(default=False)
    #: NOT NULLABLE, unlike the catalogue-derived counts, because its three inputs are never
    #: null. So the only unknown it can hold is "not yet recomputed" - and 0 is the compliant
    #: reading AND the migration default, which is why nothing clauses on it.
    unrecorded_request_header_count = models.PositiveIntegerField(default=0)
    unrecorded_request_headers = models.JSONField(default=list, blank=True)
    #: Which missing header costs an investigator most: the forwarded-for address first,
    #: because it is the only one of the three that recovers the originating address where a
    #: proxy or source translation has replaced it. EMPTY means no header is missing OR the row
    #: was not recomputed; neither matches a placement, so the baseline severity stands.
    worst_unrecorded_request_header = models.CharField(max_length=32, blank=True, default="")

    #: PAN-URL-005. Whether the CONFIGURATION SAYS the on-box engine is on - true only where
    #: the key is present and `yes`. FALSE BY DEFAULT, AND ON BOTH PA-VMs AN ABSENT KEY MEANS
    #: THE ENGINE IS ON, so this default produces a FALSE POSITIVE on exactly those rows. That
    #: is declared rather than hidden and it is the direction rules.md chooses: a finding
    #: raised on a healthy appliance is checkable in a minute, where a missing reading reported
    #: as compliant is a customer told they are safe on the strength of nothing. The companion
    #: below is true on precisely the rows where the finding may be wrong.
    local_inline_categorization_on = models.BooleanField(default=False)
    #: TRUE BY DEFAULT, which is the entire purpose: before the first normalization pass every
    #: row's on-box engine state is undetermined and saying so is what the column is for. A
    #: default of false would claim the key was read.
    #:
    #: WHAT NO COLUMN CAN HOLD is the relation itself - that an absent key means `yes` on a
    #: PA-VM and `no` on a PA-5220, with platform, major version, vsys mode and content release
    #: moving together so the estate cannot take the bundle apart.
    local_inline_categorization_undetermined = models.BooleanField(default=True)
    #: The disjunction over the two engines, carried for the sheet and DELIBERATELY NOT CLAUSED
    #: ON AS AN APPLICABILITY TEST: an applicability clause on a column whose unknown state is
    #: false would silence the exemption control on every profile whose engine state nobody
    #: established. It is here so a reader can see why that gating was declined.
    any_inline_analysis_engine_on = models.BooleanField(default=False)

    #: PAN-URL-005's third record. THE ONE CLAUSE COLUMN IN THIS FAMILY THAT READS AS COMPLIANT
    #: WHEN NOBODY LOOKED, and it is still the right column to clause on: the assertion is that
    #: an exemption EXISTS and is broad, so the finding must fire on a positive count, and
    #: there is no boolean form of it that fires on the unknown side without also firing on
    #: every profile that correctly exempts nothing - which is most of the estate. The unknown
    #: is carried by `inline_analysis_exemptions_computed`, which defaults to FALSE and fires.
    inline_analysis_exemption_count = models.PositiveIntegerField(default=0)
    #: FALSE means the count beside it is a migration default and not a reading.
    inline_analysis_exemptions_computed = models.BooleanField(default=False)
    #: The broadest exempted category's stored type, RESOLVED THROUGH THE REFERENCE - a
    #: multi-category target is broader than a list of named sites, because its reach follows
    #: the database rather than a list somebody wrote. A query cannot follow a reference, so
    #: the reach across to `CustomUrlCategory.category_type` is a derived column or it is
    #: nothing. Null also means the TARGET row is missing, which on an estate whose custom
    #: categories all arrive through the pushed read is what an uninstrumented collector gets.
    broadest_inline_analysis_exemption_type = models.CharField(
        max_length=32, null=True, blank=True, default=None)

    #: PAN-URL-006's second record. How many custom URL categories this profile PERMITS - a
    #: live carve-out in force, as distinct from a category left at the inert action. A custom
    #: category's own default IS the inert action and not the permit, which is the opposite of
    #: a predefined category and is what makes this readable from the configuration at all.
    #:
    #: 0 IS BOTH THE COMPLIANT READING AND THE MIGRATION DEFAULT. The companion is
    #: `category_catalogue_collected`, which is false on exactly the rows whose custom
    #: categories were never collected.
    permitted_custom_category_count = models.PositiveIntegerField(default=0)
    permitted_custom_categories = models.JSONField(default=list, blank=True)
    #: The weakest action any permitted custom category holds. See the normalizer: the declared
    #: value set admits the inert action as well as the permit, and the declared derivation -
    #: over the `allow` list alone - cannot produce it.
    weakest_permitted_custom_category_action = models.CharField(
        max_length=32, null=True, blank=True, default=None)

    # ----------------------------------------------------------------- DOS PROTECTION
    #
    # PAN-ZON-007 and PAN-ZON-008. TWO COLUMNS, and stage 5 declared only two on purpose: stage
    # 4 enumerated 58 key paths on this object and both halves of PAN-ZON-007 are discharged
    # without a scalar for any of them - the first onto the customer's asset inventory, the
    # second onto the RULE's action on `DosPolicyRule`. A scalar column here would be a column
    # no clause names, resting on an implicit nobody measured, on an object whose only oracle is
    # a form that was measured to prefill.
    #
    # THE REFERENCE WALK IS WHERE THE WORK IS, and it is not here: `referrer_count`, `is_used`,
    # `referrers`, `reference_reach` and `reference_reach_resolved` all ship and all now answer
    # for this kind too, because the DoS rulebase's two profile slots are collected into
    # `build.references` beside every other kind's referrer. See
    # `normalization/zone_dos_protection.py::dos_profile_references`.

    #: `type`. DOS PROTECTION ONLY, blank on every other kind. Whether this profile's thresholds
    #: count the WHOLE matched group of traffic together (`aggregate`) or EACH device in it
    #: individually (`classified`) - the per-device form PAN-ZON-007 is about.
    #:
    #: NOT `kind`, AND THE TWO ARE ONE LETTER APART IN MEANING: `kind` is this store's own
    #: discriminator for WHICH COLLECTION the entry was read from, invented here because PAN-OS
    #: has no such key; `profile_type` is the device's own mandatory `type` leaf on a DoS
    #: profile. A clause that confuses them compares a store token against a device value.
    #:
    #: MANDATORY AT COMMIT VALIDATION, measured rather than inferred: stage 4 built a second
    #: bare profile for this question alone and the commit was refused with `Validation Error:
    #: profiles -> dos-protection -> oep-zdp-dosp2 is missing 'type'`. So it is never observed
    #: absent on a committed profile and a blank here is a candidate-only entry.
    #:
    #: THE GRID AND THE DIALOG DISAGREED ABOUT THIS KEY AND THE DISAGREEMENT DISSOLVED, which a
    #: normalizer author reading a screen would have got wrong: on a bare profile the grid's Type
    #: column rendered BLANK and the dialog's Type radio rendered `Aggregate` SELECTED, in the
    #: same minute on the same entry - the grid honestly, the dialog by prefilling what OK would
    #: write. Neither was describing a state a running device holds.
    #:
    #: THE KEY SET DOES NOT VARY BY TYPE - both kinds carry the same flood and resource children,
    #: measured - but what the thresholds COUNT does, and a rule's reference is
    #: eligibility-filtered on it, so every query reporting a threshold from this object has to
    #: carry this column beside it or the number means two different things.
    PROFILE_TYPE_AGGREGATE = "aggregate"
    PROFILE_TYPE_CLASSIFIED = "classified"
    profile_type = models.CharField(max_length=16, blank=True, default="")

    #: The flood thresholds, block durations, block probabilities and concurrent-session ceiling
    #: this profile stores, as read, keyed by flood type - held for a reader, with NO reachable
    #: scalar beside it. NULL on every other kind and on a DoS profile storing none of them.
    #:
    #: NOTHING CLAUSES ON IT AND NOTHING MAY: a finding must not rest on a stored structure, and
    #: a consumer test refuses to register a JSON column as searchable at all.
    #:
    #: ITS CONTENT IS A SUBSET OF `raw_profile` BELOW, which holds the whole entry. It is kept
    #: separate because it is NORMALISED - keyed by flood type and threshold with the profile's
    #: own type beside them - where `raw_profile` is the payload as parsed, and because a
    #: remediation reads this one.
    #:
    #: STAGE 4 MEASURED NONE OF THESE IMPLICITS ON THIS OBJECT and said why: no control was paid
    #: here, this object's only oracle is the web interface, and carrying the ZONE protection
    #: profile's measurement across would assume that two nodes sharing a leaf name share a
    #: default, which this very object disproves - its `flood` node has FIVE children where the
    #: zone profile's has six, and its `red` container has FIVE where the zone profile's has
    #: three, adding `block` and `block-probability`. Same two node names, two key sets. So an
    #: absent key puts NOTHING in this column.
    flood_and_resource_settings = models.JSONField(null=True, blank=True, default=None)

    raw_profile = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["kind", "name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "kind", "name", "precedence_rank"]),
            models.Index(fields=["appliance_group", "kind", "name", "precedence_rank"]),
            models.Index(fields=["enforcement_point", "namespace_type", "namespace_value"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "kind", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_per_point_namespace",
            ),
            models.UniqueConstraint(
                fields=["appliance_group", "kind", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_per_group_namespace",
            ),
        ]

    def clean(self) -> None:
        """The scoped-object checks, plus the URL-filtering count/list agreement.

        CLAUDE.md: "A column derived from a JSON field gets a `clean()` asserting the two
        agree." Gated on the kind, because every other kind keeps the defaults - a 0 count
        beside an empty list, which agrees trivially - and because the counts mean nothing on
        a row that has no URL category catalog.

        The nullable counts are checked only when they hold a number: null is "nobody
        computed this", which has no list to disagree with.
        """
        super().clean()
        if self.kind != self.KIND_URL_FILTERING:
            return
        pairs = [
            ("unrecorded_request_header_count", self.unrecorded_request_header_count,
             "unrecorded_request_headers", self.unrecorded_request_headers),
            ("reachable_unlogged_category_count", self.reachable_unlogged_category_count,
             "reachable_unlogged_categories", self.reachable_unlogged_categories),
            ("credential_permissive_category_count", self.credential_permissive_category_count,
             "credential_permissive_categories", self.credential_permissive_categories),
        ]
        if self.inline_analysis_exemptions_computed:
            pairs.append(
                ("inline_analysis_exemption_count", self.inline_analysis_exemption_count,
                 "inline_analysis_exemptions", self.inline_analysis_exemptions))
        for count_name, count, list_name, values in pairs:
            if count is None:
                continue
            if count != len(values or []):
                raise ValidationError(
                    f"{count_name}={count} disagrees with {list_name}, which holds "
                    f"{len(values or [])}")
        # THE CARVE-OUT PAIR IS CHECKED AGAINST THE PERMITS IN THE LIST AND NOT AGAINST ITS
        # LENGTH, because the list is the inventory stage 3 asks for and the count is declared
        # over the `allow` list alone. See the normalizer.
        permits = [c for c in (self.permitted_custom_categories or [])
                   if (c or {}).get("action") == self.URL_ACTION_ALLOW]
        if self.permitted_custom_category_count != len(permits):
            raise ValidationError(
                f"permitted_custom_category_count={self.permitted_custom_category_count} "
                f"disagrees with the {len(permits)} permitted entries in "
                f"permitted_custom_categories")

    @property
    def disabled_ml_models(self) -> list[str]:
        """Models this profile does not run at all. Absent counts as disabled."""
        return sorted(m.name for m in self.ml_models.all() if not m.enabled)

    @property
    def non_blocking_ml_models(self) -> list[str]:
        """Models that do not STOP a file - off, or running in alert-only.

        What PAN-AVW-002 reports. A model set to `enable(alert-only)` is not a model doing
        nothing, but it is a model that lets the file through, which is the same outcome for
        the control's purpose and a different remediation for the engineer - hence both lists.
        """
        return sorted(m.name for m in self.ml_models.all() if not m.blocks)

    @property
    def has_disabled_ml_model(self) -> bool:
        return bool(self.disabled_ml_models)

    @property
    def has_non_blocking_ml_model(self) -> bool:
        return bool(self.non_blocking_ml_models)

    @property
    def exceptions_handing_signatures_back(self) -> list[str]:
        """Threat IDs whose exception is KNOWN to leave the signature un-stopped.

        `allow` and `alert` only. An exception at the literal `default` is NOT here, because its
        resolution is content-supplied and in no column - see
        `SecurityProfileThreatException.undecided_without_resolution`, which is how those are
        found instead.
        """
        return sorted(row.threat_id for row in self.threat_exceptions.all()
                      if row.hands_signature_back)

    @property
    def exceptions_undecided_without_resolution(self) -> list[str]:
        """Threat IDs whose exception sits at the pointer, so its effect is not in the store."""
        return sorted(row.threat_id for row in self.threat_exceptions.all()
                      if row.undecided_without_resolution)

    @property
    def widest_exempt_ip_count(self) -> int | None:
        """The SMALLEST exempt-IP count on any exception, or None where there is none.

        Smallest, because zero is the widest form: an exception narrowed to no source applies to
        every source. The name says what it MEANS rather than what it computes, because getting
        that polarity backwards is this column's whole hazard.
        """
        counts = [row.exempt_ip_count for row in self.threat_exceptions.all()]
        return min(counts) if counts else None

    @property
    def exception_detail(self) -> str:
        """Where this profile's exceptions live, for a hygiene finding.

        Names the surface because the remediation differs: a signature exception is removed
        in one place, an inline-analysis IP exemption in another, and a DNS allow-list entry
        in a third.
        """
        if not self.exception_surfaces:
            return ""
        return ", ".join(f"{n} in {surface}"
                         for surface, n in sorted(self.exception_surfaces.items()))

    @property
    def inline_detectors_not_blocking(self) -> list[str]:
        """Inline cloud-analysis detectors that do not stop the traffic.

        PAN-SPY-004 and PAN-VLN-003. Covers both ways of not blocking - a detector the
        profile never mentions, which does not run at all, and one set to `alert`, which runs
        and lets the traffic through. The second is the `enable(alert-only)` case from
        PAN-AVW-002 wearing a different name, and reading it as "enabled" would pass a
        profile that only watches.
        """
        return sorted(d.name for d in self.inline_detectors.all() if not d.blocks)

    @property
    def has_inline_detector_not_blocking(self) -> bool:
        return bool(self.inline_detectors_not_blocking)

    @property
    def worst_inline_detector_action(self) -> str:
        """The WEAKEST action any analysis engine holds, or "" for a kind with no engines.

        The graded value behind PAN-SPY-004 and PAN-VLN-003, as against the booleans above,
        which say only whether. An engine the profile never mentions is counted at its MEASURED
        implicit rather than skipped - a row is synthesized for every engine in the catalog
        with a blank configured action, and `ACTION_STRENGTH_WEAKEST_FIRST` ranks blank with the
        implicit, so an unconfigured profile reads `alert` here rather than empty.

        ORDER TAKEN FROM THE CONTROL'S OWN GRADING, not invented: `drop` is the weakest of the
        four stopping actions, which is why a profile holding drop on one engine and reset-* on
        the other four reads `drop`.
        """
        rows = list(self.inline_detectors.all())
        if not rows:
            return ""
        return SecurityProfileInlineDetector.weakest_action(
            row.configured_action for row in rows)

    @property
    def worst_unstopped_severity(self) -> str:
        """The worst severity band this profile leaves un-stopped, or "" where none is.

        The graded value behind PAN-SPY-001, read off the per-severity verdict rows. EMPTY means
        every band the control asserts is stopped - and it is also what a profile with no verdict
        rows reads, which is why nothing may clause on this column alone: the firing is carried
        by the per-rule verdict, whose NULL fires.

        **`any` IS IN THE FIELD'S MEASURED VALUE SET AND IS NOT REACHABLE FROM HERE.** The device
        offers `any` at the severity member position as its own schema default, help-string `All
        severities`, and a profile whose coverage is written there cannot be resolved into bands -
        but telling that profile from one that names bands explicitly needs the matched rule's
        severity member list, and no stored column carries it. The verdict rows answer per band
        and nothing else. The direction of the loss is safe: such a profile reads as its worst
        FAILING band, which is the most severe placement its grading has, so the error over-states
        rather than reassures.
        """
        for severity in (SecurityProfileSeverityVerdict.CRITICAL,
                         SecurityProfileSeverityVerdict.HIGH,
                         SecurityProfileSeverityVerdict.MEDIUM):
            if self.verdict(severity)[0] is False:
                return severity
        return ""

    @property
    def weakest_assessed_severity_action(self) -> str:
        """The weakest action any rule of this profile takes on a CRITICAL or HIGH exploit.

        PAN-VLN-001's grading axis, and the sibling of `worst_unstopped_severity` rather than a
        replacement for it: that one says WHICH BAND fails and this says WHAT THE PROFILE DOES,
        and stage 3 grades the vulnerability control on the second. Read off the per-band verdict
        rows' own `weakest_action`, so the summary and the detail cannot disagree.

        MEDIUM IS NOT READ. The control asserts critical and high; medium has verdict rows for
        the tab and counting it here would grade a profile by a band nothing asserts.

        THE EMPTY STRING IS NOT AN ACTION VALUE and it is the answer whenever either band has no
        covering rule at all - stage 3 is explicit that this is a different failure. It is also
        what a profile with no verdict rows reads, which is why this column carries no assertion
        of its own: the firing is the rule-grain verdict's, whose NULL fires.
        """
        bands = [SecurityProfileSeverityVerdict.CRITICAL, SecurityProfileSeverityVerdict.HIGH]
        rows = {row.severity: row for row in self.severity_verdicts.all()}
        # A BAND WITH NO ROW CONTRIBUTES THE EMPTY STRING rather than being skipped. A kind that
        # answers in these terms gets a row per band, so a missing one is an unrecomputed profile
        # and must not read as the strongest action of the band that survived.
        return SecurityProfileSeverityVerdict.weakest_of(
            [getattr(rows.get(band), "weakest_action", "") or "" for band in bands])

    @property
    def non_blocking_decoders(self) -> list[str]:
        """Protocols this antivirus profile detects malware on without stopping it.

        Reads the resolved action, not the configured one: every decoder of an unedited profile
        says `default`, and on smtp, imap and pop3 that means alert.
        """
        return sorted(d.protocol for d in self.decoders.all() if not d.blocks)

    @property
    def has_non_blocking_decoder(self) -> bool:
        return bool(self.non_blocking_decoders)

    @property
    def non_blocking_wildfire_decoders(self) -> list[str]:
        """Protocols whose WILDFIRE SIGNATURE ACTION does not stop the transfer.

        A separate question from `non_blocking_decoders`: the two columns are independent
        verdict sources and a profile can be hard on one and open on the other.
        """
        return sorted(d.protocol for d in self.decoders.all() if not d.wildfire_blocks)

    @property
    def has_non_blocking_wildfire_decoder(self) -> bool:
        return bool(self.non_blocking_wildfire_decoders)

    @property
    def non_blocking_mlav_decoders(self) -> list[str]:
        """Protocols whose WILDFIRE INLINE ML ACTION does not stop the transfer.

        `blocks is not True` rather than `not blocks`, so a row predating the column - a null,
        meaning not computed - is reported rather than passed. The label says which it is.
        """
        return sorted(f"{d.protocol} (not yet computed)" if d.mlav_blocks is None
                      else d.protocol
                      for d in self.decoders.all() if d.mlav_blocks is not True)

    @property
    def has_non_blocking_mlav_decoder(self) -> bool:
        return bool(self.non_blocking_mlav_decoders)

    @property
    def wildfire_submits_all_file_types(self) -> bool:
        """Does this WildFire analysis profile send EVERY file type for analysis?

        True only when some rule covers `any` file type. A profile with no rules submits
        nothing and is False - not None: that is a measured state, not an unknown.
        """
        return any(r.covers_all_file_types for r in self.wildfire_rules.all())

    @property
    def wildfire_coverage_gaps(self) -> list[str]:
        """Why this profile does not submit everything, in the UI's column order.

        Empty when a rule covers `any` file type, `any` application and both directions.
        """
        rules = list(self.wildfire_rules.all())
        if not rules:
            return ["no rules at all, so nothing is sent for analysis"]
        gaps = []
        if not any(r.covers_all_file_types for r in rules):
            gaps.append("no rule covers every file type")
        if not any(r.covers_all_applications for r in rules):
            gaps.append("no rule covers every application")
        if not any(r.covers_both_directions for r in rules):
            unset = [r.name for r in rules if r.covers_both_directions is None]
            gaps.append(f"no rule covers both directions (direction not set on: "
                        f"{', '.join(unset)})" if unset
                        else "no rule covers both directions")
        return gaps

    @property
    def non_blocking_application_overrides(self) -> list[str]:
        """Per-application overrides that do not stop the transfer, as labeled strings.

        `blocks is not True` rather than `not blocks`, so the unestablished `default` case is
        reported rather than passed - see SecurityProfileApplicationOverride.blocks.
        """
        return sorted(o.label for o in self.application_overrides.all() if o.blocks is not True)

    @property
    def has_non_blocking_application_override(self) -> bool:
        return bool(self.non_blocking_application_overrides)

    def verdict(self, severity: str) -> tuple[bool | None, str]:
        """(blocked, detail) for one severity, or (None, "") where the profile makes no such
        claim. Reads a prefetched `severity_verdicts` list without a query when one is loaded."""
        for row in self.severity_verdicts.all():
            if row.severity == severity:
                return row.blocked, row.detail
        return None, ""

    @property
    def critical_blocked(self) -> bool | None:
        return self.verdict(SecurityProfileSeverityVerdict.CRITICAL)[0]

    @property
    def critical_detail(self) -> str:
        return self.verdict(SecurityProfileSeverityVerdict.CRITICAL)[1]

    @property
    def high_blocked(self) -> bool | None:
        return self.verdict(SecurityProfileSeverityVerdict.HIGH)[0]

    @property
    def high_detail(self) -> str:
        return self.verdict(SecurityProfileSeverityVerdict.HIGH)[1]

    @property
    def medium_blocked(self) -> bool | None:
        return self.verdict(SecurityProfileSeverityVerdict.MEDIUM)[0]

    @property
    def medium_detail(self) -> str:
        return self.verdict(SecurityProfileSeverityVerdict.MEDIUM)[1]

    @property
    def paloalto_dns_source(self):
        """The Palo Alto Networks Content DNS row, or None for a kind that has no DNS tree.

        Always present for an anti-spyware profile, synthesized when the config is silent.
        """
        for row in self.dns_signature_sources.all():
            if row.is_paloalto_content:
                return row
        return None

    @property
    def dns_sinkholes_malicious_queries(self) -> bool | None:
        """PAN-SPY-002. None = this kind makes no claim about DNS sinkholing.

        `block` reads False: it breaks C2 resolution and does NOT identify the infected client
        behind an internal resolver, which is the other half of what the control is for.
        """
        row = self.paloalto_dns_source
        return row.sinkholes if row else None

    @property
    def dns_security_categories_not_enforcing(self) -> list[str]:
        """The asserted malicious DNS Security categories that do not block or sinkhole.

        PAN-SPY-003. Names only - the action is on the row, and the finding sentence needs
        both.
        """
        src = SecurityProfileDnsSignatureSource
        return sorted(
            row.name for row in self.dns_signature_sources.all()
            if row.source_type == src.TYPE_DNS_SECURITY
            and row.name in src.ASSERTED_MALICIOUS_CATEGORIES and not row.enforces)

    @property
    def dns_security_categories_enforced(self) -> bool | None:
        """PAN-SPY-003. None = this kind has no DNS tree and makes no claim."""
        src = SecurityProfileDnsSignatureSource
        rows = [row for row in self.dns_signature_sources.all()
                if row.source_type == src.TYPE_DNS_SECURITY
                and row.name in src.ASSERTED_MALICIOUS_CATEGORIES]
        if not rows:
            return None
        return all(row.enforces for row in rows)

    @property
    def dns_security_category_detail(self) -> str:
        """What an engineer has to change, naming each category and its action.

        `default` is reported as itself rather than as `allow`, because that is what the
        config says and the resolution to allow is the vendor's documented behavior (Help
        p.284) rather than something measured here.
        """
        src = SecurityProfileDnsSignatureSource
        parts = []
        for row in sorted(self.dns_signature_sources.all(), key=lambda r: r.name):
            if (row.source_type != src.TYPE_DNS_SECURITY
                    or row.name not in src.ASSERTED_MALICIOUS_CATEGORIES or row.enforces):
                continue
            short = row.name.replace("pan-dns-sec-", "")
            if row.action_is_implicit:
                parts.append(f"{short} is not configured")
            else:
                parts.append(f"{short} is {row.configured_action}")
        return ", ".join(parts)

    @property
    def dns_content_list_action(self) -> str:
        """The effective action on the vendor's own downloaded malicious-domain list, or "".

        The graded value behind PAN-SPY-002, as against `dns_sinkholes_malicious_queries`, which
        says only whether it sinkholes. It reads the EFFECTIVE action, so a profile that names no
        entry reads the implicit rather than empty - and `dns_sinkhole_action_is_implicit` beside
        it is how a reviewer finds the rows that rest on the implicit.
        """
        row = self.paloalto_dns_source
        return row.effective_action if row else ""

    @property
    def dns_sinkhole_action_is_implicit(self) -> bool:
        """Is the verdict resting on the Help's documented default rather than on config?"""
        row = self.paloalto_dns_source
        return bool(row and row.action_is_implicit)

    @property
    def dns_sinkhole_detail(self) -> str:
        """What an engineer has to change, or where the value came from when nothing is set."""
        row = self.paloalto_dns_source
        if row is None:
            return ""
        if row.action_is_implicit:
            return ("no DNS signature source is configured; PAN-OS Web Interface Help 11.2 "
                    "p.284 says an unconfigured Palo Alto Networks Content list sinkholes")
        detail = f"Palo Alto Networks Content action is {row.configured_action or 'unset'}"
        if row.sinkholes and not self.dns_sinkhole_ipv4:
            # The device refuses this combination, so seeing it means something else wrote it.
            return detail + ", and no sinkhole IPv4 address is set"
        return detail

    def category_verdict_row(self, category: str):
        """The row for one threat category, or None when this profile does not answer.

        Only vulnerability profiles get rows - see SecurityProfileCategoryVerdict. Walks the
        prefetched set rather than filtering, so a prefetch covers it in one query.
        """
        for row in self.category_verdicts.all():
            if row.category == category:
                return row
        return None

    @property
    def brute_force_blocked_by_source(self) -> bool | None:
        """Is the SOURCE of a brute-force attempt blocked? None = this kind does not answer.

        PAN-VLN-002. Distinct from `critical_blocked`: a `reset-both` rule blocks the threat
        and leaves the source free to try again, so it answers True there and False here.
        """
        row = self.category_verdict_row(SecurityProfileCategoryVerdict.BRUTE_FORCE)
        return row.blocks_source if row else None

    @property
    def brute_force_detail(self) -> str:
        row = self.category_verdict_row(SecurityProfileCategoryVerdict.BRUTE_FORCE)
        return row.detail if row else ""

    @property
    def brute_force_block_duration(self) -> int | None:
        """Seconds the source stays blocked, or None when the config does not say.

        NOT the same as zero, and the implicit value is unmeasured - see the verdict model.
        """
        row = self.category_verdict_row(SecurityProfileCategoryVerdict.BRUTE_FORCE)
        return row.duration if row else None

    def __str__(self) -> str:
        return f"{self.owner} / {self.kind} / {self.namespace_key} / {self.name}"


class SecurityProfileDecoder(models.Model):
    """One protocol decoder of an antivirus profile, and what it ACTUALLY does.

    PAN-AVW-001's subject, and the reason it cannot be answered from the configuration alone:
    every decoder of every unedited profile stores the literal `default`, including the shipped
    one. Measured 2026-10-07 on the lab - `/config/predefined/profiles/virus/entry[@name='default']`
    returns `action=default` on all seven decoders, and so does a profile created through the UI
    without touching a setting.

    What `default` RESOLVES to is per protocol, and the UI is the only thing that states it.
    Jason captured both profiles side by side on 2026-10-07: the predefined `default` and a
    UI-created one render identically -

        http, http2, ftp, smb   ->  reset-both
        smtp, imap, pop3        ->  alert

    Three decoders alert, which is independently what controls.json says about the shipped
    profile: "The shipped 'default' profile only alerts on several decoders - detection without
    prevention." Two sources that agree, neither of them the device's own words, which is why
    the resolution is a named table in this module rather than an assumption spread through it.

    `configured_action` keeps what the config says and `effective_action` what it means. A
    control reads the second; an engineer looking for the line to change needs the first.
    """

    #: Every decoder PAN-OS evaluates, in the order its UI lists them. The CONFIG may name
    #: fewer - or none - and the device still inspects all seven. Measured 2026-10-07.
    PROTOCOLS = ("http", "http2", "smtp", "imap", "pop3", "ftp", "smb")

    #: What the literal `default` means, per protocol. The UI's rendering, confirmed on the
    #: predefined profile, a UI-created one, and a profile written with an explicit `default`.
    #: If a PAN-OS release changes this, every antivirus finding changes with it - so it is one
    #: table, cited, and not a conditional somewhere in the normalizer.
    DEFAULT_RESOLUTION = {
        "http": "reset-both", "http2": "reset-both", "ftp": "reset-both", "smb": "reset-both",
        "smtp": "alert", "imap": "alert", "pop3": "alert",
    }

    #: WHAT AN ABSENT ACTION MEANS, and it is NOT `default`.
    #:
    #: Measured 2026-10-07 by writing three profiles and exporting the UI's own view of them:
    #: one with no decoder node at all, one with a decoder entry carrying no `action`, and one
    #: naming `default` on http alone. All three render `allow` on every protocol the config
    #: does not give a value for - including the six the third profile never mentions.
    #:
    #: So absence is the PERMISSIVE end, not the vendor default. A profile that names nothing
    #: inspects nothing. Reading absence as `default` would report such a profile as blocking
    #: malware on http when the device allows it, which is the one direction an inspection
    #: control must never fail in.
    ABSENT_ACTION = "allow"
    #: Actions that stop the transfer. Wider than the corpus's `reset-both`, the same deviation
    #: PAN-SPY-001 makes and for the same reason: a profile that drops malware has not failed to
    #: block it. Recorded in control-changes.json.
    BLOCKING_ACTIONS = frozenset({"drop", "reset-client", "reset-server", "reset-both"})

    #: WEAKEST FIRST, by how much of the transfer each action lets finish. `allow` lets the file
    #: through, `alert` records it and lets it through, and the four blockers stop it - stage 3
    #: calls those four equally strong, so their order here is the device's own enumeration order
    #: and nothing rests on it.
    #:
    #: `default` IS NOT PLACED, deliberately. On a decoder it never reaches an aggregate: the
    #: literal resolves per protocol before the row is written. On an APPLICATION EXCEPTION it is
    #: a real stored value whose resolution is per SIGNATURE and so settles nothing, which is why
    #: `SecurityProfileApplicationOverride.blocks` is null for it - so an aggregate over this
    #: order returns it unranked rather than calling it strong or weak.
    ACTION_STRENGTH_ORDER = ("allow", "alert", "drop", "reset-client", "reset-server",
                             "reset-both")

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="decoders")
    protocol = models.CharField(max_length=32)
    #: What the config holds - usually the literal `default`.
    configured_action = models.CharField(max_length=32)
    #: What that means on this protocol, after DEFAULT_RESOLUTION.
    effective_action = models.CharField(max_length=32)
    blocks = models.BooleanField()
    #: THREE ACTION COLUMNS, NOT ONE. The UI's decoder table has SIGNATURE ACTION, WILDFIRE
    #: SIGNATURE ACTION and WILDFIRE INLINE ML ACTION per protocol, and `default` resolves by
    #: the SAME per-protocol table in all three - measured 2026-10-07, the create-form capture
    #: in OptivEdgeProbe scratch/jason/ showing every row rendering identically across the
    #: three columns.
    #:
    #: They are three VERDICT SOURCES on one protocol: a signature hit, a WildFire-derived
    #: signature hit, and an inline ML verdict. A profile can reset-both on the first and allow
    #: the other two, and malware caught by WildFire is then delivered. PAN-AVW-001 read only
    #: the first until 2026-10-08.
    configured_wildfire_action = models.CharField(max_length=32, blank=True)
    effective_wildfire_action = models.CharField(max_length=32, blank=True)
    wildfire_blocks = models.BooleanField(default=False)
    configured_mlav_action = models.CharField(max_length=32, blank=True)
    effective_mlav_action = models.CharField(max_length=32, blank=True)
    #: NULLABLE, and a null means NOT COMPUTED - a row written before this column existed.
    #:
    #: The checklist's rule is that a new derived column on an already-populated model must not
    #: default to the compliant side, because the gap between migrating and re-normalizing then
    #: reads as a hardened estate. `False` here already means "does not block", which fires -
    #: but it is indistinguishable from a measured `allow`. A null fires AND says why, so
    #: "nobody has computed this yet" cannot be read as "we checked and it allows". Same
    #: obligation MasterKey's `undetermined` carries.
    mlav_blocks = models.BooleanField(null=True)

    class Meta:
        ordering = ["security_profile", "protocol"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "protocol"],
                name="integrations_unique_decoder_per_profile_protocol"),
        ]

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.protocol}: {self.effective_action}"


class SecurityProfileApplicationOverride(models.Model):
    """One per-application action override on an antivirus profile.

    WHY THIS EXISTS. PAN-AVW-001 asserts that every decoder stops the transfer, and a decoder
    action is NOT the last word: this node overrides it for a named application. A profile can
    read `reset-both` on all seven decoders and still allow malware over a named application,
    and a control that walked only `decoder` reported such a profile as hardened. Found
    2026-10-08 by enumerating the profile's key set with `action=complete` rather than reading
    a sample - the node was in the config all along and nothing looked at it.

    Measured 2026-10-08 on pan-fw-111 by writing each candidate shape:

    **The key is a REFERENCE to an application, and eligibility is ENFORCED at the write.**
    The completion offers 1454 of the device's 5552 predefined applications, and an entry
    naming one outside that set is refused - `ping 'ping' is not a valid reference`, code=12 -
    as is an application that does not exist. So the offered set is the real set and not a UI
    convenience, which is a stronger result than confirming a dropdown by clicking it.

    **An entry with NO action is accepted and stores an absent action.** An entry with an
    EMPTY action element is refused, `action is invalid`. So absent and empty are different
    here, and only one of them is reachable.

    **The literal `default` is accepted**, as it is on a decoder - but it does NOT mean the
    same thing. A decoder's `default` resolves to one action per protocol; an exception's
    resolves per SIGNATURE. Measured 2026-10-09 - see `blocks`.
    """

    #: The same seven values as a decoder's action, enumerated 2026-10-08, and enforced at the
    #: write: `action 'wibble' is not an allowed keyword`, code=12.
    ACTIONS = ("default", "allow", "alert", "drop", "reset-client", "reset-server",
               "reset-both")

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="application_overrides")
    #: As the config names it, which is a predefined application name.
    application = models.CharField(max_length=128)
    #: What the config holds. BLANK where the entry carries no action at all, which the device
    #: accepts and which is read as `allow` - the same rule as an absent decoder action.
    configured_action = models.CharField(max_length=32, blank=True)
    #: Does this override stop the transfer?
    #:
    #: NULL means NO SINGLE BOOLEAN IS TRUE OF IT, and it is reserved for the literal
    #: `default`, whose meaning here was MEASURED 2026-10-09.
    #:
    #: An exception's `default` resolves PER SIGNATURE. Two profiles carrying the same eleven
    #: `default` exceptions and differing only in their decoders - one at `default`, one
    #: explicitly INVERTED - render the bare word on all 22 rows and agree with each other.
    #: That rules out inheriting the decoder (they would disagree), the per-protocol table and
    #: a single fixed value (either would bracket). The same export brackets the decoder
    #: column in the same row, so the absence is real and not a rendering limit. Help p.272
    #: says the same: a signature's default action is the one it ships with.
    #:
    #: NOT the same mechanism as a DECODER's `default`, which does resolve to one action per
    #: protocol. Same word, same screen, two behaviours - carrying the decoder's resolution
    #: across would have been wrong.
    #:
    #: It stays null and the control REPORTS it, for a better reason than not knowing: a
    #: signature's own default is typically alert or reset-both, so an exception left at
    #: `default` lets whatever the alerting signatures catch through.
    blocks = models.BooleanField(null=True)

    class Meta:
        ordering = ["security_profile", "application"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "application"],
                name="integrations_unique_app_override_per_profile_application"),
        ]

    @property
    def label(self) -> str:
        """`app (action)` for a finding row, naming the absent and unresolved cases."""
        if not self.configured_action:
            return f"{self.application} (no action set, which allows)"
        if self.blocks is None:
            return f"{self.application} (default - each signature's own action)"
        return f"{self.application} ({self.configured_action})"

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.application}: {self.configured_action}"


class SecurityProfileWildfireRule(models.Model):
    """One match rule of a WildFire analysis profile - what gets sent for sandbox analysis.

    PAN-AVW-003's content. Measured 2026-10-09 on pan-fw-111 (PA-VM 11.2.3).

    **The kind has NO ACTION ANYWHERE.** A rule has exactly four keys - `application`,
    `file-type`, `direction`, `analysis` - enumerated against a profile that does not exist, so
    the answer is schema rather than local membership. Nothing decides what HAPPENS to a file;
    the rules decide only whether it is sent and where. So the allow/alert/reset-both vocabulary
    every antivirus question is phrased in does not apply here at all, and a control that
    assumed a shared shape across profile kinds would be asking a question this node cannot
    answer.

    **A profile that analyses NOTHING is valid configuration.** Measured by writing each shape:
    a profile with no `rules` node, one with an empty `rules` node, and a rule carrying only a
    name are all accepted. So no rows is a real state and it means nothing is submitted - the
    same trap as an antivirus profile with no decoder node, and the reason the control asks
    about the rule rather than only about the rules it finds.

    **`direction` and `analysis` stay ABSENT when not written.** The UI fills `both` and
    `public-cloud` when a rule is added through the form, so an operator-created rule always
    carries them, but the API accepts a rule with neither and stores neither. What the device
    DOES with an absent direction is NOT established - no instance exists to read and the UI
    cannot show a value that is not there - so `covers_both_directions` is null in that case
    rather than guessed, AND SO ARE THE TWO COLUMNS THEMSELVES.
    """

    #: Measured 2026-10-09 by writing each one: 12 real types plus `any`. The device refuses
    #: anything else - `file-type 'x' is not a valid reference`, code=12 - so this is the whole
    #: set on 11.2.3. It comes from the content release, so a consumer reads what is stored
    #: rather than validating against this tuple.
    FILE_TYPES = ("apk", "archive", "email-link", "eml", "flash", "jar", "linux", "MacOSX",
                  "ms-office", "pdf", "pe", "script")
    ANY = "any"
    DIRECTIONS = ("upload", "download", "both")
    ANALYSIS = ("public-cloud", "private-cloud")

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="wildfire_rules")
    name = models.CharField(max_length=64)
    #: Member lists, stored as given. `["any"]` is the passing case and is NOT normalized away
    #: - an engineer looking at a finding needs to see what the rule actually says.
    applications = models.JSONField(default=list, blank=True)
    file_types = models.JSONField(default=list, blank=True)
    #: NULL WHERE THE KEY IS ABSENT, which is what stage 5 declared for both -
    #: `default.stores: null`, `rests_on: not_assumed`. Stage 4 could not settle what the device
    #: does with an absent `direction`, and declined to promote the schema's `public-cloud` for an
    #: absent `analysis`, so nothing is established and nothing is stored. The empty string these
    #: held until 2026-10-29 WAS a value: `is_empty` compiles to `filter(field="")`, which matches
    #: `''` and does NOT match NULL, so a query written against stage 5's declaration and one
    #: written against a blank column find different rows. The device refuses an empty element on
    #: either key, so `''` was only ever the absent case wearing a value's clothes.
    direction = models.CharField(max_length=16, blank=True, null=True)
    analysis = models.CharField(max_length=16, blank=True, null=True)

    #: Derived at normalization because the search layer cannot look inside a JSON list.
    covers_all_file_types = models.BooleanField(default=False)
    covers_all_applications = models.BooleanField(default=False)
    #: NULL where `direction` is absent: the device stores nothing and nothing establishes what
    #: it then does, so this is unestablished rather than false.
    covers_both_directions = models.BooleanField(null=True)

    class Meta:
        ordering = ["security_profile", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "name"],
                name="integrations_unique_wildfire_rule_per_profile"),
        ]

    @property
    def label(self) -> str:
        """What a finding says about this rule, in the UI's own column order."""
        types = ", ".join(self.file_types) or "(none)"
        apps = ", ".join(self.applications) or "(none)"
        where = self.direction or "(direction not set)"
        return f"{self.name}: {types} / {apps} / {where}"

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.name}"


class SecurityProfileInlineDetector(models.Model):
    """One inline cloud-analysis detector on an anti-spyware or vulnerability profile.

    PAN-SPY-004 and PAN-VLN-003. Advanced Threat Prevention's deep-learning engines, which
    judge live traffic rather than waiting for a signature.

    **controls.json POINTS BOTH CONTROLS AT THE WRONG NODE.** It names
    `cloud-inline-analysis/enabled`; writing that is refused with `cloud-inline-analysis is
    invalid` (code=12) on 11.2.3-h3 with ATP licensed - measured 2026-10-10. The real node is
    `mica-engine-spyware-enabled` / `mica-engine-vulnerability-enabled`, entry-keyed by
    detector. That is what the corpus DESCRIBES - "unknown C2 (Cobalt Strike, Empire-style
    beacons)" and "SQLi, command injection" - just not where it points. Deviation recorded in
    control-changes.json; Jason approved building against the real node 2026-10-10.

    **THE TWO KINDS ARE NOT ONE SHAPE**, which is why `action_values` is per kind rather than
    a single constant:

        spyware         5 detectors   action has SIX values, including `drop`
        vulnerability   2 detectors   action has FIVE, no `drop`

    Spyware entries also carry `local-deep-learning`, which vulnerability entries do not.

    **The detector names come from the CONTENT release**, the same rule as the antivirus ML
    models, so nothing here hardcodes them - the catalog is read from the profiles in the
    build.
    """

    #: Measured 2026-10-10 by completing the container on a profile that does not exist, so
    #: these are the key SPACE rather than one device's membership.
    SPYWARE_DETECTORS = (
        "HTTP Command and Control detector", "HTTP2 Command and Control detector",
        "SSL Command and Control detector", "Unknown-TCP Command and Control detector",
        "Unknown-UDP Command and Control detector",
    )
    VULNERABILITY_DETECTORS = ("SQL Injection", "Command Injection")
    #: `drop` is spyware-only.
    SPYWARE_ACTIONS = ("alert", "allow", "drop", "reset-both", "reset-client", "reset-server")
    VULNERABILITY_ACTIONS = ("alert", "allow", "reset-both", "reset-client", "reset-server")
    #: Actions that stop the traffic rather than logging it. Same set the decoders use, minus
    #: `block-ip` which this node does not offer.
    BLOCKING_ACTIONS = frozenset({"drop", "reset-client", "reset-server", "reset-both"})
    #: What an engine the profile never mentions actually does. MEASURED 2026-10-25 on serial
    #: 691665AC334B458 (PA-VM 11.2.5) and independently on 6A9C0A9904E7D6E (11.2.3-h3, a
    #: different content release): on a COMMITTED profile storing no `mica-engine-spyware-enabled`
    #: node at all, the Available Analysis Engines grid renders ACTION `alert` for all five
    #: engines, as a bare value with no `default (...)` parenthetical. Three surfaces agree and
    #: two are not the UI - `action=complete` returns @default='yes' on alert, and the vendor's
    #: Help p.287 states "The default action for all analysis engines is alert".
    #:
    #: `enabled` ALREADY SAYS THE OPPOSITE ABOUT THE DEVICE and its verdict is still right: an
    #: unmentioned engine RUNS at alert, delivers the session and writes a threat log - it is not
    #: a engine that does not run. The column's name is a claim the measurement refutes; renaming
    #: it is a consumer decision and is recorded rather than made (OEP stage 7, anti-spyware).
    IMPLICIT_ACTION = "alert"
    #: WEAKEST FIRST, and taken from PAN-SPY-004's own severity grading rather than invented:
    #: `allow` and `alert` are the two failing values in rank order, and `drop` is the weakest of
    #: the four stopping ones - which is what makes a profile holding drop on one engine and
    #: reset-* on the other four read `drop`.
    ACTION_STRENGTH_WEAKEST_FIRST = (
        "allow", "alert", "drop", "reset-both", "reset-client", "reset-server")
    #: 11.2 ONLY, and the key does not exist at all on 11.1.13-h3/PA-5220, where completing it
    #: answers code=6 `Invalid sequence`. @default='yes' sits on `enable`.
    LOCAL_DEEP_LEARNING_VALUES = ("enable", "disable")

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="inline_detectors")
    #: As the content release names it.
    name = models.CharField(max_length=128)
    #: What the config holds. BLANK where the profile does not mention this detector, which
    #: is itself the finding - the same rule as an unmentioned antivirus ML model.
    configured_action = models.CharField(max_length=32, blank=True)
    #: WHETHER THE PROFILE MENTIONS THIS ENGINE AT ALL - true where an entry exists for it,
    #: false where the row was synthesized from the catalogue.
    #:
    #: ITS NAME IS A CLAIM ABOUT THE DEVICE AND THE MEASUREMENT REFUTES IT. `enabled: false`
    #: reads as "this engine is not running", and a spyware engine the profile never mentions
    #: RUNS at `alert`: the session is delivered and a threat log is written. What the column
    #: reliably says is that nobody configured it. The verdict it feeds is right either way,
    #: because `alert` is not a blocking action; the sentence a report builds from the column
    #: NAME would be wrong. Renaming it to `configured` is a consumer decision and is recorded
    #: rather than made (OEP stage 7, anti-spyware, 2026-10-29).
    enabled = models.BooleanField(default=False)
    #: Does it STOP the traffic, or only log it? `alert` runs and does not block, exactly as
    #: `enable(alert-only)` does on an antivirus ML model - and that distinction is why these
    #: are two booleans rather than one.
    blocks = models.BooleanField(default=False)
    #: The on-device deep-learning setting for this engine, where the profile stores one. SPYWARE
    #: ENGINES ONLY - a vulnerability entry has no such key - and BLANK on every row the lab
    #: holds, because no standing profile writes it.
    #:
    #: **NOTHING ASSERTS IT, and the column exists so that a reading stage 4 took and deliberately
    #: declined to promote has somewhere to land.** The Available Analysis Engines grid carries a
    #: Local Deep Learning column whose cells read `enable` for the HTTP and HTTP2 engines and
    #: EMPTY for the other three, and the column's own header has NO CLIENT RECTANGLE - it is in
    #: the DOM and not on the page, so nobody can be shown it. What the reading suggests is an
    #: implicit of `enable` where the engine supports the feature and nothing where it does not,
    #: which is a value conditional on WHICH ENTRY holds it; against reading the blank as
    #: unsettable, writing `enable` on the SSL engine (whose cell was blank) was ACCEPTED, so the
    #: blank is a rendering fact and not a schema one.
    #:
    #: NOTHING IS MATERIALISED HERE for that reason. A blank therefore means three things at once
    #: - the profile stores nothing, the appliance is an 11.1 build where the key does not exist,
    #: or the engine does not support the feature - and no clause may be written over it until a
    #: surface an operator can see settles which.
    local_deep_learning = models.CharField(max_length=32, blank=True)

    class Meta:
        ordering = ["security_profile", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "name"],
                name="integrations_unique_inline_detector_per_profile"),
        ]

    @classmethod
    def detectors_for(cls, kind: str) -> tuple[str, ...]:
        return {SecurityProfile.KIND_SPYWARE: cls.SPYWARE_DETECTORS,
                SecurityProfile.KIND_VULNERABILITY: cls.VULNERABILITY_DETECTORS}.get(kind, ())

    @classmethod
    def weakest_action(cls, actions) -> str:
        """The weakest of `actions`, or "" where there are none.

        AN ACTION THIS TABLE DOES NOT KNOW SORTS WEAKEST, and so does a BLANK one - the same
        rule `_weakest_action` follows in the normalizer: a value nobody has measured must not be
        read as protection. A content release adding a seventh action lands there, and so does a
        VULNERABILITY engine the profile omits, whose implicit nothing in this project has read.

        NO IMPLICIT IS SUBSTITUTED HERE. A spyware row never arrives blank, because
        `inline_detector_action` materialises the measured `alert` on the way in - which is where
        a claim about the device belongs, beside its citation.
        """
        resolved = list(actions)
        if not resolved:
            return ""
        order = cls.ACTION_STRENGTH_WEAKEST_FIRST
        return min(resolved, key=lambda a: order.index(a) if a in order else -1)

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.name}: {self.configured_action or '(unset)'}"


class SecurityProfileMlModel(models.Model):
    """One WildFire Inline ML model of an antivirus profile, and whether it is on.

    PAN-AVW-002's subject. Three things make it awkward, and all three are measured:

    **The model names come from the CONTENT release, not from PAN-OS.** controls.json says so
    and says to enumerate them on the target version before automating. So nothing here hardcodes
    them: the catalog is read from the PREDEFINED profile, which carries every model the
    device knows about. On the lab that is eight - Windows Executables, PowerShell Script 1,
    PowerShell Script 2, Executable Linked Format, MSOffice, Shell, OOXML, MachO - and a
    content update that adds a ninth adds it here with no code change.

    **An absent model means DISABLED**, the same way an absent decoder action means `allow`.
    Measured 2026-10-07: a profile written with no `mlav-engine-filebased-enabled` node at all
    renders every model as `disable (for all protocols)` in the UI. So a profile that says
    nothing about ML does no ML, and a row is synthesized for every model in the catalog
    rather than only for the ones the config names.

    **The shipped profile is STRONGER than a hand-made one here**, which is the reverse of the
    usual direction: the predefined `default` enables every model, and a profile created through
    the UI without touching anything writes `disable` for every one. An admin who builds their
    own profile to be careful ends up with less inline ML than if they had left the shipped one
    alone.
    """

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="ml_models")
    #: THREE values, enumerated from the device with action=complete on 2026-10-08:
    #: `enable`, `enable(alert-only)` and `disable`. The middle one is why this model carries
    #: two booleans rather than one - a model set to alert-only RUNS, and does not BLOCK, and a
    #: single `enabled` flag has to misreport one of those.
    ACTIONS = ("enable", "enable(alert-only)", "disable")
    RUNS = ("enable", "enable(alert-only)")
    BLOCKS = "enable"

    #: WEAKEST FIRST, and not the order a reader would guess: a model that is OFF produces
    #: nothing at all, while one on the middle setting at least produces a record of the
    #: delivery. An ABSENT model - a profile that does not mention it - is stored with a blank
    #: `configured_action` and means DISABLED, so an aggregate maps blank onto `disable` before
    #: ordering rather than treating it as an unranked value.
    #:
    #: THE WIRE LITERAL FOR THE MIDDLE STATE HAS NO SPACE, and both the vendor's Help and the UI
    #: grid spell it with one, so a later stage matching a screen label against a stored value
    #: will not match. These are the device's spellings.
    STATE_STRENGTH_ORDER = ("disable", "enable(alert-only)", "enable")
    #: What the config holds for a model the profile does not mention, and what it means.
    ABSENT_STATE = "disable"

    #: As the content release names it. Not an enum - see the class docstring.
    name = models.CharField(max_length=128)
    #: The engine runs at all: `enable` or `enable(alert-only)`.
    enabled = models.BooleanField()
    #: It stops the file rather than logging it: `enable` alone. What PAN-AVW-002 asserts, and
    #: what the corpus names for both its minimum and its preferred value.
    blocks = models.BooleanField(default=False)
    #: What the config held, for an engineer looking for the line to change. Blank where the
    #: profile does not mention this model at all, which is itself the finding.
    configured_action = models.CharField(max_length=32, blank=True)

    class Meta:
        ordering = ["security_profile", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "name"],
                name="integrations_unique_ml_model_per_profile"),
        ]

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.name}: {'on' if self.enabled else 'off'}"


class SecurityProfileSeverityVerdict(models.Model):
    """Whether one profile blocks one threat severity, and why not when it does not.

    A SATELLITE rather than columns on the profile, because the verdict is the one part of a
    security profile that is KIND-SPECIFIC. Anti-spyware and vulnerability profiles are an
    ordered list of rules matching on severity, so "does this block critical" is a question they
    answer. An antivirus profile has no such rules - it has per-protocol decoders - and a column
    that can only say yes or no would have to say NO about it, which reads as "critical threats
    are not blocked" when the truth is that the profile makes no claim in those terms.

    With the verdict here, a profile that does not answer simply has no row, and
    `SecurityProfile` is left holding only what every profile kind shares: a name, a scope, a
    precedence, whether it is predefined, and who references it. That is what lets the other
    seven profile kinds under /config/predefined/profiles - antivirus, URL filtering, file
    blocking, WildFire analysis, decryption, SCTP and SD-WAN path quality - become rows without
    a model each.

    The verdict itself is unchanged and still order-independent: see SecurityProfile's docstring.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    SEVERITY_CHOICES = [(CRITICAL, "Critical"), (HIGH, "High"), (MEDIUM, "Medium")]
    #: WEAKEST FIRST, and the eight the device holds at a profile rule's `action` - measured by
    #: completion on both lab platforms, with the Help's own action table agreeing on the eight
    #: rows applicable to a threat-rule profile when the section is read whole.
    #:
    #: THE ORDER IS STAGE 3'S GRADING ORDER AND NOT INVENTED: `allow`, then the POINTER `default`,
    #: then `alert` are the three that deliver the session, and `drop` is the weakest of the
    #: stopping ones - the same rank `SecurityProfileInlineDetector.ACTION_STRENGTH_WEAKEST_FIRST`
    #: uses on the engine node, so a profile weak in one place reads weak the same way in both.
    #:
    #: `default` SITS WITH THE FAILING VALUES ON PURPOSE. A signature's default action is
    #: "typically either Alert or Reset Both" (Help p.272), so it cannot be relied on to block -
    #: which is why `BLOCKING_ACTIONS` in the normalizer excludes it, and the shipped `default`
    #: profile is exactly that case.
    ACTION_STRENGTH_WEAKEST_FIRST = (
        "allow", "default", "alert", "drop",
        "reset-client", "reset-server", "reset-both", "block-ip")

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="severity_verdicts")
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES)
    blocked = models.BooleanField()
    #: WHY it is not blocked - the tab has to say so, because two profiles failing one severity
    #: can fail it for different reasons (an alert rule, or no catch-all rule at all).
    detail = models.CharField(max_length=255, blank=True)
    #: THE WEAKEST ACTION ANY RULE COVERING THIS BAND TAKES, on either host side, as a VALUE
    #: rather than inside a 255-character sentence. PAN-VLN-001's grading needs the value;
    #: `detail` is prose and the only operator reachable on it is `contains`. The sibling
    #: CATEGORY verdict has stored exactly this column for its own axis since it was built, which
    #: is the precedent this follows rather than a new idea.
    #:
    #: EMPTY MEANS NO RULE COVERS THE BAND AT ALL, which is not an action value and is a
    #: different failure - stage 3 says so in terms. It is the weakest member of the order above
    #: for grading purposes and `weakest_of` returns it over any action.
    #:
    #: WRITTEN FOR BOTH THREAT-RULE KINDS, not only for vulnerability. The computation is
    #: kind-generic - `severity_verdict` already walks the two host sides for vulnerability and
    #: one for spyware - and leaving it blank on spyware rows would state "no rule covers the
    #: band" about rows where one does. Only the vulnerability domain asserts it today.
    weakest_action = models.CharField(max_length=32, blank=True)

    @classmethod
    def weakest_of(cls, actions) -> str:
        """The weakest of `actions` by the order above, or "" where there are none.

        AN ACTION THE ORDER DOES NOT PLACE SORTS WEAKEST, and so does a BLANK one - the same rule
        `SecurityProfileInlineDetector.weakest_action` follows, and for the same reason: a value
        nobody has measured must not be read as protection. A content release adding a ninth
        action lands there rather than being silently dropped.
        """
        resolved = list(actions)
        if not resolved:
            return ""
        order = cls.ACTION_STRENGTH_WEAKEST_FIRST
        return min(resolved, key=lambda a: order.index(a) if a in order else -1)

    class Meta:
        ordering = ["security_profile", "severity"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "severity"],
                name="integrations_unique_verdict_per_profile_severity"),
        ]

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.severity}: {'blocked' if self.blocked else 'not blocked'}"


class SecurityProfileCategoryVerdict(models.Model):
    """Whether one profile blocks one threat CATEGORY by blocking the source, and why not.

    PAN-VLN-002's subject: brute-force signatures. A sibling of `SecurityProfileSeverityVerdict`
    and deliberately a second model rather than a column on it, because the two ask different
    questions of the same rule list. A severity verdict asks *is this threat stopped*, and any
    blocking action answers yes. This asks *is the SOURCE stopped*, which only `block-ip`
    answers - password spraying is a thousand attempts from one host, and resetting each
    connection individually leaves the attacker free to make the next attempt.

    **So `reset-both` satisfies PAN-VLN-001 and fails this control, on the same rule.** That is
    not an inconsistency: the vendor recommends reset-both for severity rules (Help p.291) and
    `block-ip` is what stops a source. A profile can be entirely correct by PAN-VLN-001 and
    still report here.

    **`block-ip` is a CHOICE NODE with children, which no other action has.** Measured
    2026-10-11 on a PA-VM 11.2.3-h3 and a PA-5220 11.1.13-h3, identically:

        track-by    REQUIRED. `source` or `source-and-destination`. Accepted at the write and
                    rejected at COMMIT when omitted - "block-ip is missing 'track-by'" - so a
                    write probe alone reports success. Established with `validate full`, which
                    runs the commit-time checks as a job without leaving an invalid candidate.
        duration    OPTIONAL, 1 to 3600 seconds, enforced at the WRITE with code=12
                    ("value=3601 should be equal to or between 1 and 3600").

    **`duration`'s implicit value is NOT established**, so nothing here asserts it. It is
    optional, the Help documents a Block Duration default for DoS profiles (p.314) and not for
    this node, and the UI tooltip was not read. The column records what the config holds and
    `None` means the config does not say - NOT that blocking is instantaneous.

    **The Block IP List is a different thing from the action.** Help p.97 says it "is supported
    on PA-3200 Series, PA-5200 Series, and PA-7000 Series firewalls", which is about the
    Monitor > Block IP List page and the hardware offload behind it - the same section
    documents software blocking as the fallback when hardware capacity is exceeded. The action
    itself completes in the PA-VM's schema, so that sentence is not a reason to scope this
    control by platform. Whether a PA-VM enforces it in software was NOT measured here.
    """

    #: One of sixteen, enumerated from both platforms 2026-10-11. Only brute-force is written
    #: today, because only PAN-VLN-002 asks - but a category is the key so the second one costs
    #: a row rather than a model.
    BRUTE_FORCE = "brute-force"
    TRACK_BY_SOURCE = "source"
    TRACK_BY_SOURCE_AND_DESTINATION = "source-and-destination"

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="category_verdicts")
    category = models.CharField(max_length=64)
    #: Is the SOURCE stopped for this category - `block-ip` with a `track-by`, across every
    #: assessed severity and both host sides. Order-independent, like the severity verdict.
    blocks_source = models.BooleanField()
    #: The weakest action found on a rule covering this category, or blank when no rule covers
    #: it. What the engineer has to change.
    weakest_action = models.CharField(max_length=32, blank=True)
    #: From the covering `block-ip` rule, when there is one. Blank/None otherwise, and None
    #: means the CONFIG IS SILENT rather than zero - see the class docstring.
    track_by = models.CharField(max_length=32, blank=True)
    duration = models.PositiveIntegerField(null=True, blank=True)
    #: WHY it is not blocked. Two profiles can fail for different reasons - no rule covering
    #: the category at all, or a covering rule whose action only resets the connection.
    detail = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["security_profile", "category"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "category"],
                name="integrations_unique_category_verdict_per_profile"),
        ]

    def __str__(self) -> str:
        state = "source blocked" if self.blocks_source else (self.detail or "not blocked")
        return f"{self.security_profile} / {self.category}: {state}"


class SecurityProfileDnsSignatureSource(models.Model):
    """One DNS signature source of an anti-spyware profile, and whether it sinkholes.

    PAN-SPY-002's subject. The Help names four sources on the DNS Policies tab (p.283) and they
    are not interchangeable:

        Palo Alto Networks Content   the `lists` node, included with Threat Prevention. This
                                     control's subject, stored as `default-paloalto-dns`.
        DNS Security                 a LICENSED cloud service, the `dns-security-categories`
                                     node - PAN-SPY-003, and a different action enum.
        Advanced DNS Security        a third licensed service, absent from the corpus entirely.
        External Dynamic Lists       operator-added domain lists, also under `lists`.

    **An EDL is NOT asserted.** Help p.284: "By default, policy actions for domain lists are
    configured to Allow", and an EDL with an `alert` action is the documented way to express a
    DNS exception. Firing on one would report a deliberate allow-list as a failure. Rows are
    written for EDLs so the tab can show them, with `is_paloalto_content` false, and the control
    filters on that flag.

    **ABSENCE IS DOCUMENTED AS PASSING here, which inverts almost every other control in this
    domain.** Help p.284 says it twice - "By default, the locally-accessed Palo Alto Networks
    Content DNS signatures are sinkholed" and "The default action for Palo Alto Networks DNS
    signatures is sinkhole". So a profile with no `botnet-domains` node at all gets a
    synthesized row with `action_is_implicit` set, an effective action of `sinkhole`, and no
    finding.

    **THAT IMPLICIT VALUE IS DOCUMENTED AND NOT MEASURED**, and it is the one thing here a read
    cannot settle: PAN-OS omits an element matching its default, so an absent action and a
    default action look identical in the config. The evidence is two sentences of vendor
    documentation plus the fact that the predefined `default` profile writes `alert`
    EXPLICITLY - which it would not need to do if alert were the default. Against it: `strict`
    writes `sinkhole` explicitly too. `action_is_implicit` exists so the undecided case is
    visible rather than silently folded into a pass, and so a second query can report it
    without a schema change if the measurement comes out the other way.

    DECIDED 2026-10-11, Jason: assume the documentation is right. The pass stands, and what it
    rests on is recorded here rather than left as an open question - a UI click would still
    settle it, and `action_is_implicit` is how the affected profiles would be found if it ever
    does. See PAN-SPY-002 in control-changes.json.

    **The two predefined profiles DISAGREE**, measured 2026-10-11 on a PA-VM 11.2.3-h3:

        strict    lists/default-paloalto-dns action sinkhole, sinkhole/ipv4-address
                  `pan-sinkhole-default-ip`, ipv6-address `::1`
        default   lists/default-paloalto-dns action ALERT, and no sinkhole node at all

    So this control is NOT satisfied by the shipped `default` profile, and the payload contract
    said it was until 2026-10-11 - a fact recorded from reading `strict` and generalised to
    both.
    """

    PALOALTO_CONTENT = "default-paloalto-dns"
    #: Measured on both platforms 2026-10-11. A CHOICE node: `{"sinkhole": null}`, not text.
    ACTIONS = ("alert", "allow", "block", "sinkhole")
    #: What the Help says an unconfigured Palo Alto Networks Content list does (p.284).
    DOCUMENTED_IMPLICIT_ACTION = "sinkhole"

    #: Which of the Help's four signature sources this row is. They share a screen and almost
    #: nothing else: three different action enums, two different child key sets, and opposite
    #: meanings for absence.
    TYPE_PALOALTO_CONTENT = "paloalto-content"
    TYPE_EDL = "edl"
    TYPE_DNS_SECURITY = "dns-security-category"
    TYPE_ADVANCED_DNS_SECURITY = "advanced-dns-security-category"
    SOURCE_TYPE_CHOICES = [
        (TYPE_PALOALTO_CONTENT, "Palo Alto Networks Content"),
        (TYPE_EDL, "External Dynamic List"),
        (TYPE_DNS_SECURITY, "DNS Security category"),
        (TYPE_ADVANCED_DNS_SECURITY, "Advanced DNS Security category"),
    ]

    #: PAN-SPY-003's subject. TEN, and now PROVED COMPLETE rather than read off a sample.
    #:
    #: Completing the container returns an entry's CHILDREN, not the name space, so these were
    #: first read from the predefined profiles' membership - weaker evidence, since membership
    #: says what those profiles happen to name. On 2026-10-11 a write probe settled it: PAN-OS
    #: validates a category name as a REFERENCE, so `pan-dns-sec-dga` is refused with
    #: "'pan-dns-sec-dga' is not a valid reference" (code=12) while the ten are accepted.
    #: A refused name therefore proves non-existence.
    #:
    #: Measured on pan-fw-201, PA-VM 11.2.5, content 9157-10279, WITH a DNS Security licence -
    #: the combination that rules out both licence-gating and content-staleness.
    DNS_SECURITY_CATEGORY_NAMES = (
        "pan-dns-sec-adtracking", "pan-dns-sec-benign", "pan-dns-sec-cc", "pan-dns-sec-ddns",
        "pan-dns-sec-grayware", "pan-dns-sec-malware", "pan-dns-sec-parked",
        "pan-dns-sec-phishing", "pan-dns-sec-proxy", "pan-dns-sec-recent",
    )
    #: TWO, and 11.2-ONLY: completing the node on a PA-5220 running 11.1.13-h3 answers
    #: `Invalid sequence`. In no corpus control at all.
    ADVANCED_CATEGORY_NAMES = ("pan-adns-sec-dnsmisconfig", "pan-adns-sec-hijacking")

    #: THE CATEGORIES PAN-SPY-003 ASSERTS, and only these.
    #:
    #: controls.json's minimum names "the C2 and malware DNS Security categories" and its
    #: preferred extends the same action to "phishing and DNS-tunneling categories, with DGA,
    #: newly-registered, and parked at sinkhole or alert per risk tolerance". The checklist
    #: says assert the preferred, so C2, malware and phishing - and the ones the corpus itself
    #: marks as a risk-tolerance judgement are deliberately NOT asserted, because an estate
    #: can reasonably leave newly-registered domains alerting.
    #:
    #: NEITHER A DGA NOR A DNS-TUNNELING CATEGORY EXISTS, and that is proved rather than
    #: unfound: `pan-dns-sec-dga`, `-dns-tunnel`, `-tunneling` and `-dnstunnel` are all refused
    #: as invalid references on a licensed device running current content. So two of the names
    #: the corpus's preferred value reasons about cannot be asserted at all.
    #:
    #: Its "newly-registered" DOES exist, as `pan-dns-sec-recent` - `pan-dns-sec-newly-registered`
    #: is refused. That one is a naming difference, not a missing feature, and it is still not
    #: asserted because the corpus leaves it to risk tolerance.
    #: `pan-dns-sec-benign`, -adtracking, -grayware, -proxy and -ddns are not named by the
    #: corpus and are not asserted; sinkholing benign domains would be a defect, not a finding.
    ASSERTED_MALICIOUS_CATEGORIES = (
        "pan-dns-sec-cc", "pan-dns-sec-malware", "pan-dns-sec-phishing",
    )
    #: `default`, `allow`, `block`, `sinkhole` - FOUR, measured on both platforms. No `alert`,
    #: which the Palo Alto Networks Content list has and the ADVANCED node also has.
    CATEGORY_ACTIONS = ("default", "allow", "block", "sinkhole")
    #: FIVE: the four above plus `alert`. A third action enum on the same screen.
    ADVANCED_CATEGORY_ACTIONS = ("default", "allow", "alert", "block", "sinkhole")
    #: What counts as enforcing a malicious category. controls.json's description says
    #: "Malicious categories must sinkhole/block", so BLOCK PASSES HERE - unlike PAN-SPY-002,
    #: where the corpus asks for sinkhole alone and blocking loses the infected client. The two
    #: controls differ because their corpus entries differ, not by oversight; `sinkholes`
    #: records the stricter reading beside this one.
    ENFORCING_ACTIONS = frozenset({"block", "sinkhole"})
    #: What a DNS Security category does when left at `default`. Help p.284 is explicit and
    #: parallel: "the locally-accessed Palo Alto Networks Content DNS signatures are sinkholed,
    #: while the cloud-based DNS Security is set to allow", and "If you want to enable
    #: sinkholing using DNS Security, you must configure the action on DNS queries to sinkhole".
    #: So `default` does not enforce, and BOTH predefined profiles leave all twelve categories
    #: there.
    CATEGORY_IMPLICIT_ACTION = "default"

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="dns_signature_sources")
    #: As the config names it - `default-paloalto-dns`, or an EDL's own name.
    name = models.CharField(max_length=128)
    #: Is this THE Palo Alto Networks Content list? Kept as its own column because
    #: PAN-SPY-002's query names it, and a control's query is a contract.
    is_paloalto_content = models.BooleanField(default=False)
    source_type = models.CharField(
        max_length=40, choices=SOURCE_TYPE_CHOICES, default=TYPE_PALOALTO_CONTENT)
    #: What the config holds. BLANK means the config does not name this source at all.
    configured_action = models.CharField(max_length=32, blank=True)
    #: What it therefore does - the configured action, or the documented implicit one.
    effective_action = models.CharField(max_length=32, blank=True)
    #: Does it sinkhole? `block` stops C2 resolution and does NOT identify the infected client
    #: behind an internal resolver, which is half of what the control is for, so it is false
    #: here. Help p.285 offers it as the fallback - "If you can't sinkhole the traffic, block
    #: it" - and controls.json sets both minimum and preferred to `sinkhole`.
    sinkholes = models.BooleanField(default=False)
    #: Does it stop the resolution AT ALL - block or sinkhole? What PAN-SPY-003 asserts for a
    #: malicious DNS Security category, because that corpus entry says "sinkhole/block". For
    #: the Palo Alto Networks Content list this is true of `block` as well, and PAN-SPY-002
    #: still reports it: two booleans, two controls, one row.
    enforces = models.BooleanField(default=False)
    #: True when nothing in the config said so and the effective action came from the Help.
    action_is_implicit = models.BooleanField(default=False)

    class Meta:
        ordering = ["security_profile", "-is_paloalto_content", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "name"],
                name="integrations_unique_dns_source_per_profile"),
        ]

    def __str__(self) -> str:
        how = " (implicit)" if self.action_is_implicit else ""
        return f"{self.security_profile} / {self.name}: {self.effective_action}{how}"


class SecurityProfileThreatException(models.Model):
    """One per-signature override on one anti-spyware or vulnerability profile.

    PAN-SPY-005's own subject, and the row PAN-SPY-001 needs and cannot have today. The estate
    already held a COUNT - `SecurityProfile.threat_exception_count`, summed over all five
    exception surfaces - which answers *does an exception exist* and cannot answer *does an
    exception hand a critical signature back to a non-stopping action*. An exception's action set
    is the SAME EIGHT as a profile rule's action, measured at the field's own position on three
    builds, which is exactly why one exception can undo a severity verdict that passed.

    **ONE SURFACE OF FIVE, deliberately.** The five are `threat-exception`,
    `botnet-domains/threat-exception`, `botnet-domains/whitelist` (three entry-keyed collections)
    and `inline-exception-ip-address`, `inline-exception-edl-url` (two member lists). This model
    is the first of them - the one whose entries carry a per-signature ACTION, which is the only
    surface that can reverse a severity verdict. The other four stay as counts in
    `exception_surfaces` until a control asserts something about an individual entry on them.

    **THE NAME SPACE IS NOT CLOSED.** Measured: an arbitrary numeric name is ACCEPTED at the
    write with NO reference check, unlike the engine and category collections where a bogus name
    is refused. So a row here can name a signature that does not exist, and a reader must not
    treat `threat_id` as resolvable.

    **`default` IS A POINTER AND NO COLUMN HOLDS WHAT IT RESOLVES TO.** An absent action, and an
    absent exception entry, both leave the signature at its own content action, which the grid
    renders per row as `default (alert)` - the same pointer notation the DNS Security categories
    use. The resolution is content-supplied and rendered only by the device's own dialog, so no
    read a collector issues carries it. `action` therefore stores the literal, which is on the
    firing side for PAN-SPY-005 (an exception exists at all) and is UNDECIDABLE for PAN-SPY-001
    without the resolution. That is a gap recorded rather than a pass taken.
    """

    #: The literal an absent action asserts - a POINTER to the signature's own content action,
    #: not an action. Measured on serial 691665AC334B458: on the committed keyless profile all
    #: thirty catalogue rows read `default (alert)`, and the one row written moved to a bare
    #: `allow` while the other twenty-nine kept the parenthetical in the same read.
    IMPLICIT_ACTION = "default"
    #: The SAME EIGHT as a profile rule's action, measured with action=complete at the field's own
    #: position on all three lab builds, with NO @default on any of them. That identity is what
    #: makes PAN-SPY-001 depend on PAN-SPY-005.
    ACTIONS = ("default", "allow", "alert", "drop", "reset-client", "reset-server", "reset-both",
               "block-ip")
    #: Actions that stop the signature. `default` is NOT here and nor is `alert`: a signature
    #: handed back to its content action is not known to be stopped.
    BLOCKING_ACTIONS = frozenset({"drop", "reset-client", "reset-server", "reset-both",
                                  "block-ip"})

    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="threat_exceptions")
    #: The threat ID as the operator wrote it. See the class docstring: not a closed name space.
    threat_id = models.CharField(max_length=64)
    #: The action this exception gives the signature, INCLUDING the literal `default`. Never
    #: blank: an absent action is materialised to the pointer, which is what the device does.
    action = models.CharField(max_length=32, default=IMPLICIT_ACTION)
    #: How many source addresses the exception is narrowed to, and ZERO IS THE WIDEST FORM -
    #: the exception then applies to every source. THE POLARITY IS THE OPPOSITE OF WHAT A COUNT
    #: USUALLY READS AS, and the device's own grid makes the worst state look like no state: the
    #: cell renders BLANK when the collection is absent and a COUNT when it is not. A reader who
    #: takes a zero here for the compliant answer has it backwards.
    #:
    #: A count rather than a list because the members are an entry-keyed collection, settled by
    #: refusal - `<member>10.1.1.2</member>` is rejected and `<entry name='10.1.1.1'/>` accepted.
    exempt_ip_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["security_profile", "threat_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile", "threat_id"],
                name="integrations_unique_threat_exception_per_profile"),
        ]

    @property
    def hands_signature_back(self) -> bool:
        """Does this exception leave the signature un-stopped by the profile's own rules?

        TRUE for `allow` and `alert` - the two values that deliver the session. `default` is
        NEITHER, and this property says so by being False: the pointer's resolution is not in the
        store, so claiming it hands the signature back would assert something nothing read.
        `undecided_without_resolution` is the companion that says which case it is.
        """
        return self.action in ("allow", "alert")

    @property
    def undecided_without_resolution(self) -> bool:
        """Is this exception's effect unknowable from the configuration alone?

        TRUE for the literal `default`, whose resolution is content-supplied and rendered only by
        the device's own dialog. The pair of booleans is what keeps `hands_signature_back`'s
        False from reading as "this exception is harmless".
        """
        return self.action == self.IMPLICIT_ACTION

    def __str__(self) -> str:
        return f"{self.security_profile} / {self.threat_id}: {self.action}"


class SecurityProfileGroup(ScopedPolicyObject):
    """Objects > Security Profile Groups. Modeled because it is how profiles reach rules: on the
    lab every Panorama-shared rule protection arrives through a group, and a predefined profile
    counts as used when a group names it. Not assessed itself."""

    #: Computed here: referenced but never defined. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE, related_name="security_profile_groups")
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE, related_name="security_profile_groups",
        null=True, blank=True)
    appliance_group = models.ForeignKey(
        ApplianceGroup, on_delete=models.CASCADE, related_name="security_profile_groups",
        null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="security_profile_groups")

    spyware_profile = models.CharField(max_length=255, blank=True)
    vulnerability_profile = models.CharField(max_length=255, blank=True)
    #: Every profile type the group names, `{type: [names]}` - antivirus, URL filtering and the
    #: rest are read here so their controls do not need a second walk. Not searchable.
    members = models.JSONField(default=dict, blank=True)
    raw_group = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "name", "precedence_rank"]),
            models.Index(fields=["appliance_group", "name", "precedence_rank"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_group_per_point_namespace",
            ),
            models.UniqueConstraint(
                fields=["appliance_group", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_security_profile_group_per_group_namespace",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.owner} / {self.namespace_key} / {self.name}"
