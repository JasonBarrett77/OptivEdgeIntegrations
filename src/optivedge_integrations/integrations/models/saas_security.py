"""The four `saas-security` models: approval marking, URL-filtering posture, policy posture, ACE.

PAN-SAS-001 to 005. Four grains over three objects and one device-wide singleton:

    SanctionedApplicationMarking   a verdict over one enforcement point's application-tag entries
    SaasUrlFilteringPosture        a verdict over the URL Filtering profiles it can reach
    SaasApplicationPolicyPosture   a verdict over its rulebase and its application filters
    CloudAppEngineSetting          one appliance's App-ID Cloud Engine, configured and actual

WHY THREE OF THE FOUR ARE VERDICTS AND NOT ENTRIES. Stage 4 measured the commonest state of this
domain as NO ENTRY AT ALL: no `application-tag` container on any of the four lab appliances before
stage 6 wrote one, no `http-header-insertion` child on any url-filtering profile at any scope, no
`application-filter` on three of four, and no rule naming a function child application anywhere.
The per-entry grain has no row for that, so a predicate cannot compare against it - and every one
of these columns therefore defaults to its FIRING value, which is what makes a row nobody has
recomputed report itself rather than pass.

THE ROW IS KEYED ON `enforcement_point`, WHICH IS NOT WHAT STAGE 5 DECLARED AND IS THE SHIPPED
CONVENTION. Stage 5's identity names `appliance` plus `vsys_name` and predicts TWO rows for one
synchronised HA configuration. An `EnforcementPoint` carries exactly one of
`appliance`/`appliance_group` (`models/collected.py::EnforcementPoint.clean`) and a Panorama-managed
pair holds one point for the pair, so a synchronised rulebase produces ONE row here. That is the
same correction `DecryptionRulebaseVerdict` records: the prediction is a claim about THIS schema
rather than about the device, and `SecurityRule` has keyed on the enforcement point since it was
written. `appliance` and `vsys_name` are reachable through the foreign key and are not duplicated
as columns.

A DISABLED RULE COUNTS, EVERYWHERE IN THIS DOMAIN, AND I BELIEVE THAT IS WRONG. Stage 5's
`computes` for `function_apps_are_refused`, `effective_action_for_function_apps` and
`tenant_restriction_in_force` never mentions the `disabled` leaf, and every one of the sixteen lab
subjects stage 6 left standing for them is a rule written `disabled: yes` - with stage 6's
expectation table reading each as "the first rule that matches it carries `deny`". So the shipped
derivation includes disabled rules, because that is the only reading under which the estate it was
graded against means anything. The direction of the error is the unsafe one: a disabled deny rule
reports a refusal that no session will ever meet. `DecryptionRulebaseVerdict` takes the opposite
decision in the same repository (`normalization/decryption.py::rulebase_verdict` filters
`not r.disabled`), so the two domains disagree about one word. Recorded in the stage 7 artifact's
`spec_gaps`; what would close it is a `disabled` clause in stage 5's own `computes`, or a
companion column separating "refused" from "refused by a rule that is in force".

NO PROVENANCE ROW IS WRITTEN FOR ANY COLUMN OF THE THREE VERDICT MODELS. A verdict is computed
rather than read: no payload key supplies it, so there is no marker to store, and the entries it
ranges over carry their own. The cost is stated rather than hidden - a control whose finding turned
on whether a marking was PUSHED cannot be written against these subjects, and on this estate every
url-filtering profile that carries content is pushed.

`CloudAppEngineSetting` IS THE EXCEPTION AND STORES TWO MEASURED KEYS with provenance, because
`deviceconfig/setting/cloudapp` is a singleton with a real key and a real marker. Its other three
columns are derived, two of them from an OPERATIONAL reply, which `ProvenanceType` has no member
for - the shipped convention for that is to declare the column derived and write no row, as
`LoggingSettings` does for its runtime columns.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel
from .collected import EnforcementPoint, ManagementStation
from .provenance import ProvenancedMixin


#: The two PAN-OS web categories PAN-SAS-004 is about - consumer file storage and personal
#: publishing. A module constant rather than a per-row column because the control names them
#: and no configuration key carries the pair; the normalizer imports this and nothing else
#: decides which categories the verdict ranges over.
CONSUMER_STORAGE_CATEGORIES = ("online-storage-and-backup", "personal-sites-and-blogs")


class SanctionedApplicationMarking(ProvenancedMixin, SyncTrackedModel):
    """One enforcement point's approved-application inventory, as a verdict. PAN-SAS-001.

    The firewall holds no list of what the business approved - the approval MARKING is the
    firewall's only record of it - so no column can compare the marked set against an approved
    set, and the control reduces to whether the mechanism is used at all and whether the
    appliance's partitions agree.

    THE COUNT IS OF THE PREDEFINED `Sanctioned` TAG AND NOTHING ELSE, and two measured traps sit
    in that sentence. One of the predefined tag values the device offers is literally named
    `empty`, so a reader treating the string `empty` as an absence stores a real marking as no
    marking. And `action=set` MERGES into a member list rather than replacing it, so the marking
    is a SET: the device accepts an application marked `Sanctioned` AND `Tolerated` at once, and
    the count is membership of the set rather than equality with it.

    WHAT THE VERDICT CANNOT SAY. A marking pushed from a Panorama device group counts toward the
    count - it is in force here - and this row has no column saying where a marking was authored,
    so "this partition approves nothing" cannot be told from "this partition's whole inventory is
    pushed". The remediation names the firewall's own vsys node, which an engineer cannot edit for
    a pushed marking.
    """

    #: Every column. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "sanctioned_application_count",
        "marked_application_names",
        "appliance_is_multi_vsys",
        "marking_is_inconsistent_across_vsys",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE,
        related_name="sanctioned_application_markings")
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE,
        related_name="sanctioned_application_markings")
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="sanctioned_application_markings")

    #: How many applications this partition marks with the predefined `Sanctioned` tag, over the
    #: union of the merged and the pushed reads. ZERO IS THE FIRING VALUE and it is also the
    #: measured state of every vsys in this lab that stage 6 did not write to: by the vendor's own
    #: rule an estate that marks nothing treats every application as unsanctioned.
    #:
    #: A COUNT AND NOT A PRESENCE TEST, for a measured reason: stage 4 found the container ABSENT
    #: on two appliances and present-but-empty elsewhere for sibling objects, and a truthiness
    #: test splits those the wrong way. The lab holds the sharper case - vsys2 of fw-core-tpa-b
    #: has a POPULATED container whose one entry carries no `tag` child at all, so the collection
    #: is non-empty and the marked count is nil.
    sanctioned_application_count = models.PositiveIntegerField(default=0)
    #: The names, sorted, beside the reachable count. NOT SEARCHABLE and deliberately so: it is
    #: what the remediation is written against. Every name is a VALIDATED foreign key into the
    #: predefined App-ID namespace - stage 4 measured the device refusing an entry for an
    #: application that does not exist - so a consumer may treat each one as resolvable.
    marked_application_names = models.JSONField(default=list, blank=True)
    #: Whether the owning appliance partitions its configuration at all, which is the condition
    #: under which asking about agreement between partitions means anything. TRUE IS THE DEFAULT
    #: AND THAT IS THE POINT: an applicability column defaulting to "does not apply" silently
    #: removes the control from every row nobody has recomputed.
    #:
    #: Taken from the MERGED read's vsys roster, which is the view that carries a
    #: template-contributed entry: measured on fw-core-tpa-b, the merged roster holds NINE vsys
    #: where `action=show` answers eight, the ninth being supplied by a template.
    appliance_is_multi_vsys = models.BooleanField(default=True)
    #: Whether this partition's set of sanctioned applications differs from any sibling
    #: partition's, over the UNION of applications named anywhere on the appliance. TRUE FIRES.
    #:
    #: The union is not decoration: stage 4 measured that the commonest form of the inconsistency
    #: is an application present in one vsys's collection and ABSENT from another's, so ranging
    #: over the rows that exist would miss it. What this column CANNOT say is which side is in
    #: force - precedence for this node across vsys, shared and a Panorama push is unmeasured -
    #: and it is deliberately narrowed to the appliance's own partitions, because the vendor's
    #: sentence also covers firewalls sharing one Panorama device group and that half needs the
    #: management station.
    marking_is_inconsistent_across_vsys = models.BooleanField(default=True)

    class Meta:
        ordering = ["enforcement_point", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point"],
                name="integrations_unique_sanctioned_app_marking_per_point"),
        ]
        indexes = [
            models.Index(fields=["enforcement_point"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["sanctioned_application_count"]),
            models.Index(fields=["marking_is_inconsistent_across_vsys"]),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} sanctioned application marking"

    def clean(self) -> None:
        if self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError(
                "A sanctioned application marking must belong to the same management station as "
                "its enforcement point.")


class SaasUrlFilteringPosture(ProvenancedMixin, SyncTrackedModel):
    """What one enforcement point's URL Filtering profiles do for SaaS. PAN-SAS-002 and 004.

    Two questions off one object: whether any reachable profile inserts a tenant-restriction
    header into traffic a rule of this partition actually carries, and how the partition treats
    the web categories that carry consumer file storage and personal publishing.

    NO PROFILE ROW EXISTS TO HANG THIS ON, which is why the grain is the partition. The parent
    object belongs to another domain's subject and
    `normalization/security_profiles.py::PROFILE_KINDS` holds four kinds without `url-filtering`,
    so normalization writes no url-filtering profile row at all today - the collector already has
    the content and the registry drops it. Adding that kind is the url-filtering domain's decision
    and not this one's; this model reads the payload directly.

    THE REACHABLE SET SPANS FOUR PLACES AND MISSING ONE IS SILENT. A profile reachable from a
    partition may sit in the partition's own container, in the FIREWALL's own shared namespace,
    or be pushed from Panorama Shared or a device group - and the pushed half is invisible to the
    read a collector naturally reaches for. Measured 2026-10-29 on fw-core-tpa-b: the device-wide
    `show config pushed-shared-policy` reply carries no `profiles` key at all, while the per-vsys
    reply and the `/config/panorama/vsys/entry/profiles` read each carry two pushed url-filtering
    profiles for the same vsys. A derivation resting on the device-wide op read alone reports
    every pushed profile in this estate as absent.
    """

    #: `consumer_storage_category_treatment`, weakest first. The five after the sentinel are the
    #: url-filtering profile's own per-action list names; `in-no-restricting-list` is this
    #: pipeline's token for a state the configuration NEVER WRITES, because a predefined category
    #: explicitly set to permit is not stored - so the reading is an enumeration over the category
    #: namespace rather than a membership test over the stored members.
    TREATMENT_IN_NO_RESTRICTING_LIST = "in-no-restricting-list"
    TREATMENT_ALLOW = "allow"
    TREATMENT_ALERT = "alert"
    TREATMENT_CONTINUE = "continue"
    TREATMENT_OVERRIDE = "override"
    TREATMENT_BLOCK = "block"
    #: Ordered weakest to strongest. WALK THIS; do not sort, and do not write a rank literal -
    #: the column stores the LEAST restrictive treatment any covered category gets, so the order
    #: IS the semantics.
    TREATMENT_ORDER = (
        TREATMENT_IN_NO_RESTRICTING_LIST,
        TREATMENT_ALLOW,
        TREATMENT_ALERT,
        TREATMENT_CONTINUE,
        TREATMENT_OVERRIDE,
        TREATMENT_BLOCK,
    )
    #: The treatments that count as actively restricting - interrupted, held behind a password,
    #: or refused. `alert` is NOT one: the visit happens and is merely recorded.
    RESTRICTING_TREATMENTS = (TREATMENT_CONTINUE, TREATMENT_OVERRIDE, TREATMENT_BLOCK)

    #: Every column. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "url_filtering_profiles_read",
        "header_insertion_type_entry_count",
        "tenant_restriction_in_force",
        "tenant_header_without_value_count",
        "rule_bound_tenant_list_count",
        "consumer_storage_category_treatment",
        "consumer_storage_categories_are_restricted",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE,
        related_name="saas_url_filtering_postures")
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE,
        related_name="saas_url_filtering_postures")
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="saas_url_filtering_postures")

    #: THE MOST IMPORTANT COLUMN HERE, and it exists because of a measured confusion: stage 4
    #: recorded that in the collected payload "no header insertion" and "url-filtering was never
    #: collected" are the SAME absence, so a control firing on the first fires on every estate
    #: until normalization changes. False means nobody looked.
    #:
    #: It cannot, however, tell a partition that genuinely holds no profile from one nobody read -
    #: the computation is existential over the profiles found - and that limit is stage 5's own
    #: declaration implemented as written.
    url_filtering_profiles_read = models.BooleanField(default=False)
    #: The unit of COVERAGE, and the cardinality is measured rather than assumed: a second `type`
    #: entry under one `http-header-insertion` entry is refused with "At most 1 occurrence is
    #: allowed for type/entry", so covering N applications takes N sibling entries and a count of
    #: PROFILES carrying header insertion counts the wrong thing.
    header_insertion_type_entry_count = models.PositiveIntegerField(default=0)
    #: The whole of PAN-SAS-002's first half in one verdict, in the direction that PASSES - so
    #: FALSE is the finding. A three-hop traversal: rule to profile group to profile to header
    #: insertion, resolved across the vsys, the firewall's own shared namespace and the pushed
    #: reads.
    #:
    #: THE DIRECT HOP IS THE ONE THAT WORKS IN THIS LAB AND THE GROUP HOP IS THE ONE THAT DOES
    #: NOT. Measured 2026-10-29: no local `profiles/profile-group` container exists on any of the
    #: three appliances read, and all three pushed profile groups (`default_profile_group`,
    #: `default`, `OutBound-Block`) name no url-filtering member at all - so a derivation joining
    #: rule to profile through a group alone finds nothing, and one joining only directly finds
    #: the single positive case stage 6 built.
    tenant_restriction_in_force = models.BooleanField(default=False)
    #: Headers that name a header and carry no value - a tenant restriction naming no tenant,
    #: which reads as configured and restricts nothing. A SECOND defect WITHIN a configuration
    #: that exists: nothing fires on this column alone, so a zero on a partition nobody walked
    #: means nothing and `url_filtering_profiles_read` is what says so.
    #:
    #: The stored header NAME cannot be trusted to be one of the vendor's two: stage 4 wrote
    #: `X-Oep-Not-A-Header` under the Office365 type, the device ACCEPTED it and a candidate
    #: carrying it committed. So the derivation reads the stored string rather than the schema.
    tenant_header_without_value_count = models.PositiveIntegerField(default=0)
    #: How many rules of this partition reference a SaaS Tenant List - the native route the
    #: control prefers where it is supported. ZERO DOES NOT FIRE: the object is created when a
    #: SaaS Security Inline recommendation is imported and no appliance in this lab holds the
    #: subscription, so absence is expected rather than a finding.
    #:
    #: The REFERENCE and not the member count, because the member count has no row to come from:
    #: nothing normalises `profiles/saas-tenant-list`, and a bare entry carrying no `list` child
    #: commits - so a rule can reference a tenant list that restricts nothing. The keyword `any`
    #: is not an object and is not counted; measured on both PA-VMs, where unrelated rules carry
    #: `saas-tenant-list` member `any`.
    rule_bound_tenant_list_count = models.PositiveIntegerField(default=0)
    #: One of TREATMENT_ORDER - the LEAST restrictive treatment any covered category gets. The
    #: firing value must be the explicit migration default: a CharField migrated empty would match
    #: no placement and the control would report nothing on every partition in the estate until
    #: the recompute ran.
    consumer_storage_category_treatment = models.CharField(
        max_length=32, default=TREATMENT_IN_NO_RESTRICTING_LIST)
    #: PAN-SAS-004's verdict, in the direction that passes, so FALSE is the finding. Kept as its
    #: own column rather than left to the query because the failing side is THREE of six values
    #: and a clause list is one conjunction with no `or`.
    consumer_storage_categories_are_restricted = models.BooleanField(default=False)

    class Meta:
        ordering = ["enforcement_point", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point"],
                name="integrations_unique_saas_url_filtering_posture_per_point"),
        ]
        indexes = [
            models.Index(fields=["enforcement_point"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["tenant_restriction_in_force"]),
            models.Index(fields=["consumer_storage_category_treatment"]),
            models.Index(fields=["consumer_storage_categories_are_restricted"]),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} SaaS URL filtering posture"

    def clean(self) -> None:
        if self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError(
                "A SaaS URL filtering posture must belong to the same management station as its "
                "enforcement point.")


class SaasApplicationPolicyPosture(ProvenancedMixin, SyncTrackedModel):
    """What one enforcement point's application policy does about SaaS. PAN-SAS-003 and 004.

    Two questions off two objects: whether the upload, sharing and delete FUNCTIONS of permitted
    applications are refused, and whether the partition selects cloud applications by ATTRIBUTE
    rather than one name at a time.

    THE POPULATION FOR THE FIRST QUESTION COMES FROM THE PREDEFINED CATALOGUE, and without it the
    two function columns hold their firing defaults. Measured 2026-10-29 at
    `/config/predefined/application` on three appliances: `dropbox-uploading` and
    `dropbox-downloading` carry `application-container: dropbox` and `use-applications/member:
    [dropbox-base]` and NO `parent-app` leaf, while `dropbox-delete` carries `parent-app:
    dropbox-base` as well - so `parent-app` alone identifies a function child on one of the three
    and the relation has to be read as "names, in `use-applications` or `parent-app`, another
    entry sharing its `application-container`". `dropbox-base` itself carries the same container
    and names only `ssl`, `web-browsing`, `google-base` and `grpc`, none of which is in that
    container, which is what keeps the base application out of the population.

    `deny` IS NOT THE ONLY REFUSAL. The `action` leaf's value set is six, measured identically on
    all four lab appliances with `@default='yes'` on `allow`, and `drop`, `reset-client`,
    `reset-server` and `reset-both` are all denials in this control's sense while none of them is
    the string `deny` the catalogue's own set command writes. A query matching the literal `deny`
    reports a compliant partition as failing.
    """

    #: `effective_action_for_function_apps`. The six are the `action` leaf's measured value set;
    #: `no-rule` is the SENTINEL for a partition whose rulebase names no function child
    #: application at all, which is the state every appliance in this lab was in before stage 6
    #: wrote six rules, and which sorts as benign on any equality against `allow`.
    ACTION_NO_RULE = "no-rule"
    ACTION_ALLOW = "allow"
    ACTION_DENY = "deny"
    ACTION_DROP = "drop"
    ACTION_RESET_CLIENT = "reset-client"
    ACTION_RESET_SERVER = "reset-server"
    ACTION_RESET_BOTH = "reset-both"
    #: The five that REFUSE. Membership of this tuple is the whole of "is the function refused",
    #: and it is five rather than one for the reason in the class docstring.
    REFUSING_ACTIONS = (
        ACTION_DENY, ACTION_DROP, ACTION_RESET_CLIENT, ACTION_RESET_SERVER, ACTION_RESET_BOTH)
    #: Weakest first, for the reduction to the LEAST restrictive first-match action. The sentinel
    #: sits at the weak end with `allow`, because a function nothing names is permitted exactly as
    #: a function a rule allows is - the count beside the column is what tells the two apart.
    ACTION_ORDER = (
        ACTION_NO_RULE, ACTION_ALLOW, ACTION_DENY, ACTION_DROP,
        ACTION_RESET_CLIENT, ACTION_RESET_SERVER, ACTION_RESET_BOTH)

    #: Every column. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "function_app_rule_count",
        "function_apps_are_refused",
        "effective_action_for_function_apps",
        "cloud_app_filter_count",
        "cloud_app_selection_is_refused",
        "cloud_app_selection_excludes_approved",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE,
        related_name="saas_application_policy_postures")
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE,
        related_name="saas_application_policy_postures")
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="saas_application_policy_postures")

    #: How many rules of the MERGED rulebase - local, pushed pre and pushed post together - name
    #: at least one function child application. Zero does not fire on its own; it is what tells
    #: "no rule names them" from "a rule names them and permits them", which the verdict column
    #: beside it reports as the same false.
    function_app_rule_count = models.PositiveIntegerField(default=0)
    #: PAN-SAS-003's verdict, in the direction that passes, so FALSE is the finding - and false is
    #: also what a rulebase naming none of them holds. The assertion is a RELATION BETWEEN TWO
    #: RULES, a deny on the function child evaluated before an allow on the base application, and
    #: rule order is positional rather than a column.
    function_apps_are_refused = models.BooleanField(default=False)
    #: One of ACTION_ORDER - the least restrictive first-match action across every function child
    #: application named in this partition. The sentinel is the explicit migration default for the
    #: same reason as the treatment column above.
    effective_action_for_function_apps = models.CharField(
        max_length=16, default=ACTION_NO_RULE)
    #: How many application filters reachable from this partition select cloud applications by
    #: ATTRIBUTE. Three criteria carry that claim and not one - the cloud-service boolean, a
    #: storage or file-sharing subcategory, and the file-transfer boolean - so the test is a
    #: disjunction and a later stage reading which criterion was used must not look for one path.
    #:
    #: An absent `is-saas` is a DON'T-CARE and not a boolean false: the leaf accepts exactly one
    #: value, `yes`, and refuses `no`. A normaliser mapping it to a boolean defaulting to false
    #: would have every filter in an estate deliberately excluding SaaS applications.
    cloud_app_filter_count = models.PositiveIntegerField(default=0)
    #: Whether such a selection exists AND a rule names it AND that rule refuses what it selects.
    #: FALSE is the finding. The traversal is measured as half-blind downstream:
    #: `SecurityRuleApplication` stores a bare member string and nothing resolves it, so a rule
    #: naming a filter cannot be told from one naming an application of the same name - which is
    #: why this column asserts the selection's EXISTENCE and USE rather than its contents.
    cloud_app_selection_is_refused = models.BooleanField(default=False)
    #: Whether EVERY such selection carves the organisation's own approved applications out, by
    #: naming them in `exclude` or by selecting on the approval marking. FALSE is the finding, and
    #: false is what a partition with no qualifying filter holds too: stage 5's declared default
    #: is the firing side, so an empty population is NOT treated as vacuously true.
    #:
    #: An absent `tagging` means the filter does not select on the marking AT ALL and is NOT
    #: equivalent to its `no-tag` branch. Collapsing the two reports a filter that catches
    #: unmarked applications where the configuration catches everything.
    cloud_app_selection_excludes_approved = models.BooleanField(default=False)

    class Meta:
        ordering = ["enforcement_point", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point"],
                name="integrations_unique_saas_app_policy_posture_per_point"),
        ]
        indexes = [
            models.Index(fields=["enforcement_point"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["function_apps_are_refused"]),
            models.Index(fields=["effective_action_for_function_apps"]),
            models.Index(fields=["cloud_app_selection_is_refused"]),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} SaaS application policy posture"

    def clean(self) -> None:
        if self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError(
                "A SaaS application policy posture must belong to the same management station as "
                "its enforcement point.")


class CloudAppEngineSetting(ProvenancedMixin, SyncTrackedModel):
    """One appliance's App-ID Cloud Engine - switched off in configuration, and not running.

    PAN-SAS-005, and the premise PAN-SAS-003 and PAN-SAS-004 rest on. TWO FINDINGS FROM ONE NODE
    THAT POINT OPPOSITE WAYS ON THIS ESTATE: the configuration says the engine is not disabled,
    and the engine itself reports that it is not working. Measured on three appliances
    2026-10-29 - `show cloud-appid connection-to-cloud` answers "ACE Error: License check failed"
    with "Cloud connection: failed" and "Device cert status: Not installed, Invalid or Not pushed
    to daemons" on every one of them.

    ONE ROW PER APPLIANCE, because `deviceconfig/setting/cloudapp` is a device-wide singleton with
    no entry name and no vsys. On an HA pair the setting is synchronised and this produces two
    rows for one real configuration, which nothing downstream deduplicates - and here that
    prediction IS right, unlike the vsys-scoped models above, because a device-wide setting takes
    an appliance directly.

    `identity.row_is` SAYS `one_entry_of_the_object` AND THAT IS NOT TRUE OF THIS NODE. Stage 5
    said so itself: the member vocabulary offers an entry of a collection or a verdict over
    entries, and a singleton settings node is neither. A `singleton_node` member is what would
    fit. Nothing here depends on the answer; the note exists so a reader comparing this model
    against the declaration is not left to guess which side is wrong.

    THE DEVICE CERTIFICATE IS A SECOND PRECONDITION AND IT IS NOT IN `request license info` AT
    ALL, so a remediation reading only the licence would buy a subscription and still have no
    engine. That is why the reason column exists beside the verdict.
    """

    #: `ace_failure_reason`. THIS VOCABULARY IS THE PIPELINE'S OWN, not the device's: the
    #: underlying conditions are measured, but the command's reply is free text whose wording
    #: moves with the build - 11.1.13-h3 says "Check if SaaS license is installed and active"
    #: where 11.2 says "Check if SaaS license or Ai Access license is installed and active",
    #: measured on one appliance of each the same day.
    REASON_LICENSE_CHECK_FAILED = "license_check_failed"
    REASON_DEVICE_CERTIFICATE_MISSING = "device_certificate_missing"
    REASON_CLOUD_CONNECTION_FAILED = "cloud_connection_failed"
    REASON_DISABLED_BY_CONFIGURATION = "disabled_by_configuration"
    REASON_HEALTHY = "healthy"
    #: The command was never issued, or its reply carried no recognisable ACE marker. A REAL
    #: TOKEN rather than null, deliberately: the applicability clause on PAN-SAS-005 is a negated
    #: equality, and a text column defaulting to the empty string makes a negated equality fire
    #: for free.
    REASON_UNREAD = "unread"
    #: The order the conditions are tested in. The licence first because it is the condition every
    #: other one fails behind, and the configured disable last because it is the only one that is
    #: not in the operational reply.
    REASON_ORDER = (
        REASON_LICENSE_CHECK_FAILED,
        REASON_DEVICE_CERTIFICATE_MISSING,
        REASON_CLOUD_CONNECTION_FAILED,
        REASON_DISABLED_BY_CONFIGURATION,
    )

    #: The three computed columns. `ace_disabled` and `cloudapp_server_address` are NOT here -
    #: they are measured keys and carry real provenance rows, which is the whole reason this
    #: subject stores provenance while the three verdict models above store none.
    #:
    #: `ace_not_operational` and `ace_failure_reason` come from an OPERATIONAL reply, which
    #: `ProvenanceType` has no member for: its fallthrough for an unmarked present value is
    #: `local`, "defined on this device", which is the one thing such a value is not. Declaring
    #: them derived is the shipped convention - `LoggingSettings` does the same for its runtime
    #: columns - and it is accurate about the only thing a reader must not get wrong, that the
    #: value did not come from the configuration.
    DERIVED_FIELDS = (
        "is_missing",
        "cloudapp_node_read",
        "ace_not_operational",
        "ace_failure_reason",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE, related_name="cloud_app_engine_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="cloud_app_engine_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="cloud_app_engine_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="cloud_app_engine_settings")

    #: The vendor's own `disable` key with the vendor's own POLARITY - true means somebody
    #: switched the engine off on purpose, which is the permissive state for every control that
    #: depends on it. NOT INVERTED: the column keeps the key as the device spells it and the query
    #: decides what it means.
    #:
    #: NULLABLE, in exactly one state: the merged snapshot carried no `deviceconfig/setting`
    #: subtree, so the key is neither present nor absent but UNREAD. That is different from the
    #: absent key, where the assumed default below puts `false` in the column with a provenance
    #: row saying it was assumed. `cloudapp_node_read` is what a control reads instead of scoring
    #: the null as a value, and nothing in this domain clauses on this column.
    #:
    #: The implicit `false` is AN INFERENCE AND NOT A VENDOR FACT - the key's negated spelling,
    #: the vendor's checkbox polarity and the device's own help string "prevent icd from
    #: automatically fetching cloud app data" are all leads. Stage 4 declined to licence it as a
    #: measurement and recorded why it cannot be measured on this estate at all: no positive
    #: control can move the operational oracle while the licence check fails on every appliance.
    ace_disabled = models.BooleanField(default=False, null=True, blank=True)
    #: Whether the merged snapshot carried the `deviceconfig/setting` subtree at all. It is the
    #: answer to "is this unknown", which the query language has no operator for.
    cloudapp_node_read = models.BooleanField(default=False)
    #: Whether the engine is NOT working, for any reason - no subscription, no device certificate,
    #: no cloud connection, or a configured disable - in the direction that fires, so TRUE is the
    #: finding. TRUE until a pass asks the engine: an appliance nobody asked has no working engine
    #: anybody established, and the configuration half of this node reads reassuringly on every
    #: appliance in this lab.
    ace_not_operational = models.BooleanField(default=True)
    #: Which condition is stopping it, so a finding can name the remediation rather than only the
    #: symptom. One of the REASON_* values.
    ace_failure_reason = models.CharField(max_length=48, default=REASON_UNREAD)
    #: The cloud endpoint override, where one is written. STORES NOTHING for the absent key -
    #: stage 4 recorded the implicit as unmeasured with `not_assumed` and its reading of the
    #: absence rests on the key's name and position rather than on any measurement, and nothing in
    #: this domain asserts it, so a wrong value would be worse than no value. Null and not the
    #: empty string for that reason, and `not_searchable`.
    #:
    #: A COLUMN NO CONTROL ASSERTS, declared because it is the OTHER child of a two-child
    #: singleton: a model holding one child and not the other reads as a measurement nobody took
    #: rather than as a decision.
    cloudapp_server_address = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        ordering = ["appliance", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="integrations_unique_cloud_app_engine_setting_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance"]),
            models.Index(fields=["management_station"]),
            models.Index(fields=["ace_not_operational"]),
            models.Index(fields=["ace_failure_reason"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} App-ID Cloud Engine"

    def clean(self) -> None:
        if self.appliance.management_station_id != self.management_station_id:
            raise ValidationError(
                "A cloud app engine setting must belong to the same management station as its "
                "appliance.")
