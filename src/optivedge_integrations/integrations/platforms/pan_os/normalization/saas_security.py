"""Normalization for the `saas-security` domain. PAN-SAS-001 to 005.

Four models, two entry points:

    normalize_saas_security(enforcement_point)   the three vsys-scoped verdicts, in one pass
    normalize_cloud_app_engine(appliance)        the device-wide App-ID Cloud Engine row

THE THREE VERDICTS SHARE ONE PASS because they share one payload parse. The rulebase is read by
two of them, the url-filtering container by two, the vsys roster by one, and every one of them has
to union the firewall's own content with the PUSHED content for the same enforcement point. Three
passes would be three walks of a 1.4 MB merged config and three chances for them to disagree about
what one collection contained.

THE REACHABLE SET IS FOUR PLACES AND SKIPPING ONE IS SILENT, which is the one thing to get right
here. For a vsys-scoped object - a url-filtering profile, an application filter, a saas-tenant-list
- the definitions in force are the partition's own, the FIREWALL's own `/config/shared`, and
whatever Panorama pushed from Shared or from a device group. Measured 2026-10-29 on fw-core-tpa-b:

    show config pushed-shared-policy                  no `profiles` key at all
    show config pushed-shared-policy <vsys>vsys1      profiles/url-filtering, 2 entries
    config get /config/panorama/vsys/.../profiles     the same 2 entries

so a derivation resting on the device-wide op read reports every pushed url-filtering profile in
this estate as absent, with no error. `collectors/pushed_profiles.py` already records the
PLATFORM half of that asymmetry; this is the per-vsys half of the same reading.

TWO PAYLOAD SHAPES THAT BREAK A NAIVE READER, both measured here the same day:

- A PUSHED rule's `action` is a DICT and not a string: measured on all three appliances read, a
  pushed pre-rule carries `{'@loc': <scope>, '#text': <the action>}`. So `rule.get("action")` is
  not the action and a comparison against a literal is false for every pushed rule on every
  appliance - silently, with no error, so a verdict that ranks rules simply never sees a pushed
  one. `security_profiles.py::rule_action` is the shipped reader and is imported here.
- A CANDIDATE-DERIVED member arrives decorated: stage 4 measured a staged `tag` member as
  `{'#text': 'Sanctioned', '@admin': ..., '@dirtyId': ...}` and a committed one as a bare string.
  `iter_member_values` already handles both; a `str(member)` loop loses every staged value.

A DISABLED RULE COUNTS, EVERYWHERE HERE, AND THE MODEL DOCSTRING SAYS WHY AND WHY IT IS PROBABLY
WRONG. Do not "fix" it in this module alone - `models/saas_security.py`'s class docstring and the
stage 7 artifact's `spec_gaps` carry the reasoning, and the sixteen lab subjects this domain was
graded against are all disabled rules.
"""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    CloudAppEngineSetting,
    EnforcementPoint,
    SaasApplicationPolicyPosture,
    SaasUrlFilteringPosture,
    SanctionedApplicationMarking,
    Snapshot,
)
from optivedge_integrations.integrations.models.provenance import FieldProvenance
from optivedge_integrations.integrations.models.saas_security import (
    CONSUMER_STORAGE_CATEGORIES,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.cloud_appid import (
    CLOUD_APPID_CONNECTION_SOURCE_TYPE,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.predefined import (
    PREDEFINED_APPLICATION_SOURCE_TYPE,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    Implicit,
    ensure_list,
    entry_container,
    iter_member_values,
    merged_shared,
    merged_vsys_entry,
    parse_text_field,
    parse_yes_no_field,
    pushed_shared,
    pushed_vsys_panorama,
    pushed_vsys_profiles,
    scalar_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot as latest_appliance_merged_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.security_profiles import (
    # THE SHIPPED READER FOR A RULE'S ACTION, and it already covers both shapes this domain
    # meets. Reused rather than rewritten: measured on three appliances 2026-10-29, a rule in the
    # firewall's own rulebase carries `action` as a plain string while a PUSHED rule carries
    # `{"@loc": ..., "#text": ...}`, so a literal comparison is false for every pushed rule - and
    # this helper additionally handles the CHOICE form (`{"reset-both": None}`) that a security
    # PROFILE's rules use and a security rule does not. A private copy here would have been one
    # more reader of the same leaf with one fewer shape covered.
    rule_action,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    write_node_row,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    is_panorama_managed,
    latest_merged_snapshot,
    latest_pushed_shared_snapshot,
    latest_pushed_vsys_profiles_snapshot,
    latest_pushed_vsys_snapshot,
)


#: The one predefined tag the firewall reads as an approval marking. Stage 4 measured the
#: predefined tag namespace and one of its members is literally named `empty`, with a @vxpath of
#: /config/predefined/tag/entry[@name='empty'] - so a reader treating the string `empty` as an
#: absence stores a real marking as no marking. Compare against this constant and nothing else.
SANCTIONED_TAG = "Sanctioned"

#: The keyword a member list uses for "anything", which is not the name of an object. Measured on
#: both lab PA-VMs: unrelated rules carry `saas-tenant-list` member `any` and `category` member
#: `any`, so a count of rules "naming an object" has to exclude it or every rule counts.
ANY_KEYWORD = "any"

#: The per-action category lists on a url-filtering profile that this domain reads, weakest first.
#: `block-reply` and `isolate` are DELIBERATELY ABSENT: a category reachable only through one of
#: those is restricted in fact and would reduce to a weaker token than the truth, which is the
#: wrong direction - but `isolate` is 11.2-only, absent from the CLI grammar and offered in no
#: dropdown, and stage 3 flagged both as unplaced with no value set measured. Settling them needs
#: a device read this stage's input does not carry; recorded in the artifact's `spec_gaps`.
CATEGORY_LIST_NAMES = ("allow", "alert", "continue", "override", "block")

#: The `type` entry names the vendor ships that insert a TENANT RESTRICTION - an identifier saying
#: which corporate account of a SaaS service a request may reach. Stage 4 measured six type names
#: at `type/entry/@name`, identically on all four appliances across both builds: these three plus
#: `Youtube Safe Search`, `Custom` and `Dynamic Fields`. Safe Search is not a tenant restriction;
#: the other two are operator-defined, so they are matched on the HEADER NAME below instead.
#:
#: THIS SET IS THIS STAGE'S OWN and stage 5 declared none - recorded in the artifact's
#: `spec_gaps`. What would close it is a measured value set on stage 5's own declaration saying
#: which of the six type entries carry a tenant restriction.
TENANT_RESTRICTION_TYPE_NAMES = frozenset({
    "Microsoft Office365 Tenant Restrictions",
    "Dropbox Network Control",
    "Google Apps Access Control",
})

#: Header names that carry a tenant restriction under an operator-defined type. Stage 4 measured
#: that under the Office365 type the device offers exactly two names and under `Custom` it offers
#: NONE - so the value set is a function of the parent entry's key - and that THE ENUM IS NOT
#: ENFORCED AT EITHER GATE: `X-Oep-Not-A-Header` was accepted at the write under the Office365
#: type and a candidate carrying it COMMITTED. So a stored header name may be anything, and this
#: set widens the type test rather than narrowing it.
TENANT_RESTRICTION_HEADER_NAMES = frozenset({
    "Restrict-Access-To-Tenants",
    "Restrict-Access-Context",
    "X-Dropbox-allowed-Team-Ids",
    "X-GooGApps-Allowed-Domains",
})

#: The vendor's own CHARACTERISTIC tags that mark an App-ID as a FUNCTION of another application.
#: Measured 2026-10-29 over one appliance's whole catalogue, which is the only place this
#: vocabulary exists: `[Uploading]` 257 entries, `[Downloading]` 153, `[Posting]` 115,
#: `[Deleting]` 109, `[Editing]` 92, `[Sharing]` 83 - against `[Web App]` on 3,065 and
#: `[Generative AI]` on 537, neither of which is a function. The square brackets are the vendor's
#: and are part of the stored member value.
#:
#: THESE ARE NOT THE OPERATOR'S MARKINGS. The same `tag` key on an `application-tag` entry holds
#: the approval marking PAN-SAS-001 counts, and the Objects > Applications grid renders both in
#: one column - which is the measured confusion that control exists to avoid. These are read off
#: /config/predefined/application and never off a vsys.
#:
#: THIS SET IS THIS STAGE'S OWN; stage 5 declared no value set for it, and nothing says whether
#: `[Editing]` and `[Posting]` are in the control's sense of "function". Stage 3 names upload,
#: sharing and delete; all six are included because excluding a function tag would let a rule
#: that PERMITS an editing or posting function pass unexamined. Recorded in the artifact's
#: `spec_gaps`.
FUNCTION_TAGS = frozenset({
    "[Uploading]", "[Downloading]", "[Posting]", "[Deleting]", "[Editing]", "[Sharing]",
})

#: The application-filter criteria that make a selection an ATTRIBUTE-DRIVEN selection of cloud
#: applications. Three carry the claim and not one, which is why the test below is a disjunction:
#: stage 4 measured a boolean marking an application as a cloud service, the application
#: subcategory collection (62 values, including both a storage and a file-sharing member), and a
#: boolean for whether the application transfers files.
CLOUD_APP_FILTER_SUBCATEGORIES = frozenset({"file-sharing", "storage-backup"})

#: The implicit for `deviceconfig/setting/cloudapp/disable`. AN INFERENCE AND NOT A VENDOR FACT,
#: which is why it is `assumed` and renders as not measured: the key's negated spelling, the
#: vendor's own checkbox polarity at help p.796 ("Deselect this checkbox to enable ACE or select
#: this checkbox to disable ACE") and the device's help string "prevent icd from automatically
#: fetching cloud app data" are three leads and no measurement. Stage 4 declined to licence it and
#: recorded why it cannot be measured on this estate at all: no positive control can move the
#: operational oracle while the licence check fails on every appliance. The Help has been wrong in
#: this estate before - `disable-http` is documented implicit `no` and measures `yes`.
ACE_DISABLE_ABSENT = Implicit.assumed(
    False,
    "the key is spelled as a negation and the vendor's own checkbox polarity (help p.796, "
    "'Deselect this checkbox to enable ACE or select this checkbox to disable ACE') reads the "
    "absence as the engine not being deliberately switched off. Stage 4 declined to licence this "
    "as a measurement: the bar needs a rendering or a behaviour separating 'the engine is on' "
    "from 'the key is not set', and no positive control can move the operational oracle while "
    "the licence check fails on all four lab appliances",
)

#: The implicit for `cloudapp-srvr-addr/address`. STORES NOTHING. Stage 4 recorded the implicit as
#: unmeasured with `not_assumed` and did not probe it - its reading of the absence, that the
#: firewall uses the vendor's own endpoint, rests on the key's name and its position under a
#: server-address container rather than on any measurement - and nothing in this domain asserts
#: it, so a wrong value would be worse than no value.
ACE_SERVER_ADDRESS_ABSENT = Implicit.not_assumed(
    "stage 4 recorded this implicit as unmeasured with not_assumed and did not probe it; its "
    "reading of the absence rests on the key's name and its position under a server-address "
    "container rather than on any measurement, and nothing in this domain asserts the column"
)


# ---------------------------------------------------------------------------
# Snapshot readers
# ---------------------------------------------------------------------------

def latest_cloud_appid_connection_snapshot(appliance: Appliance) -> Snapshot | None:
    """The newest `show cloud-appid connection-to-cloud` reply for one appliance, or None.

    Its own reader because nothing maps a source type to one: the normalizer that wants a
    snapshot writes this, which is why the source type is a constant beside the command.
    """
    return (
        Snapshot.objects.filter(
            appliance=appliance, source_type=CLOUD_APPID_CONNECTION_SOURCE_TYPE)
        .order_by("-collected_at", "-pk")
        .first()
    )


def latest_predefined_application_snapshot(appliance: Appliance) -> Snapshot | None:
    """The newest `/config/predefined/application` read for one appliance, or None.

    Per appliance and not per enforcement point: the catalogue is appliance-wide, and the entry
    count differs by appliance in this estate because it arrives with content updates.
    """
    return (
        Snapshot.objects.filter(
            appliance=appliance, source_type=PREDEFINED_APPLICATION_SOURCE_TYPE)
        .order_by("-collected_at", "-pk")
        .first()
    )


# ---------------------------------------------------------------------------
# Pure readers over the payloads — provable without a device read
# ---------------------------------------------------------------------------

def merged_vsys_roster(payload: dict[str, Any]) -> list[str]:
    """Every vsys name the MERGED read reports for the appliance, in the payload's order.

    THE MERGED VIEW AND NOT `action=show`, deliberately: measured on both PA-5220s, `action=get`
    answers NINE vsys where `action=show` answers eight, the ninth being an entry a template
    supplies whole. A roster taken from the narrower view reports a nine-partition appliance as an
    eight-partition one, and `appliance_is_multi_vsys` is a count over this list.
    """
    config = payload.get("config")
    if not isinstance(config, dict):
        return []
    devices = config.get("devices")
    if not isinstance(devices, dict):
        return []
    device_entries = [e for e in ensure_list(devices.get("entry")) if isinstance(e, dict)]
    if not device_entries:
        return []
    vsys = device_entries[0].get("vsys")
    if not isinstance(vsys, dict):
        return []
    return [str(e.get("@name") or "") for e in ensure_list(vsys.get("entry"))
            if isinstance(e, dict) and e.get("@name")]


def sanctioned_applications(node: Any) -> list[str]:
    """The application names one `application-tag` container marks with the approval tag.

    A COUNT OVER MEMBERS AND NOT A TRUTHINESS TEST ON THE CONTAINER. The lab holds the case that
    separates them: vsys2 of fw-core-tpa-b has a POPULATED container whose single entry carries no
    `tag` child at all, so the collection is non-empty and the marked set is empty.

    `iter_member_values` and not a `str(member)` loop, because a candidate-derived member arrives
    as `{'#text': 'Sanctioned', '@admin': ..., '@dirtyId': ...}` and stringifying that loses the
    value entirely.
    """
    _, entries = entry_container(node, "application-tag")
    marked: list[str] = []
    for entry in entries:
        name = str(entry.get("@name") or "")
        if not name:
            continue
        tags = {value for value, _ in iter_member_values(entry.get("tag"))}
        if SANCTIONED_TAG in tags:
            marked.append(name)
    return marked


def application_tag_names(node: Any) -> list[str]:
    """Every application NAMED in one `application-tag` container, marked or not.

    The union this list contributes to is what makes the cross-partition comparison right: stage 4
    measured that the commonest form of the inconsistency is an application present in one vsys's
    collection and ABSENT from another's, so a comparison ranging over the rows that exist misses
    it.
    """
    _, entries = entry_container(node, "application-tag")
    return [str(e.get("@name") or "") for e in entries if e.get("@name")]


def security_rules(node: Any) -> list[dict[str, Any]]:
    """One partition's own security rules, from the merged read's `rulebase/security/rules`."""
    _, entries = entry_container(node, "rulebase", "security", "rules")
    return entries


def pushed_security_rules(panorama: dict[str, Any]) -> tuple[list[dict[str, Any]],
                                                             list[dict[str, Any]]]:
    """(pre, post) security rules from a pushed-policy `panorama` subtree.

    `rulebase` IS NOT A KEY IN THE PUSHED REPLY. Its root is `policy`, the subtree is `panorama`
    and the children are `pre-rulebase` and `post-rulebase` - so a walk written for the merged
    spelling finds nothing here and finds it silently, which for a verdict about an absence
    manufactures a wrong finding. BOTH have to be read: a vsys evaluates pre-rules before its own
    and post-rules after.
    """
    pre: list[dict[str, Any]] = []
    post: list[dict[str, Any]] = []
    for key, sink in (("pre-rulebase", pre), ("post-rulebase", post)):
        branch = panorama.get(key)
        if isinstance(branch, dict):
            sink.extend(entry_container(branch, "security", "rules")[1])
    return pre, post


def rule_members(rule: dict[str, Any], key: str) -> list[str]:
    """One rule's member list for `key`, with the `any` keyword kept - callers drop it."""
    return [value for value, _ in iter_member_values(rule.get(key))]


def url_filtering_profiles(scopes: list[tuple[str, dict[str, Any]]]) -> list[tuple[str, str,
                                                                                  dict[str, Any]]]:
    """(scope_label, profile_name, entry) for every url-filtering profile in the given scopes.

    `scopes` is the caller's reachable set - the partition, the firewall's own shared namespace,
    and the pushed roots - built by `reachable_scopes` so that only one place decides what
    "reachable" means. Deduplicated by (scope, name) and NOT across scopes: the same name at two
    scopes is a legitimate override pair and collapsing it would discard the losing definition.
    """
    found: list[tuple[str, str, dict[str, Any]]] = []
    seen: set[tuple[str, str]] = set()
    for label, node in scopes:
        _, entries = entry_container(node, "profiles", "url-filtering")
        for entry in entries:
            name = str(entry.get("@name") or "")
            if (label, name) in seen:
                continue
            seen.add((label, name))
            found.append((label, name, entry))
    return found


def application_filters(scopes: list[tuple[str, dict[str, Any]]]) -> list[tuple[str, str,
                                                                                dict[str, Any]]]:
    """(scope_label, filter_name, entry) for every application filter in the given scopes."""
    found: list[tuple[str, str, dict[str, Any]]] = []
    seen: set[tuple[str, str]] = set()
    for label, node in scopes:
        _, entries = entry_container(node, "application-filter")
        for entry in entries:
            name = str(entry.get("@name") or "")
            if (label, name) in seen:
                continue
            seen.add((label, name))
            found.append((label, name, entry))
    return found


def profile_group_url_filtering(scopes: list[tuple[str, dict[str, Any]]]) -> dict[str, set[str]]:
    """group name -> the url-filtering profile names it binds, over every reachable scope.

    THE GROUP HOP, and in this estate it resolves to nothing: measured 2026-10-29, no appliance
    read has a local `profiles/profile-group` container at all, and all three pushed groups -
    `default_profile_group`, `default` and `OutBound-Block`, each @loc=shared - name only virus,
    data-filtering, file-blocking and vulnerability members. So every rule that carries a profile
    GROUP reaches no url-filtering profile through it, which is the measured reason the direct hop
    below cannot be dropped in favour of the group one.

    Both local `profiles/profile-group` and the pushed reply's top-level `profile-group` are read,
    because the two spell it at different depths.
    """
    bound: dict[str, set[str]] = {}
    for _, node in scopes:
        for path in (("profiles", "profile-group"), ("profile-group",)):
            _, entries = entry_container(node, *path)
            for entry in entries:
                name = str(entry.get("@name") or "")
                if not name:
                    continue
                members = {v for v, _ in iter_member_values(entry.get("url-filtering"))}
                bound.setdefault(name, set()).update(m for m in members if m)
    return bound


def rule_reachable_url_filtering_profiles(
    rules: list[dict[str, Any]],
    groups: dict[str, set[str]],
) -> set[str]:
    """Every url-filtering profile name any of these rules puts on the traffic.

    TWO HOPS AND BOTH ARE NEEDED. `profile-setting` is a CHOICE node: a rule names individual
    profiles or one group, never both. The direct arm is
    `profile-setting/profiles/url-filtering/member` and the group arm is
    `profile-setting/group/member`, resolved through `groups`.

    DISABLED RULES ARE INCLUDED - see the module docstring. The single positive case in this lab
    is a rule written `disabled: yes`.
    """
    reached: set[str] = set()
    for rule in rules:
        setting = rule.get("profile-setting")
        if not isinstance(setting, dict):
            continue
        profiles = setting.get("profiles")
        if isinstance(profiles, dict):
            reached.update(v for v, _ in iter_member_values(profiles.get("url-filtering")) if v)
        for group_name, _ in iter_member_values(setting.get("group")):
            reached.update(groups.get(group_name, set()))
    return reached


def type_entries(profile: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """(http_header_insertion_entry, type_entry) pairs under one url-filtering profile.

    AT MOST ONE TYPE PER INSERTION ENTRY, measured: a second `<entry name='Custom'/>` under one
    `http-header-insertion` entry is refused with code=12 "At most 1 occurrence is allowed for
    type/entry". So the unit of COVERAGE is the type entry, and a count of profiles carrying
    header insertion counts the wrong thing. The loop does not assume the cardinality.
    """
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    _, insertions = entry_container(profile, "http-header-insertion")
    for insertion in insertions:
        _, types = entry_container(insertion, "type")
        for type_entry in types:
            pairs.append((insertion, type_entry))
    return pairs


def type_inserts_tenant_restriction(type_entry: dict[str, Any]) -> bool:
    """Whether one `type` entry inserts a tenant restriction.

    By the entry's own name where the vendor ships a tenant-restriction class, and otherwise by
    the HEADER names it writes - because `Custom` and `Dynamic Fields` are operator-defined and
    the device offers no header names under them at all. The header test reads the stored string
    rather than trusting the schema: the enum is enforced at neither the write nor the commit.
    """
    if str(type_entry.get("@name") or "") in TENANT_RESTRICTION_TYPE_NAMES:
        return True
    for header in entry_container(type_entry, "headers")[1]:
        if str(header.get("header") or "") in TENANT_RESTRICTION_HEADER_NAMES:
            return True
    return False


def category_treatment(
    profiles: list[tuple[str, str, dict[str, Any]]],
    rules: list[dict[str, Any]],
) -> str:
    """The LEAST restrictive treatment any covered category gets, over the whole surface.

    AN ENUMERATION AND NOT A MEMBERSHIP TEST, and that is measured rather than preferred: a
    predefined category explicitly set to permit is NEVER WRITTEN, so the configuration holds five
    member lists and the question is which of the ninety-odd categories appears in none of them. A
    profile naming 29 of 90 and leaving 61 implicit passes a membership test and is exactly the
    configuration this control exists to catch - so a category in no list reduces to the weakest
    rank, which is also the vendor's own default for it (help p.296, all categories Allow).

    TWO REDUCTIONS, both to the WEAK end. Per category, the weakest treatment any reachable
    profile gives it, because a permissive profile that also applies leaves the category
    reachable. Then the weakest across the covered categories, because the control is failed by
    its weakest link.

    A SECURITY RULE CONTRIBUTES through its `category` member list, which stage 5 names as part of
    the restricting surface: a rule naming the category explicitly counts as `block` where its
    action refuses and `allow` otherwise. THE KEYWORD `any` IS NOT A NAMING - measured, most rules
    in this estate carry `category` member `any` - and counting it would let one allow-all rule
    decide the column for every category on the appliance. No lab subject exercises this arm:
    every rule stage 6 left standing was written with no `category` list at all.
    """
    order = SaasUrlFilteringPosture.TREATMENT_ORDER
    weakest = SaasUrlFilteringPosture.TREATMENT_BLOCK
    for category in CONSUMER_STORAGE_CATEGORIES:
        per_category = SaasUrlFilteringPosture.TREATMENT_IN_NO_RESTRICTING_LIST
        found = False
        for _, _, profile in profiles:
            for list_name in CATEGORY_LIST_NAMES:
                if list_name not in profile:
                    continue
                members = {v for v, _ in iter_member_values(profile.get(list_name))}
                if category in members:
                    rank = list_name
                    if not found or order.index(rank) < order.index(per_category):
                        per_category = rank
                        found = True
        for rule in rules:
            members = set(rule_members(rule, "category"))
            if category not in members:
                continue
            rank = (SaasUrlFilteringPosture.TREATMENT_BLOCK
                    if rule_action(rule) in SaasApplicationPolicyPosture.REFUSING_ACTIONS
                    else SaasUrlFilteringPosture.TREATMENT_ALLOW)
            if not found or order.index(rank) < order.index(per_category):
                per_category = rank
                found = True
        if order.index(per_category) < order.index(weakest):
            weakest = per_category
    return weakest


def function_child_applications(payload: Any) -> set[str]:
    """Every App-ID the predefined catalogue records as a FUNCTION CHILD of another application.

    MEASURED 2026-10-29 at /config/predefined/application on three appliances, and TWO OBVIOUS
    MARKERS ARE BOTH WRONG - one silently, one by a factor of forty.

        dropbox-uploading     tag=[Uploading],[Web App]   container=dropbox  use-apps=[dropbox-base]
        dropbox-downloading   tag=[Downloading],[Web App] container=dropbox  use-apps=[dropbox-base]
        dropbox-delete        tag=[Deleting],[Web App]    container=dropbox  use-apps=[dropbox-base]
                                                                             parent-app=dropbox-base
        dropbox-base          tag=[Web App]               container=dropbox  use-apps=[google-base,
                                                                               grpc, ssl, web-browsing]

    `parent-app` IS CARRIED BY ONE OF THE THREE, so a derivation resting on it alone under-counts
    silently: it finds `dropbox-delete` and misses the upload and download functions the control
    is mostly about.

    `application-container` PLUS A SAME-CONTAINER PARENT IS NOT A FUNCTION, and this was found by
    the readback rather than by reading. 2,982 of 5,552 entries carry a container and 2,048 of
    them name a same-container parent, so that test called 37% of the App-ID namespace a function
    child - and on fw-core-tpa-b it counted 26 of vsys1's 33 rules as naming one, against the one
    rule stage 6 built, and reduced the action to `allow` on a partition whose only function rule
    denies. Every ordinary sub-application of a container passes that test.

    WHAT SEPARATES THEM IS THE VENDOR'S OWN FUNCTION TAG, which is also how the Objects >
    Applications grid renders a function as an indented child. Measured on one appliance's
    catalogue: `[Uploading]` 257, `[Downloading]` 153, `[Posting]` 115, `[Deleting]` 109,
    `[Editing]` 92, `[Sharing]` 83, against `[Web App]` 3,065 - and `dropbox-base` carries
    `[Web App]` alone. These are CHARACTERISTIC tags the vendor ships and NOT the operator's
    markings, which is the confusion PAN-SAS-001 exists to avoid in the other direction.

    THE PARENT TEST STAYS, as a conjunction. Stage 5 asks for a function child OF ANOTHER
    APPLICATION, and 44 of the 809 tagged entries on one appliance - `blog-posting`,
    `ameba-blog-posting` and their kind - carry a function tag with no parent in their container
    at all, so they are functions of nothing. Dropping them errs toward FIRING: a deny rule on one
    of them now reduces to the `no-rule` sentinel rather than to `deny`, which reports rather than
    passing.

    THE POPULATION MOVES WITH THE CONTENT RELEASE and is not a property of the estate: 765, 649
    and 772 on the three appliances read the same day. So any count over it is a reading of one
    day's catalogue, and a count of applications whose upload function is refused is a LOWER BOUND
    over a namespace this pipeline has not enumerated.

    AN EMPTY SET WHERE THERE IS NO SNAPSHOT, which makes `function_app_rule_count` zero and
    `function_apps_are_refused` false - both the firing side. No column separates that from a
    rulebase naming no function application; stage 5 declared no companion for it and one invented
    here would sit beyond every check stage 5 makes. Recorded in the artifact's `spec_gaps`, and
    the caller's return value says whether the catalogue was present.
    """
    if not isinstance(payload, dict):
        return set()
    application = payload.get("application")
    if not isinstance(application, dict):
        return set()
    container_of: dict[str, str] = {}
    parents_named: dict[str, set[str]] = {}
    function_tagged: set[str] = set()
    for entry in ensure_list(application.get("entry")):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("@name") or "")
        if not name:
            continue
        container = scalar_value(entry.get("application-container"))[0]
        if container:
            container_of[name] = container
        named = {v for v, _ in iter_member_values(entry.get("use-applications")) if v}
        parent_app = scalar_value(entry.get("parent-app"))[0]
        if parent_app:
            named.add(parent_app)
        parents_named[name] = named
        if {t for t, _ in iter_member_values(entry.get("tag"))} & FUNCTION_TAGS:
            function_tagged.add(name)
    children: set[str] = set()
    for name in function_tagged:
        container = container_of.get(name)
        if not container:
            continue
        for candidate in parents_named.get(name, ()):
            if candidate != name and container_of.get(candidate) == container:
                children.add(name)
                break
    return children


def filter_selects_cloud_applications(entry: dict[str, Any]) -> bool:
    """Whether one application filter selects cloud applications by ATTRIBUTE.

    A DISJUNCTION OF THREE CRITERIA, because stage 4 measured three that carry the claim: the
    cloud-service boolean, a storage or file-sharing subcategory, and the file-transfer boolean.
    A later stage asking WHICH criterion a selection used has to read all three rather than look
    for one path.

    AN ABSENT `is-saas` IS A DON'T-CARE AND NOT A BOOLEAN FALSE. The leaf accepts exactly one
    value, `yes`, and refuses `no` with code=12 - so a normaliser mapping it to a boolean
    defaulting to false would have every filter in an estate deliberately excluding SaaS
    applications. Presence is read, never a parsed boolean.
    """
    if scalar_value(entry.get("is-saas"))[0].lower() == "yes":
        return True
    if scalar_value(entry.get("transfers-files"))[0].lower() == "yes":
        return True
    subcategories = {v for v, _ in iter_member_values(entry.get("subcategory"))}
    return bool(subcategories & CLOUD_APP_FILTER_SUBCATEGORIES)


def filter_excludes_approved(entry: dict[str, Any]) -> bool:
    """Whether one filter carves the organisation's approved applications out of its selection.

    Either by naming members in `exclude`, or by selecting on the approval marking at all.

    AN ABSENT `tagging` MEANS THE FILTER DOES NOT SELECT ON THE MARKING and is NOT equivalent to
    its `no-tag` branch: the two are different selections, and a consumer collapsing them reports
    a filter that catches unmarked applications where the configuration catches everything. So
    presence of the `tagging` node is what is read, not a value inside it.
    """
    if {v for v, _ in iter_member_values(entry.get("exclude"))} - {""}:
        return True
    return isinstance(entry.get("tagging"), dict)


def parse_cloud_appid_connection(payload: Any) -> dict[str, Any]:
    """Classify `show cloud-appid connection-to-cloud`'s free text into three conditions.

    Returns {"recognised": bool, "license_ok": bool, "device_cert_ok": bool,
    "cloud_connection_ok": bool}.

    THE PAYLOAD IS A BARE STRING for this read - `extract_result_payload` returns the result
    whatever its type, and this command's result is one multi-line string - so `payload.get(...)`
    would raise and `payload or {}` does not save it, a non-empty string being truthy.

    MATCHED ON THE STABLE FRAGMENTS, because the wording moves with the build: measured the same
    day, 11.2.5 answers "Check if SaaS license or Ai Access license is installed and active" where
    11.1.13-h3 answers "Check if SaaS license is installed and active".

    EVERY CONDITION IS UNSATISFIED UNTIL THE REPLY SAYS OTHERWISE. The only values measured on
    this estate are the failing ones, so "healthy" cannot be inferred from the absence of a
    failure marker alone - it requires the line to be present and to read as healthy. That is the
    safe direction and it means `healthy` is a token no appliance in this lab can reach.
    """
    text = payload if isinstance(payload, str) else ""
    if isinstance(payload, dict):
        # A future build answering with structure rather than text. Not observed; the text is
        # recovered where one key holds it, and the reply is otherwise unrecognised.
        text = "\n".join(str(v) for v in payload.values() if isinstance(v, str))
    lowered = text.lower()
    recognised = any(marker in lowered for marker in (
        "ace error", "cloud connection:", "device cert status:", "summary of ace grpc client"))
    license_ok = "license check failed" not in lowered
    device_cert_ok = False
    cloud_connection_ok = False
    for line in text.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("device cert status:"):
            value = stripped.split(":", 1)[1].strip()
            device_cert_ok = bool(value) and not any(
                bad in value for bad in ("not installed", "invalid", "not pushed"))
        elif stripped.startswith("cloud connection:"):
            value = stripped.split(":", 1)[1].strip()
            cloud_connection_ok = bool(value) and "fail" not in value and "down" not in value
    return {
        "recognised": recognised,
        "license_ok": license_ok and recognised,
        "device_cert_ok": device_cert_ok,
        "cloud_connection_ok": cloud_connection_ok,
    }


def cloud_app_engine_condition(conditions: dict[str, Any], *,
                               snapshot_exists: bool,
                               ace_disabled: bool | None) -> tuple[bool, str]:
    """(ace_not_operational, ace_failure_reason) from the op reply and the configured key.

    THE ORDER IS THE LICENCE FIRST, because it is the condition every other one fails behind: on
    all three appliances read, the licence check fails AND the cloud connection fails AND the
    device certificate is missing, and reporting the certificate would send a remediation at the
    symptom. The configured disable is tested LAST because it is the only condition that is not in
    the operational reply.

    WHERE THE COMMAND WAS NEVER ISSUED BUT THE CONFIGURATION SAYS DISABLED, the reason is
    `disabled_by_configuration` and not `unread`. Stage 5's `computes` offers both - "the first
    condition in the operational reply that is not satisfied, OR THE CONFIGURED DISABLE WHERE THAT
    IS THE CAUSE, or `healthy`, or `unread` where the command was never issued" - and where the
    configuration names a cause, saying `unread` discards an answer the row already holds. Both
    tokens admit the row through PAN-SAS-005's applicability clause and both leave
    `ace_not_operational` true, so the choice changes the remediation text and not the finding.
    I decided it; it is recorded in the stage 7 artifact's note.
    """
    if snapshot_exists and conditions.get("recognised"):
        if not conditions.get("license_ok"):
            return True, CloudAppEngineSetting.REASON_LICENSE_CHECK_FAILED
        if not conditions.get("device_cert_ok"):
            return True, CloudAppEngineSetting.REASON_DEVICE_CERTIFICATE_MISSING
        if not conditions.get("cloud_connection_ok"):
            return True, CloudAppEngineSetting.REASON_CLOUD_CONNECTION_FAILED
        if ace_disabled:
            return True, CloudAppEngineSetting.REASON_DISABLED_BY_CONFIGURATION
        return False, CloudAppEngineSetting.REASON_HEALTHY
    if ace_disabled:
        return True, CloudAppEngineSetting.REASON_DISABLED_BY_CONFIGURATION
    return True, CloudAppEngineSetting.REASON_UNREAD


# ---------------------------------------------------------------------------
# The three verdicts, computed — pure, over the parsed payloads
# ---------------------------------------------------------------------------

def reachable_scopes(
    merged_payload: dict[str, Any],
    vsys_name: str,
    pushed_roots: list[dict[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    """The scopes whose definitions are in force at one enforcement point, labelled.

    ONE PLACE DECIDES WHAT REACHABLE MEANS, so the four verdict computations cannot disagree about
    it. The firewall's own `/config/shared` is included because a profile or filter defined there
    is reachable from every partition of the appliance - measured, stage 6 wrote one of each at
    that scope on a PA-VM, committed them and read them back - and the pushed roots are included
    because a pushed definition is in force here even though the firewall cannot edit it.
    """
    scopes: list[tuple[str, dict[str, Any]]] = [
        ("vsys", merged_vsys_entry(merged_payload, vsys_name)),
        ("firewall-shared", merged_shared(merged_payload)),
    ]
    for index, root in enumerate(pushed_roots):
        if isinstance(root, dict) and root:
            scopes.append((f"pushed-{index}", root))
    return scopes


def sanctioned_marking_verdict(
    merged_payload: dict[str, Any],
    vsys_name: str,
    pushed_roots: list[dict[str, Any]],
) -> dict[str, Any]:
    """PAN-SAS-001's four columns for one enforcement point.

    EVERY VALUE AN EMPTY ESTATE YIELDS IS THE FIRING ONE, except the cross-partition verdict on a
    single-vsys appliance - which is false because nothing disagrees, and whose row the
    applicability column excludes rather than passing.

    THE CROSS-PARTITION COMPARISON IS OVER THE MERGED PAYLOAD'S OTHER VSYS ENTRIES, which one read
    already carries: `show config merged` is one call for the whole device, so no second
    collection is needed and no ordering obligation falls on the caller.
    """
    roster = merged_vsys_roster(merged_payload)
    this_vsys = merged_vsys_entry(merged_payload, vsys_name)

    marked = set(sanctioned_applications(this_vsys))
    named = set(application_tag_names(this_vsys))
    for root in pushed_roots:
        if isinstance(root, dict) and root:
            marked.update(sanctioned_applications(root))
            named.update(application_tag_names(root))

    siblings: dict[str, set[str]] = {}
    for other in roster:
        if other == vsys_name:
            continue
        other_entry = merged_vsys_entry(merged_payload, other)
        siblings[other] = set(sanctioned_applications(other_entry))
        named.update(application_tag_names(other_entry))

    # Over the UNION of applications named anywhere on the appliance, not over the rows that
    # exist: the commonest form of the inconsistency is an application in one partition's
    # collection and absent from another's.
    union = named | marked | {app for apps in siblings.values() for app in apps}
    inconsistent = any(
        {app for app in union if app in marked} != {app for app in union if app in sibling_marked}
        for sibling_marked in siblings.values()
    )

    return {
        "sanctioned_application_count": len(marked),
        "marked_application_names": sorted(marked),
        "appliance_is_multi_vsys": len(roster) > 1,
        "marking_is_inconsistent_across_vsys": inconsistent,
    }


def url_filtering_posture_verdict(
    merged_payload: dict[str, Any],
    vsys_name: str,
    pushed_roots: list[dict[str, Any]],
) -> dict[str, Any]:
    """PAN-SAS-002's and PAN-SAS-004's seven columns for one enforcement point."""
    scopes = reachable_scopes(merged_payload, vsys_name, pushed_roots)
    profiles = url_filtering_profiles(scopes)
    groups = profile_group_url_filtering(scopes)

    this_vsys = merged_vsys_entry(merged_payload, vsys_name)
    rules = list(security_rules(this_vsys))
    for root in pushed_roots:
        if isinstance(root, dict) and root:
            pre, post = pushed_security_rules(root)
            rules.extend(pre)
            rules.extend(post)

    reached = rule_reachable_url_filtering_profiles(rules, groups)

    type_entry_count = 0
    tenant_in_force = False
    headers_without_value = 0
    for _, profile_name, profile in profiles:
        for _, type_entry in type_entries(profile):
            type_entry_count += 1
            if not type_inserts_tenant_restriction(type_entry):
                continue
            if profile_name in reached:
                tenant_in_force = True
            for header in entry_container(type_entry, "headers")[1]:
                if not scalar_value(header.get("value"))[0]:
                    headers_without_value += 1

    tenant_list_rules = sum(
        1 for rule in rules
        if {m for m in rule_members(rule, "saas-tenant-list") if m and m != ANY_KEYWORD}
    )

    treatment = category_treatment(profiles, rules)
    return {
        "url_filtering_profiles_read": bool(profiles),
        "header_insertion_type_entry_count": type_entry_count,
        "tenant_restriction_in_force": tenant_in_force,
        "tenant_header_without_value_count": headers_without_value,
        "rule_bound_tenant_list_count": tenant_list_rules,
        "consumer_storage_category_treatment": treatment,
        "consumer_storage_categories_are_restricted": (
            treatment in SaasUrlFilteringPosture.RESTRICTING_TREATMENTS),
    }


def application_policy_verdict(
    merged_payload: dict[str, Any],
    vsys_name: str,
    pushed_roots: list[dict[str, Any]],
    function_children: set[str],
) -> dict[str, Any]:
    """PAN-SAS-003's and PAN-SAS-004's six columns for one enforcement point.

    THE FIRST-MATCH WALK IS IN DATAPLANE ORDER ACROSS SCOPES: pushed PRE-rules first, then the
    firewall's own, then pushed POST-rules. That ordering is the whole of PAN-SAS-003 - the
    assertion is a relation between two rules, a deny on the function child evaluated BEFORE an
    allow on the base application - and reading only the local rulebase ranks the wrong set.

    `SecurityRule.effective_order` and `SecurityRule.config_source` already model that ranking for
    the stored rows; this computation takes it from the payload the same pass parsed, so that two
    normalizers cannot disagree about what one collection contained and no ordering obligation
    falls on the caller.
    """
    this_vsys = merged_vsys_entry(merged_payload, vsys_name)
    pre: list[dict[str, Any]] = []
    post: list[dict[str, Any]] = []
    for root in pushed_roots:
        if isinstance(root, dict) and root:
            root_pre, root_post = pushed_security_rules(root)
            pre.extend(root_pre)
            post.extend(root_post)
    ordered = pre + list(security_rules(this_vsys)) + post

    naming_rules = 0
    named_children: set[str] = set()
    for rule in ordered:
        hit = {m for m in rule_members(rule, "application") if m in function_children}
        if hit:
            naming_rules += 1
            named_children.update(hit)

    actions: list[str] = []
    for child in sorted(named_children):
        for rule in ordered:
            if child in rule_members(rule, "application"):
                actions.append(rule_action(rule))
                break

    order = SaasApplicationPolicyPosture.ACTION_ORDER
    if actions:
        known = [a for a in actions if a in order]
        effective = min(known, key=order.index) if known else SaasApplicationPolicyPosture.ACTION_ALLOW
        refused = all(a in SaasApplicationPolicyPosture.REFUSING_ACTIONS for a in actions)
    else:
        effective = SaasApplicationPolicyPosture.ACTION_NO_RULE
        # A rulebase naming none of them refuses none of them either. The same false as "nobody
        # ranked it", honestly, with the count beside it telling the two apart.
        refused = False

    scopes = reachable_scopes(merged_payload, vsys_name, pushed_roots)
    qualifying = [(label, name, entry) for label, name, entry in application_filters(scopes)
                  if filter_selects_cloud_applications(entry)]
    qualifying_names = {name for _, name, _ in qualifying}

    selection_refused = any(
        rule_action(rule) in SaasApplicationPolicyPosture.REFUSING_ACTIONS
        and {m for m in rule_members(rule, "application")} & qualifying_names
        for rule in ordered
    )
    # NOT VACUOUSLY TRUE on an empty population: stage 5's declared default for this column is
    # the firing side, and an absent exclusion is the commonest state and the one that has to
    # report. A partition with no qualifying filter carves nothing out.
    excludes_approved = bool(qualifying) and all(
        filter_excludes_approved(entry) for _, _, entry in qualifying)

    return {
        "function_app_rule_count": naming_rules,
        "function_apps_are_refused": refused,
        "effective_action_for_function_apps": effective,
        "cloud_app_filter_count": len(qualifying),
        "cloud_app_selection_is_refused": selection_refused,
        "cloud_app_selection_excludes_approved": excludes_approved,
    }


# ---------------------------------------------------------------------------
# Persisting
# ---------------------------------------------------------------------------

def _replace_for_point(model, enforcement_point: EnforcementPoint):
    """Drop this point's rows of one model and their provenance. Returns the content type.

    Delete-and-recreate rather than `update_or_create`, for the reason
    `interface_management_profiles.py` records: `update_or_create` cannot REMOVE a row, and a
    leftover row of a verdict model reports a conclusion about a configuration that is gone.
    """
    content_type = ContentType.objects.get_for_model(model)
    object_ids = list(
        model.objects.filter(enforcement_point=enforcement_point).values_list("pk", flat=True))
    if object_ids:
        FieldProvenance.objects.filter(
            content_type=content_type, object_id__in=object_ids).delete()
    model.objects.filter(enforcement_point=enforcement_point).delete()
    return content_type


def _pushed_roots_for_point(enforcement_point: EnforcementPoint) -> tuple[list[dict[str, Any]],
                                                                         dict[str, bool]]:
    """Every pushed root in force at one enforcement point, and which reads supplied them.

    THREE READS AND NOT ONE, measured rather than chosen - see the module docstring. A missing
    snapshot is a reading in its own right rather than an error: `latest_pushed_shared_snapshot`
    returns None for an APPLIANCE-owned point, because Panorama collects that read per group, and
    an unmanaged firewall has no pushed tree at all.

    `pushed_vsys_panorama` absorbs the literal "No shared policy pushed to device" a vsys with no
    device-group assignment answers - measured on vsys6 of fw-core-tpa-b today - which
    `Snapshot.payload` stores as a bare `str`, so a reader doing `payload.get(...)` raises on
    exactly the partitions that are fine.
    """
    roots: list[dict[str, Any]] = []
    seen = {"pushed_vsys": False, "pushed_shared": False, "pushed_vsys_profiles": False}

    vsys_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    if vsys_snapshot is not None:
        seen["pushed_vsys"] = True
        roots.append(pushed_vsys_panorama(vsys_snapshot.payload))

    shared_snapshot = latest_pushed_shared_snapshot(enforcement_point)
    if shared_snapshot is not None:
        seen["pushed_shared"] = True
        roots.append(pushed_shared(shared_snapshot.payload))

    profiles_snapshot = latest_pushed_vsys_profiles_snapshot(enforcement_point)
    if profiles_snapshot is not None:
        seen["pushed_vsys_profiles"] = True
        roots.append(pushed_vsys_profiles(profiles_snapshot.payload))

    return [r for r in roots if isinstance(r, dict) and r], seen


def normalize_saas_security(enforcement_point: EnforcementPoint) -> dict[str, Any]:
    """Replace one enforcement point's three SaaS verdict rows. PAN-SAS-001 to 004.

    THREE MODELS IN ONE PASS, because they are three conclusions about one payload parse - the
    same argument `normalize_decryption_policy` makes for its two. Computed from the payload this
    call read rather than from rows another normalizer wrote, so this carries NO ordering
    obligation on its caller: running it first or last gives the same answer and there is no first
    collection on which it would read nothing.

    A ROW IS WRITTEN EVEN WHERE THE PARTITION HOLDS NOTHING AT ALL, which is the whole reason these
    three models exist: a vsys with no application-tag container, no url-filtering profile and no
    rulebase is the commonest state in this estate and is what three of the five controls fire on.

    A MISSING MERGED SNAPSHOT RAISES, which is the point-level failure the layering says still
    raises: there is nothing to iterate. A missing PUSHED snapshot does not - it is a reading, and
    the returned dict says which reads supplied a root.
    """
    merged_snapshot = latest_merged_snapshot(enforcement_point)
    if merged_snapshot is None:
        raise ValueError(f"missing merged config snapshot for {enforcement_point}")
    payload = merged_snapshot.payload
    if not isinstance(payload, dict):
        raise ValueError(
            f"merged config snapshot for {enforcement_point} is "
            f"{type(payload).__name__}, not a config payload")

    pushed_roots, reads_seen = _pushed_roots_for_point(enforcement_point)
    if is_panorama_managed(enforcement_point) and not reads_seen["pushed_vsys"]:
        raise ValueError(f"missing pushed VSYS snapshot for {enforcement_point}")

    appliance = merged_snapshot.appliance
    catalogue_snapshot = (
        latest_predefined_application_snapshot(appliance) if appliance is not None else None)
    function_children = (
        function_child_applications(catalogue_snapshot.payload)
        if catalogue_snapshot is not None else set())

    vsys_name = enforcement_point.vsys_name
    marking = sanctioned_marking_verdict(payload, vsys_name, pushed_roots)
    url_filtering = url_filtering_posture_verdict(payload, vsys_name, pushed_roots)
    policy = application_policy_verdict(payload, vsys_name, pushed_roots, function_children)

    with transaction.atomic():
        for model, values in (
            (SanctionedApplicationMarking, marking),
            (SaasUrlFilteringPosture, url_filtering),
            (SaasApplicationPolicyPosture, policy),
        ):
            _replace_for_point(model, enforcement_point)
            # NO PROVENANCE ROW ON ANY OF THE THREE, not even `__entry__`: the row is not an
            # entry and every column is in DERIVED_FIELDS, so `provenance_for` answers `derived`
            # without a stored row and `test_declared_derived_fields` would fail if one existed.
            model.objects.create(
                management_station=enforcement_point.management_station,
                enforcement_point=enforcement_point,
                source_snapshot=merged_snapshot,
                **values,
            )

    return {
        "sanctioned_application_markings": 1,
        "saas_url_filtering_postures": 1,
        "saas_application_policy_postures": 1,
        "predefined_application_catalogue_collected": catalogue_snapshot is not None,
        "function_child_applications_known": len(function_children),
        "pushed_reads": reads_seen,
        **marking,
        **url_filtering,
        **policy,
    }


def normalize_cloud_app_engine(appliance: Appliance) -> dict[str, Any]:
    """Replace one appliance's App-ID Cloud Engine row. PAN-SAS-005.

    TWO HALVES FROM TWO READS THAT POINT OPPOSITE WAYS on this estate: the merged config says
    whether somebody switched the engine off, and the operational reply says whether it is
    running. Without the operational snapshot `ace_not_operational` stays true and
    `ace_failure_reason` says which - the firing side, and accurate rather than merely safe.

    `write_node_row` and not delete-and-recreate, because the row IS the appliance: there is no
    named entry and no row to be left over. It writes a provenance row only for the two measured
    keys and deletes only those, so a second normalizer writing other columns of this model later
    would not erase them.
    """
    merged_snapshot = latest_appliance_merged_snapshot(appliance)
    if merged_snapshot is None:
        raise ValueError(f"missing merged config snapshot for {appliance}")
    payload = merged_snapshot.payload
    if not isinstance(payload, dict):
        raise ValueError(
            f"merged config snapshot for {appliance} is {type(payload).__name__}, "
            f"not a config payload")

    config = payload.get("config") if isinstance(payload.get("config"), dict) else {}
    devices = config.get("devices") if isinstance(config.get("devices"), dict) else {}
    device_entries = [e for e in ensure_list(devices.get("entry")) if isinstance(e, dict)]
    device_entry = device_entries[0] if device_entries else {}
    deviceconfig = device_entry.get("deviceconfig")
    setting = deviceconfig.get("setting") if isinstance(deviceconfig, dict) else None

    # THE COLUMN THAT SEPARATES "nobody looked" FROM "nobody switched it off". The subtree is what
    # decides it, not the `cloudapp` node: an absent `cloudapp` under a present `setting` is a key
    # that was read and found absent, which the assumed default below is for.
    node_read = isinstance(setting, dict)
    cloudapp = setting.get("cloudapp") if node_read else None

    provenance: list[tuple[str, Any, str | None]] = []
    if node_read:
        disabled, raw_key, raw_prov = parse_yes_no_field(
            (cloudapp or {}).get("disable") if isinstance(cloudapp, dict) else None,
            implicit=ACE_DISABLE_ABSENT)
        provenance.append(("ace_disabled", raw_key, raw_prov))
        server_container = (
            cloudapp.get("cloudapp-srvr-addr") if isinstance(cloudapp, dict) else None)
        address, addr_key, addr_prov = parse_text_field(
            server_container.get("address") if isinstance(server_container, dict) else None,
            implicit=ACE_SERVER_ADDRESS_ABSENT)
        provenance.append(("cloudapp_server_address", addr_key, addr_prov))
        # `stores: null` with `rests_on: not_assumed` is the declaration that means STORE
        # NOTHING, so the absent key lands on None rather than on an empty string a query could
        # mistake for a value somebody wrote.
        server_address = address or None
    else:
        # The one state in which `ace_disabled` is NULL: the key is neither present nor absent
        # but unread. No provenance row either - nothing tracks a field nobody read.
        disabled = None
        server_address = None

    connection_snapshot = latest_cloud_appid_connection_snapshot(appliance)
    conditions = parse_cloud_appid_connection(
        connection_snapshot.payload if connection_snapshot is not None else None)
    not_operational, reason = cloud_app_engine_condition(
        conditions, snapshot_exists=connection_snapshot is not None, ace_disabled=disabled)

    with transaction.atomic():
        write_node_row(
            CloudAppEngineSetting,
            appliance,
            merged_snapshot,
            {
                "ace_disabled": disabled,
                "cloudapp_node_read": node_read,
                "ace_not_operational": not_operational,
                "ace_failure_reason": reason,
                "cloudapp_server_address": server_address,
            },
            provenance=tuple(p for p in provenance if p[1] is not ABSENT),
        )

    return {
        "cloud_app_engine_settings": 1,
        "cloudapp_node_read": node_read,
        "ace_disabled_is_unread": disabled is None,
        "ace_connection_snapshot_collected": connection_snapshot is not None,
        "ace_not_operational": not_operational,
        "ace_failure_reason": reason,
    }
