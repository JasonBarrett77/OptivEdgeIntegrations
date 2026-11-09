"""PAN-OS url-filtering profiles and custom URL categories: the reads, and the verdicts.

PAN-URL-001 to PAN-URL-006. This module holds what is SPECIFIC to the url-filtering kind and to
the custom-category collection beside it; the rows themselves are written by
`normalization/security_profiles.py`, which owns `SecurityProfile` and already issues every read
both subjects need. Nothing here opens a connection or touches the database except
`replace_custom_url_categories`.

WHY THE VERDICTS ARE COLUMNS AND NOT CLAUSES. A url-filtering profile's PERMIT SET IS NOT IN THE
PROFILE: `allow` is what the device OMITS for a predefined category, so a profile that permits
all ninety names them nowhere, and the answer to "what does this profile leave reachable" is the
DEVICE'S OWN CATALOG minus the five or six restricting lists. That is a set difference over a
collection the entry does not contain, with a default supplied per member, which no predicate of
one field, one operator and one literal can express.

THREE MEASURED SHAPES EVERY READER HERE HAS TO SURVIVE, all of which type-check:

  a pushed member is {"@loc": "shared", "#text": "malware"} and a local one is the bare string,
  so `"malware" in members` is FALSE on every pushed profile in this estate AND DOES NOT RAISE.
  Members are read through `member_values`, which is the one reader that handles both.

  `credential-enforcement/mode` is a CHOICE NODE: {"mode": {"group-mapping": "any"}} on the wire
  and {"mode": {"disabled": null}} for the empty arm, with a text value REFUSED at the write -
  `<mode>disabled</mode>` answers code=12 "credential-enforcement -> mode is unexpected". A
  reader expecting a value gets an empty string, so the chosen arm is read as the child key's
  NAME through `choice_child`.

  the predefined entry's `local-inline-cat` is {"@minver": "10.2.0", "#text": "yes"}. @minver is
  NOT a provenance marker, so `scalar_value` reads the text correctly and classifies the key as
  locally configured - which is wrong about a vendor-shipped entry no administrator can edit.
  The reading site is what has to say so, which is why every reader below takes `predefined`.

THE SIX SITE-ACCESS LISTS ARE MUTUALLY EXCLUSIVE, measured: adding `gambling` to `continue`
while it sat in `isolate` on the same entry is refused code=12 "'gambling' is already in use".
So a category's effective action is "which of the six holds it, and the per-kind default if none
does" - `allow` for a predefined category, because the permit is the omission, and `none` for a
custom one, because a key-less profile renders every custom category inert.

AND THE CREDENTIAL ACTION OF A CATEGORY IS A FUNCTION OF A DIFFERENT LIST. The device derives
`block` for every category the SITE-ACCESS `block` list names, with nothing written under
credential-enforcement: measured on the predefined `default`, which has no credential node at
all and whose dialog grid reads 13 credential blocks on 6A9C0A9904E7D6E, 12 on 691665AC334B458
and 13 on 013201001475, each set equal to its own site-access block set - while the LIST grid's
credential cell reads `Allow Categories (90)` / `Block Categories (0)` on the same entry in the
same minute. A query joining on membership of the credential lists reports every estate's
credential posture as fully permissive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from django.contrib.contenttypes.models import ContentType

from optivedge_integrations.integrations.models import (
    ApplianceGroup,
    CustomUrlCategory,
    EnforcementPoint,
    FieldProvenance,
    PolicyObjectNamespace,
    PolicyObjectScope,
    SecurityProfile,
    Snapshot,
    precedence_for,
    scope_for,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    PREDEFINED,
    Implicit,
    choice_child,
    classify_prov_type,
    ensure_list,
    entry_provenance,
    member_values,
    parse_yes_no_field,
    provenance_raw_key,
    provenance_value,
    scalar_value,
    was_absent,
)
# THE WEAKEST-BY-AN-EXPLICIT-ORDER HELPER, already written and already measured, and already
# imported under this name by `security_profiles.py` for the same reason: None where nothing was
# collected, and a member the order does not place returned AS THE DEVICE GAVE IT rather than
# silently dropped. The second property is what makes it right for the two risk gradings here -
# stage 3 placed six category names of eighty-eight-to-ninety and said the rest take the
# baseline, so an unplaced member has to survive to the column and match no placement.
#
# It is used in BOTH directions. The order is the scale, not the question: passing an
# action order weakest-first returns the weakest action, and passing a risk order worst-first
# returns the worst category.
from optivedge_integrations.integrations.platforms.pan_os.normalization.ike import (
    _weakest as weakest_member,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    choose_local_appliance,
)


#: The snapshot `collect_show_predefined_url_categories` persists. One per appliance.
URL_CATEGORY_CATALOGUE_SOURCE_TYPE = "show_predefined_url_categories"

#: The collection key both subjects live under, inside `profiles`.
PROFILE_COLLECTION = "url-filtering"
CATEGORY_COLLECTION = "custom-url-category"


# --------------------------------------------------------------------------- what an absence is

_LIST_SHARED_BASIS = (
    "stage4-url-filtering.json fields.{key}.implicit, status measured, may_materialise true: "
    "an absent list asserts that no category holds this action. Measured on a committed "
    "key-less profile on serial 691665AC334B458 and reproduced on 6A9C0A9904E7D6E and "
    "013201001475 - the dialog's Categories grid rendered all 90 at `allow` and 0 at `block` - "
    "with the positive control paid: writing one member moved exactly that row."
)
_LIST_UNMEASURED_BASIS = (
    "stage4-url-filtering.json fields.{key}.implicit records status `unmeasured` and "
    "consumer_disposition `not_assumed` with may_materialise false: state C never paid a "
    "positive control on this list, so nothing establishes what its absence asserts. An empty "
    "list and an absent key are ONE state on the wire - the device drops an empty container - "
    "so a materialised [] here would be a measurement nobody took."
)

#: THE SIX SITE-ACCESS LISTS. (payload key, column, implicit). Three carry a measured absence
#: and three do not, and the split is stage 4's rather than a shape of the data: `block`,
#: `allow` and `isolate` were given positive controls and `alert`, `continue` and `override`
#: were not. Storing [] for the second three would claim a measurement nobody took, and a
#: verdict computed over all six has to treat the null as "the categories in this list are not
#: known" - which is why the verdicts read as the failing side when any contributing list is
#: null.
SITE_ACCESS_LISTS = (
    ("block", "block_categories",
     Implicit.measured([], _LIST_SHARED_BASIS.format(key="block"))),
    ("alert", "alert_categories",
     Implicit.not_assumed(_LIST_UNMEASURED_BASIS.format(key="alert"))),
    ("allow", "allow_categories",
     Implicit.measured([], (
         "stage4-url-filtering.json fields.allow.implicit, status measured, may_materialise "
         "true: an absent `allow` list does NOT mean nothing is allowed - it means nothing was "
         "EXPLICITLY allowed, and because `allow` is what the device omits for a predefined "
         "category the explicit list never contains one. The key-less subject rendered 90 "
         "categories at `allow` with no `allow` key in its configuration."))),
    ("continue", "continue_categories",
     Implicit.not_assumed(_LIST_UNMEASURED_BASIS.format(key="continue"))),
    ("override", "override_categories",
     Implicit.not_assumed(_LIST_UNMEASURED_BASIS.format(key="override"))),
    ("isolate", "isolate_categories",
     Implicit.measured([], (
         "stage4-url-filtering.json fields.isolate.implicit, status measured, "
         "may_materialise true: an absent `isolate` list asserts no category is sent to remote "
         "browser isolation, on the two builds that carry the key at all - the 19-key set on "
         "both PA-VMs, absent from both PA-5220s' 17, confirmed by a write refused code=13 on "
         "serial 013201001475."))),
)

#: THE FOUR CREDENTIAL LISTS, under `credential-enforcement`. `block`'s absence is measured from
#: both sides; the other three were never given a positive control.
CREDENTIAL_LISTS = (
    ("block", "credential_block_categories",
     Implicit.measured([], (
         "stage4-url-filtering.json fields.credential-enforcement/block.implicit, status "
         "measured, may_materialise true: measured on the predefined `default`, which has no "
         "credential-enforcement node at all and renders 13 credential blocks on serial "
         "6A9C0A9904E7D6E, 12 on 691665AC334B458 and 13 on 013201001475, each set equal to its "
         "own site-access block set; and from the other side by writing ONLY "
         "`block/member=malware` onto a key-less subject and watching that one row's credential "
         "cell move with it, with no key written under credential-enforcement. So an empty "
         "credential block list does not mean no category refuses credentials - it means none "
         "was CONFIGURED to."))),
    ("alert", "credential_alert_categories",
     Implicit.not_assumed(
         _LIST_UNMEASURED_BASIS.format(key="credential-enforcement/alert"))),
    ("allow", "credential_allow_categories",
     Implicit.not_assumed(
         _LIST_UNMEASURED_BASIS.format(key="credential-enforcement/allow"))),
    ("continue", "credential_continue_categories",
     Implicit.not_assumed(
         _LIST_UNMEASURED_BASIS.format(key="credential-enforcement/continue"))),
)

CREDENTIAL_MODE_ABSENT = Implicit.measured(
    SecurityProfile.CREDENTIAL_MODE_DISABLED,
    "stage4-url-filtering.json fields.credential-enforcement/mode.implicit, status measured, "
    "may_materialise true: the Mode control renders `Disabled` on a committed entry carrying no "
    "credential-enforcement node at all - serials 691665AC334B458, 6A9C0A9904E7D6E and "
    "013201001475, three appliances, two major versions, both vsys modes - and the positive "
    "control moved it to `Use Group Mapping`. THIS DEFAULT FIRES: `disabled` is the value "
    "PAN-URL-003's first half reports on.")

_HEADER_MEASURED = Implicit.measured(
    False,
    "stage4-url-filtering.json fields.log-http-hdr-user-agent.implicit, status measured, "
    "may_materialise true: unticked on every key-less committed subject on three appliances and "
    "on the predefined `default`, with a positive control paid on this key. THIS DEFAULT FIRES: "
    "false is the failing side of PAN-URL-004's assertion.")

_HEADER_ASSUMED = (
    "four of the method's five points are paid and the positive control on THIS key is not: "
    "unticked on every key-less committed subject read on three appliances and on the "
    "predefined `default`, and still unticked after a seven-key batch moved its siblings. One "
    "write settles it. The value is non-null deliberately - an assumed declaration holding "
    "None is "
    "persisted as not_configured and the declaration and the row would then disagree - and it "
    "still fires, which is the direction rules.md requires.")

CLOUD_INLINE_CAT_ABSENT = Implicit.measured(
    False,
    "stage4-url-filtering.json fields.cloud-inline-cat.implicit, status measured, "
    "may_materialise true: the cloud-side engine is OFF when the key is absent, on all three "
    "appliances a browser reached, across both major versions and both vsys modes, and on the "
    "one appliance holding an Advanced URL Filtering license as well as the three that do not. "
    "The positive control wrote `yes` and the box rendered ticked. THIS DEFAULT FIRES.")

#: THE ONE IMPLICIT ON THIS OBJECT THAT IS A RELATION RATHER THAN A CONSTANT, and nothing is
#: materialised at any price. The condition is NOT a sibling field - it is the APPLIANCE.
LOCAL_INLINE_CAT_ABSENT = Implicit.not_assumed(
    "stage4-url-filtering.json fields.local-inline-cat.implicit records status `conditional` "
    "with consumer_disposition `not_assumed` and may_materialise false. On a committed key-less "
    "profile the box renders TICKED on serial 691665AC334B458 (PA-VM 11.2.5) and 6A9C0A9904E7D6E "
    "(PA-VM 11.2.3-h3) and UNTICKED on 013201001475 (PA-5220 11.1.13-h3), with the positive "
    "control paid on both sides. A consumer that materialised `yes` from a PA-VM reading onto a "
    "PA-5220 would report an on-box analysis engine the device's own interface says is off. The "
    "one candidate cause stage 4 could rule out is the Advanced URL Filtering subscription: "
    "6A9C0A9904E7D6E renders TICKED and holds no URL filtering license of any kind.")

MLAV_EXCEPTION_ABSENT = Implicit.measured(
    [],
    "stage4-url-filtering.json fields.mlav-category-exception.implicit, status measured, "
    "may_materialise true: an absent key asserts that NOTHING is exempted from either engine - "
    "the Inline Categorization tab's exception grid renders ZERO rows on serials "
    "691665AC334B458, 6A9C0A9904E7D6E and 013201001475 - and the positive control wrote one "
    "member and the grid gained exactly that row. THE KEY IS NEGATED, so this is the one "
    "materialised [] in this family that legitimately reassures: an empty exemption list IS the "
    "good state.")

LOG_CONTAINER_PAGE_ONLY_ABSENT = Implicit.measured(
    True,
    "stage4-url-filtering.json fields.log-container-page-only.implicit, status measured, "
    "may_materialise true: THE ONLY KEY ON THIS OBJECT WHOSE IMPLICIT IS `yes` ON EVERY "
    "APPLIANCE. Ticked on a committed key-less profile on serials 691665AC334B458, "
    "6A9C0A9904E7D6E and 013201001475 and on the predefined `default`; the positive control "
    "wrote `no` and the box rendered unticked, so the control moves in the direction that could "
    "have exposed a stuck control. Vendor Help p.299 documents it as default enabled and the "
    "device agrees.")

#: The three request-header keys, mapped to their columns and declarations. ONLY THE FIRST IS
#: MEASURED - see `_HEADER_ASSUMED`.
HEADER_KEYS = (
    ("log-http-hdr-user-agent", "log_http_header_user_agent", _HEADER_MEASURED),
    ("log-http-hdr-referer", "log_http_header_referer",
     Implicit.assumed(False, _HEADER_ASSUMED)),
    ("log-http-hdr-xff", "log_http_header_xff",
     Implicit.assumed(False, (
         _HEADER_ASSUMED + " DOWNGRADED from `measured` by stage 4's own review: the only "
         "write attempted on this key was the refusal probe `enabled`, so the key was never "
         "set."))),
)

CATEGORY_TYPE_ABSENT = Implicit.not_assumed(
    "stage4-url-filtering.json objects.custom-url-category.fields.type.implicit, status "
    "not_applicable, may_materialise false: THE KEY IS MANDATORY AT COMMIT VALIDATION, so it "
    "has no absent state at all and an absence asserts nothing. `Validation Error: ... is "
    "missing 'type' / custom-url-category is invalid` on serial 691665AC334B458 job 191 and the "
    "same message naming vsys3 on 013201001475 jobs 492 and 493, while action=set accepted the "
    "key-less entry without comment. Materialising `URL List` would describe a candidate no "
    "committed device can hold.")

MATCH_ENTRIES_ABSENT = Implicit.not_assumed(
    "stage4-url-filtering.json objects.custom-url-category.fields.list.implicit records status "
    "`unmeasured` with consumer_disposition `not_assumed` and may_materialise false: state C "
    "wrote no member to this key at all, so the write path's handling of a URL pattern against "
    "a category name under the two `type` values is untested and nothing establishes what an "
    "absent `list` asserts. A null is NOT an empty list: an entry with no members matches "
    "nothing, which for a `URL List` is inert and for a `Category Match` is unmeasured.")


# --------------------------------------------------------------------------- the readers

def member_list_field(
    node: Any, *, implicit: Implicit, predefined: bool = False,
) -> tuple[list[str] | None, Any, str | None]:
    """A PAN-OS member list, declaring what an absent key means. The list analogue of
    `parse_yes_no_field`, and it exists for the same reason: storing a value for an absent key
    is a claim about PAN-OS, so the site has to say whether it can back it.

    Returns (value, raw_key, raw_provenance_value). The value is the `implicit`'s - which may be
    None - when the key was ABSENT, and the raw key is the declaration itself so the provenance
    row records WHY the stored value is what it is.

    Members are read through `member_values`, so a pushed {"@loc": ..., "#text": ...} member and
    a bare local string both come out as the name.
    """
    if node is None:
        return implicit.value, implicit, None
    values = [name for name, _prov in member_values(node) if name]
    # The CONTAINER's own marker, which is what says where the list came from. `scalar_value`
    # returns no text for a container and the marker pair is exactly what is wanted here.
    _text, raw_key, raw_prov = scalar_value(node)
    if predefined:
        return values, PREDEFINED, None
    return values, raw_key, raw_prov


def _predefined_key(raw_key: Any, *, predefined: bool) -> Any:
    """`PREDEFINED` for a key the payload CARRIES on a vendor-shipped entry.

    No payload key marks a predefined entry and `classify_prov_type`'s fallthrough is `local`,
    so without this every leaf of the shipped `default` profile records "defined on this device"
    about an object no administrator wrote and nobody can edit. An ABSENT key keeps its own
    `Implicit`: what PAN-OS does without the key is the same fact whoever shipped the entry.
    """
    if not predefined or was_absent(raw_key):
        return raw_key
    return PREDEFINED


def url_filtering_profile_values(
    entry: dict[str, Any], *, predefined: bool = False,
) -> tuple[dict[str, Any], list[tuple[str, Any, str | None]]]:
    """The eighteen MEASURED url-filtering columns off one profile entry, with provenance.

    Returns ({column: value}, [(column, raw_key, raw_value), ...]). Every one of the eighteen
    carries a row, because for every one of them a reader is owed the difference between a value
    read and a value inferred - and two of the three request headers are inferred.
    """
    values: dict[str, Any] = {}
    provenance: list[tuple[str, Any, str | None]] = []

    for key, column, implicit in SITE_ACCESS_LISTS:
        value, raw_key, raw_prov = member_list_field(
            entry.get(key), implicit=implicit, predefined=predefined)
        values[column] = value
        provenance.append((column, raw_key, raw_prov))

    # THE CREDENTIAL NODE, which is absent on most profiles in this estate. An absent PARENT
    # makes every child absent, and each child's own declaration is what then applies - so
    # there is no special case here: `.get` on {} answers None for all five.
    credential = entry.get("credential-enforcement")
    credential = credential if isinstance(credential, dict) else {}
    mode_node = credential.get("mode")
    if mode_node is None:
        values["credential_detection_mode"] = CREDENTIAL_MODE_ABSENT.value
        provenance.append(("credential_detection_mode", CREDENTIAL_MODE_ABSENT, None))
    else:
        arm, _child = choice_child(mode_node, SecurityProfile.CREDENTIAL_MODES)
        _text, raw_key, raw_prov = scalar_value(mode_node)
        # A PRESENT NODE HOLDING NO KNOWN ARM keeps the measured absent value rather than an
        # empty string: the node exists, so the provenance stays the key's own, and the value
        # the device renders for a mode it does not understand is not something anyone measured.
        values["credential_detection_mode"] = arm or CREDENTIAL_MODE_ABSENT.value
        provenance.append(("credential_detection_mode",
                           _predefined_key(raw_key, predefined=predefined), raw_prov))

    for key, column, implicit in CREDENTIAL_LISTS:
        value, raw_key, raw_prov = member_list_field(
            credential.get(key), implicit=implicit, predefined=predefined)
        values[column] = value
        provenance.append((column, raw_key, raw_prov))

    for key, column, implicit in HEADER_KEYS:
        value, raw_key, raw_prov = parse_yes_no_field(entry.get(key), implicit=implicit)
        values[column] = value
        provenance.append((column, _predefined_key(raw_key, predefined=predefined), raw_prov))

    for key, column, implicit in (
        ("cloud-inline-cat", "cloud_inline_categorization", CLOUD_INLINE_CAT_ABSENT),
        ("local-inline-cat", "local_inline_categorization", LOCAL_INLINE_CAT_ABSENT),
        ("log-container-page-only", "log_container_page_only",
         LOG_CONTAINER_PAGE_ONLY_ABSENT),
    ):
        value, raw_key, raw_prov = parse_yes_no_field(entry.get(key), implicit=implicit)
        values[column] = value
        provenance.append((column, _predefined_key(raw_key, predefined=predefined), raw_prov))

    value, raw_key, raw_prov = member_list_field(
        entry.get("mlav-category-exception"), implicit=MLAV_EXCEPTION_ABSENT,
        predefined=predefined)
    values["inline_analysis_exemptions"] = value
    provenance.append(("inline_analysis_exemptions", raw_key, raw_prov))

    return values, provenance


def url_category_catalogue(payload: Any) -> list[str]:
    """Every category name the DEVICE reports, from a `show predefined pan-url-categories`
    payload. [] when the read is missing or unrecognisable, which the caller turns into
    `category_catalogue_collected = False` rather than into a denominator of zero.

    The read roots under `result.pan-url-categories`, whose entries carry `@name`, `@id` and
    `index`. Only the name is used: the id is content-release-local and the index is the grid's
    row order.
    """
    for candidate in (
        payload,
        payload.get("result") if isinstance(payload, dict) else None,
        (payload.get("response") or {}).get("result") if isinstance(payload, dict) else None,
    ):
        if not isinstance(candidate, dict):
            continue
        node = candidate.get("pan-url-categories")
        if not isinstance(node, dict):
            continue
        names = [str(e.get("@name") or "") for e in ensure_list(node.get("entry"))
                 if isinstance(e, dict)]
        return [n for n in names if n]
    return []


def latest_url_category_catalogue_snapshot(
    enforcement_point: EnforcementPoint,
) -> Snapshot | None:
    """The newest catalog read for the appliance that speaks for this point.

    Appliance-wide, like every `show predefined` read, so it hangs off the appliance and not off
    the point - and `choose_local_appliance` is the one definition of which appliance's
    configuration speaks for a point.
    """
    appliance = choose_local_appliance(enforcement_point)
    if appliance is None:
        return None
    return (Snapshot.objects
            .filter(appliance=appliance, source_type=URL_CATEGORY_CATALOGUE_SOURCE_TYPE)
            .order_by("-collected_at", "-pk").first())


# --------------------------------------------------------------------------- custom categories

@dataclass(slots=True)
class NormalizedCustomUrlCategory:
    source_snapshot: Snapshot
    config_source: str
    name: str
    namespace_type: str
    namespace_value: str
    precedence_rank: int
    category_type: str
    #: None means the key was absent and nothing is assumed - NOT an empty list.
    match_entries: list[str] | None
    raw_category: dict[str, Any]
    field_provenance_data: list[tuple[str, Any, str | None]]

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.name, str(self.namespace_type), self.namespace_value)

    @property
    def match_entry_count(self) -> int | None:
        return None if self.match_entries is None else len(self.match_entries)


def normalize_custom_url_category(
    *, source_snapshot: Snapshot, config_source: str, namespace_type: str, namespace_value: str,
    entry: dict[str, Any], predefined: bool = False,
) -> NormalizedCustomUrlCategory:
    """One custom-url-category entry.

    `predefined` is accepted and is always False today: there is NO predefined custom-category
    namespace - the predefined CATALOG is a different collection reached by an op command - so
    the parameter exists to keep the signature honest beside its profile sibling rather than to
    be passed.
    """
    entry_rk, entry_rv = entry_provenance(entry)
    # `type` IS A TEXT LEAF AND ITS VALUE IS A DICT ON A PUSHED ENTRY, where @loc decorates the
    # leaf's value and not only the entry: `{"@loc": "shared", "#text": "URL List"}` on every
    # one of this estate's 22 pushed categories. `scalar_value` is the reader that survives it.
    type_text, type_rk, type_rv = scalar_value(entry.get("type"))
    if was_absent(type_rk):
        type_text, type_rk = "", CATEGORY_TYPE_ABSENT
    elif predefined:
        type_rk = PREDEFINED
    match_entries, match_rk, match_rv = member_list_field(
        entry.get("list"), implicit=MATCH_ENTRIES_ABSENT, predefined=predefined)
    return NormalizedCustomUrlCategory(
        source_snapshot=source_snapshot,
        config_source=config_source,
        name=str(entry.get("@name") or ""),
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_for(namespace_type),
        category_type=type_text,
        match_entries=match_entries,
        raw_category=entry,
        field_provenance_data=[
            ("__entry__", entry_rk, entry_rv),
            ("category_type", type_rk, type_rv),
            ("match_entries", match_rk, match_rv),
        ],
    )


@dataclass(frozen=True, slots=True)
class CategoryReference:
    """One thing naming a custom URL category, and where from.

    `shared_scope` is what decides which definitions the referrer can see: a shared referrer
    cannot see vsys definitions, so resolution starts one rung in. Same rule as a profile
    reference - see `_resolve_reference` in security_profiles.py.
    """
    name: str
    referrer: str
    surface: str
    shared_scope: bool


def rule_category_references(root: Any, *, where: str, pushed: bool,
                             shared_root: bool) -> list[CategoryReference]:
    """Every security rule in `root` naming a URL category.

    WALKS FOR THE KEY RATHER THAN THE PATH, like the profile referrer walk and for the same
    reason - an enumerated path list is only as good as its hiding places. The key `category`
    holding a MEMBER LIST is the rule surface and nothing else: measured 2026-10-29 over a
    1.3 MB merged payload, `category` appears as a member list at
    `vsys/entry/rulebase/security/rules/entry/category` and NOWHERE ELSE. The profile rule's own
    `category` is a text leaf and the App-ID catalog's is a text leaf, so both are skipped by
    the shape test alone.

    `any` is dropped: it is the wildcard rather than a category, and every rule on three of the
    four lab appliances holds exactly that.
    """
    found: list[CategoryReference] = []

    def walk(node: Any, path: str, owner: str, owner_loc: str | None) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item, path, owner, owner_loc)
            return
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            if key.startswith("@") or key == "#text":
                continue
            if key == "category" and isinstance(value, dict) and "member" in value:
                shared = (owner_loc == "shared") if pushed else shared_root
                for name, _prov in member_values(value):
                    if name and name != "any":
                        found.append(CategoryReference(
                            name=name, referrer=owner or f"{where}{path}",
                            surface="rulebase/security/rules/entry/category/member",
                            shared_scope=shared))
                continue
            if key == "entry":
                for item in ensure_list(value):
                    if isinstance(item, dict):
                        walk(item, path,
                             f"{where}{path.strip('/')}/{item.get('@name')}",
                             item.get("@loc", owner_loc))
                continue
            walk(value, f"{path}/{key}", owner, owner_loc)

    walk(root, "", "", None)
    return found


#: Which of a url-filtering profile's eleven member-list columns reference a custom category,
#: and the field path each one is. The SITE-ACCESS and CREDENTIAL lists both do - the member
#: pool is identical, measured by `action=complete` at both positions - and so does the
#: exemption list, which is the ONE surface where a custom category is the only possible
#: referent.
PROFILE_REFERENCE_SURFACES = tuple(
    [(column, f"profiles/url-filtering/entry/{key}/member")
     for key, column, _implicit in SITE_ACCESS_LISTS]
    + [(column, f"profiles/url-filtering/entry/credential-enforcement/{key}/member")
       for key, column, _implicit in CREDENTIAL_LISTS]
    + [("inline_analysis_exemptions",
        "profiles/url-filtering/entry/mlav-category-exception/member")]
)


def _surface_label(surface: str) -> str:
    """The part of a reference surface that distinguishes it from its siblings.

    `profiles/url-filtering/entry/allow/member` becomes `allow` and
    `profiles/url-filtering/entry/credential-enforcement/allow/member` becomes
    `credential-enforcement/allow`, so the two cannot produce one referrer string.
    """
    return surface.removeprefix("profiles/url-filtering/entry/").removesuffix("/member")


def profile_category_references(profiles: list) -> list[CategoryReference]:
    """Every custom-category name the url-filtering profiles name, from the rows themselves.

    READ OFF THE NORMALIZED PROFILES AND NOT BY A SECOND WALK, deliberately: the eleven lists
    have already been read through `member_values`, so a walk here would be a second reading of
    one node free to drift from the first - and it would have to re-solve the pushed-member
    shape that is the whole reason the first reading exists.

    A NULL LIST CONTRIBUTES NOTHING AND IS NOT AN EMPTY ONE. Three site-access lists and three
    credential lists store null where stage 4 paid no positive control, so a category named only
    in one of those is invisible to this walk. That is a real limit of the denominator and it is
    why `reference_surfaces_searched` names the surfaces rather than claiming completeness.
    """
    found: list[CategoryReference] = []
    for profile in profiles:
        if profile.kind != SecurityProfile.KIND_URL_FILTERING:
            continue
        shared = scope_for(profile.namespace_type) == PolicyObjectScope.SHARED
        label = (f"url-filtering profile {profile.name} "
                 f"({profile.namespace_type}:{profile.namespace_value})")
        for column, surface in PROFILE_REFERENCE_SURFACES:
            # THE REFERRER STRING CARRIES THE WHOLE SURFACE, not the list's action name. The
            # site-access `allow` list and `credential-enforcement/allow` are different
            # surfaces whose last-but-one path element is the same word, so a label built from
            # that word collapsed two real references into one - and
            # `attribute_category_references` de-duplicates by the string. MEASURED: on serial
            # 6A9C0A9904E7D6E the local profile `all_site_access_actions` names seventeen of the
            # estate's categories in both its site-access `allow` list and its credential
            # `allow` list, and every one of their referrer counts came back exactly one short.
            for name in (profile.url_filtering.get(column) or []):
                found.append(CategoryReference(
                    name=name, referrer=f"{label}/{_surface_label(surface)}",
                    surface=surface, shared_scope=shared))
    return found


def attribute_category_references(
    references: list[CategoryReference], categories: list[NormalizedCustomUrlCategory],
) -> tuple[dict[tuple[str, str, str], list[str]], list[CategoryReference]]:
    """Map each reference to the definition it resolves to: vsys, then shared.

    Returns ({category key: [referrer, ...]}, unresolved references). THE UNRESOLVED LIST IS NOT
    EMPTY IN THIS ESTATE and that is not a collection fault: measured 2026-10-29, both PA-5220s
    hold a security rule whose `category` names `Camera`, and the nearest thing that exists is
    the pushed category `Camera-access`. A reference naming nothing is dropped rather than
    raising, because a rule somebody wrote before this pipeline existed must not take down an
    enforcement point's build.
    """
    by_scope: dict[str, dict[str, NormalizedCustomUrlCategory]] = {
        PolicyObjectScope.VSYS: {}, PolicyObjectScope.SHARED: {},
        PolicyObjectScope.VENDOR: {}}
    for category in categories:
        by_scope[scope_for(category.namespace_type)].setdefault(category.name, category)
    attributed: dict[tuple[str, str, str], list[str]] = {}
    unresolved: list[CategoryReference] = []
    for reference in dict.fromkeys(references):
        scopes = (PolicyObjectScope.ORDER[1:] if reference.shared_scope
                  else PolicyObjectScope.ORDER)
        target = next((by_scope[s][reference.name] for s in scopes
                       if reference.name in by_scope[s]), None)
        if target is None:
            unresolved.append(reference)
            continue
        referrers = attributed.setdefault(target.key, [])
        if reference.referrer not in referrers:
            referrers.append(reference.referrer)
    return attributed, unresolved


def categories_in_scope(
    categories: list[NormalizedCustomUrlCategory], namespace_type: str,
) -> dict[str, str]:
    """{name: category_type} for the custom categories a profile at `namespace_type` can act on.

    THE DENOMINATOR IS A PROPERTY OF THE PROFILE'S SCOPE AND NOT OF THE APPLIANCE, measured: a
    vsys-scoped key-less profile's Categories grid has 113 rows on serial 691665AC334B458 - 90
    predefined plus the custom ones - and a SHARED-scoped profile on the same appliance in the
    same session has 90 and no custom category at all. So a shared profile cannot be given an
    action on a custom category that a vsys profile on the same appliance can.

    A VENDOR-SCOPED profile is treated as a shared one here, which is DERIVED and not measured:
    the predefined `default` is read-only - every control on its dialog grays - so no custom
    category can be given an action on it either way, and the two readings cannot differ in any
    value this model stores.

    Resolution is by scope, most specific first, so a vsys definition shadows a shared one of
    the same name.
    """
    if scope_for(namespace_type) != PolicyObjectScope.VSYS:
        return {}
    resolved: dict[str, str] = {}
    for scope in PolicyObjectScope.ORDER:
        for category in categories:
            if scope_for(category.namespace_type) != scope:
                continue
            resolved.setdefault(category.name, category.category_type)
    return resolved


# --------------------------------------------------------------------------- the verdicts

def effective_site_access_action(
    name: str, values: dict[str, Any], *, is_custom: bool,
) -> str:
    """Which action this profile holds this category at.

    The six lists are mutually exclusive, so the first that holds the name is the answer. The
    DEFAULT when none does is what the two kinds of category differ on, and it is the whole
    reason this is a traversal rather than a lookup:

        a PREDEFINED category defaults to `allow` - the permit is what the device omits, which
        is why a profile permitting all ninety names them nowhere;
        a CUSTOM category defaults to `none` - inert, matching nothing. Measured: a key-less
        profile renders every custom category at `none` and every predefined one at `allow`.
    """
    for key, column, _implicit in SITE_ACCESS_LISTS:
        if name in (values.get(column) or []):
            return key
    return SecurityProfile.URL_ACTION_NONE if is_custom else SecurityProfile.URL_ACTION_ALLOW


def effective_credential_action(
    name: str, values: dict[str, Any], site_access_action: str,
) -> str:
    """Which credential-submission action this profile holds this category at.

    THE SITE-ACCESS COUPLING IS APPLIED HERE AND IT IS NOT STORED ANYWHERE: the device derives
    `block` for every category the site-access `block` list names, with nothing written under
    credential-enforcement. See the module docstring for the measurement.

    The default when no credential list names it and site access does not refuse it is `allow`,
    for the same reason the site-access default is: the permit is the omission.
    """
    if site_access_action == SecurityProfile.URL_ACTION_BLOCK:
        return SecurityProfile.URL_ACTION_BLOCK
    for key, column, _implicit in CREDENTIAL_LISTS:
        if name in (values.get(column) or []):
            return key
    return SecurityProfile.URL_ACTION_ALLOW


@dataclass(slots=True)
class UrlFilteringContext:
    """What a url-filtering row's verdicts need that is not on the entry.

    `catalog` is the device's own category names and `collected` says whether the read
    answered at all - which is a fact about the COLLECTION rather than about the configuration,
    and is why it needs a column of its own.
    """
    catalogue: tuple[str, ...] = ()
    collected: bool = False
    categories: list = field(default_factory=list)


def url_filtering_verdicts(
    values: dict[str, Any], *, namespace_type: str, context: UrlFilteringContext,
) -> dict[str, Any]:
    """The twenty-seven DERIVED url-filtering columns for one profile row.

    {} is never returned: every column is written, because each one's default is a claim and
    leaving the model's default standing on a url-filtering row would make "nobody computed
    this" indistinguishable from "this is the answer" on exactly the columns stage 5 says must
    be able to tell those apart.
    """
    custom = categories_in_scope(context.categories, namespace_type)
    catalogue = list(context.catalogue)
    # THE CATALOGUE IS COLLECTED OR IT IS NOT, and for a profile whose scope admits custom
    # categories the custom collection is part of the answer. A shared or vendor profile has no
    # custom categories in scope, so only the operational read decides.
    collected = bool(catalogue) and context.collected

    out: dict[str, Any] = {}
    out["category_catalogue_collected"] = collected
    out["category_catalogue_size"] = (len(catalogue) + len(custom)) if collected else None

    # EVERY CATEGORY THE PROFILE CAN ACT ON, with the action it holds. Built once: nine of the
    # columns below are different questions of this one map.
    actions: dict[str, str] = {}
    if collected:
        for name in catalogue:
            actions[name] = effective_site_access_action(name, values, is_custom=False)
        for name in custom:
            actions[name] = effective_site_access_action(name, values, is_custom=True)

    # ---- PAN-URL-001: the three confirmed-hostile categories.
    hostile = {name: actions.get(name) for name in SecurityProfile.HOSTILE_URL_CATEGORIES}
    unblocked = [{"category": name, "action": action}
                 for name, action in hostile.items()
                 if action is not None and action != SecurityProfile.URL_ACTION_BLOCK]
    out["all_hostile_categories_blocked"] = bool(
        collected and all(a == SecurityProfile.URL_ACTION_BLOCK for a in hostile.values()))
    out["unblocked_hostile_categories"] = unblocked
    out["weakest_hostile_category_action"] = (
        weakest_member([a for a in hostile.values() if a],
                       SecurityProfile.URL_ACTION_WEAKEST_FIRST) if collected else None)

    # ---- PAN-URL-002: reachable AND unlogged, over the catalogue MINUS the three above, which
    # PAN-URL-001 owns. A category refused outright is not reachable; one at `none` is inert and
    # matches nothing, so it is not reachable either.
    graded = [n for n in actions if n not in SecurityProfile.HOSTILE_URL_CATEGORIES]
    unlogged = [{"category": n, "action": actions[n]} for n in sorted(graded)
                if actions[n] in SecurityProfile.URL_UNLOGGED_ACTIONS]
    out["all_reachable_categories_logged"] = bool(collected and not unlogged)
    out["reachable_unlogged_categories"] = unlogged
    out["reachable_unlogged_category_count"] = len(unlogged) if collected else None
    out["worst_reachable_unlogged_category"] = (
        weakest_member([c["category"] for c in unlogged],
                       SecurityProfile.URL_CATEGORY_RISK_WORST_FIRST) if collected else None)

    # ---- PAN-URL-003: corporate credential submission.
    credential = {n: effective_credential_action(n, values, actions[n]) for n in actions}
    out["credential_submission_blocked_for_every_category"] = bool(
        collected and actions
        and all(a == SecurityProfile.URL_ACTION_BLOCK for a in credential.values()))
    permissive = [{"category": n, "action": credential[n]} for n in sorted(actions)
                  if actions[n] in SecurityProfile.URL_REACHABLE_ACTIONS
                  and credential[n] == SecurityProfile.URL_ACTION_ALLOW]
    out["all_reachable_categories_credential_restricted"] = bool(collected and not permissive)
    out["credential_permissive_categories"] = permissive
    out["credential_permissive_category_count"] = len(permissive) if collected else None
    out["worst_credential_permissive_category"] = (
        weakest_member([c["category"] for c in permissive],
                       SecurityProfile.URL_CATEGORY_RISK_WORST_FIRST) if collected else None)

    # ---- PAN-URL-004: the three request headers. NO CATALOGUE NEEDED - the three inputs are
    # this row's own booleans and are never null, so these four columns are the only ones in
    # this family that are answered on every row.
    missing = [label for column, label in SecurityProfile.REQUEST_HEADER_LABELS
               if not values.get(column)]
    out["records_all_request_headers"] = not missing
    out["unrecorded_request_headers"] = missing
    out["unrecorded_request_header_count"] = len(missing)
    out["worst_unrecorded_request_header"] = missing[0] if missing else ""

    # ---- PAN-URL-005: the two real-time page analysis engines and the exemption list.
    local = values.get("local_inline_categorization")
    exemptions = values.get("inline_analysis_exemptions")
    out["local_inline_categorization_on"] = local is True
    out["local_inline_categorization_undetermined"] = local is None
    out["any_inline_analysis_engine_on"] = bool(
        values.get("cloud_inline_categorization")) or local is True
    out["inline_analysis_exemptions_computed"] = exemptions is not None
    out["inline_analysis_exemption_count"] = len(exemptions or [])
    # THE REACH ACROSS TO THE CATEGORY'S OWN TYPE, which is what makes this derived rather than
    # measured. It fails silently where the TARGET row is missing, so the type is null on
    # exactly the estate where the categories are in force through the pushed read and nobody
    # issued it - which is why `categories_in_scope` is resolved and not assumed.
    exempt_types = [custom[n] for n in (exemptions or []) if custom.get(n)]
    out["broadest_inline_analysis_exemption_type"] = weakest_member(
        exempt_types, SecurityProfile.URL_CATEGORY_TYPE_BROADEST_FIRST)

    # ---- PAN-URL-006's second record: custom-category carve-outs.
    #
    # THE INVENTORY AND THE COUNT ARE BOTH OVER `allow_categories`, which is stage 5's own
    # `computes` for the count: "the number of names in `allow_categories` whose referent is a
    # custom URL category". So the only action an entry here can hold is `allow`, and the
    # declared value set's other member - the inert action - cannot arise. That mismatch is
    # recorded in the stage 7 artifact's spec_gaps rather than resolved here: holding the inert
    # action would mean the inventory covered every in-scope custom category rather than the
    # permitted ones, and `stores` says it covers the ones the profile PERMITS.
    permitted = [{"category": n, "action": SecurityProfile.URL_ACTION_ALLOW}
                 for n in sorted(values.get("allow_categories") or []) if n in custom]
    out["permitted_custom_categories"] = permitted
    out["permitted_custom_category_count"] = len(permitted)
    out["weakest_permitted_custom_category_action"] = (
        SecurityProfile.URL_ACTION_ALLOW if permitted else None)
    return out


# --------------------------------------------------------------------------- writing

def replace_custom_url_categories(
    owner: EnforcementPoint | ApplianceGroup,
    categories: list[NormalizedCustomUrlCategory],
    referrers: dict[tuple[str, str, str], list[str]],
    surfaces_searched: tuple[str, ...] = CustomUrlCategory.REFERENCE_SURFACES,
) -> list[CustomUrlCategory]:
    """Write the definitions `owner` owns, replacing what it holds.

    As `replace_security_profiles`: the caller passes everything visible from the point and this
    keeps its own share, because shared scope belongs to the appliance group - the unit that
    holds ONE /config/shared and one Panorama-Shared push. Storing a shared-scoped object per
    enforcement point copied a single observation once per vsys.
    """
    from_shared = scope_for
    keep_here = (
        (lambda c: from_shared(c.namespace_type) != PolicyObjectScope.SHARED)
        if isinstance(owner, EnforcementPoint)
        else (lambda c: from_shared(c.namespace_type) == PolicyObjectScope.SHARED))
    owner_kwargs = ({"enforcement_point": owner} if isinstance(owner, EnforcementPoint)
                    else {"appliance_group": owner})
    owner.custom_url_categories.all().delete()

    content_type = ContentType.objects.get_for_model(CustomUrlCategory)
    created: list[CustomUrlCategory] = []
    for normalized in (c for c in categories if keep_here(c)):
        used_by = referrers.get(normalized.key, [])
        row = CustomUrlCategory.objects.create(
            management_station=owner.management_station, **owner_kwargs,
            source_snapshot=normalized.source_snapshot,
            config_source=normalized.config_source,
            name=normalized.name, namespace_type=normalized.namespace_type,
            namespace_value=normalized.namespace_value,
            precedence_rank=normalized.precedence_rank,
            category_type=normalized.category_type,
            match_entries=normalized.match_entries,
            match_entry_count=normalized.match_entry_count,
            # WHETHER THE LIST WAS READ AND COUNTED, which is what separates a category that
            # matches nothing from one nobody read. The count is nullable for exactly that
            # reason and this boolean is how a query asks about the null.
            match_entry_count_computed=normalized.match_entries is not None,
            referrer_count=len(used_by), is_used=bool(used_by),
            reference_surfaces_searched=list(surfaces_searched),
            raw_category=normalized.raw_category,
            last_synced_at=normalized.source_snapshot.collected_at,
        )
        rows = [FieldProvenance(
            content_type=content_type, object_id=row.pk, field_name=name,
            provenance_type=classify_prov_type(rk), raw_key=provenance_raw_key(rk),
            raw_value=provenance_value(rk, rv))
            for name, rk, rv in normalized.field_provenance_data if rk is not ABSENT]
        if rows:
            FieldProvenance.objects.bulk_create(rows)
        created.append(row)
    return created


__all__ = [
    "CATEGORY_COLLECTION",
    "CategoryReference",
    "NormalizedCustomUrlCategory",
    "PROFILE_COLLECTION",
    "PROFILE_REFERENCE_SURFACES",
    "URL_CATEGORY_CATALOGUE_SOURCE_TYPE",
    "UrlFilteringContext",
    "attribute_category_references",
    "categories_in_scope",
    "effective_credential_action",
    "effective_site_access_action",
    "latest_url_category_catalogue_snapshot",
    "member_list_field",
    "normalize_custom_url_category",
    "profile_category_references",
    "replace_custom_url_categories",
    "rule_category_references",
    "url_category_catalogue",
    "url_filtering_profile_values",
    "url_filtering_verdicts",
]
