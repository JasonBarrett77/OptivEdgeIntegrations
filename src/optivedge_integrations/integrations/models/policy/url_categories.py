"""Objects > Custom Objects > URL Category - the named list a URL filtering profile points at.

PAN-URL-006's subject, and a subject in its own right rather than a detail of the profile: the
control asserts over the OBJECT - whether anything points at it - and the entry's one mandatory
key decides which of two incompatible things it is, which changes the reading of every profile
that names it.

A POLICY OBJECT IN THE PAN-OS SENSE. It lives under `vsys/entry/profiles/custom-url-category`
or `shared/profiles/custom-url-category`, arrives from Panorama through the pushed read, and a
profile's member list names it - so it scopes exactly like an address object: vsys scope on the
enforcement point, shared scope on the appliance group. See `ScopedPolicyObject`.

NO `kind` COLUMN, deliberately. `category_type` discriminates what the entry MATCHES and not
what kind of row it is: both types are the same shape with the same three keys, so the type is a
graded column rather than part of the identity.

@uuid IS AN IDENTITY ON THE DEVICE AND IS DELIBERATELY NOT THIS ROW'S. Measured 2026-10-29 on
serial 691665AC334B458: every custom-url-category entry carries one and no url-filtering profile
entry does, and it survives the commit where the @dirtyId stamps do not. A finding joins on the
NAME a profile's member list holds, which is the only thing a reference carries.

WHAT THIS MODEL CANNOT SAY, and it is a real asymmetry rather than an untested step: a custom
category's MEMBERSHIP is readable from configuration and its RESOLUTION is readable from nowhere.
The predefined catalogue has an op command; this collection has none - `show system state filter`
was searched for *url*, *category* and *custom* and the CLI index for two terms, and the compiled
state tree has nothing for this object. So a `Category Match` entry's actual reach - the
INTERSECTION of the predefined categories its `list` names, not their union - is not stored and
cannot be.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from ..collected import ApplianceGroup, EnforcementPoint, ManagementStation
from .objects import ScopedPolicyObject


class CustomUrlCategory(ScopedPolicyObject):

    #: Computed here: the member count, the referrer walk and what the walk covered. None of
    #: them has a payload key, so none can carry a provenance row. See
    #: ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "match_entry_count",
        "match_entry_count_computed",
        "is_used",
        "referrer_count",
        "reference_surfaces_searched",
    )

    #: The two values the `type` leaf holds, measured on all three lab builds. A `URL List`
    #: matches the named sites; a `Category Match` matches sites in ALL of the predefined
    #: categories its members name.
    TYPE_URL_LIST = "URL List"
    TYPE_CATEGORY_MATCH = "Category Match"
    TYPE_CHOICES = [
        (TYPE_URL_LIST, "URL List"),
        (TYPE_CATEGORY_MATCH, "Category Match"),
    ]

    #: Every reference surface the walk behind `is_used` covers, by field path. STORED ON THE
    #: ROW rather than only written here, because a finding that says `unreferenced` has to say
    #: where it looked - and the denominator is 4 surfaces of roughly 39. Stage 2's referrer
    #: enumeration returns 39 referrer fields pooling 69 scopes; authentication rules,
    #: decryption rules, quality-of-service rules, two other profile types' exception lists,
    #: twelve fields on an AI-security profile and a secure-web-gateway allowed-category field
    #: at template scope are NOT among these.
    REFERENCE_SURFACES = (
        "profiles/url-filtering/entry/block/member",
        "profiles/url-filtering/entry/alert/member",
        "profiles/url-filtering/entry/allow/member",
        "profiles/url-filtering/entry/continue/member",
        "profiles/url-filtering/entry/override/member",
        "profiles/url-filtering/entry/isolate/member",
        "profiles/url-filtering/entry/credential-enforcement/block/member",
        "profiles/url-filtering/entry/credential-enforcement/alert/member",
        "profiles/url-filtering/entry/credential-enforcement/allow/member",
        "profiles/url-filtering/entry/credential-enforcement/continue/member",
        "profiles/url-filtering/entry/mlav-category-exception/member",
        "rulebase/security/rules/entry/category/member",
    )

    management_station = models.ForeignKey(
        ManagementStation, on_delete=models.CASCADE, related_name="custom_url_categories")
    enforcement_point = models.ForeignKey(
        EnforcementPoint, on_delete=models.CASCADE, related_name="custom_url_categories",
        null=True, blank=True)
    appliance_group = models.ForeignKey(
        ApplianceGroup, on_delete=models.CASCADE, related_name="custom_url_categories",
        null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE, related_name="custom_url_categories")

    #: WHICH OF TWO INCOMPATIBLE THINGS THIS ENTRY IS, and the dangerous value is the minority
    #: one - 5 of this estate's 22 - and it is invisible in the member list of any profile that
    #: names it.
    #:
    #: THE KEY IS MANDATORY AT COMMIT VALIDATION, so it has no absent state and an absence
    #: asserts nothing. Three commits on two platforms established it: `Validation Error: ... is
    #: missing 'type' / custom-url-category is invalid` on serial 691665AC334B458 job 191 and
    #: the same message naming vsys3 on 013201001475 jobs 492 and 493 - while `action=set`
    #: accepted the key-less entry without comment and `action=complete` reported `type`
    #: exactly like its optional siblings. Stage 2 recorded a schema default of `URL List` for
    #: this leaf and it asserts nothing.
    #:
    #: ON A PUSHED ENTRY THE VALUE IS A DICT, NOT A STRING: `type` reads
    #: {"@loc": "shared", "#text": "URL List"} on every one of this estate's 22 pushed
    #: categories, so `type == "URL List"` is FALSE on all of them and DOES NOT RAISE. Blank
    #: here therefore means the row came from somewhere that did not carry the key, which in
    #: practice means that dict was read as a bare string.
    category_type = models.CharField(
        max_length=32, choices=TYPE_CHOICES, blank=True, default="")

    #: What this category matches - a list of URL patterns on a `URL List` entry, or a list of
    #: PREDEFINED CATEGORY NAMES on a `Category Match` one. The same key holds two incompatible
    #: kinds of thing and only `category_type` says which.
    #:
    #: NULL IS NOT AN EMPTY LIST. Stage 4 wrote no member to this key at all, so nothing
    #: establishes what an absent `list` asserts: an entry with no members matches nothing,
    #: which for a `URL List` is inert and for a `Category Match` is unmeasured.
    #: `Implicit.not_assumed` is what writes the null.
    match_entries = models.JSONField(null=True, blank=True, default=None)

    #: The breadth an engineer sees before deciding whether an unreferenced category is safe to
    #: remove. NULLABLE rather than 0, because 0 means "this category matches nothing" - a real
    #: and inert state - and a stored 0 on an unrecomputed row would claim it.
    match_entry_count = models.PositiveIntegerField(null=True, blank=True, default=None)
    #: The companion that makes the null askable: there is no is-null operator in the query
    #: language. FALSE means the count beside it is a migration default and not a reading.
    match_entry_count_computed = models.BooleanField(default=False)

    #: PAN-URL-006. FALSE means unreferenced, which is the FINDING side - so an unwalked row
    #: reports as unreferenced and every error this reading makes is in that direction. The
    #: risk is a service-affecting change on a live object, which is why stage 3 bounds the
    #: deliverable to candidates for review and never a removal instruction.
    is_used = models.BooleanField(default=False)
    referrer_count = models.PositiveIntegerField(default=0)
    #: Which of `REFERENCE_SURFACES` the walk that produced `is_used` actually covered. Empty
    #: means no surface was searched, which is what an unwalked row holds, and it is presented
    #: beside the finding so that `unreferenced` is never printed without its denominator.
    reference_surfaces_searched = models.JSONField(default=list, blank=True)

    #: For the tab and for inspection. A control queries the columns above, never this - see
    #: CLAUDE.md, "A control queries columns, never JSON".
    raw_category = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "name", "precedence_rank"]),
            models.Index(fields=["appliance_group", "name", "precedence_rank"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_custom_url_category_per_point",
            ),
            models.UniqueConstraint(
                fields=["appliance_group", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_custom_url_category_per_group",
            ),
        ]

    def clean(self) -> None:
        """The scoped-object checks, plus the count/list agreement CLAUDE.md requires.

        A null count has no list to disagree with: it means nobody computed one.
        """
        super().clean()
        if self.match_entry_count is None:
            return
        if self.match_entry_count != len(self.match_entries or []):
            raise ValidationError(
                f"match_entry_count={self.match_entry_count} disagrees with match_entries, "
                f"which holds {len(self.match_entries or [])}")

    def __str__(self) -> str:
        return f"{self.name} ({self.category_type or 'type not read'})"
