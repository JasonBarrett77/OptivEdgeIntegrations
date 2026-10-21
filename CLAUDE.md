# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

**Every claim here names the file and line that checks it.** Nothing here is a claim about
PAN-OS behaviour or about this repo's history: vendor behaviour belongs in `docs/` and in a
normalizer's `Implicit` citation, history belongs in git. If a line here contradicts the code
it cites, the code wins and the line is a defect — fix it in the same change.

Paths are relative to `src/optivedge_integrations/integrations/` unless they begin with `./`,
which means the repository root.

## Principles, which cite nothing

**Every other claim in this file names the code that checks it. These do not, and that is
deliberate** - decided by Jason, 2026-10-21. A principle that shapes every judgement is worth more
than any single checkable claim, and the honest cost is that nobody can re-audit it mechanically.
Keep this list to a handful. Anything that CAN cite code belongs below instead.

- **Failure must be proportionate to what is unknown.** It is the reasoning behind
  `pushed_entry_scope`'s visible fallback, the per-entry issue model, and `pushed_shared()`
  raising where `pushed_vsys_panorama()` returns `{}`. Losing one object's scope is not a reason
  to fail an enforcement point's whole build; being handed a shape nobody has seen is.

**`./DECISIONS.md` holds what this file deliberately excludes**: decisions about code that LOOKS
dead and is not, and shapes that look wrong and are deliberate. Read it before deleting anything
that appears unused - four routes nothing links to, a notes feature knowingly broken, and a
missing list page are all there with the reason and who decided.

## What this repository is

A reusable Django **domain package** — firewall config collection, normalization, storage. A
downstream project owns `manage.py`, root settings, root URLs and the database; this repo has
none of them (`./DEPLOYMENT.md:9-11`). It depends on **OptivEdge**, declared as a git URL
(`./pyproject.toml:21`), which supplies `base.html`, the shared components, the plugin registry
and `optivedge.urls`.

`OptivEdge/DEPLOYMENT.md` is the single authority on host-project wiring; `./DEPLOYMENT.md`
covers only what is specific to this package and defers to it (`./DEPLOYMENT.md:3-6`). Read
both before changing anything a downstream project consumes.

This package contains no authentication or authorization: a grep of `src/` for
`LoginRequiredMixin`, `login_required` and `PermissionRequired` returns nothing. Every view,
`/developer/` included (`views.py::DeveloperView`), is open unless the host project gates it.

## Commands

Two installs, not one: `optivedge` is a git URL here (`./pyproject.toml:21`), which pip treats
as conflicting with a local editable of the same package.

```bash
python -m pip install -e ~/PythonProjects/OptivEdge
python -m pip install -e . --no-deps
```

The test suite runs against `./tests/settings.py` — test-only settings, not a wiring example
(`./tests/settings.py:1-13`) — which sets `ROOT_URLCONF = "optivedge.urls"`
(`./tests/settings.py::ROOT_URLCONF`) and so needs `optivedge` installed beside this package:

```bash
DJANGO_SETTINGS_MODULE=tests.settings python -m django test optivedge_integrations.integrations
```

Tests live in `tests.py` and `tests_security_profiles.py`. Anything exercising migrations, other
installed apps or a real database needs a downstream project.

## Where a PAN-OS claim goes

`docs/<vendor>/<api-surface>/` records how to read a vendor's configuration without getting a
plausible wrong answer. It is partitioned by API surface, not product role
(`docs/README.md:12-22`), and it is explicitly not architecture — that is this file
(`docs/README.md:3-5`). Each guide names the devices and versions it was established against,
and anything unmeasured is marked inline (`docs/README.md:50-54`). Start at
`docs/palo-alto/pan-os/read-config-sources.md`.

A statement about what PAN-OS does cannot be checked against this repository, so it does not
belong in this file.

**A question about what PAN-OS does, that nobody here can answer, goes to
`OptivEdgeProbe/archive/requests/`.** That is where this project's questions about device
behaviour are recorded and where their answers come back - `open/` is asked and not yet
worked, `answered/` is the same file moved, carrying the answer and an `open:` list of what
it did NOT settle. Read it before measuring anything yourself: a question already answered
there is cheaper to look up than to re-derive, and one already open tells you somebody is
waiting on the same thing.

## App boundaries

- `optivedge_integrations` is a distribution root, not a Django app: it holds only
  `./src/optivedge_integrations/settings/components.py::OPTIVEDGE_INTEGRATIONS_APPS` and the `integrations` app.
- The app label is **`integrations`** and differs from the package name (`apps.py::IntegrationsConfig`).
  Renaming it breaks migrations, content types and every `"integrations.X"` reference.
- `ready()` imports `lifecycle` (`apps.py::ready`); that import is what connects the
  `server_started` receiver. A new receiver needs the same treatment.
- `app_meta.py` is the whole integration surface with the shell: `URL_MOUNT`
  (`app_meta.py::URL_MOUNT`), `HEALTH_INDICATOR` (`app_meta.py::HEALTH_INDICATOR`), `SIDEBAR_SECTION`
  (`app_meta.py::SIDEBAR_SECTION`). New routes go in `urls.py`; this package never owns root.
- **A new route name must be added to the sidebar item's `active_names`**
  (`app_meta.py::SIDEBAR_SECTION`), or the sidebar silently stops highlighting on that page. Asserted for
  the enforcement-point pages at `tests.py::test_enforcement_point_pages_light_up_management_stations`.
- `/developer/` is deliberately absent from `SIDEBAR_SECTION`, and a test keeps it that way
  (`tests.py::test_page_is_not_advertised_in_the_sidebar`).
- `package-data` must list every shipped non-`.py` file (`./pyproject.toml:27-35`); a wheel
  missing one installs an app that cannot hand out the file it exists to hand out.

## Provenance: one mechanism, no alternatives

`ProvenancedMixin` (`models/provenance.py::ProvenancedMixin`) plus `FieldProvenance` rows
(`models/provenance.py::FieldProvenance`) are how a normalized model records where a value came from. One row
per tracked field per object, unique on `(content_type, object_id, field_name)`
(`models/provenance.py::FieldProvenance`). Do not add a second mechanism.

`field_name="__entry__"` records the entry's own provenance rather than a field's
(`models/provenance.py::FieldProvenance`). A model whose row **is** a single value still uses the mixin
with `__entry__` for that value — `PermittedSource` (`models/management_interface.py::PermittedSource`) and
`ManagementService` (`models/management_interface.py::ManagementService`).

Member and tag models are the exception: they store a plain `prov = CharField`
(`models/policy/rules.py::SecurityRuleValue`, `models/policy/objects.py::AddressObjectTag`) fed by
`platforms/pan_os/normalization/common.py::iter_member_values`. Do not convert them opportunistically, and
do not extend the pattern to anything else.

### A missing row means one thing: nothing tracks that field

An absent payload key **records a row too** (`models/provenance.py::FieldProvenance`). There are ten
provenance types (`models/provenance.py::ProvenanceType`): four for a present key
(`local`/`template`/`device_group`/`panorama`), one for a present vendor-shipped entry
(`predefined`), three for an absent key
(`pan_os_default`/`assumed_default`/`not_configured`), `derived`, which is never stored, and
`unknown`, which is the only member the enum does not document and which belongs to none of the
groupings - if you are reaching for it, that is the sign to ask rather than to store it.

Consumers ask the grouped constants rather than listing types — `ABSENT_TYPES` for "did anyone
configure this", `DEFAULTED_TYPES` for "is the stored value a default"
(`models/provenance.py::FieldProvenance`).

`derived` is a **declaration**, not a row: name the column in the model's `DERIVED_FIELDS`
(`models/provenance.py::ProvenancedMixin`), which is what `provenance_for()` answers from
(`models/provenance.py::provenance_for`). `DerivedFieldDeclarationTests` (`tests.py::DerivedFieldDeclarationTests`) fails if a
declared field has a stored row, or if a declared name is not a real field.

### Reading a leaf

All of these are in `platforms/pan_os/normalization/common.py`, which the rest of this section
abbreviates to `common.py`. Use them rather than inspecting markers by hand.

Each row cites the DEFINITION rather than a line, because a line number in this file rots
silently and a renamed helper should fail loudly: `python -m probe.cite_check` in OptivEdgeProbe
resolves them all.

| helper | checks at | for |
|---|---|---|
| `parse_yes_no_field(node, *, implicit=)` | `platforms/pan_os/normalization/common.py::parse_yes_no_field` | a yes/no leaf, absence declared |
| `parse_integer_field(node, *, implicit=)` | `platforms/pan_os/normalization/common.py::parse_integer_field` | an integer leaf, absence declared |
| `parse_text_field(node, *, implicit=)` | `platforms/pan_os/normalization/common.py::parse_text_field` | a text leaf, absence declared |
| `scalar_value(node)` | `platforms/pan_os/normalization/common.py::scalar_value` | low-level; returns `ABSENT` and writes no row |
| `entry_provenance(entry)` | `platforms/pan_os/normalization/common.py::entry_provenance` | a named entry's own marker (`@ptpl`/`@loc` only) |
| `classify_prov_type(raw_key)` | `platforms/pan_os/normalization/common.py::classify_prov_type` | raw key → `ProvenanceType` value |
| `was_absent(raw_key)` | `platforms/pan_os/normalization/common.py::was_absent` | the only correct absence test; see below |
| `ABSENT`, `PREDEFINED` | `platforms/pan_os/normalization/common.py::ABSENT`, `platforms/pan_os/normalization/common.py::PREDEFINED` | raw-key sentinels |

`implicit=` is not optional, deliberately (`platforms/pan_os/normalization/common.py::parse_yes_no_field`). Declare it with
`Implicit.measured(value, citation)` (`platforms/pan_os/normalization/common.py::measured`), `Implicit.assumed(value, why)`
(`platforms/pan_os/normalization/common.py::assumed`) or `Implicit.not_assumed(why)` (`platforms/pan_os/normalization/common.py::not_assumed`). The bare constructor refuses
to build one that says neither (`platforms/pan_os/normalization/common.py::__post_init__`), and a citation under 12 characters is
rejected as uncheckable (`platforms/pan_os/normalization/common.py::__post_init__`, `platforms/pan_os/normalization/common.py::measured`).

**A tracked field read through bare `scalar_value` gets `ABSENT` and writes no row**
(`platforms/pan_os/normalization/common.py:14-16`, `platforms/pan_os/normalization/common.py::scalar_value`), which then states "nothing tracks this field" about a
field nobody configured. Read it through a `parse_*_field`.

Three traps, all of which type-check:

- `Implicit.assumed(None, why)` records `not_configured`, not `assumed_default`, because
  `stores_nothing` turns on value and citation both being absent (`platforms/pan_os/normalization/common.py::Implicit`). For a
  text field whose inferred value is "nothing", write `Implicit.assumed("", why)`.
- `raw_key is ABSENT` is no longer the absence test — an absent key arrives as an `Implicit`.
  Ask `was_absent()` (`platforms/pan_os/normalization/common.py::was_absent`).
- A vendor-shipped entry must be given `PREDEFINED` as its raw key by the **reading** site
  (`platforms/pan_os/normalization/common.py:19-25`), because no payload key marks it and the fallthrough in
  `classify_prov_type` is `local` (`platforms/pan_os/normalization/common.py::classify_prov_type`).

### The marker key set

`_PROVENANCE_KEYS = ("@ptpl", "@loc", "@panorama")` (`platforms/pan_os/normalization/common.py::_PROVENANCE_KEYS`) is what `scalar_value`
scans and what `classify_prov_type` maps (`platforms/pan_os/normalization/common.py::classify_prov_type`). `entry_provenance` checks
`@ptpl` and `@loc` only, because at entry level `@panorama` is a boolean routing flag
(`platforms/pan_os/normalization/common.py::entry_provenance`).

`@src` sits outside that set and is handled in exactly one module, which maps it to `PANORAMA`
for an entry (`platforms/pan_os/normalization/interface_management_profiles.py::PROVENANCE_ATTRIBUTES`). If you
need `@src` elsewhere, decide it deliberately rather than assuming either answer.

How much provenance survives an override is in
`docs/palo-alto/pan-os/read-template-provenance.md`.

**`@overrides` is a fourth marker, and it is DELIBERATELY NOT SCANNED.** Decided by Jason,
2026-10-21. Measured on a lab firewall the same day: it names the nearest ancestor DEVICE
GROUP whose copy a device-group object displaces, and it appears under `action=get` only.

Two reasons, and the second is the stronger one.

A finding reports WHERE A FIX GOES. That is the device group now defining the value, which
`@loc` already gives. The displaced copy is history - it tells you what the value used to
be somewhere else, which no control asserts and no customer acts on.

And **`@overrides` is ABSENT when the displaced copy is the Shared device group's**, so a
missing value means both "nothing was displaced" and "Shared's copy was displaced". A
column that cannot tell those apart is worse than no column: it reads as an answer. If a
control ever needs the displaced copy, that ambiguity has to be solved before the column
is worth adding.

The measurement is claim S-094 in `OptivEdgeProbe reference/config-sources-and-provenance-claims.json`.
Nothing in `platforms/` reads `@overrides`; the only `overrides` in this package is
`application_overrides` on a security profile, which is unrelated.

## A control queries columns, never JSON

A `JSONField` here is for display and inspection. If a control needs a value inside one,
promote it to a real column in normalization and let the control query that — a JSON lookup is
unindexed and matches nothing when the vendor renames a key, so a control resting on one stops
finding anything instead of failing (`models/wildfire_settings.py::WildfireSettings`). The pattern is a
JSON field paired with the column a control actually reads
(`models/wildfire_settings.py::WildfireSettings`); `models/policy/search.py::SecurityRuleSearchVocabularyEntry` is the precomputed
searchable form for rule grounding.

**A column derived from a JSON field gets a `clean()` asserting the two agree** —
`models/interface_management_profile.py::clean` (count against names) and
`models/certificates.py::Certificate` (verdict against the values it came from).

## Topology and ownership

```
ManagementStation            models/collected.py:12    Panorama or standalone-firewall connection
 └─ ApplianceGroup           models/collected.py:41    standalone / ha_pair / cluster
     └─ Appliance            models/collected.py:107   keyed by serial_number per station
         └─ EnforcementPoint models/collected.py:148   a vsys
             └─ EnforcementNode  models/collected.py:227  an Appliance joined into a point
Snapshot                     models/collected.py:270   raw payload + metadata
```

- An `EnforcementPoint` has **exactly one** of `appliance` / `appliance_group`, enforced in
  `clean()` (`models/collected.py::EnforcementPoint`), and carries two conditional `UniqueConstraint`s —
  one point per vsys name per owner (`models/collected.py::EnforcementPoint`). That guarantee is not
  expressible through `EnforcementNode`; preserve it in any replacement.
- **"Is this Panorama-managed?" is `is_panorama_managed()`**
  (`platforms/pan_os/normalization/snapshots.py::is_panorama_managed`), which reads
  `ManagementStation.station_type`. Never infer it from `appliance_group` being set — a
  locally-managed HA pair is exactly what `ApplianceGroup` is for. Four normalizers and the
  address explainer gate on that one function; extend it rather than re-deriving it.
- The key is `vsys_name`: both unique constraints are on it
  (`models/collected.py::EnforcementPoint`), and `vsys_display_name` carries none
  (`models/collected.py::EnforcementPoint`). Never match, join or re-key on the display name; why is in
  `docs/palo-alto/pan-os/identify-a-vsys.md`.
- `in_scope` (`models/collected.py::EnforcementPoint`) is what collection follows, through the
  `get_in_scope_*` helpers (`platforms/pan_os/flows.py::get_in_scope_appliances`, `:422`, `:429`).
- Which appliance's merged config speaks for an enforcement point is
  `choose_local_appliance()` (`platforms/pan_os/normalization/snapshots.py::choose_local_appliance`). Device-wide
  settings take an appliance directly, so they produce a row per HA node.
- A `Snapshot` attaches to **exactly one** scope target, enforced in `clean()`
  (`models/collected.py::Snapshot`). Everything downstream traces back to one.
- A scoped policy object has exactly one owner and the owner must match the scope: shared scope
  belongs to the appliance group, vsys scope to the enforcement point
  (`models/policy/objects.py::ScopedPolicyObject`).
- **Shared scope is rebuilt before any of its enforcement points**, because replacing addresses
  is a delete-and-recreate that rule address refs FK into
  (`platforms/pan_os/flows.py::renormalize_in_scope_configuration`). The entry point is
  `normalize_appliance_group_shared_scope()` (`platforms/pan_os/normalization/__init__.py::normalize_appliance_group_shared_scope`).
- `DeviceGroupBinding` is **derived** from `device_group` provenance rows and means "has pushed
  here", not "is assigned here" (`device_group_bindings.py:1-11`). It is rebuilt after the
  refresh, from the rows that refresh just wrote, inside the helper both refresh paths use
  (`views.py::_refresh_station_in_scope_tracked`).

## Policy object scope and precedence

`PolicyObjectNamespace` records where a definition came from (`models/policy/base.py::PolicyObjectNamespace`);
`PolicyObjectScope` is the axis that decides which one wins (`models/policy/base.py::PolicyObjectScope`);
`SCOPE_BY_NAMESPACE` maps one to the other (`models/policy/base.py::SCOPE_BY_NAMESPACE`).

- Walk `PolicyObjectScope.ORDER` explicitly; do not sort (`models/policy/base.py::PolicyObjectScope`).
- `scope_for()` raises on a namespace it does not know (`models/policy/base.py::scope_for`): a new
  namespace must state its scope.
- `precedence_for()` derives the rank (`models/policy/base.py::precedence_for`). Never write a rank
  literal, or the rank and the namespace can disagree.
- A pushed entry's scope comes from `@loc`, never from which query returned it, in one
  implementation — `pushed_entry_scope()`
  (`platforms/pan_os/normalization/common.py::pushed_entry_scope`). Its unmarked fallback stays visible
  through `pushed_entry_is_unmarked()` (`platforms/pan_os/normalization/common.py::pushed_entry_is_unmarked`).
- `name_is_owned()` (`platforms/pan_os/normalization/security_rules.py::name_is_owned`) is the single
  definition of "does anything here already answer to this name". Rule resolution and literal
  synthesis must both ask it; two answers let a synthetic row shadow a real object.
- Rule normalization order is maps → synthesis → resolution, and the comment there says why
  (`platforms/pan_os/normalization/security_rules.py::replace_security_rules`). Do not move synthesis into the
  per-rule loop.

## Normalization failures

Per-entry failures are `PolicyObjectIssue` (`platforms/pan_os/normalization/types.py::PolicyObjectIssue`);
`severity` describes the problem, `disposition` describes what was done, and the two are
independent (`platforms/pan_os/normalization/types.py::PolicyObjectIssue`). Point-level reads — a missing
snapshot, an unrecognisable payload root — still raise, because there is nothing to iterate
(`platforms/pan_os/normalization/addresses.py::build_normalized_addresses`); otherwise a builder returns its issues
alongside its results (`platforms/pan_os/normalization/addresses.py::build_normalized_addresses`,
`platforms/pan_os/normalization/regions.py::build_normalized_regions`).

`NormalizationIssue` (`models/normalization.py::NormalizationIssue`) persists them and is **state, not history**:
replaced per owner on every run, which makes "is anything wrong now?" an `EXISTS`
(`models/normalization.py:1-14`). Three owners — enforcement point, appliance group, appliance —
because the work has three scopes, and owning an appliance's issues by group would have one HA
peer's run delete the other's (`models/normalization.py::NormalizationIssue`). `is_consequent` marks an issue
caused by another issue in the same run (`models/normalization.py::NormalizationIssue`).

Surfacing: `has_normalization_errors()` is an `EXISTS` for the shell indicator
(`diagnostics/health.py::has_normalization_errors`); `normalization_health()` counts for the report with roots
separated from consequences (`diagnostics/health.py::normalization_health`); `normalization_indicator()` returns
**None** when nothing is wrong, so the icon's presence is itself the signal
(`diagnostics/health.py::normalization_indicator`).

`diagnostics/` is read-only plain functions — no views, no management commands, no writes
(`diagnostics/__init__.py:1-4`). Keep it that way; `/developer/` is where actions go.

## Normalization lifecycle

- **Every path that normalizes announces itself first.** A new one calls
  `begin_normalization()` (`lifecycle.py::begin_normalization`) or, from a view, `normalization_refused()`
  (`views.py::normalization_refused`), which returns a redirect when a receiver raises `NormalizationRefused`
  (`lifecycle.py::NormalizationRefused`). It is `send`, not `send_robust`, because a refusal has to stop the
  caller (`lifecycle.py::begin_normalization`).
- **Normalization never deletes a collection** (`lifecycle.py:11-12`). Snapshots are its input.
- A `RUNNING` run is a live one — there is no age limit (`views.py:990-992`).
  `close_interrupted_runs` answers `server_started` and closes what a restart killed
  (`lifecycle.py:58-73`).
- A consumer asks `integration_work_in_progress()` before reading normalized rows
  (`lifecycle.py::integration_work_in_progress`).
- Background work runs on a **daemon** thread with no request (`views.py::ManagementStationInScopeSyncView`), so its
  outcome is its run and events and never a flash message; a second start is refused
  (`views.py::collection_in_progress`, `views.py::ManagementStationInScopeSyncView`); an unexpected exception closes only that
  collection's own runs (`views.py::_run_station_collection_in_background`).

## PAN-OS platform layering

`platforms/pan_os/` is strictly bottom-up. Put new logic in the matching layer rather than
reaching across:

1. `collectors/` — talk to the XML API, return raw payloads.
2. `normalization/` — raw payloads to normalized dataclasses, independent of persistence. The
   public entry points are re-exported from `platforms/pan_os/normalization/__init__.py`.
3. `persistence/` — upsert into models, one module per topology level
   (`platforms/pan_os/persistence/`: `appliance.py`, `appliance_group.py`,
   `enforcement_point.py`, `panorama.py`).
4. `flows.py` — composes collect → normalize → persist per target and collects failures per
   appliance and per point rather than aborting the run (`platforms/pan_os/flows.py::renormalize_in_scope_configuration`).

`orchestration/pan_os.py` sits **above** `flows.py` and composes a platform refresh with
app-level derived-data rebuilds (`orchestration/pan_os.py:1`). Prefer it for anything that must
run after a sync but is not PAN-OS collection or persistence.

`scripted_collection/` is a second implementation of the collector command set in another
language, with nothing in the language linking the two: `ScriptedCollectionScriptTests`
(`tests.py::ScriptedCollectionScriptTests`) compares it against the collector constants, which are the source. Its README
is the authority on why it is written as it is (`scripted_collection/README.md:9-40`).

## Views and templates

`views.py` is UI-only composition; vendor session, collection and persistence logic stay in
`platforms/pan_os/` or `orchestration/` (`views.py:1-5`). Shared row and label shaping lives in
`presentation.py:1-5`, not in a view or a template.

- Django's `{# #}` comment is single-line only: a multi-line one renders as literal text with a
  200 response. `TemplateCommentHygieneTests` (`tests.py::TemplateCommentHygieneTests`) asserts this across every
  template; use `{% comment %}…{% endcomment %}`.
- Messages are rendered per page, not by the shell: a content template that calls
  `messages.success` without its own loop shows nothing. Copy
  `templates/integrations/partials/enforcement_point_detail_content.html:25-32`.
- A content template owns its own scrolling. Copy the wrapper at
  `templates/integrations/partials/enforcement_point_detail_content.html:2-3`.

## Queries that grow with the estate

Any `__in` list whose length grows with the size of the estate goes through
`chunked()` (`query_chunking.py::chunked`, `CHUNK_SIZE = 900` at `query_chunking.py::CHUNK_SIZE`). The SQLite
host-parameter cap is a property of the build rather than of the schema, so the same query
succeeds where the code is written and fails on a customer's machine
(`query_chunking.py:1-17`). A list bounded by something small does not need it.

## Git hooks

Run this once per clone, before anything else:

```bash
git config core.hooksPath .githooks
```

A committed hook directory does nothing until git is pointed at it, and git cannot make that
automatic — a clone without it looks identical and enforces nothing.

`pre-commit` catches a model change with no migration, which nothing else notices
(`./.githooks/pre-commit:2-5`). `pre-push` repeats it and runs the suite. Both **fail rather
than skip** when they cannot find a Python that imports Django
(`./.githooks/pre-commit:14-15`); `OPTIVEDGE_PYTHON` overrides the interpreter
(`./.githooks/pre-commit:17`).

**Do not use `--no-verify`.** These hooks are the only enforcement in play, so bypassing one
removes a check rather than deferring it. If a hook fails, fix what it found or say why it is
wrong.

## Adding a model for a control

Most models here exist because an OptivEdgeAssessments control needs one. The checklist for that
work is `OptivEdgeAssessments/src/assessments/docs/building-a-control.md` — read it before
adding a model or a normalizer, and add to it when it misses something.
