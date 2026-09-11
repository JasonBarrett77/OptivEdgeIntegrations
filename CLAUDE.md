# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

OptivEdgeIntegrations is a reusable Django **domain package** — firewall config collection, normalization and
storage — not a standalone deployable project. It is installed as a dependency (`pip install -e .` for local
dev, or via git URL) by a separate downstream Django project that owns `manage.py`, root settings, root URLs,
and the database. This repo has no `manage.py` and no *downstream* Django settings module of its own — Django
model/view code cannot be exercised as part of a real deployment without a configured downstream project. It
does have a committed `tests/settings.py`, but that exists solely to run this repo's own test suite in
isolation (see "Commands").

It depends on **OptivEdge** (`optivedge`), declared in `pyproject.toml` — the shared Django app-shell
framework. The generic shell code this repo used to carry was extracted into that package: `base.html` and the
shared component templates, the `app_registry.py` plugin registry, `templatetags/lucide.py`,
`context_processors.py`, the root `urls.py`, and `ApplicationEnvironment` (deployment/engagement metadata, not
firewall data). OptivEdgeIntegrations and OptivEdgeAssessments are now peer domain apps that both plug into
OptivEdge, rather than one depending on the other's leftovers. Do not reintroduce shell/framework concerns
here — they belong in OptivEdge.

`OptivEdge/DEPLOYMENT.md` is the single authority on host-project wiring (`INSTALLED_APPS`/`TEMPLATES`/urls,
the `deployment_template/` engagement generator, the offline wheel bundle) for the whole stack. This repo's own
`DEPLOYMENT.md` covers only what is specific to this package — what it contributes to a host project, its
dependencies, the `integrations` app label, packaging rules — and defers to OptivEdge's for the rest. Read both
before changing anything that affects how downstream projects consume this package.

Vendor reading guides live in `src/optivedge_integrations/integrations/docs/`, partitioned by **API
surface** (`docs/<vendor>/<api-surface>/`). They record how to read a vendor's configuration without
getting a plausible wrong answer — which source silently omits what, which parameter is ignored rather
than rejected, which absent key means "on". That is knowledge that cuts across modules, so it belongs
neither in a docstring nor here: this file stays architecture, boundaries and model semantics, and points
at them. `docs/README.md` explains the partition rule and why the manager/managed relationship is
deliberately not in the directory tree. Start at `docs/palo-alto/pan-os/read-config-sources.md`.

## Commands

Editable install for local development. `optivedge` must be installed alongside it, and this cannot be one
`pip install` — this package declares `optivedge` as a git URL, which pip treats as conflicting with a local
editable of the same package (`ResolutionImpossible`). Install OptivEdge first, then this package with
`--no-deps`:

```bash
python -m pip install -e ~/PythonProjects/OptivEdge
python -m pip install -e . --no-deps
python -m pip install requests xmltodict
```

`DEPLOYMENT.md` has the same sequence extended to OptivEdgeAssessments.

Non-Django import sanity check (validates plain-Python modules only; does not touch Django models):

```bash
python - <<'PY'
import optivedge
import optivedge_integrations
import optivedge_integrations.settings.components
import optivedge_integrations.integrations.apps
import optivedge_integrations.integrations.app_meta
PY
```

Run this repo's own test suite (`src/optivedge_integrations/integrations/tests.py`) via the committed
`tests/settings.py` — a minimal, test-only settings module (not a downstream integration example; see
`tests/settings.py`'s docstring and `DEPLOYMENT.md` for that). It composes `OPTIVEDGE_APPS` +
`OPTIVEDGE_INTEGRATIONS_APPS` and sets `ROOT_URLCONF = "optivedge.urls"`, so it requires `optivedge` installed
editable alongside this package:

```bash
DJANGO_SETTINGS_MODULE=tests.settings python -m django test optivedge_integrations.integrations
DJANGO_SETTINGS_MODULE=tests.settings python -m django test optivedge_integrations.integrations.tests.DeviceConfigurationNormalizationTests
DJANGO_SETTINGS_MODULE=tests.settings python -m django test optivedge_integrations.integrations.tests.DeviceConfigurationNormalizationTests.test_some_case
```

Validating full downstream Django behavior (models, migrations, views, other installed apps) still requires
a real downstream project:

```bash
python manage.py check
python manage.py migrate
python manage.py runserver
```

## Architecture

### Package/app boundaries

- `optivedge_integrations` — thin distribution root, not a Django app. It holds only
  `settings/components.py` (which exports `OPTIVEDGE_INTEGRATIONS_APPS`) and the `integrations` app. There is
  no `templates/`, no `templatetags/`, no `app_registry.py` and no root `urls.py` here — all of that lives in
  `optivedge` now. Anything reaching for `optivedge_integrations.app_registry`,
  `optivedge_integrations.context_processors` or `optivedge_integrations.templatetags.lucide` is reading a
  stale doc or a pre-split downstream project.
- `optivedge_integrations.integrations` (label **`integrations`**, do not rename) — owns all domain models,
  migrations, views, forms, PAN-OS platform code, its own `templates/integrations/`, and
  `templatetags/local_time.py`. The label is preserved deliberately across a package rename; changing it
  breaks migrations, content types, and FK/model references (`integrations.SecurityRule`, etc.).

### How this package plugs into the OptivEdge shell

`integrations/app_meta.py` is the whole integration surface — the plugin convention defined by
`optivedge.app_registry`, which discovers an `app_meta` module in every installed app:

- `URL_MOUNT = {"prefix": "integrations/", "module": "optivedge_integrations.integrations.urls"}` mounts every
  route in this package under `/integrations/`. `optivedge.urls` owns the root namespace and appends
  `optional_app_urlpatterns()`; this package must never try to own root. New routes go in
  `integrations/urls.py`.
- `SIDEBAR_SECTION` contributes the "Firewall Integrations" and "Notes" nav sections. Each item carries an
  `active_names` set of URL names that light it up — **when a route name is added to `urls.py`, add it there
  too**, or the sidebar silently stops highlighting on that page.

Shared UI primitives come from OptivEdge and are used directly: `{% extends "base.html" %}` and
`{% include "components/…" %}` in this package's templates, `optivedge.views.RightOverlayMixin` in `views.py`,
and `TEXT_INPUT_CLASS`/`MONO_TEXT_INPUT_CLASS`/`TEXTAREA_CLASS` from `optivedge.forms` in `forms.py`. Django's
app-directories template loader resolves those includes by relative path across *every* installed app's
`templates/` directory, so no import is needed for templates — but `optivedge` must be in `INSTALLED_APPS`
alongside this package for any of it to resolve.

### Modelling a config item for a control

Most new models here exist because an OptivEdgeAssessments control needs one. **The checklist
for that work is `OptivEdgeAssessments/src/assessments/docs/building-a-control.md`** — read it
before adding a model or a normalizer for a control, and add to it when something is missed.
The items that land in this repository are: enumerate the real key set from the device rather
than a sample, measure the implicit value instead of assuming it, scope by config subtree,
populate both HA peers, and never skip a payload you cannot parse.

### A control queries columns, never JSON

A JSONField here is for **display and inspection**, never for a finding to rest on. If a
control needs a value that currently lives inside one, promote it to a real column in
normalization and let the control query that.

    permitted_ip_values   JSON, not searchable    permitted_ip_count    column, searchable
    bound_interface_names JSON, not searchable    bound_interface_count column, searchable
    protocol_algorithms   JSON, not searchable    allows_sha1           column, searchable

Two of the four reasons fail silently, which is why this is a rule rather than a preference: a
JSON lookup is unindexed, and it matches nothing when the vendor renames a key — so the control
stops finding anything instead of breaking. It also puts a vendor payload's shape inside a
control definition, where no schema protects it and no migration catches it. And a raw payload
(`raw_rule`, `raw_profile`) is not normalized data at all: a control reading one has its own
private interpretation of the config, which is what normalization exists to prevent. Those are
never registered as searchable.

Where a column is derived from a JSON field, give the model a `clean()` that asserts the two
agree — `bound_interface_count` and `SslTlsServiceProfile.allows_sha1` both do.

## Provenance: one pattern, no alternatives

**Every normalized model that can carry a pushed value uses `ProvenancedMixin` and writes
`FieldProvenance` rows. Do not invent a second mechanism.** `SecurityRule`,
`PolicyObjectBase` (address objects, groups, regions), the seven device-wide settings models
(`PasswordComplexityPolicy`, `AuthenticationSettings`, `LoginBanner`, `ManagementTlsBinding`,
`MasterKey`, `UpdateServerSettings`, `LoggingSettings`), `AdminUser`, `PasswordProfile`,
`InterfaceManagementProfile`, `ManagementInterface`, `ManagementService` and `PermittedSource`
all do this, and fourteen normalizer modules write the rows.

The helpers in `platforms/pan_os/normalization/common.py` are the only supported way to read
it. Use them rather than inspecting `@ptpl` by hand:

    scalar_value(node)          -> (value, raw_key, raw_provenance_value)
    parse_yes_no_field(node, default_effective=)  same, for a yes/no leaf
    parse_integer_field(node, default_effective=) same, for an integer leaf
    entry_provenance(entry)     -> (raw_key, raw_value) for a named entry's own marker
    classify_prov_type(raw_key) -> the FieldProvenance.ProvenanceType value
    ABSENT                      raw_key sentinel: the key was not in the payload

Three states, and the difference between the last two is the point:

    raw_key is ABSENT   the key was absent. PAN-OS supplied its own default and nobody
                        pushed or wrote anything. Write NO row - its absence is the answer.
    raw_key is None     present with no marker. Write a row typed `local`.
    raw_key is "@ptpl"  pushed. Write a row typed by classify_prov_type.

A model whose row IS a single value - `ManagementService`, `PermittedSource` - still uses the
mixin, with `field_name="__entry__"` for that value's own provenance. A bespoke
`provenance = CharField` was tried here and removed: it could not hold the type, could not be
queried by type, and could not distinguish a PAN-OS default from a locally written value.

`@src` is not provenance. It appears on containers as `src="tpl"` and is a routing marker;
`_PROVENANCE_KEYS` is the authoritative set.

For how much provenance survives an override, and why an unmarked value is ambiguous, see
`docs/palo-alto/pan-os/read-template-provenance.md`.

### Topology model hierarchy (`integrations/models/collected.py`)

```
ManagementStation (Panorama or standalone firewall connection)
 └─ ApplianceGroup (standalone / ha_pair / cluster)
     └─ Appliance (physical/virtual device, keyed by serial_number per station)
         └─ EnforcementPoint (a vsys; belongs to exactly one Appliance OR one ApplianceGroup, never both)
             └─ EnforcementNode (join of an Appliance into a group-scoped EnforcementPoint)
```

`EnforcementPoint.in_scope` is the flag that determines what actually gets collected/normalized on a sync
(see `get_in_scope_*` helpers in `platforms/pan_os/flows.py`) — most of the domain model exists to support
appliance-group HA topologies where a vsys-level enforcement point spans multiple physical nodes.

**`ApplianceGroup` models the HA/multi-appliance relationship, and nothing else.** `group_type` is
standalone/ha_pair/cluster and `active_appliance` names the active node; it exists so several appliances can
be managed as one unit. Nothing about it concerns Panorama.

**The `EnforcementPoint` appliance/appliance_group XOR does not mean "standalone vs HA", and must not be
read as a Panorama-management discriminant.** It was, until `normalization/snapshots.py::is_panorama_managed`
replaced that inference with `ManagementStation.station_type` (`PAN_PANORAMA` / `PAN_FIREWALL`).

The old reading held only by accident: the Panorama path is the only discovery path ever completed,
`normalization/panorama.py` is the sole production site that creates an `EnforcementPoint`, and it always
sets `appliance_group` — so `appliance_group IS NOT NULL` coincided with Panorama-managed.
`EnforcementPoint.appliance` is never set outside tests. The non-Panorama collection path was
**intentionally** left incomplete, and locally-managed devices can legitimately be in an HA group — that is
what `ApplianceGroup` is for. The first such pair collected would have raised "missing pushed shared policy
snapshot" for a device that never had one, and could not have.

`is_panorama_managed()` is the single definition of that question; everything asking "should pushed Panorama
data exist for this point?" goes through it. It gates both pushed sources — pushed-shared **and** pushed-vsys
— in `addresses.py`, `regions.py` and `security_rules.py`, since neither exists without Panorama. When the
non-Panorama collection path is completed, that helper is the seam.

`EnforcementPoint.appliance` / `.appliance_group` still carry the two conditional `UniqueConstraint`s (one
enforcement point per vsys name per owner), which is not expressible through `EnforcementNode` — so
preserve that guarantee in any replacement. Note what it guarantees: one row per **slot**, not one row per
firewall (see "`vsys_name` is the key" below). `get_in_scope_*` in `flows.py` `select_related`s
`management_station` to keep the discriminant from costing a query per point.

### `vsys_name` is the key, and it identifies a slot rather than a firewall

`EnforcementPoint` is keyed on `vsys_name` (`@name`, always `vsysN`), and that is correct — it is the only
vsys identifier that is always present and always unique. `vsys_display_name` is stored for **display only**;
never match, join or re-key on it. Three reasons, all measured (OptivEdgeProbe `archive/catalog/findings/`:
`vsys-identity`, `vsys-template-vs-device-group-binding`, `ha-peer-vsys-label-divergence`):

* It is **optional** on the device, and Panorama **synthesises** it from `@name` when absent. We read it from
  `show devices all`, so an unlabelled vsys arrives as `vsys_display_name="vsys6"` — Panorama's invention,
  indistinguishable from a real label. The UI then renders `vsys6 / vsys6`.
* It is often **not device-local state**: when a Panorama template supplies it the device marks the node
  `@src="tpl"` and refuses to change it locally.
* Panorama binds **device groups by slot and templates by label**. Relabelling a vsys moves its zones and
  interfaces to a different slot while its policy stays put. The two identifiers can disagree, and on an HA
  pair the label can occupy a different slot on each peer.

`vsys_name` identifying a slot rather than a firewall is the part with teeth: a vsys can be deleted and a
different one created in the same slot, and the device-group assignment follows the slot. There is no
vendor-supplied durable identity to use instead.

Follow the stance in that catalog — expect best practice, check it, report the deviation — which leaves two
known gaps here, both in `normalization/panorama.py`:

* `enforcement_point.vsys_display_name = vsys_display_name; save()` overwrites on every sync. A changed
  display-name is the strongest available signal that a slot changed hands, and it is currently discarded
  rather than reported. No signal is conclusive, so this should surface for a human, never auto-re-key.
* A synthesised display-name is stored as though it were configured. Distinguishing "no label" from
  "labelled `vsys6`" needs the device's own config, not `show devices all`.

**HA pairs:** collecting from the active and treating it as authoritative for the group is right for
addresses and policy, and wrong for the label-to-slot map, which is per appliance. `observed_vsys_entries`
is already read per appliance; keep it that way.

`Snapshot` (raw collected JSON payload + metadata) attaches to **exactly one** scope target
(management_station / appliance_group / appliance / enforcement_point / enforcement_node) — `clean()`
enforces this. Everything downstream (normalization, the device-wide settings models, policy objects) traces
back to a source `Snapshot`.

### Scoped policy objects are owned by their SCOPE, not by the collection that found them

`AddressObject` / `AddressGroup` / `Region` carry two nullable owner FKs, exactly one set:

```
vsys scope    -> enforcement_point   local-vsys, pushed device-group
shared scope  -> appliance_group     local-shared, Panorama-shared
vendor        -> enforcement_point   builtin/predefined, synthesized per point
```

Shared scope belongs to the **appliance group** because the group is the unit holding one
configuration — every vsys on it reads the same `/config/shared` and receives the same Panorama-Shared push.
Storing it per enforcement point copied a single observation once per vsys: 264 objects became 1,320 rows on
a five-vsys PA-5220. `ScopedPolicyObject.clean()` enforces that the owner matches the scope.

Vendor objects stay on the point: two synthesized objects, so the duplication costs nothing.

**Shared scope is the union across every in-scope point, not a sample of one.** Panorama does not push the
same shared set to every vsys — shared-object optimization pushes only what each device group references, so
a Panorama-Shared object can appear in one vsys's per-vsys response and not another's. Deriving group-wide
shared scope from a single representative point left such objects owned by **nobody**: the group pass never
saw them, and the owning point's pass discards shared scope by design. Every rule referencing one then failed
with `unresolved address reference`. `normalize_appliance_group_shared_objects()` reads every in-scope point
and unions the shared halves, keyed on `(name, namespace_type, namespace_value)`; overlap is expected since
the non-vsys response is in every point's build, but **disagreeing values raise** — shared scope is a single
namespace, so one name cannot hold two values.

**Write order is load-bearing.** `replace_addresses()` is a delete-and-recreate and
`SecurityRuleAddressRef.address_object` FKs point at these rows, so rewriting shared scope *after* a point's
rules were normalized would cascade those refs away. `renormalize_in_scope_configuration()` runs the
per-group shared pass **before** any enforcement point — both the renormalize and full-refresh paths go
through it, so the ordering lives in one place.

`build_address_lookup_maps()` unions both owners; neither alone is the set a vsys can see.

**Migration 0015 is destructive by design.** Shared-scope rows had no derivable group owner — the
information lives in the raw `Snapshot` payload, not in the normalized row — so it deletes all scoped policy
objects and security rules and requires a **renormalize** to repopulate. That is safe because the data is
fully re-derivable from stored snapshots without contacting a device.

### Object normalization fails per object, not per enforcement point

`build_normalized_addresses()` and `build_normalized_regions()` return
`(..., list[PolicyObjectIssue])`. One entry that cannot be normalized is **skipped and recorded**; the rest
still normalize. Security rules have always worked this way (`SecurityRuleFailure`) — objects were the
outlier, and the cost was misattribution: one unclassifiable entry discarded the whole point, and every rule
then reported the fault against whatever it happened to reference first, so the cause was invisible among its
own consequences.

The split is "is there anything to iterate":

```
POINT-LEVEL — still raises          PER-ENTRY — recorded and skipped
missing merged snapshot             entry with an unsupported type
missing pushed-shared snapshot      entry with no @name
missing pushed-vsys snapshot        duplicate name in one scope
unusable pushed payload or root     the two pushed reads disagreeing about a name
```

`PolicyObjectIssue` carries **severity** and **disposition**, and they are independent — conflating them was
the first version's mistake:

```
severity=error    this should not be possible, so the data cannot be trusted
severity=warning  something had to be inferred, but the state itself is expected

disposition=skipped   the object is absent; rules referencing it fail, visibly
disposition=kept      the object is present, possibly on a guess
```

| Case | severity | disposition |
|---|---|---|
| entry with an unsupported type, or no `@name` | error | skipped |
| duplicate name in one scope | **error** | kept |
| the two pushed reads disagreeing about a name | **error** | kept |
| pushed entry with no `@loc` | warning | kept |

The two `error`+`kept` rows are the ones that need explaining. Both are states PAN-OS rejects, so they can
only be our fault — hence *error*. But dropping the object makes every referencing rule fail, reporting the
fault against rules that are fine, which is the misattribution this design exists to remove — hence *kept*.

The **only** genuine warning is a pushed entry with no `@loc`: absence of the marker is a real, observed
state and the scope is a documented fallback, not a fault.

`raw_entry` is carried for drill-through, since a name and a reason rarely explain a payload problem alone.

`NormalizationIssue` (`models/normalization.py`) persists them, and is **state, not history** — replaced per
owner on every run, in the same transaction that replaces that owner's objects. That is the whole reason it
is a model rather than an `IntegrationEvent`: a health indicator has to clear itself when a clean run
happens, and an append-only log never does. Answering "is anything wrong right now?" against events would
mean joining to the latest run per point — a query that grows with history and would run on every page load.
Replacing the rows makes it an `EXISTS`.

Both are worth keeping. The event log answers *what happened during that sync*; this answers *can I trust the
data I am looking at*.

Owned like the objects it describes — enforcement point for vsys-scoped work, appliance group for
shared-scoped. `PolicyObjectIssue.shared_scope` carries which owner an entry was headed for, because **both**
passes see every issue; without it each one is recorded twice.

Rule failures live in the same table (`kind="security rule"`), which is what makes **root-versus-consequent**
computable. A rule that failed because an object it references also failed is marked `is_consequent`, so a
report says *1 root, 1,300 consequent* rather than *1,301 errors* pointing at objects that were fine. The
link is structural: `UnresolvedAddressReference` carries the name, and `_with_rule_context()` preserves it
when adding rule context — the wrapper used to rebuild a plain `ValueError` and threw the link away.

Each pass replaces only its **own kinds**, since both own rows for the same enforcement point and the rule
pass would otherwise erase what the object pass just recorded.

### Surfacing it — the shell indicator and the report

`app_meta.HEALTH_INDICATOR` points at `diagnostics.health:normalization_indicator`, which returns **None**
when nothing is wrong. OptivEdge's shell then renders nothing at all, on every page, so the icon's presence
*is* the signal — there is no count in the chrome, because a number invites a threshold and no amount of
unnormalized data is acceptable. The root count appears in the tooltip only.

`NormalizationIssueListView` (`/integrations/normalization-issues/`) is where counts and severity live. It
**leads with root causes** and groups consequences under what they could not resolve, so one failed object
reads as *"this failed, and here is everything it took with it"* rather than as N separate problems. The
shell indicator is the only thing that links to it.

`diagnostics.health` exposes the two shapes the UI needs: `has_normalization_errors()` is an `EXISTS` for the
shell indicator — binary, because a count invites a threshold and no number of unnormalized objects is fine —
and `normalization_health()` counts for the report, roots separated from consequences.

### Diagnostics (`integrations/diagnostics/`)

Read-only reporting over normalized data. Plain functions — no views, no management commands — so the same
logic serves a developer page, a shell session or a script. Nothing here writes to the database.

`policy_object_census` answers "did shared-scope rows collapse to one copy per appliance group?":

```python
before = capture_census(label="before-renormalize")
write_census(before)                     # -> ./policy-object-census/<label>-<ts>.json
# migrate 0015, then renormalize
compare_censuses(before, capture_census(label="after-renormalize"))
```

Computation is separate from persistence deliberately: a page can render `capture_census()` live without
writing anything, while the before/after case needs the baseline to outlive the migration that invalidates
it. `capture_census()` is safe against a **pre-migration** schema — the `appliance_group` column may not
exist yet, and its absence is recorded (`schema_has_appliance_group_owner`) rather than raised, which matters
because the baseline is captured before migrating.

The headline number is `rows_per_object` — shared rows ÷ distinct shared objects **per appliance group**. It
should be **1.0**; anything higher means one observation is stored more than once. On the lab five-vsys
PA-5220 the before/after is `1320 -> 264` rows at `5.0 -> 1.0`.

The appliance group must be in that key. `namespace_value` is the literal string `"shared"` for every
shared-scope object, so keying on `(namespace_value, name)` collapses *the same name in different groups*
into one entry — a correct three-group deployment then reports `3.0` and can never reach 1.0. Pre-migration
the rows hang off enforcement points, so the group is reached through them; that is what makes the two
snapshots comparable.

**Derived values are computed at capture time and frozen into the file.** Reinstalling does not recompute a
stored snapshot, so a fix to the metric cannot repair one — and a pre-migration baseline cannot be
recaptured. `CENSUS_VERSION` is bumped whenever a stored value changes meaning, and `compare_censuses()`
flags a mismatch instead of presenting stale numbers as current. The live census on `/developer/` is
recomputed per request, so it always reflects the installed code.

`distinct_shared` changing between snapshots is worth explaining but is **not** automatically a fault. Moving
objects to the group owner alone cannot change which objects exist — but if normalization logic also changed
between the captures (the `@loc` scope fix moves objects between vsys and shared scope), the shared set
legitimately differs.

`compare_censuses()` returns `observations` as plain statements rather than pass/fail, since the expected
magnitude depends on how many vsys each group has. It does flag three things outright: duplication that
survived, a change in *which* objects exist, and dependent rows left at zero — which means the renormalize
never ran.

`name_collisions` reports (owner, name) pairs appearing more than once — exactly what the **Stage B** unique
constraints will reject. Check it reads `0 / 0` before adding them: a constraint added blind fails the
migration partway through, and seeing the offenders as data beats seeing them as an `IntegrityError`.

Each colliding pair carries `rows_detail` — `namespace_type`, `namespace_value`, `precedence_rank` and the
synthetic flags of every row involved. Those are exactly the columns the *existing*
`unique(owner, name, namespace_type, namespace_value)` constraint permits to differ, so they always contain
the answer. `diagnose_collisions()` turns them into a verdict, and `/developer/` renders it for the **live**
census — a collision is current state, not a delta, so seeing why should not require capturing a snapshot.
The three verdicts are not interchangeable:

- **synthetic + collected** — we manufactured the collision. The device never had it, and no constraint on
  collected data is at fault. Stage B has to either exclude synthetic rows or namespace them separately.
- **all synthetic** — we produced the same object twice; a dedupe bug on our side.
- **all collected** — either the device really presents it, contradicting the measured PAN-OS rejection, or
  the namespace classification is wrong.

#### Ordering inside `normalize_enforcement_point_security_rules()` is load-bearing

```
delete rules + stale negated complements
build_address_lookup_maps()          <- FIRST
realize_literal_address_objects()    <- reads the maps, appends what it creates
per-rule: resolve + persist          <- reads the same maps
```

Synthesis has to know whether a name is already owned, and the maps are what answer that. Built the other way
round — as this was — synthesis ran *before* the answer existed and had to approximate it with a flat set of
names gathered from its own queries: a subtly different question ("does a row with this name exist"), blind
to regions, and re-hydrating every `AddressObject` row a second time purely to read `.name`.

`name_is_owned()` is now the single definition of that question, called by the synthesis guard and reached
from the other side by `resolve_rule_address_refs()` before it raises `UnresolvedAddressReference`. **They
must agree**: a name the resolver would have matched must never be synthesized over, or the synthetic row
shadows a real object and the rule is reported as matching traffic the firewall never matches. One function
means any check resolution grows is inherited by synthesis for free.

Two properties keep the in-place map mutation safe, and both would break if synthesis moved:

- It runs **outside any savepoint**. Inside the per-rule `transaction.atomic()`, a synthesized row would
  vanish on that rule's failure while the map kept pointing at it, leaving a dead pk for every later rule to
  resolve against — an FK error blamed on the wrong rule, or a reused pk silently naming a different object.
- It only writes names **nothing owns**, so the map entry is empty and the append cannot create a second
  candidate in one scope — the state `effective_in_scope_order()` raises on. That is an `assert`, not a
  comment, because it is what would break silently if the ownership check were relaxed.

Do not move literal synthesis into the per-rule loop. Resolution raises on the *first* miss rather than
collecting misses, so on-miss synthesis needs a re-resolve after each one, and the obvious loop does not
terminate when the name is not IP-shaped: `build_literal_address_object_spec()` returns `None` and the
identical miss recurs.

The first collision found in real data was **all synthetic**, and its fix is instructive.
`realize_literal_address_objects()` keyed its dedupe on `(name, namespace_type, namespace_value)`, so
`172.200.255.254` typed into a local rule *and* a pushed rule became two rows — `local_vsys` and
`pushed_vsys_effective`, same value, same scope, same rank, same owner. But `literal_namespace()` returns
those two purely by **provenance**, and provenance is not a precedence level, so they were never two
candidates to resolve between. **A literal is deduplicated by name alone.** When one appears with both
provenances, `LITERAL_NAMESPACE_PREFERENCE` picks deterministically (local first — cosmetic, since scope and
rank are identical either way) and `raw_object["namespaces"]` keeps the full set, because a row can carry
only one `namespace_type` and dropping the other silently would be worse.

Synthesis is also skipped when a **collected** object of that name exists in any namespace, on the point *or
its group*. A rule member is a name reference first — **measured**, not assumed: an object *named*
`172.200.255.254` holding `10.99.99.99/32` makes a rule sourcing that string compile to `10.99.99.99`, while
a control member no object owns compiles to itself (OptivEdgeProbe `rule-member-name-beats-literal`). PAN-OS
accepts both the name and the unrelated value, and nothing in the configuration marks which reading applies.

Note the reasoning runs opposite to the intuition. Suppressing synthesis does **not** assume the collected
object matches the literal; it is correct *because* they may differ — synthesising
`172.200.255.254 = 172.200.255.254` beside a collected `172.200.255.254 = 10.99.99.99/32` would record an
address the firewall does not enforce. The general rule is stronger than the synthesis case:
`resolve_rule_address_refs()` must resolve **every** member as a name first, whatever it looks like, since
reading an IP-shaped member as an address fails silently and completely.

Checking the group matters since shared-scope objects moved there; the EP's own rows cannot see them.

#### Three things are called "synthesis" and only one of them can collide

Confusing them leads to applying the suppression rule above where it does not belong:

| Path | Creates | Name | Can collide with a collected object? |
|---|---|---|---|
| rule literal | `AddressObject`, `synthetic_kind=rule_literal` | the literal as written | **yes** — this is the suppression case |
| negated complement | `AddressObject`, `synthetic_kind=negated_complement` | `__negated_complement__<rule>__<side>` | no — rule-scoped and `__`-prefixed |
| EDL/FQDN refresh | `AddressObjectResolvedEntry` | none — FK to an existing `AddressObject` | no — it never creates an `AddressObject` |

The **"Refresh EDL/FQDN cache"** action resolves runtime content onto objects that were already
collected. It matches nothing by name and synthesises no object, so nothing suppresses it and nothing can:
it must always run, exactly as intended. There is no guarantee that a collected object's value matches
anything we compute, which is precisely why resolved entries hang off the object rather than replacing it.

Only the rule-literal path shares a namespace with collected objects, and it is the only one where "does an
object already own this name?" is even a question.
`rows_per_object` covers only the shared side; this also covers the enforcement point, where a vsys-scoped
object and a vendor object could share a name.

`address_reference.explain_address_reference(point, name)` diagnoses
`unresolved address reference: <name>`. That message says a name is in neither the point's objects nor its
group's; it does not say why, and the answer is usually in the raw snapshot rather than the normalized rows.
The explainer walks the same path normalization does — which read carried the entry, its `@loc`, which owner
should therefore hold it, and where it actually is — and separates the two cases that look identical from the
event log: **the device never reported it** (collection or stale snapshots) versus **the device reported it
and nothing stored it** (normalization).

It reports **owner totals** first, because that is the decisive number when shared references fail
wholesale: a group holding zero objects means the shared pass never ran or failed, and the object named in
the rule error is incidental. `group_in_scope_for_shared_pass` separates *ran and failed* — which leaves an
`AddressNormalizationFailed` event — from *was never selected*, which leaves no event at all, since
`get_in_scope_appliance_groups()` picks groups by having at least one in-scope enforcement point.

The explainer **runs the real address build** and reports what it does, because a rule error naming one
object is usually downstream of the whole build failing: `resolve_rule_address_refs()` raises on the *first*
unresolved member and source is processed before destination, so "every rule fails on a `NET-*` source" is
indistinguishable from "this point has no objects at all" by reading the event log. It also prints each
pushed payload's top-level keys, so a product whose response roots at neither `shared` nor `policy.panorama`
is visible immediately — a cloud NGFW is a different product from VM-series, not merely a different
configuration.

**Several paths now raise where they used to return empty**, deliberately: an absent `@loc`, conflicting
pushed definitions, an unrecognised pushed payload root. Each is a better failure than a silent wrong
answer — but each also converts a partial result into *none at all*, which is a plausible cause for
normalization that "worked before" and now fails wholesale for one enforcement point.

**The two pushed responses are stored at different scopes**, and that asymmetry matters when a group holds
more than one appliance: the per-vsys response is stored on the **enforcement point**, the non-vsys response
on the **appliance group**. So shared scope can be built from a different appliance's snapshot than the one
the point's own reads resolve to — `latest_pushed_shared_snapshot()` takes the newest snapshot on the group
regardless of which appliance produced it. While pushed objects were scoped by read position this was
invisible, because everything came from the point's own response; once `@loc` routes shared objects to the
non-vsys read it becomes load-bearing. A cloud NGFW presenting several instances under one group, with only
one in scope, is the case to watch. The explainer reports the chosen appliance, the group's appliances,
duplicate hostnames, and how many group-scoped pushed snapshots compete.

It also catches the failure that masquerades as one missing object: a pushed entry with **no `@loc`** makes
`pushed_entry_scope()` raise, which fails the whole build for that point — so *every* object from that read
is missing, not just the one named in the rule error.

**Django's `{# #}` comment is single-line only.** A multi-line one is *not* stripped — it renders as literal
text on the page, with no error and a 200 response. Use `{% comment %}…{% endcomment %}` for anything
spanning lines. `TemplateCommentHygieneTests` asserts this across every template, because it is invisible in
review and only shows up by looking at the rendered page.

**Content templates own their own scrolling.** `base.html` puts `overflow-hidden` on `<body>` and gives the
content block a full-height flex container, so a page that just emits a tall `<div>` clips at the viewport
with no scrollbar. Wrap it the way `enforcement_point_detail_content.html` does — a
`flex h-full w-full min-h-0 min-w-0` section around a `min-h-0 flex-1 overflow-auto` div.

**Test the developer page by rendering it, not by calling the function.** (This and the
other method lessons in this file are consolidated in OptivEdgeProbe
`archive/catalog/procedures/establish-a-fact.md` — worth reading before measuring anything,
though it is now frozen: new lessons go here, beside the code they bear on.) The explainer's own tests all
called `explain_address_reference()` directly, so the template was never exercised with an explanation
present and it 500'd on first real use. The view's `try/except` cannot help — a template error happens after
the view returns. Note also that Django resolves a `default:` filter argument **eagerly**, so
`{{ a|default:b }}` raises when `b` is absent; prefer building a single display string in Python over making
the template branch on shape.

### The developer page (`/developer/`)

`DeveloperView` renders the live census, captures labelled snapshots, and compares any two. It is
**deliberately absent from `app_meta.py`'s `SIDEBAR_SECTION`** — reachable only by typing the URL — and a
test asserts that, so it does not drift into the navigation.

It is **not access-controlled by this package**. This repo has no auth model; a downstream project exposing
it publicly must gate it in its own middleware or URL conf.

Keep the naming split: the page is `/developer/` because it will grow *actions* (trigger a renormalize,
force a sync), while `diagnostics/` is strictly read-only. If everything under `/developer/` stays read-only,
renaming it then is fair.

Messages are rendered **per page** in this codebase, not by the shell — `base.html` has no messages block, so
each content template loops `{% for message in messages %}` itself. A new page that calls `messages.success`
without that loop will silently show nothing.

### Collection → normalization → persistence pipeline (PAN-OS)

`integrations/platforms/pan_os/` is layered strictly bottom-up; keep new PAN-OS logic in the matching layer
rather than reaching across:

1. `collectors/` — talk to the PAN-OS XML API (`session.py`/`flows.py` open sessions), return raw
   `PANOSCollectedResponse` payloads (managed devices, merged config, pushed shared policy).
2. `normalization/` — turn raw payloads into normalized dataclasses (`addresses.py`, `security_rules.py`,
   `device_configuration.py`, `panorama.py`, `snapshots.py`), independent of persistence.
3. `persistence/` — upsert normalized data into models, one module per topology level (`appliance.py`,
   `appliance_group.py`, `enforcement_point.py`, `panorama.py`).
4. `flows.py` — composes collector → normalize → persist per topology target and produces the in-scope
   refresh result (`refresh_in_scope_configuration_snapshots`); collects failures per-appliance/per-point
   rather than aborting the whole run (see the `*Failure` dataclasses).

`integrations/orchestration/pan_os.py` sits **above** `platforms/pan_os/flows.py`: it composes a platform
refresh with app-level derived-data rebuilds (currently the security-rule search vocabulary). Prefer this
layer for anything that needs to run after a sync but isn't PAN-OS-specific collection/persistence logic.

### Provenance and config-source model

Two related but distinct concepts track "where did this value come from":

- **`FieldProvenance`** (`models/provenance.py`) — a generic-relation, one-row-per-tracked-field record
  (`ProvenancedMixin` adds the `field_provenance` `GenericRelation`) capturing whether a field's value came
  from `local` / `template` / `device_group` / `panorama` / `unknown` PAN-OS config layers. Absence of a row
  for a field means the key was absent from the source payload — never infer a default from a missing row.
  `field_name = "__entry__"` records entry-level (not field-level) provenance.
- **`config_source`** (`CONFIG_SOURCE_CHOICES` in `models/policy/base.py`: `local` / `pushed_pre` /
  `pushed_post` / `default`) — a per-object classification of which PAN-OS rulebase/config layer an object
  or rule was pulled from. It sits alongside `PolicyObjectNamespace` (which scope an object was found in)
  and `PolicyObjectScope` (which one wins on a name collision). `PolicyObjectPrecedence` is the *numeric
  encoding* of the scope — derived by `precedence_for()`, never written as a literal, so the rank and the
  namespace cannot disagree.

### Object scope resolution (PAN-OS)

This section records device behaviour established by direct measurement against a Panorama-managed PA-5220
(11.1.13-h3, multi-vsys) and a PA-VM (11.2.3, single-vsys) in 2026-08. Configuration reads cannot answer
these questions — PAN-OS reports every definition as-is and never names a winner — so each claim below comes
from compiled policy (`show running security-policy-addresses`) or from a commit that PAN-OS accepted or
rejected.

**There are two scopes, and scope is the only precedence axis.**

```
vsys-specific   >   shared
```

Ownership — firewall-local vs Panorama-pushed — is **not** a precedence level. Two owners cannot occupy the
same scope under the same name: PAN-OS rejects the configuration rather than picking a winner (local-vsys +
pushed-vsys is refused at the candidate write; local-shared + Panorama-shared passes the write and fails at
commit validation). A successful config write therefore proves nothing; only a successful commit does.

Panorama decides *scope*, the firewall decides *precedence*:

```
Panorama Shared    -> shared scope
ANY device group   -> vsys scope     (including a container DG with no devices assigned)
```

**`PolicyObjectScope` is how this is modelled.** Namespaces record *provenance*; the scope decides who wins:

```
namespace                 scope    rank
local_vsys                vsys     10
pushed_vsys_effective     vsys     10
panorama_device_group     vsys     10
local_shared              shared   20
panorama_shared           shared   20
builtin / predefined      vendor   90 / 95   (position assumed, never measured)
```

`effective_in_scope_order()` walks `PolicyObjectScope.ORDER` explicitly rather than sorting, because the
order *is* the rule. **Two candidates in one scope raises** — PAN-OS rejects that configuration, so a device
cannot present it, and picking one would bury a collection or `@loc` classification fault.

This replaced a four-level ladder that was wrong twice: `LOCAL_SHARED (20)` sat ahead of
`PUSHED_VSYS_EFFECTIVE (30)`, inverting the measured result where pushed-DG `10.221.1.1` beat local-shared
`10.222.1.1` in compiled policy; and ranks 10/30 and 20/40 gave distinct positions to pairs PAN-OS rejects,
describing states that cannot exist. It matched every observation available at the time — underdetermined,
not supported.

All seven `namespace_type` values are kept; only their use as an ordering is gone.

**Classify pushed objects by `@loc`, never by which query returned them.** This is the rule that makes one
code path work for both multi-vsys and single-vsys devices, with no branch on operating mode:

```
@loc = "shared"        -> shared scope
@loc = <device-group>  -> vsys scope
(absent)               -> firewall-local; use read position to tell vsys from shared
```

Neither signal suffices alone: `@loc` separates the two Panorama scopes, read position separates the two
local ones. `common.pushed_entry_scope()` is the single implementation. An absent `@loc` on a pushed entry falls back to
**vsys scope** — the narrower of the two, so an unmarked entry cannot leak across a group's other vsys the
way a wrong shared classification would. What scope such an entry really occupies is **unmeasured**; this is
a conservative default, and `pushed_entry_is_unmarked()` exists so diagnostics can surface it rather than
letting it become another silent inference.

**What unmarked entries actually are is not established.** `azure-healthcheck-address` reads like a vendor
injection, but that is a reading of a name. A firewall-local object surfacing in the pushed response fits
equally — local objects carry no marker anywhere. That distinction matters: if they are local, the vsys
fallback duplicates what `merged` already yields, and two candidates in one scope is rejected at resolution.
`diagnostics.unmarked_pushed_entries()` counts them and splits them by whether the same name appears in
`merged`, which settles it.

This used to raise, on the grounds that all 398 pushed entries across both lab devices carried a marker.
That count was right and the generalisation wrong: an Azure cloud firewall pushes `azure-healthcheck-address`
with no provenance key, and the raise failed one enforcement point's **entire** address build — 242 objects
and ~1,300 rules — over a single vendor-injected entry. **Failure has to be proportionate to what is
unknown**: not knowing one object's scope is not a reason to discard every object and rule for a point.

`common.merge_pushed_entries()` merges the non-vsys and per-vsys reads into one set before classifying,
keyed by `(name, namespace_type, namespace_value)`. That key is what makes both measured cases work without
branching on device type:

- **single-vsys** — the two responses are byte-identical, so each object arrives twice with the same `@loc`,
  collapses to one row, and is scoped correctly. Read position instead emitted **104 rows for 52 objects**,
  all mis-scoped as vsys.
- **multi-vsys** — a name defined in both Panorama Shared and a device group arrives twice with *different*
  `@loc`, so it stays two rows. That is a real cross-scope override pair; collapsing it would discard the
  losing definition and hide the override entirely.

A key collision whose entries disagree raises — one object with two different definitions in one scope is a
state PAN-OS rejects, so it can only mean a collection fault.

**Enumerating definitions for an enforcement point takes three reads**, in this order; first hit wins:

```
1  vsys scope    merged -> devices.entry[0].vsys.entry[@name=V].address.entry[@name=N]
                 pushed-shared-policy vsys=V -> policy.panorama.address...  where @loc != "shared"
2  shared scope  merged -> config.shared.address.entry[@name=N]
                 pushed-shared-policy (no vsys) -> shared.address... or policy.panorama.address...
                                                   where @loc == "shared"
```

**The non-vsys pushed response roots differently by device, and `pushed_shared()` accepts both.**

```
result.shared            multi-vsys PA-5220, 11.1.13-h3
result.policy.panorama   single-vsys PA-VM,  11.2.3
```

Do not branch on device type to pick one — two samples cannot separate model, version and vsys mode, and
`@loc` classification makes the distinction unnecessary anyway. Reading only `shared` returned `{}` silently
on the PA-VM; no objects were lost there only because its two pushed reads are byte-identical, so the
per-vsys read caught what this one dropped. A device with that shape **and** genuine separation between the
two reads would lose every Panorama-Shared object with no error — and the PA-5220 has exactly such
separation: shared-object optimization keeps its 176 Shared objects out of every per-vsys response, making
the non-vsys read the only path to them.

A dict carrying neither root **raises**. An unrecognised shape is not evidence of an empty one.

**`show config merged` contains no Panorama-pushed policy objects.** The name invites the opposite
assumption: it is the firewall's local running config merged with Panorama **template** config, and
templates carry device/network settings, not policy objects. On the lab PA-5220 it is blind to 178
Panorama-Shared objects and every device-group object. Seeing only a local value in `merged` for a name that
also exists in Panorama Shared does *not* show that PAN-OS resolved the two and chose local — it shows the
Panorama definition was never in the data set. OEI already reads the three sources separately and does not
make this mistake; the note guards against a future "simplification" onto `merged` alone.

**A vsys with no device-group assignment still resolves Panorama-Shared objects.** Panorama sends nothing
*for* such a vsys and its per-vsys pushed read returns the bare string `No shared policy pushed to device` —
but Shared objects were delivered to the *device*, and the vsys reads them out of device-wide shared scope
like any other. An empty per-vsys pushed read must therefore never be taken to mean an empty object set;
skipping shared-scope collection on that basis would under-report the vsys by the entire Shared set.

**A name can match more than one object namespace, and the two cases need opposite handling.**
Measured on a PA-VM 11.2.3:

```
address object  +  address group   REJECTED   at the candidate WRITE
address object  +  EDL             REJECTED   at COMMIT VALIDATION
address group   +  EDL             REJECTED   at COMMIT VALIDATION
anything above  +  region          LEGAL      the REGION wins
custom region   +  predefined      LEGAL      UNION - both sets of addresses live
```

Objects, groups and EDLs are **one namespace**; a device cannot present a collision between
them, so `resolve_rule_address_refs()` raises if it sees one — that means *our* collection or
classification is wrong. EDLs only fail at commit rather than at the write because they live
under `/external-list` rather than `/address`, so the write-time uniqueness check misses them.

Regions are a **separate namespace** and win. Proven inert, not inferred: given a name that was
both, the address object's own address did not match the rule carrying its name, and neither did
a static group holding a routable member. PAN-OS reports it at commit as
`Warning: <name> is used as a region, not an address object` — it says "address object" even for
a group, naming the namespace rather than the type.

Predefined region names are **not reserved**: `US` may simultaneously be an address object, a
group, a custom region and the predefined region. So this is reachable in ordinary configurations,
and the earlier behaviour — raising on any multi-namespace hit — failed normalization for
configurations the firewall had accepted.

**Open gap:** a custom region sharing a predefined region's name *unions* with it. The `region` FK
points at the custom definition only, so computing a region's address extent from it alone
under-reports. Nothing depends on that today because predefined region ranges are not modelled.

**A disabled Panorama device-group rule is not pushed to the firewall at all** — not present-and-disabled,
simply not delivered. Anything enumerating "which rules exist here" from pushed policy silently omits every
disabled Panorama rule, and the objects those rules reference *are* still pushed. Reference counting
therefore cannot decide whether an object is safe to remove.

### Deliberate asymmetries — do not "clean these up"

**`pushed_shared()` raises on a non-dict payload; `pushed_vsys_panorama()` returns `{}`.** This looks like an
oversight and is not. They answer different questions:

```
pushed_vsys_panorama('No shared policy pushed to device') -> {}          correct
pushed_shared('No shared policy pushed to device')        -> ValueError  correct
```

A vsys with no device group having nothing pushed is an ordinary, *measured* state, so the per-vsys reader
is right to absorb it. A Panorama-managed device answering the **device-wide** shared query with something
that is not config data has never been observed, and nothing establishes it is benign — it would fit a lost
Panorama association or a query sent to the wrong target equally well. Returning `{}` there would convert an
unexplained response into a confident "this device has no shared objects", silently dropping every
Panorama-Shared object for that enforcement point.

Symmetry between sibling functions is not a reason on its own. The per-vsys reader earned its tolerance by
measurement; the non-vsys one has no such warrant.

### Known gap — `show config merged` is CANDIDATE-based, so collection can normalize uncommitted config

**Not yet addressed. Measured 2026-08-25** (OptivEdgeProbe `merged-config-is-candidate-based`).

`collect_show_merged_config` is the source for local address objects, zones and regions. It does **not**
return what the firewall enforces:

```
local candidate    show config candidate         uncommitted
local running      show config running           committed, NO template content
pushed template    show config pushed-template   committed by a Panorama push
merged             = candidate + pushed-template
```

Three failure shapes, and the middle one is the dangerous one because nothing looks wrong:

| Staged, uncommitted | Enforced | Collected |
|---|---|---|
| addition | absent | **present** — object that enforces nothing |
| modification | `10.99.1.1/32` | **`10.99.2.2/32`** — same name, wrong value, no error anywhere |
| deletion | present | **absent** — a live control missing from the assessment |

**The candidate is a full copy of running, not a delta**, so a contaminated payload cannot be repaired
after the fact — the candidate *replaced* running in that view. Correct-when-clean is the whole property:
with nothing staged, `candidate == running` byte for byte, and `merged` is then exactly right.

**What to do about it, when someone gets to it:**

1. **Detect, don't reconstruct.** `sha(show config running) == sha(show config candidate)` — byte-identical
   when clean, divergent the moment anything is staged. No diffing, per device, two extra op calls.
   `check pending-changes` is the cheaper alternative — one call, returns yes/no, exists on both
   Panorama and firewalls — but it is **journal-based, not a candidate-vs-running diff**: an edit
   followed by its own reversal still reports dirty until a revert. So it cannot prove two configs
   equal, only that nobody has touched anything. Over-reporting is the safe direction here, and it
   is a configure-mode command dispatched as `type=op`.
2. On a dirty candidate, prefer stamping the snapshot and raising a `NormalizationIssue` over refusing the
   sync: it is usually one admin mid-edit, most of the config is still fine, and the health indicator already
   exists to carry the signal.
3. **`show config running` is NOT a substitute** — it contains no template config at all and no `@ptpl`
   markers. Zones and interfaces defined in a template are simply absent from it.
4. **`show config effective-running`** is the source that would make this a non-problem, and it requires
   **Superuser**. Rejected — a collector should not hold Superuser to read configuration.
5. Reconstructing from `running` + `pushed-template` is blocked on **local-versus-template precedence**,
   which is unmeasured. PAN-OS tracks it (`set failed, may need to override template object first`), but
   guessing would produce a merged view wrong in a new way.

Related: Panorama's `merge-with-candidate-cfg` push option (off by default, and the probe's pushes omit it)
commits the device candidate as part of a policy push — which turns this contamination from transient into
permanent.

### Zone normalization is measured, not inferred (2026-08-25)

`normalization/zones.py` was validated against a PA-5220 (11.1.13-h3) by creating each shape live. Its
docstring used to warn that the payload shapes were guesses; that is no longer true.

Confirmed correct: the zone path; all six type subtrees; `zone-protection-profile` and `log-setting` under
`network`; `enable-user-identification` at entry level; `user-acl` member lists; both interface-address
shapes; every container under `network.interface` (ethernet, aggregate-ethernet, loopback, tunnel, vlan);
multiple addresses on one interface; and `unique(enforcement_point, name)` — `transit` exists in five vsys at
once, so per-EP scoping is load-bearing rather than decorative.

Three details worth not re-deriving:

* **The type subtrees are mutually exclusive by silent REPLACEMENT.** Adding `layer2` to a zone that had
  `layer3` deletes `layer3` — PAN-OS does not reject it. So "first subtree found wins" is safe and the
  iteration order of `ZONE_NETWORK_TYPES` cannot matter.
* **An empty subtree serializes as `"layer2": null`**, so the type check must test *key presence*, not
  truthiness. A truthiness check returns `unknown` for every bare zone.
* **`packet_buffer_protection` is a true tri-state, and `None` means ON.** All three states were driven on a
  live device (11.1.13-h3, 2026-08-25):

  | Config | Meaning | Field |
  |---|---|---|
  | element **absent** | default, which is **enabled** | `None` |
  | `enable-packet-buffer-protection: no` | explicitly off — what the UI writes when you untick | `False` |
  | `enable-packet-buffer-protection: yes` | explicitly on | `True` |

  `None` is the normal reading for a real zone, not an edge case: all 19 lab zones show the box ticked in the
  UI and carry no element. **Never render `None` as disabled** — it is the opposite.

  Note the UI can only produce *absent* or *no*: ticking the box writes nothing, because ticked is the
  default. So a stored `yes` came from the API, a template, or Panorama — never from a human in the UI. (The
  field also read the wrong element name, `packet-buffer-protection`, until 2026-08-25; PAN-OS rejects that
  one outright.)

* **IPv4 and IPv6 sit under different nodes and both are collected.** `ipv6.address.entry[@name]` was not
  read at all until 2026-08-25, so every IPv6 address was dropped and an IPv6-only interface reported none —
  which `ZoneInterface` documents as meaning "we did not reach them". `ipv6.enabled` is deliberately not
  consulted: the field is what is *configured*, so an address under a disabled stack still shows.

* **Layer2 and virtual-wire zones carry members and parse correctly** — measured by configuring `ethernet1/2`
  as layer2 and `ethernet1/3`+`1/4` as a virtual-wire pair. Non-layer3 interfaces are indexed with an *empty*
  address list rather than omitted, which is the distinction `ZoneInterface` exists to preserve.

Still unmeasured: DHCP-addressed interfaces.

**Every UI field is now collected** (migration `0018`). The element names were captured from a zone
configured in the firewall UI rather than guessed, because **not one is derivable from its label**:

| UI label | Element | Location |
|---|---|---|
| Enable Device Identification | `enable-device-identification` | zone entry, beside `enable-user-identification` |
| Device-ID ACL include/exclude | `device-acl` / `include-list` / `exclude-list` / `member` | zone entry — `device-acl`, **not** `device-id-acl` |
| Enable L3 & L4 Header Inspection | `net-inspection` | under `network` |
| Pre-NAT: User-ID | `prenat-identification` / `enable-prenat-user-identification` | under `network` |
| Pre-NAT: Device-ID | `prenat-identification` / `enable-prenat-device-identification` | under `network` |
| Pre-NAT: Source Lookup | `prenat-identification` / `enable-prenat-source-policy-lookup` | under `network` |
| Pre-NAT: Enable Original ID Downstream | `prenat-identification` / `enable-prenat-source-ip-downstream` | under `network` |

All eight new fields default **off** when absent — the opposite of `packet_buffer_protection`, which is the
only tri-state on the model.

`user-acl` and `device-acl` are structurally identical and modelled the same way. Their members **mix literal
addresses with address-object and address-group names** — `ag-agent-desktop-services` in the captured sample
is a group. They are stored as written with no reference resolution, so anything computing the addresses an
ACL covers has to resolve them itself.

### Known gap — only the address family is normalized into models

Rule fields divide into two families, and they are modelled very differently:

- **source / destination** — fully resolved. `resolve_rule_address_refs()` turns every member into a
  `SecurityRuleSourceAddressRef` / `SecurityRuleDestinationAddressRef` row carrying both the `raw_value` as
  written *and* an FK to what it resolved to: `AddressObject`, `AddressGroup`, or `Region`. Static groups are
  flattened one row per member, nested groups recurse, rule-literal IPs are synthesized into `AddressObject`
  rows (`synthetic_kind`), ambiguity across namespaces raises, and an unresolvable member raises.
- **everything else** — `service`, `application`, `category`, `source-user`, HIP, SaaS user/tenant, zones,
  profiles — subclass `SecurityRuleValue`: `value` + `prov` + `position`. Plain strings, no FK, because
  service, tag and application objects are **never normalized into models at all**.

So a service reference is the string `"web-browsing-svc"` with nothing behind it. Any assessment needing to
reason about what a service *is* (port ranges, protocol, overlap) cannot, today.

Worth revisiting. Two things to know before doing it:

1. The scope and precedence rules in "Object scope resolution" are **measured for address objects only**.
   Service, tag, application and schedule objects are *assumed* to scope the same way — that is inference,
   not measurement, and should be verified on a device before being relied on.
2. If service objects do get normalized, they should reuse the same scope classification (`@loc`, then read
   position) rather than growing a parallel implementation.

### Test fixtures build the shape production creates (`integrations/tests.py`)

`_create_panorama_enforcement_point()` used to set `appliance` and leave `appliance_group` null — a shape no
collection path produces. On it the group-scoped pushed-shared branch was inert, so 13 tests were passing
without exercising the code they targeted; fixing the discriminant surfaced all 13 at once.

Both helpers now build the production shape, enforcement point on the group:

- `_create_grouped_enforcement_point(...)` — takes `station_type` explicitly, for tests that care which side
  of the discriminant they are on.
- `_create_panorama_enforcement_point(...)` — delegates with `PAN_PANORAMA` and also creates the
  pushed-shared-policy snapshot a Panorama-managed point always has in reality. Pass
  `with_pushed_shared=False` to assert on its absence.

Do not reintroduce an enforcement point whose `appliance` is set directly; nothing in production does that,
and it silently disables the pushed-shared path.

### Management surfaces are a second model, not more fields

The device-wide settings models — `LoginBanner`, `AuthenticationSettings`, `UpdateServerSettings`
and the rest — are one row per appliance. None of them models administrative
*surfaces*: three exist on the management side alone (MGT, aux-1, aux-2), and a fourth axis
lives entirely outside `deviceconfig`, since any layer-3 data-plane interface may carry an
`interface-management-profile`.

`ManagementInterface` (`models/management_interface.py`) is the row for those, one per
surface, because a finding has to name the door it found open — "allowed to `ethernet1/1`",
not "allowed". `PermittedSource` holds its literal source restrictions; PAN-OS rejects
address objects, groups, hostnames and ranges on both planes, so nothing there resolves.
`normalize_management_interfaces()` populates all four planes from one merged-config
snapshot, and the traversal is a data list rather than a branch because vlan, loopback and
tunnel carry the profile with **no `layer3` node in the path** — a uniform walk misses them.

Services are deliberately absent from that model. The two planes disagree about both the
service set and the polarity of an absent key, and no control has needed them yet. See
`docs/palo-alto/pan-os/network/read-an-interface-management-profile.md`.

### Observability model (`models/events.py`)

`IntegrationRun` (one row per sync attempt, `station`/`appliance` scope, `succeeded`/`partial`/`failed`)
and `IntegrationEvent` (append-only log, always anchored to a `management_station`, optionally to a `run`
and/or an involved object — appliance/appliance_group/enforcement_point) replaced an older flat
`IntegrationSyncRun` model. When adding new sync/collection code paths, emit `IntegrationEvent`s rather than
swallowing exceptions — a prior silent-failure bug came from collection code catching and discarding errors
without recording an event.

### Views

`integrations/views.py` is UI-only composition (Django CBVs) — vendor session/collection/persistence logic
must stay in `platforms/pan_os/` or `orchestration/`, not in views. The management-station detail view is
tab-based (`TAB_DETAILS` / `TAB_APPLIANCE_GROUPS` / `TAB_ENFORCEMENT_POINTS` / `TAB_EVENTS`); each tab's
context is built lazily in `build_management_station_detail_context` so unrelated tabs don't issue queries.
`presentation.py` holds shared row/label-shaping helpers so multiple views/templates don't duplicate
`config_source` → label logic or address/security-rule row shaping.

## Git hooks

`.githooks/` is committed and enabled per clone with:

    git config core.hooksPath .githooks

**Each clone must run that once** - a committed hook directory does nothing until git is
pointed at it, and git cannot make that automatic.

`pre-commit` checks only for MODEL CHANGES WITH NO MIGRATION. That is worth its own hook
because nothing else notices: the tests pass, the app runs, and the break surfaces later in
someone else's environment as an unexplained schema mismatch. `pre-push` repeats it and runs
the full suite.

Both fail rather than skip when they cannot find a Python that imports django, and say how to
fix it. `OPTIVEDGE_PYTHON` overrides the interpreter.

A reminder, not a gate: `--no-verify` skips them, and github.com does not support server-side
hooks.

## Git hooks: enable them, never bypass them

**First thing in a fresh clone, before any other work:**

    git config core.hooksPath .githooks

Hooks live outside the tree by default, so the committed `.githooks/` directory does NOTHING
until git is pointed at it. Git cannot automate this. A clone without it looks identical to a
clone with it and enforces nothing — that silence is the whole risk.

**Never use `git commit --no-verify` or `git push --no-verify`.** There is no CI gate behind
these hooks: github.com does not support server-side hooks, and by decision this project does
not run GitHub Actions. The hooks are therefore the ONLY enforcement, and bypassing one is not
deferring a check, it is removing it. If a hook fails, fix what it found or say why it is wrong
— do not step around it.

## Every new model is checked against the certificate reference list

`OptivEdgeProbe/scratch/certificate-reference-locations.csv` lists all 67 places PAN-OS lets a
certificate be referenced, derived from the device command schema. Two controls depend on it -
"expired AND in use" and "used nowhere" - and both are deferred until enough of those locations
are backed by real models. A location the reference map misses becomes a certificate reported
unused while it is in use, which breaks the thing it was protecting.

Confirm a row with one `action=complete` call on its xpath: a typed reference field answers with
`@vxpath`, the full xpath of the referenced definition, which proves the edge outright. **An
empty result is not disproof** - completions are eligibility-filtered, so they describe what is
valid on THAT device rather than what the schema allows, and a real reference field on a device
holding no qualifying certificate returns nothing. The full method is in the generator's
docstring, `OptivEdgeProbe/scratch/build_certificate_reference_matrix.py`.

**When you add a normalized model, do three things before calling it done:**

1. Open the CSV and look for reference points whose config subtree your model now covers. Set
   `covered_by` to your model's name on those rows. That is how the deferred controls stop
   being deferred - incrementally, as domains land, rather than in one push at the end.
2. If your subtree contains a certificate reference the CSV does NOT list, the CSV is wrong.
   Add the row and record in `notes` how you found it. The derivation has been incomplete
   before: filtering on leaf key missed `ike gateway ... local-certificate name <value>`,
   where the leaf is `name` and only the parent says it holds a certificate.
3. Regenerate with `python -m scratch.build_certificate_reference_matrix`. Tracking columns are
   merged by path, so nothing you wrote is lost.

**Do NOT build a model because it appears on that list.** The list is a coverage checklist, not
a work queue - a model still waits until a control asks for it. Most of these locations will
acquire models as their own domains are built. The ones that never do are the exotics, and the
technique for those is a decision to be taken with the evidence in hand rather than now.

Note the scope split before assuming a row applies: twelve of the direct points are
`log-collector`, `wildfire-appliance` and `wildfire-appliance-cluster`, which are Panorama's
configuration of managed appliances rather than firewall configuration.

The scan is also worth keeping AFTER the models exist, as a coverage check on them: a reference
found at a path no model owns is a normalization gap, and should surface as a
`NormalizationIssue` rather than being silently invisible.
