# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

OptivEdgeIntegrations is a reusable Django **framework package**, not a standalone deployable project. It is installed
as a dependency (`pip install -e .` for local dev, or via git URL) by a separate downstream Django project
that owns `manage.py`, root settings, root URLs, and the database. This repo has no `manage.py` and no
*downstream* Django settings module of its own — Django model/view code cannot be exercised as part of a
real deployment without a configured downstream project. It does have a committed `tests/settings.py`, but
that exists solely to run this repo's own test suite in isolation (see "Commands").

Full downstream integration instructions (installing, wiring `INSTALLED_APPS`/`TEMPLATES`/urls, migrations,
troubleshooting) live in `DEPLOYMENT.md`. Read it before changing anything that affects how downstream
projects consume this package (app labels, settings components, URL composition, template locations).

## Commands

Editable install for local development:

```bash
python -m pip install -e .
```

Non-Django import sanity check (validates plain-Python modules only; does not touch Django models):

```bash
python - <<'PY'
import optivedge_integrations
import optivedge_integrations.app_registry
import optivedge_integrations.context_processors
import optivedge_integrations.integrations.apps
import optivedge_integrations.templatetags.lucide
PY
```

Run this repo's own test suite (`src/optivedge_integrations/integrations/tests.py`) via the committed
`tests/settings.py` — a minimal, test-only settings module (not a downstream integration example; see
`tests/settings.py`'s docstring and `DEPLOYMENT.md` for that). Requires `optivedge` installed editable
alongside this package:

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

- `optivedge_integrations` (label `optivedge_integrations`) — root framework app; owns shared templates (`templates/`), template tags
  (`templatetags/lucide.py`), settings components (`settings/components.py`), and the optional-app registry
  (`app_registry.py`).
- `optivedge_integrations.integrations` (label **`integrations`**, do not rename) — owns all domain models, migrations,
  views, and PAN-OS platform code. The label is preserved deliberately across a package rename; changing it
  breaks migrations, content types, and FK/model references (`integrations.SecurityRule`, etc.).
- `optivedge_integrations.app_registry` provides a plugin convention for *other* downstream apps: any installed app may
  expose an `app_meta.py` with `URL_MOUNT = {"prefix": ..., "module": ...}` and/or `SIDEBAR_SECTION`, picked
  up automatically via `optional_app_urlpatterns()` / `sidebar_sections()`. `optivedge_integrations.urls` should only
  compose framework-level URL modules (`include("optivedge_integrations.integrations.urls")` + `optional_app_urlpatterns()`)
  — new integration routes belong in `optivedge_integrations/integrations/urls.py`, not the root `urls.py`.

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
preserve that guarantee in any replacement. `get_in_scope_*` in `flows.py` `select_related`s
`management_station` to keep the discriminant from costing a query per point.

`Snapshot` (raw collected JSON payload + metadata) attaches to **exactly one** scope target
(management_station / appliance_group / appliance / enforcement_point / enforcement_node) — `clean()`
enforces this. Everything downstream (normalization, `DeviceConfigurationProfile`, policy objects) traces
back to a source `Snapshot`.

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
  and `PolicyObjectPrecedence` (which one wins on a name collision). **`PolicyObjectPrecedence` currently
  encodes a resolution model that has been measured false** — see the next section before relying on it.

### Object scope resolution (PAN-OS) — measured, and not what the code assumes

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

**`PolicyObjectPrecedence` encodes a four-level ladder that is wrong twice over:**

```
LOCAL_VSYS 10 < LOCAL_SHARED 20 < PUSHED_VSYS_EFFECTIVE 30 < PANORAMA_SHARED 40
```

1. `LOCAL_SHARED (20)` ahead of `PUSHED_VSYS_EFFECTIVE (30)` is **inverted** — a pushed device-group object
   is vsys-scoped and beats a firewall-local shared object. Measured directly: pushed-DG `10.221.1.1` beat
   local-shared `10.222.1.1` in compiled policy.
2. Ranks 10/30 and 20/40 model coexistence for pairs PAN-OS **rejects**, describing states that cannot exist.

The ladder matched every earlier observation; it was underdetermined, not supported. Keep all seven
`namespace_type` values — they are useful provenance — but stop treating them as precedence levels.

**Classify pushed objects by `@loc`, never by which query returned them.** This is the rule that makes one
code path work for both multi-vsys and single-vsys devices, with no branch on operating mode:

```
@loc = "shared"        -> shared scope
@loc = <device-group>  -> vsys scope
(absent)               -> firewall-local; use read position to tell vsys from shared
```

Neither signal suffices alone: `@loc` separates the two Panorama scopes, read position separates the two
local ones. `common.pushed_entry_scope()` is the single implementation; an absent `@loc` on a pushed entry
**raises** rather than falling back to read position (398 pushed entries were checked across both lab
devices and every one carries it, so absence is unobserved and guessing is what produced the original bug).

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
