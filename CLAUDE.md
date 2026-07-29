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
  or rule was pulled from, used alongside `PolicyObjectNamespace`/`PolicyObjectPrecedence` to resolve
  overlapping objects across local vsys, local shared, pushed-effective, Panorama shared, and Panorama
  device-group namespaces (higher precedence wins when names collide).

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
