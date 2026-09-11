# OptivEdgeIntegrations Deployment Instructions

**Host-project wiring is documented in OptivEdge, not here.** `OptivEdge/DEPLOYMENT.md` is the single
authority for standing up a deployment: creating an engagement project from `deployment_template/`, building
the offline wheel bundle, and configuring `INSTALLED_APPS` / `TEMPLATES` / root urls for the whole stack. Read
it first. This file covers only what is specific to *this* package.

OptivEdgeIntegrations is a reusable Django domain package — firewall config collection, normalization and
storage. It is not deployable on its own: it has no `manage.py` and no root settings, and it requires
**OptivEdge** (the shared app shell) to be installed alongside it. A downstream host project owns `manage.py`,
root settings, root URLs, and the database.

## What this package contributes to a host project

| | |
|---|---|
| Django app | `optivedge_integrations.integrations`, label **`integrations`** |
| Settings component | `OPTIVEDGE_INTEGRATIONS_APPS` (from `optivedge_integrations.settings.components`) |
| Routes | mounted at `/integrations/` by OptivEdge's plugin registry, via `integrations/app_meta.py` |
| Navigation | the "Firewall Integrations" and "Notes" sidebar sections, via the same `app_meta.py` |
| Migrations | the `integrations` app's own |

It contributes **no** shell, base templates, context processors, template libraries, or root URL patterns —
those come from OptivEdge. There is no root `urls.py` and no `app_registry` in this package; a host project
that imports `optivedge_integrations.app_registry`, `optivedge_integrations.context_processors` or
`optivedge_integrations.templatetags.lucide` is following a pre-split doc and will fail at import.

## Version requirements and dependencies

```text
Python >= 3.12
Django >= 6.0, < 6.1
```

Declared in `pyproject.toml`:

```toml
dependencies = [
    "Django>=6.0,<6.1",
    "requests>=2.31",
    "xmltodict>=0.13",
    "optivedge @ git+https://github.com/JasonBarrett77/OptivEdge.git@main",
]
```

The `optivedge` dependency floats on `@main`; prefer a tag or commit SHA for repeatable deployments.

## Installing

From GitHub — pip resolves the `optivedge` dependency automatically:

```bash
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdgeIntegrations.git@main#egg=optivedge-integrations"
```

For repeatable installs, prefer a tag:

```bash
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdgeIntegrations.git@v0.1.0#egg=optivedge-integrations"
```

Working on this package alongside a local OptivEdge checkout is **not** a single `pip install -e` — the
git-URL dependency on `optivedge` conflicts with a local editable of it. Follow "Co-development with local
checkouts of the whole stack" in `OptivEdge/DEPLOYMENT.md`; the short form is:

```bash
python -m pip install -e ~/PythonProjects/OptivEdge
python -m pip install -e ~/PythonProjects/OptivEdgeIntegrations --no-deps
python -m pip install requests xmltodict
```

## Django app label

The integrations app intentionally preserves its label across the package rename:

```python
class IntegrationsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "optivedge_integrations.integrations"
    label = "integrations"
```

This preserves model labels such as `integrations.SecurityRule`, `integrations.ManagementStation` and
`integrations.ManagementInterface`. Do not rename it casually — it would break migrations, content
types, foreign keys, and the canonical query references OptivEdgeAssessments stores in the database.

## Packaging rules

Runtime package data must stay under `src/optivedge_integrations/`, and be declared in `pyproject.toml`:

```toml
[tool.setuptools.package-data]
"optivedge_integrations.integrations" = [
    "templates/**/*.html",
]
```

Templates belong to the `integrations` app (`src/optivedge_integrations/integrations/templates/integrations/`),
not to the distribution root. Do not rely on root-level `templates/` or project-relative file paths.

## Validating a change to this package

Its own test suite runs in isolation against the committed `tests/settings.py`, and requires `optivedge`
installed alongside:

```bash
DJANGO_SETTINGS_MODULE=tests.settings python -m django test optivedge_integrations.integrations
```

Full Django behavior — migrations, views, the rendered shell — can only be validated from a host project:

```bash
python manage.py check
python manage.py migrate
python manage.py runserver
```

## Publishing a version

Only tag a release after a host project can successfully run `check`, `migrate` and `runserver` against it:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Downstream projects and `OptivEdgeAssessments/pyproject.toml` should then pin the tag rather than `@main`.

## Troubleshooting

**`ModuleNotFoundError: optivedge_integrations.app_registry`** (or `.context_processors`, or
`.templatetags.lucide`) — the host project is wired for the pre-split layout. Those modules live in
`optivedge` now; see `OptivEdge/DEPLOYMENT.md`.

**`TemplateDoesNotExist: base.html`** — `optivedge` is missing from `INSTALLED_APPS`. This package's templates
extend it, and the app-directories loader only searches installed apps.

**`NoReverseMatch` for a `management_station_*` URL name** — `integrations` is missing from `INSTALLED_APPS`,
so OptivEdge's registry never found its `app_meta.py` and never mounted `/integrations/`.

**Sidebar item stops highlighting on a page** — a route name was added to `integrations/urls.py` without being
added to the matching `active_names` set in `integrations/app_meta.py`.

**`ImproperlyConfigured: Requested setting INSTALLED_APPS`** — Django models were imported outside a
configured project. Expected when running plain Python imports against model modules.
