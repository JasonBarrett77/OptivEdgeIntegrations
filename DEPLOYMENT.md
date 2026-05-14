# OptivEdge Framework Deployment Instructions

OptivEdge is a reusable Django framework package. It is not intended to be deployed directly as a standalone Django project. Downstream Django projects install OptivEdge as a dependency and include its Django apps, URLs, templates, and migrations.

## Repository Purpose

This repository provides the shared OptivEdge framework layer, including:

* reusable Django apps
* integration data models
* PAN-OS collection and normalization logic
* shared templates and template tags
* shared framework URL composition
* framework settings components

Downstream projects remain responsible for:

* `manage.py`
* root Django settings
* root URL configuration
* environment variables
* database configuration
* deployment configuration
* project-specific apps and workflows

## Package Layout

Expected repository structure:

```text
OptivEdge/
├── pyproject.toml
├── README.md
├── src/
│   └── optivedge/
│       ├── __init__.py
│       ├── apps.py
│       ├── urls.py
│       ├── settings/
│       │   ├── __init__.py
│       │   └── components.py
│       ├── integrations/
│       │   ├── apps.py
│       │   ├── models/
│       │   ├── migrations/
│       │   ├── platforms/
│       │   ├── orchestration/
│       │   ├── views.py
│       │   └── urls.py
│       ├── templates/
│       └── templatetags/
└── .gitignore
```

## Version Requirements

OptivEdge currently targets:

```text
Python >= 3.12
Django >= 6.0, < 6.1
```

The Django dependency should be declared in `pyproject.toml`:

```toml
[project]
requires-python = ">=3.12"
dependencies = [
    "Django>=6.0,<6.1",
    "requests>=2.31",
    "xmltodict>=0.13",
]
```

## Installing OptivEdge in a Downstream Project

Create and activate a virtual environment in the downstream project:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

Install OptivEdge from GitHub:

```bash
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdge.git@main#egg=optivedge"
```

For repeatable installs, prefer a tag:

```bash
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdge.git@v0.1.0#egg=optivedge"
```

For local development against a checked-out copy:

```bash
python -m pip install -e ~/PythonProjects/OptivEdge
```

## Configuring a Downstream Django Project

Create a normal Django project:

```bash
django-admin startproject config .
```

Edit `config/settings.py`.

Import OptivEdge settings components:

```python
from optivedge.settings.components import (
    OPTIVEDGE_APPS,
    OPTIVEDGE_CONTEXT_PROCESSORS,
    OPTIVEDGE_TEMPLATE_LIBRARIES,
)
```

Add OptivEdge apps to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    *OPTIVEDGE_APPS,
]
```

Configure templates:

```python
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "libraries": {
                **OPTIVEDGE_TEMPLATE_LIBRARIES,
            },
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                *OPTIVEDGE_CONTEXT_PROCESSORS,
            ],
        },
    },
]
```

Edit `config/urls.py`:

```python
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("", include("optivedge.urls")),
    path("admin/", admin.site.urls),
]
```

## Running Django Checks and Migrations

From the downstream project root:

```bash
python manage.py check
python manage.py migrate
```

Expected migrations include the OptivEdge `integrations` app:

```text
Applying integrations.0001_initial... OK
Applying integrations.0002_addressobject_is_edl_and_more... OK
Applying integrations.0003_managementplaneprofile... OK
Applying integrations.0004_securityrulesearchvocabularyentry... OK
Applying integrations.0005_client_engagementenvironment... OK
```

## Running the Development Server

```bash
python manage.py runserver
```

Open:

```text
http://127.0.0.1:8000/
```

If the OptivEdge home page renders, the framework package, app config, URL config, templates, and migrations are working.

## Development Workflow for OptivEdge

When changing OptivEdge itself:

```bash
cd ~/PythonProjects/OptivEdge
source .venv/bin/activate
```

Install the framework editable for local validation:

```bash
python -m pip install -e .
```

Run a basic non-Django import check:

```bash
python - <<'PY'
import optivedge
import optivedge.app_registry
import optivedge.context_processors
import optivedge.integrations.apps
import optivedge.templatetags.lucide

print("OptivEdge non-Django import check passed")
PY
```

Django model imports require a configured Django settings module. Validate full Django behavior from a downstream test project using:

```bash
python manage.py check
python manage.py migrate
python manage.py runserver
```

## URL Organization Convention

OptivEdge should keep URL ownership close to the app that owns the views.

Preferred structure:

```text
src/optivedge/urls.py
src/optivedge/integrations/urls.py
```

`src/optivedge/integrations/urls.py` should define integration-owned routes.

`src/optivedge/urls.py` should only compose framework-level URL modules:

```python
from django.urls import include, path

from optivedge.app_registry import optional_app_urlpatterns

urlpatterns = [
    path("", include("optivedge.integrations.urls")),
]

urlpatterns += optional_app_urlpatterns()
```

Future integration views should generally be added to:

```text
src/optivedge/integrations/urls.py
```

not directly to:

```text
src/optivedge/urls.py
```

## Template Organization

Shared framework templates live under:

```text
src/optivedge/templates/
```

The root OptivEdge app must be installed so Django can discover shared templates:

```python
OPTIVEDGE_APPS = [
    "optivedge.apps.OptivEdgeConfig",
    "optivedge.integrations.apps.IntegrationsConfig",
]
```

The `integrations` app owns integration-specific templates under:

```text
src/optivedge/templates/integrations/
```

## Django App Labels

The integrations app intentionally preserves the Django app label:

```python
class IntegrationsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "optivedge.integrations"
    label = "integrations"
```

This preserves model labels such as:

```text
integrations.SecurityRule
integrations.ManagementStation
integrations.ManagementPlaneProfile
```

Do not rename the app label casually. Changing it would affect migrations, content types, foreign keys, and downstream canonical query references.

## Publishing a Version

Only tag a release after a downstream Django project can successfully run:

```bash
python manage.py check
python manage.py migrate
python manage.py runserver
```

Create and push a tag:

```bash
cd ~/PythonProjects/OptivEdge
git status
git tag v0.1.0
git push origin v0.1.0
```

Downstream projects should then pin the tag:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@v0.1.0#egg=optivedge
```

## Troubleshooting

### `TemplateDoesNotExist: workspace.html`

Cause: the root `optivedge` Django app is not installed.

Confirm `OPTIVEDGE_APPS` includes:

```python
"optivedge.apps.OptivEdgeConfig"
```

### `NoReverseMatch` for an OptivEdge URL name

Cause: the downstream project included `optivedge.urls`, but the framework URL module does not include the route-owning app’s URLs.

Confirm `src/optivedge/urls.py` includes:

```python
path("", include("optivedge.integrations.urls")),
```

### `ImproperlyConfigured: Requested setting INSTALLED_APPS`

Cause: Django models were imported outside a configured Django project.

This is expected if running plain Python imports against model modules. Validate models from a configured downstream Django project using:

```bash
python manage.py check
```

### SSH install fails with `Permission denied (publickey)`

Use HTTPS:

```bash
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdge.git@main#egg=optivedge"
```

Or configure SSH keys for the current WSL/Linux environment.

## Minimal Downstream `requirements.txt`

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@v0.1.0#egg=optivedge
```

During active development, a downstream project may temporarily use:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@main#egg=optivedge
```

Production or repeatable builds should use a tag or commit SHA, not floating `main`.
