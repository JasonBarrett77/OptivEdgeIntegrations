"""Minimal settings module for running this repo's own test suite in isolation.

Not a downstream integration example - see DEPLOYMENT.md for how a real host project
should configure OptivEdgeIntegrations. This exists solely so
`optivedge_integrations.integrations`'s own tests
(`src/optivedge_integrations/integrations/tests.py`) can run with a one-line command
instead of hand-assembling a throwaway Django project each time. Requires `optivedge`
installed editable alongside this package (see DEPLOYMENT.md).

Usage (from the repo root, with both packages installed editable):

    DJANGO_SETTINGS_MODULE=tests.settings python -m django test optivedge_integrations.integrations
"""

from optivedge.settings.components import (
    OPTIVEDGE_APPS,
    OPTIVEDGE_CONTEXT_PROCESSORS,
    OPTIVEDGE_TEMPLATE_LIBRARIES,
)
from optivedge_integrations.settings.components import OPTIVEDGE_INTEGRATIONS_APPS

SECRET_KEY = "optivedge-integrations-test-settings-not-for-production"
DEBUG = True
USE_TZ = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    *OPTIVEDGE_APPS,
    *OPTIVEDGE_INTEGRATIONS_APPS,
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "optivedge.urls"

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

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
