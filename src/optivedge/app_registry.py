"""Simple optional app registry helpers.

Installed apps may expose a small `app_meta.py` module with:

- `URL_MOUNT = {"prefix": "...", "module": "..."}`
- `SIDEBAR_SECTION = {...}`
"""

from __future__ import annotations

from importlib import import_module

from django.apps import apps
from django.urls import include, path


def iter_app_meta():
    for app_config in apps.get_app_configs():
        module_name = f"{app_config.name}.app_meta"
        try:
            yield import_module(module_name)
        except ModuleNotFoundError as exc:
            if exc.name == module_name:
                continue
            raise


def optional_app_urlpatterns():
    patterns = []
    for app_meta in iter_app_meta():
        mount = getattr(app_meta, "URL_MOUNT", None)
        if not mount:
            continue
        patterns.append(path(mount["prefix"], include(mount["module"])))
    return patterns


def sidebar_sections():
    sections = []
    for app_meta in iter_app_meta():
        section = getattr(app_meta, "SIDEBAR_SECTION", None)
        if section:
            if isinstance(section, list):
                sections.extend(section)
            else:
                sections.append(section)
    return sections
