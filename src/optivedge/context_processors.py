"""Shared template context processors."""

from .app_registry import sidebar_sections


def optional_app_navigation(request):
    return {
        "optional_sidebar_sections": sidebar_sections(),
    }
