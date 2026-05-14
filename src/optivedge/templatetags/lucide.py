from __future__ import annotations

import re
from functools import lru_cache
from importlib.resources import files

from django import template
from django.utils.safestring import mark_safe


register = template.Library()

SVG_CLASS_RE = re.compile(r'\sclass="[^"]*"')
SVG_OPEN_RE = re.compile(r"<svg\b")


@lru_cache(maxsize=None)
def _read_icon(name: str) -> str:
    icon_path = files("optivedge").joinpath(
        "templates",
        "components",
        "icons",
        f"{name}.svg",
    )
    return icon_path.read_text(encoding="utf-8").strip()


@register.simple_tag
def lucide(name: str, **attrs: str) -> str:
    svg = _read_icon(name)
    class_name = attrs.pop("class", "").strip()

    if class_name:
        if SVG_CLASS_RE.search(svg):
            svg = SVG_CLASS_RE.sub(f' class="{class_name}"', svg, count=1)
        else:
            svg = SVG_OPEN_RE.sub(f'<svg class="{class_name}"', svg, count=1)

    if "aria-hidden" not in svg:
        svg = SVG_OPEN_RE.sub('<svg aria-hidden="true"', svg, count=1)

    return mark_safe(svg)
