"""Shared PAN-OS normalization helpers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def first_text(mapping: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        if isinstance(value, (str, int, float)):
            text = str(value).strip()
            if text:
                return text
    return ""


def iter_nested_entries(node: Any) -> Iterable[dict[str, Any]]:
    if isinstance(node, list):
        for item in node:
            yield from iter_nested_entries(item)
        return

    if not isinstance(node, dict):
        return

    if "entry" in node:
        for item in ensure_list(node["entry"]):
            if isinstance(item, dict):
                yield item

    for value in node.values():
        yield from iter_nested_entries(value)
