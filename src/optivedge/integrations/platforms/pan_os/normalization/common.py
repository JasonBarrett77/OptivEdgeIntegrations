"""Shared PAN-OS normalization helpers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


# ---------------------------------------------------------------------------
# Provenance helpers — used across all PAN-OS normalizers
# ---------------------------------------------------------------------------

# Returned as raw_key when the payload key was absent entirely.
# Callers check `raw_key is ABSENT` to skip FieldProvenance row creation.
ABSENT = object()

_PROVENANCE_KEYS = ("@ptpl", "@loc", "@panorama")


def classify_prov_type(raw_key: str | None) -> str:
    """Map a raw PAN-OS provenance key to a FieldProvenance.ProvenanceType value."""
    if raw_key == "@ptpl":
        return "template"
    if raw_key == "@loc":
        return "device_group"
    if raw_key == "@panorama":
        return "panorama"
    return "local"


def scalar_value(node: Any) -> tuple[str, Any, str | None]:
    """Extract value and provenance from a PAN-OS scalar node.

    Returns (value, raw_key, raw_provenance_value) where:
    - raw_key is ABSENT if node is None (field absent from payload)
    - raw_key is None if the node is a plain string (locally configured)
    - raw_key is "@ptpl" | "@loc" | "@panorama" when a provenance marker is present
    """
    if node is None:
        return "", ABSENT, None
    if isinstance(node, dict):
        text = str(node.get("#text") or "").strip()
        for key in _PROVENANCE_KEYS:
            if key in node:
                return text, key, str(node[key] or "")
        return text, None, None
    return str(node).strip(), None, None


def parse_yes_no_field(
    node: Any,
    *,
    default_effective: bool,
) -> tuple[bool, Any, str | None]:
    """Parse a PAN-OS yes/no boolean scalar.

    Returns (effective_value, raw_key, raw_provenance_value).
    raw_key is ABSENT when the field was not present in the payload.
    """
    raw_value, raw_key, raw_prov = scalar_value(node)
    if not raw_value:
        return default_effective, raw_key, raw_prov
    return raw_value.lower() == "yes", raw_key, raw_prov


def parse_integer_field(
    node: Any,
    *,
    default_effective: int,
) -> tuple[int, Any, str | None]:
    """Parse a PAN-OS integer scalar.

    Returns (effective_value, raw_key, raw_provenance_value).
    raw_key is ABSENT when the field was not present in the payload.
    """
    raw_value, raw_key, raw_prov = scalar_value(node)
    if not raw_value:
        return default_effective, raw_key, raw_prov
    try:
        return int(raw_value), raw_key, raw_prov
    except ValueError:
        return default_effective, raw_key, raw_prov


def entry_provenance(entry: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return (raw_key, raw_value) for an entry's own provenance annotation.

    Checks @ptpl and @loc only. @panorama is intentionally excluded here
    because at the entry level it appears as the boolean flag "@panorama": "true"
    (a routing signal used by default_rule_source), not a provenance pointer.
    Scalar-level @panorama is handled by scalar_value().
    """
    for key in ("@ptpl", "@loc"):
        if key in entry:
            return key, str(entry[key] or "")
    return None, None


def iter_member_values(node: Any) -> list[tuple[str, str]]:
    """Return (value, prov_string) for each member in a PAN-OS member/entry list.

    prov_string is the raw @loc/@ptpl value, or "" for locally-defined members.
    Used for member and tag models that store provenance as a direct CharField,
    not as FieldProvenance rows.
    """
    if node is None:
        return []
    if isinstance(node, dict):
        node_prov = ""
        for key in _PROVENANCE_KEYS:
            if key in node:
                node_prov = str(node[key] or "")
                break

        # Handle entry-keyed lists (e.g. profile-setting entries)
        entries = node.get("entry")
        if entries is not None:
            values: list[tuple[str, str]] = []
            for item in ensure_list(entries):
                if isinstance(item, dict):
                    item_prov = node_prov
                    for key in _PROVENANCE_KEYS:
                        if key in item:
                            item_prov = str(item[key] or "")
                            break
                    values.append((str(item.get("#text") or item.get("@name") or ""), item_prov))
                else:
                    values.append((str(item), node_prov))
            return values

        # Standard member lists
        members = ensure_list(node.get("member"))
        values = []
        for member in members:
            if isinstance(member, dict):
                member_prov = node_prov
                for key in _PROVENANCE_KEYS:
                    if key in member:
                        member_prov = str(member[key] or "")
                        break
                values.append((str(member.get("#text") or ""), member_prov))
            else:
                values.append((str(member), node_prov))
        return values

    if isinstance(node, list):
        return [(str(m), "") for m in node]
    return [(str(node), "")]


def member_values(node: Any) -> list[tuple[str, str]]:
    """Alias for iter_member_values — used by address normalizer."""
    return iter_member_values(node)


# ---------------------------------------------------------------------------
# General structural helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Payload structure helpers — shared across address and security rule normalizers
# ---------------------------------------------------------------------------

# Literal string returned by the PAN-OS API for show_pushed_shared_policy_vsys when a
# vsys has no Panorama device group assignment. This is a legitimate first-class state:
# a vsys can be fully operational with local rules on a Panorama-managed appliance.
# The vsys can still reference objects pushed to the device's shared scope by Panorama.
NO_PUSHED_POLICY_MESSAGE = "No shared policy pushed to device"


def merged_vsys_entry(payload: dict[str, Any], vsys_name: str) -> dict[str, Any]:
    """Return the named vsys entry dict from a show_merged_config payload."""
    config = payload.get("config", {})
    devices = config.get("devices", {}) if isinstance(config, dict) else {}
    device_entry = ensure_list(devices.get("entry"))[0] if isinstance(devices, dict) and ensure_list(devices.get("entry")) else {}
    vsys = device_entry.get("vsys", {}) if isinstance(device_entry, dict) else {}
    for entry in ensure_list(vsys.get("entry")) if isinstance(vsys, dict) else []:
        if isinstance(entry, dict) and entry.get("@name") == vsys_name:
            return entry
    return {}


def pushed_vsys_panorama(payload: dict[str, Any] | Any) -> dict[str, Any]:
    """Extract the panorama subtree from a show_pushed_shared_policy_vsys payload.

    Returns {} when payload is NO_PUSHED_POLICY_MESSAGE (vsys has no device group
    assignment in Panorama — a legitimate operational state, not an error).
    """
    if payload == NO_PUSHED_POLICY_MESSAGE:
        return {}
    if not isinstance(payload, dict):
        raise ValueError(f"unexpected pushed policy payload type: {type(payload).__name__}")
    policy = payload.get("policy", {})
    if not isinstance(policy, dict):
        raise ValueError(f"unexpected pushed policy root type: {type(policy).__name__}")
    panorama = policy.get("panorama", {})
    if not isinstance(panorama, dict):
        raise ValueError(f"unexpected pushed panorama subtree type: {type(panorama).__name__}")
    return panorama
