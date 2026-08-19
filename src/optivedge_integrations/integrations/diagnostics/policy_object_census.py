"""Row-count census for scoped policy objects.

Built to answer one question, and to keep answering it afterwards: **did shared-scope
rows collapse from one-copy-per-vsys to one copy per appliance group?**

Before scoped objects were owned by their scope, every vsys on a group stored its own
copy of the group's shared objects — 264 objects became 1,320 rows on a five-vsys
PA-5220. Capture a census before the migration + renormalize, another after, and compare.

Computation is separate from persistence on purpose. `capture_census()` returns a plain
dict, so a developer page can render it live without writing anything; `write_census()`
and `load_census()` exist for the before/after case, where the "before" has to outlive
the migration that invalidates it.

    before = capture_census(label="before-renormalize")
    write_census(before)                      # -> ./policy-object-census/<label>-<ts>.json
    # ... migrate, renormalize ...
    print(compare_censuses(before, capture_census(label="after-renormalize")))

Safe to run against a **pre-migration** database: the appliance_group column may not
exist yet, and that absence is recorded rather than raised.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone as dt_timezone
import json
from pathlib import Path
from typing import Any

from django.db import connection

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressObject,
    ManagementStation,
    PolicyObjectScope,
    Region,
    SecurityRule,
    SecurityRuleDestinationAddressRef,
    SecurityRuleSourceAddressRef,
    scope_for,
)

#: Where write_census() puts files when no path is given. Relative to the working
#: directory, so it lands beside the downstream project rather than inside this package.
DEFAULT_CENSUS_DIR = Path("policy-object-census")

SCOPED_MODELS = {
    "AddressObject": AddressObject,
    "AddressGroup": AddressGroup,
    "Region": Region,
}

RELATED_MODELS = {
    "SecurityRule": SecurityRule,
    "SecurityRuleSourceAddressRef": SecurityRuleSourceAddressRef,
    "SecurityRuleDestinationAddressRef": SecurityRuleDestinationAddressRef,
}


def _has_owner_column(model) -> bool:
    """Whether the appliance_group column exists in the database yet.

    A census taken *before* migration 0015 runs against a schema without it. Reporting
    that as a fact beats raising, since the pre-migration census is precisely the
    baseline this tool exists to capture.
    """
    with connection.cursor() as cursor:
        columns = connection.introspection.get_table_description(cursor, model._meta.db_table)
    return any(column.name == "appliance_group_id" for column in columns)


def _scope_counts(rows: list[tuple[str, Any, Any]]) -> dict[str, int]:
    counts: Counter = Counter()
    for namespace_type, _, _ in rows:
        try:
            counts[scope_for(namespace_type)] += 1
        except ValueError:
            counts["<unmapped>"] += 1
    return dict(counts)


def _duplication(rows: list[tuple[str, Any, Any]]) -> dict[str, Any]:
    """How many rows exist per distinct shared-scope object.

    This is the headline number. Shared scope is group-wide, so each distinct name should
    exist exactly once per appliance group. A factor above 1.0 means the same observation
    is stored more than once — which is what owning shared objects per enforcement point
    did, at one copy per vsys.
    """
    shared = [r for r in rows if _safe_scope(r[0]) == PolicyObjectScope.SHARED]
    if not shared:
        return {"shared_rows": 0, "distinct_shared": 0, "rows_per_object": None}
    distinct = len({(namespace_value, name) for _, namespace_value, name in shared})
    return {
        "shared_rows": len(shared),
        "distinct_shared": distinct,
        "rows_per_object": round(len(shared) / distinct, 3) if distinct else None,
    }


def _safe_scope(namespace_type: str) -> str:
    try:
        return scope_for(namespace_type)
    except ValueError:
        return "<unmapped>"


def _model_census(model, *, has_owner_column: bool) -> dict[str, Any]:
    fields = ["namespace_type", "namespace_value", "name"]
    rows = list(model.objects.values_list(*fields))

    census: dict[str, Any] = {
        "total_rows": len(rows),
        "by_scope": _scope_counts(rows),
        "by_namespace": dict(Counter(namespace_type for namespace_type, _, _ in rows)),
        "duplication": _duplication(rows),
    }

    if has_owner_column:
        census["by_owner"] = {
            "enforcement_point": model.objects.filter(enforcement_point__isnull=False).count(),
            "appliance_group": model.objects.filter(appliance_group__isnull=False).count(),
            "orphaned": model.objects.filter(
                enforcement_point__isnull=True, appliance_group__isnull=True
            ).count(),
        }
    else:
        census["by_owner"] = None  # pre-migration schema; see _has_owner_column
    return census


def _station_breakdown(*, has_owner_column: bool) -> list[dict[str, Any]]:
    """Per station -> group -> point counts, so a surprising total can be located."""
    stations = []
    for station in ManagementStation.objects.order_by("hostname", "pk"):
        groups = []
        for group in station.appliance_groups.order_by("name", "pk"):
            entry: dict[str, Any] = {
                "name": group.name,
                "group_type": group.group_type,
                "enforcement_points": [],
            }
            if has_owner_column:
                entry["shared_scope_rows"] = {
                    label: model.objects.filter(appliance_group=group).count()
                    for label, model in SCOPED_MODELS.items()
                }
            for point in group.enforcement_points.order_by("vsys_name", "pk"):
                entry["enforcement_points"].append({
                    "vsys_name": point.vsys_name,
                    "in_scope": point.in_scope,
                    "rows": {
                        label: model.objects.filter(enforcement_point=point).count()
                        for label, model in SCOPED_MODELS.items()
                    },
                })
            groups.append(entry)
        stations.append({
            "hostname": station.hostname,
            "station_type": station.station_type,
            "appliance_groups": groups,
        })
    return stations


def capture_census(*, label: str = "") -> dict[str, Any]:
    """Count scoped policy objects and how they are owned. Read-only."""
    has_owner_column = _has_owner_column(AddressObject)
    return {
        "label": label,
        "captured_at": datetime.now(dt_timezone.utc).isoformat(),
        "schema_has_appliance_group_owner": has_owner_column,
        "models": {
            label_: _model_census(model, has_owner_column=has_owner_column)
            for label_, model in SCOPED_MODELS.items()
        },
        "related_totals": {
            label_: model.objects.count() for label_, model in RELATED_MODELS.items()
        },
        "stations": _station_breakdown(has_owner_column=has_owner_column),
    }


def write_census(census: dict[str, Any], path: Path | str | None = None) -> Path:
    """Persist a census as JSON. Returns the path written."""
    if path is None:
        stamp = census["captured_at"].replace(":", "").replace("-", "")[:15]
        name = f"{census.get('label') or 'census'}-{stamp}.json"
        DEFAULT_CENSUS_DIR.mkdir(parents=True, exist_ok=True)
        path = DEFAULT_CENSUS_DIR / name
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(census, indent=2, sort_keys=True))
    return path


def load_census(path: Path | str) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def list_censuses(directory: Path | str | None = None) -> list[dict[str, Any]]:
    """Saved censuses, newest first, as {path, label, captured_at, ...} summaries.

    Reads each file rather than parsing its name, so a census written to an explicit
    path is listed with the same detail as one written to the default directory.
    Unreadable files are reported with an `error` key instead of being skipped - a
    baseline that cannot be loaded is exactly the thing worth seeing.
    """
    directory = Path(directory) if directory is not None else DEFAULT_CENSUS_DIR
    if not directory.exists():
        return []
    entries: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        entry: dict[str, Any] = {"path": str(path), "filename": path.name}
        try:
            census = load_census(path)
        except (OSError, json.JSONDecodeError) as exc:
            entry["error"] = str(exc)
        else:
            entry.update({
                "label": census.get("label") or "",
                "captured_at": census.get("captured_at") or "",
                "schema_has_appliance_group_owner": census.get("schema_has_appliance_group_owner"),
                "total_rows": {
                    name: data.get("total_rows")
                    for name, data in (census.get("models") or {}).items()
                },
            })
        entries.append(entry)
    entries.sort(key=lambda e: e.get("captured_at") or "", reverse=True)
    return entries


def compare_censuses(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Diff two censuses and say whether shared-scope duplication was removed.

    `observations` are plain statements a caller can render as-is. They are deliberately
    not phrased as pass/fail: a drop is expected, but the right magnitude depends on how
    many vsys each group has, so the numbers are reported rather than judged.
    """
    result: dict[str, Any] = {
        "before_label": before.get("label"),
        "after_label": after.get("label"),
        "before_captured_at": before.get("captured_at"),
        "after_captured_at": after.get("captured_at"),
        "models": {},
        "observations": [],
    }

    for label in SCOPED_MODELS:
        b = before["models"].get(label, {})
        a = after["models"].get(label, {})
        b_dup = b.get("duplication", {}) or {}
        a_dup = a.get("duplication", {}) or {}
        result["models"][label] = {
            "total_rows": {"before": b.get("total_rows"), "after": a.get("total_rows"),
                           "delta": _delta(b.get("total_rows"), a.get("total_rows"))},
            "shared_rows": {"before": b_dup.get("shared_rows"), "after": a_dup.get("shared_rows"),
                            "delta": _delta(b_dup.get("shared_rows"), a_dup.get("shared_rows"))},
            "distinct_shared": {"before": b_dup.get("distinct_shared"), "after": a_dup.get("distinct_shared")},
            "rows_per_object": {"before": b_dup.get("rows_per_object"), "after": a_dup.get("rows_per_object")},
            "by_owner": {"before": b.get("by_owner"), "after": a.get("by_owner")},
        }

        rows_per = a_dup.get("rows_per_object")
        if rows_per is not None and rows_per > 1.0:
            result["observations"].append(
                f"{label}: {rows_per} rows per distinct shared object after — shared scope is "
                f"still stored more than once; expected 1.0 once it is owned by the group"
            )
        if (b_dup.get("distinct_shared") or 0) and a_dup.get("distinct_shared") != b_dup.get("distinct_shared"):
            result["observations"].append(
                f"{label}: distinct shared objects changed {b_dup.get('distinct_shared')} -> "
                f"{a_dup.get('distinct_shared')} — deduplication should not change WHICH objects exist, "
                f"so this is worth explaining before trusting the drop"
            )
        owner = a.get("by_owner") or {}
        if owner.get("orphaned"):
            result["observations"].append(
                f"{label}: {owner['orphaned']} rows have neither owner set"
            )

    for label in RELATED_MODELS:
        b = before["related_totals"].get(label)
        a = after["related_totals"].get(label)
        result.setdefault("related_totals", {})[label] = {
            "before": b, "after": a, "delta": _delta(b, a)
        }
        if b and not a:
            result["observations"].append(
                f"{label}: {b} -> 0. Migration 0015 clears these; a renormalize should have "
                f"rebuilt them, so zero here means the renormalize did not run or failed"
            )

    if not result["observations"]:
        result["observations"].append(
            "No anomalies: shared scope is stored once per appliance group and dependent "
            "rows were rebuilt."
        )
    return result


def _delta(before: int | None, after: int | None) -> int | None:
    if before is None or after is None:
        return None
    return after - before
