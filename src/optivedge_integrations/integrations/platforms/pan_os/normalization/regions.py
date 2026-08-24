"""PAN-OS custom Region normalization helpers.

This module owns normalization of merged and pushed PAN-OS custom Region objects
(Objects > Regions) into enforcement-point scoped Django models. Mirrors
`addresses.py`'s address-group handling, but name-only — no member IP ranges or
geo-location, since rule resolution only needs to know the region exists and which
object it is.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from django.contrib.contenttypes.models import ContentType

from optivedge_integrations.integrations.models import (
    ApplianceGroup,
    EnforcementPoint,
    FieldProvenance,
    PolicyObjectNamespace,
    precedence_for,
    Region,
    SecurityRule,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    classify_prov_type,
    ensure_list,
    entry_provenance,
    merge_pushed_entries,
    merged_shared,
    merged_vsys_entry,
    pushed_shared,
    pushed_vsys_panorama,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
    is_panorama_managed,
    latest_merged_snapshot,
    latest_pushed_shared_snapshot,
    latest_pushed_vsys_snapshot,
)


@dataclass(slots=True)
class NormalizedRegion:
    source_snapshot: Snapshot
    config_source: str
    name: str
    namespace_type: str
    namespace_value: str
    precedence_rank: int
    raw_region: dict[str, Any]
    # (field_name, raw_key_or_ABSENT, raw_prov_value)
    field_provenance_data: list[tuple[str, Any, str | None]]


def normalize_region(
    *,
    source_snapshot: Snapshot,
    config_source: str,
    namespace_type: str,
    namespace_value: str,
    entry: dict[str, Any],
) -> NormalizedRegion:
    entry_rk, entry_rv = entry_provenance(entry)
    return NormalizedRegion(
        source_snapshot=source_snapshot,
        config_source=config_source,
        name=str(entry.get("@name") or ""),
        namespace_type=namespace_type,
        namespace_value=namespace_value,
        precedence_rank=precedence_for(namespace_type),
        raw_region=entry,
        field_provenance_data=[
            ("__entry__", entry_rk, entry_rv),
        ],
    )


def _region_entries(root: dict[str, Any]) -> list[dict[str, Any]]:
    region_node = root.get("region")
    if not isinstance(region_node, dict):
        return []
    return [entry for entry in ensure_list(region_node.get("entry")) if isinstance(entry, dict)]


def build_normalized_regions(
    enforcement_point: EnforcementPoint,
) -> tuple[list[NormalizedRegion], list[PolicyObjectIssue]]:
    """Regions for this point. Per-entry failures are reported, not raised - see
    build_normalized_addresses() for the reasoning and the point-level exceptions."""
    merged_snapshot = latest_merged_snapshot(enforcement_point)
    pushed_shared_snapshot = latest_pushed_shared_snapshot(enforcement_point)
    pushed_snapshot = latest_pushed_vsys_snapshot(enforcement_point)
    if merged_snapshot is None:
        raise ValueError(f"missing merged config snapshot for {enforcement_point}")
    if is_panorama_managed(enforcement_point) and pushed_shared_snapshot is None:
        raise ValueError(f"missing pushed shared policy snapshot for {enforcement_point}")
    if is_panorama_managed(enforcement_point) and pushed_snapshot is None:
        raise ValueError(f"missing pushed VSYS snapshot for {enforcement_point}")

    merged_root = merged_vsys_entry(merged_snapshot.payload, enforcement_point.vsys_name)
    merged_shared_root = merged_shared(merged_snapshot.payload)
    pushed_shared_root = pushed_shared(pushed_shared_snapshot.payload) if pushed_shared_snapshot is not None else {}
    pushed_root = pushed_vsys_panorama(pushed_snapshot.payload) if pushed_snapshot is not None else {}

    normalized_regions: list[NormalizedRegion] = []
    issues: list[PolicyObjectIssue] = []

    def collect(entry, source, build):
        name = str(entry.get("@name") or "") if isinstance(entry, dict) else ""
        if not name:
            issues.append(PolicyObjectIssue(
                kind="region", name="", severity=PolicyObjectIssue.ERROR,
                node="region", source=source,
                reason="entry has no @name, so it cannot be identified or referenced",
                raw_entry=entry if isinstance(entry, dict) else {},
            ))
            return
        try:
            normalized_regions.append(build())
        except Exception as exc:  # noqa: BLE001 - one bad entry must not take the rest
            issues.append(PolicyObjectIssue(
                kind="region", name=name, severity=PolicyObjectIssue.ERROR,
                node="region", source=source,
                reason=f"{type(exc).__name__}: {exc}", raw_entry=entry,
            ))

    for entry in _region_entries(merged_root):
        collect(entry, "merged vsys", lambda entry=entry: normalize_region(
                source_snapshot=merged_snapshot,
                config_source=SecurityRule.SOURCE_LOCAL,
                namespace_type=PolicyObjectNamespace.LOCAL_VSYS,
                namespace_value=enforcement_point.vsys_name,
                entry=entry,
        ))

    for entry in _region_entries(merged_shared_root):
        collect(entry, "merged shared", lambda entry=entry: normalize_region(
                source_snapshot=merged_snapshot,
                config_source=SecurityRule.SOURCE_LOCAL,
                namespace_type=PolicyObjectNamespace.LOCAL_SHARED,
                namespace_value="shared",
                entry=entry,
        ))

    # Both pushed reads merged, then classified per entry by @loc - never by which read
    # returned them. See common.merge_pushed_entries() / common.pushed_entry_scope().
    region_entries, region_conflicts = merge_pushed_entries(
        [(pushed_shared_root, pushed_shared_snapshot), (pushed_root, pushed_snapshot)],
        "region", vsys_name=enforcement_point.vsys_name, label=str(enforcement_point),
    )
    for reason, entry in region_conflicts:
        issues.append(PolicyObjectIssue(
            kind="region", name=str(entry.get("@name") or ""),
            severity=PolicyObjectIssue.WARNING, node="region", source="pushed",
            reason=reason, raw_entry=entry,
        ))
    for entry, snapshot, namespace_type, namespace_value in region_entries:
        collect(entry, "pushed", lambda entry=entry, snapshot=snapshot, namespace_type=namespace_type, namespace_value=namespace_value: normalize_region(
                source_snapshot=snapshot,
                config_source=SecurityRule.SOURCE_PUSHED_PRE,
                namespace_type=namespace_type,
                namespace_value=namespace_value,
                entry=entry,
        ))

    from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import (
        _drop_unnamed_and_duplicates,
    )

    normalized_regions, tail_issues = _drop_unnamed_and_duplicates(normalized_regions, "region")
    issues.extend(tail_issues)
    return normalized_regions, issues


def replace_regions(
    owner: EnforcementPoint | ApplianceGroup,
    normalized_regions: list[NormalizedRegion],
) -> list[Region]:
    """Write the regions `owner` owns. See replace_addresses() for the ordering rule."""
    from optivedge_integrations.integrations.platforms.pan_os.normalization.addresses import is_shared_scope

    keep_here = (
        (lambda n: not is_shared_scope(n.namespace_type))
        if isinstance(owner, EnforcementPoint)
        else (lambda n: is_shared_scope(n.namespace_type))
    )
    normalized_regions = [n for n in normalized_regions if keep_here(n)]
    owner_kwargs = (
        {"enforcement_point": owner}
        if isinstance(owner, EnforcementPoint)
        else {"appliance_group": owner}
    )

    owner.regions.all().delete()

    region_ct = ContentType.objects.get_for_model(Region)

    created_regions: list[Region] = []
    for normalized in normalized_regions:
        region = Region.objects.create(
            management_station=owner.management_station,
            **owner_kwargs,
            source_snapshot=normalized.source_snapshot,
            config_source=normalized.config_source,
            name=normalized.name,
            namespace_type=normalized.namespace_type,
            namespace_value=normalized.namespace_value,
            precedence_rank=normalized.precedence_rank,
            raw_region=normalized.raw_region,
            last_synced_at=normalized.source_snapshot.collected_at,
        )
        prov_rows = [
            FieldProvenance(
                content_type=region_ct,
                object_id=region.pk,
                field_name=fname,
                provenance_type=classify_prov_type(rk),
                raw_key=rk or "",
                raw_value=rv or "",
            )
            for fname, rk, rv in normalized.field_provenance_data
            if rk is not ABSENT
        ]
        if prov_rows:
            FieldProvenance.objects.bulk_create(prov_rows)
        created_regions.append(region)

    return created_regions
