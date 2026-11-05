"""Read-oriented presentation helpers for normalized integration data.

These helpers keep common label and row-shaping logic out of individual views
when multiple apps render the same normalized integration models.
"""

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressObject,
    FieldProvenance,
    SecurityRule,
    SecurityRuleAddressRef,
)


def address_breadth_label(num_hosts: int | None) -> str:
    """One side of a rule's address breadth, as a reader sees it. `Unknown` is NOT `0`.

    A side is unmeasurable when it names a dynamic address group or a region, or an EDL/FQDN
    with no resolved content or content truncated at the collection ceiling. Printing 0 there
    would make the rule nobody could measure read as the tightest rule on the page, which is
    the failure PAN-POL-002 exists to catch.

    Here rather than in either consumer because BOTH of OptivEdgeAssessments' surfaces show it
    - the configuration explorer's rule rows and the findings sheet's Sources/Destinations
    columns - and two copies of the wording is two things to keep in step.
    """
    if num_hosts is None:
        return "(Unknown addresses)"
    return f"({num_hosts:,} address{'' if num_hosts == 1 else 'es'})"


def security_rule_config_source_label(config_source: str) -> str:
    if config_source == SecurityRule.SOURCE_PUSHED_PRE:
        return "Pre-Rulebase"
    if config_source == SecurityRule.SOURCE_PUSHED_POST:
        return "Post-Rulebase"
    return dict(SecurityRule.CONFIG_SOURCE_CHOICES).get(
        config_source,
        config_source.replace("_", " ").title(),
    )


def address_config_source_label(config_source: str) -> str:
    if config_source == SecurityRule.SOURCE_LOCAL:
        return "Local"
    if config_source in {SecurityRule.SOURCE_PUSHED_PRE, SecurityRule.SOURCE_PUSHED_POST}:
        return "Pushed"
    return config_source.replace("_", " ").title()


def listed_member_values(security_rule: SecurityRule, related_name: str) -> list[str]:
    return [value.value for value in getattr(security_rule, related_name).all()]


def joined_member_values(security_rule: SecurityRule, related_name: str) -> str:
    return ", ".join(listed_member_values(security_rule, related_name))


def listed_address_ref_values(
    security_rule: SecurityRule,
    related_name: str,
) -> list[str]:
    seen: set[tuple[int, str]] = set()
    values: list[str] = []
    for ref in getattr(security_rule, related_name).all():
        key = (ref.position, ref.raw_value)
        if key in seen:
            continue
        seen.add(key)
        values.append(ref.raw_value)
    return values


def listed_address_ref_members(
    security_rule: SecurityRule,
    related_name: str,
) -> list[str]:
    """What the rule NAMES, a static group counted rather than repeated.

    `resolve_static_group_members` flattens group membership onto the ref rows - one row per
    resolved target, each carrying the GROUP's name in `raw_value` - which is what lets an
    object reached only through a nested group be found without walking groups. A reader that
    prints `raw_value` per row therefore prints a three-member group's name three times.
    Measured on the lab 2026-11-05: eight rules, and the same cell wrong on the findings tab,
    in the workbook and on the remediation page. Jason, on a production estate: *"application
    groups appear to be duplicated in the source field ... individual address objects are not
    duplicated, which is interesting"* - and that is the tell, because an address object is one
    row and a static group is one row per member.

    THE COUNT IS KEPT rather than dropped. A group is one name on the rule and N addresses in
    effect, and the breadth line under this cell is the second half of that sentence; the count
    is what ties the two together. A row for a nested DYNAMIC group counts as one member, which
    is what it is - one entry of the group - and the breadth line already reads `(Unknown
    addresses)` when one is present.

    `listed_address_ref_values` is the same read without the counts, and is what the
    configuration explorer's rule rows use.
    """
    counted: dict[tuple[int, str], int] = {}
    kinds: dict[tuple[int, str], str] = {}
    for ref in getattr(security_rule, related_name).all():
        key = (ref.position, ref.raw_value)
        counted[key] = counted.get(key, 0) + 1
        kinds.setdefault(key, ref.ref_type)
    lines = []
    for (_position, raw_value), count in counted.items():
        if kinds[(_position, raw_value)] == (
                SecurityRuleAddressRef.RefType.STATIC_ADDRESS_GROUP):
            lines.append(f"{raw_value} ({count} member{'' if count == 1 else 's'})")
        else:
            lines.append(raw_value)
    return lines


def joined_address_ref_values(
    security_rule: SecurityRule,
    related_name: str,
) -> str:
    return ", ".join(listed_address_ref_values(security_rule, related_name))


def _entry_provenance_record(scoped_object) -> FieldProvenance | None:
    """Read the entry-level FieldProvenance row (field_name="__entry__") off a prefetched
    `field_provenance` GenericRelation, without issuing a fresh query per object."""
    for record in scoped_object.field_provenance.all():
        if record.field_name == "__entry__":
            return record
    return None


def entry_provenance_label(scoped_object) -> str:
    record = _entry_provenance_record(scoped_object)
    return record.get_provenance_type_display() if record else ""


def entry_device_group_name(scoped_object) -> str:
    record = _entry_provenance_record(scoped_object)
    if record and record.provenance_type == FieldProvenance.ProvenanceType.DEVICE_GROUP:
        return record.raw_value
    return ""


def build_address_object_row(address_object: AddressObject) -> dict:
    resolved_entries = list(address_object.resolved_entries.all())
    resolved_as_of = max((entry.collected_at for entry in resolved_entries), default=None)
    return {
        "kind": "Object",
        "config_source_label": address_config_source_label(address_object.config_source),
        "location": entry_provenance_label(address_object),
        "device_group_name": entry_device_group_name(address_object),
        "name": address_object.name,
        "value_type": address_object.get_address_type_display(),
        "value": address_object.value,
        "tags": [tag.value for tag in address_object.tags.all()],
        "members": [],
        "description": address_object.description,
        "source_snapshot": address_object.source_snapshot,
        # EDL(ip)/FQDN only: resolved via the separate "Refresh EDL/FQDN Cache" action, not
        # regular config sync - this is cached runtime state (EDL download cache, DNS
        # resolution), so it's surfaced with its own timestamp rather than implied to be as
        # current as the rest of this row.
        "resolved_entry_count": len(resolved_entries),
        "resolved_as_of": resolved_as_of,
        # System-generated objects (a literal address typed directly into a rule, or the
        # computed effective range for a negated rule) never came from the device's own
        # config - flagged so they're never mistaken for a real PAN-OS-configured object.
        "is_synthetic": address_object.is_synthetic,
        "synthetic_kind_display": address_object.get_synthetic_kind_display() if address_object.is_synthetic else "",
    }


def build_address_group_row(address_group: AddressGroup) -> dict:
    members = [member.value for member in address_group.members.all()]
    return {
        "kind": "Group",
        "config_source_label": address_config_source_label(address_group.config_source),
        "location": entry_provenance_label(address_group),
        "device_group_name": entry_device_group_name(address_group),
        "name": address_group.name,
        "value_type": "Static Group" if members else "Dynamic Group",
        "value": address_group.dynamic_filter,
        "tags": [tag.value for tag in address_group.tags.all()],
        "members": members,
        "description": "",
        "source_snapshot": address_group.source_snapshot,
        "resolved_entry_count": 0,
        "resolved_as_of": None,
        "is_synthetic": False,
        "synthetic_kind_display": "",
    }
