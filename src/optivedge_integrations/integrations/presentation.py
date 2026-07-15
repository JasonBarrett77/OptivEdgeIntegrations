"""Read-oriented presentation helpers for normalized integration data.

These helpers keep common label and row-shaping logic out of individual views
when multiple apps render the same normalized integration models.
"""

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressObject,
    SecurityRule,
    SecurityRuleAddressRef,
)


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


def joined_address_ref_values(
    security_rule: SecurityRule,
    related_name: str,
) -> str:
    return ", ".join(listed_address_ref_values(security_rule, related_name))


def entry_provenance_label(scoped_object) -> str:
    """Read the entry-level FieldProvenance row (field_name="__entry__") off a prefetched
    `field_provenance` GenericRelation, without issuing a fresh query per object."""
    for record in scoped_object.field_provenance.all():
        if record.field_name == "__entry__":
            return record.get_provenance_type_display()
    return ""


def build_address_object_row(address_object: AddressObject) -> dict:
    return {
        "kind": "Object",
        "config_source_label": address_config_source_label(address_object.config_source),
        "provenance": entry_provenance_label(address_object),
        "name": address_object.name,
        "value_type": address_object.get_address_type_display(),
        "value": address_object.value,
        "tags": [tag.value for tag in address_object.tags.all()],
        "members": [],
        "description": address_object.description,
        "source_snapshot": address_object.source_snapshot,
    }


def build_address_group_row(address_group: AddressGroup) -> dict:
    members = [member.value for member in address_group.members.all()]
    return {
        "kind": "Group",
        "config_source_label": address_config_source_label(address_group.config_source),
        "provenance": entry_provenance_label(address_group),
        "name": address_group.name,
        "value_type": "Static Group" if members else "Dynamic Group",
        "value": address_group.dynamic_filter,
        "tags": [tag.value for tag in address_group.tags.all()],
        "members": members,
        "description": "",
        "source_snapshot": address_group.source_snapshot,
    }
