"""Normalization result types."""

from __future__ import annotations

from dataclasses import dataclass, field

from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressObject,
    Appliance,
    ApplianceGroup,
    EnforcementNode,
    EnforcementPoint,
    DeviceConfigurationProfile,
    Region,
    SecurityRule,
)


@dataclass(slots=True)
class SecurityRuleFailure:
    """One rule's normalization failed (an unresolvable source/destination member, etc.) and
    was skipped - scoped to that single rule, not the whole enforcement point."""

    name: str
    config_source: str
    rule_position: int
    error_text: str


@dataclass(slots=True)
class PolicyObjectIssue:
    """One object's normalization failed or was inferred - scoped to that object, not the
    whole enforcement point. The sibling of SecurityRuleFailure, which has worked this way
    all along; objects were the outlier, where one bad entry discarded everything.

    severity distinguishes the two cases the report has to tell apart:

        error    the object was SKIPPED. Rules referencing it will fail, visibly.
        warning  the object was KEPT, but something about it was inferred rather than
                 read - an unmarked @loc, a duplicate resolved by insertion order. Nothing
                 downstream fails, which is exactly why it needs surfacing somewhere.

    raw_entry is carried for drill-through: a name and a reason rarely explain a payload
    problem on their own.
    """

    kind: str
    name: str
    severity: str
    reason: str
    node: str = ""
    source: str = ""
    raw_entry: dict = field(default_factory=dict)

    ERROR = "error"
    WARNING = "warning"


@dataclass(slots=True)
class PANOSNormalizedCollection:
    address_objects: list[AddressObject]
    address_groups: list[AddressGroup]
    appliances: list[Appliance]
    appliance_groups: list[ApplianceGroup]
    enforcement_points: list[EnforcementPoint]
    enforcement_nodes: list[EnforcementNode]
    device_configuration_profiles: list[DeviceConfigurationProfile]
    security_rules: list[SecurityRule]
    regions: list[Region] = field(default_factory=list)
    security_rule_failures: list[SecurityRuleFailure] = field(default_factory=list)
    policy_object_issues: list[PolicyObjectIssue] = field(default_factory=list)
