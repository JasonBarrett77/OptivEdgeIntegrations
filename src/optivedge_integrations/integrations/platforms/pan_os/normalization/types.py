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
    #: The object name this rule could not resolve, when that is why it failed. Lets a
    #: rule failure be linked to the object issue that caused it, so a report can say
    #: "1 root, 1300 consequent" instead of "1301 errors".
    unresolved_name: str = ""


@dataclass(slots=True)
class PolicyObjectIssue:
    """One object's normalization went wrong - scoped to that object, not the whole
    enforcement point. The sibling of SecurityRuleFailure, which has worked this way all
    along; objects were the outlier, where one bad entry discarded everything.

    `severity` describes THE PROBLEM. `disposition` describes WHAT WE DID. They are
    independent, and conflating them was the first version's mistake:

        severity=error   this should not be possible, so the data cannot be trusted
        severity=warning something had to be inferred, but the state itself is expected

        disposition=skipped  the object is absent; rules referencing it will fail, visibly
        disposition=kept     the object is present, possibly on a guess

    A duplicate name in one scope is error+kept: PAN-OS rejects that configuration, so it
    can only be our fault (error) - but dropping it makes every referencing rule fail,
    reporting the fault against rules that are fine, so the first is kept (kept). An
    unmarked @loc is warning+kept: absence of the marker is a real, observed state, and
    the scope is a documented fallback rather than a fault.

    raw_entry is carried for drill-through: a name and a reason rarely explain a payload
    problem on their own.
    """

    kind: str
    name: str
    severity: str
    reason: str
    disposition: str = "skipped"
    #: For a rule failure, the object name it could not resolve.
    related_object_name: str = ""
    #: Set when this issue is a consequence of another in the same run.
    is_consequent: bool = False
    #: Whether the entry belongs to shared scope. Issues follow the same ownership rule as
    #: the objects they describe - shared to the appliance group, everything else to the
    #: enforcement point - so the two passes cannot both record the same one.
    shared_scope: bool = False
    node: str = ""
    source: str = ""
    raw_entry: dict = field(default_factory=dict)

    ERROR = "error"
    WARNING = "warning"
    SKIPPED = "skipped"
    KEPT = "kept"


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
