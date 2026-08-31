"""Integration domain models.

This package owns persistence-facing integration entities used by current and
future consumer apps. Keep cross-app semantics explicit and extend carefully
while the normalization model is still evolving.
"""

from .base import SyncTrackedModel, TimestampedModel
from .provenance import FieldProvenance, ProvenancedMixin
from .collected import (
    Appliance,
    ApplianceGroup,
    EnforcementNode,
    EnforcementPoint,
    ManagementStation,
    Snapshot,
)
from .events import IntegrationEvent, IntegrationRun
from .device_configuration import DeviceConfigurationProfile
from .interfaces import Interface
from .management_interface import (
    ManagementInterface,
    ManagementService,
    SERVICE_NAMES,
    PermittedSource,
    parse_permitted_source,
)
from .normalization import NormalizationIssue
from .notes import Note
from .zones import Zone, ZoneInterface
from .policy import (
    AddressGroup,
    AddressGroupMember,
    AddressGroupTag,
    AddressObject,
    AddressObjectResolvedEntry,
    AddressObjectTag,
    CONFIG_SOURCE_CHOICES,
    PolicyObjectBase,
    PolicyObjectNamespace,
    PolicyObjectPrecedence,
    PolicyObjectScope,
    precedence_for,
    scope_for,
    Region,
    ScopedPolicyObject,
    SecurityRule,
    SecurityRuleApplication,
    SecurityRuleCategory,
    SecurityRuleDestinationAddressRef,
    SecurityRuleDestinationHip,
    SecurityRuleFromZone,
    SecurityRuleProfile,
    SecurityRuleProfileGroup,
    SecurityRuleSearchVocabularyEntry,
    SecurityRuleSaasTenant,
    SecurityRuleSaasUser,
    SecurityRuleService,
    SecurityRuleSourceAddressRef,
    SecurityRuleSourceHip,
    SecurityRuleSourceUser,
    SecurityRuleAddressRef,
    SecurityRuleToZone,
    SecurityRuleValue,
)

__all__ = [
    "Appliance",
    "FieldProvenance",
    "ProvenancedMixin",
    "ApplianceGroup",
    "AddressGroup",
    "AddressGroupMember",
    "AddressGroupTag",
    "AddressObject",
    "AddressObjectResolvedEntry",
    "AddressObjectTag",
    "CONFIG_SOURCE_CHOICES",
    "EnforcementNode",
    "EnforcementPoint",
    "IntegrationEvent",
    "IntegrationRun",
    "ManagementStation",
    "DeviceConfigurationProfile",
    "Interface",
    "ManagementInterface",
    "ManagementService",
    "SERVICE_NAMES",
    "PermittedSource",
    "parse_permitted_source",
    "NormalizationIssue",
    "Note",
    "PolicyObjectBase",
    "PolicyObjectNamespace",
    "PolicyObjectPrecedence",
    "PolicyObjectScope",
    "precedence_for",
    "scope_for",
    "Region",
    "ScopedPolicyObject",
    "SecurityRule",
    "SecurityRuleApplication",
    "SecurityRuleCategory",
    "SecurityRuleDestinationAddressRef",
    "SecurityRuleDestinationHip",
    "SecurityRuleFromZone",
    "SecurityRuleAddressRef",
    "SecurityRuleProfile",
    "SecurityRuleProfileGroup",
    "SecurityRuleSearchVocabularyEntry",
    "SecurityRuleSaasTenant",
    "SecurityRuleSaasUser",
    "SecurityRuleService",
    "SecurityRuleSourceAddressRef",
    "SecurityRuleSourceHip",
    "SecurityRuleSourceUser",
    "SecurityRuleToZone",
    "SecurityRuleValue",
    "Snapshot",
    "SyncTrackedModel",
    "TimestampedModel",
    "Zone",
    "ZoneInterface",
]
