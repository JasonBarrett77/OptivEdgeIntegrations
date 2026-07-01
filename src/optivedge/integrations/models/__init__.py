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
    IntegrationSyncRun,
    ManagementStation,
    Snapshot,
)
from .environment import ApplicationEnvironment
from .device_configuration import DeviceConfigurationProfile
from .policy import (
    AddressGroup,
    AddressGroupMember,
    AddressGroupTag,
    AddressObject,
    AddressObjectTag,
    CONFIG_SOURCE_CHOICES,
    PolicyObjectBase,
    PolicyObjectNamespace,
    PolicyObjectPrecedence,
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
    "AddressObjectTag",
    "ApplicationEnvironment",
    "CONFIG_SOURCE_CHOICES",
    "EnforcementNode",
    "EnforcementPoint",
    "IntegrationSyncRun",
    "ManagementStation",
    "DeviceConfigurationProfile",
    "PolicyObjectBase",
    "PolicyObjectNamespace",
    "PolicyObjectPrecedence",
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
]
