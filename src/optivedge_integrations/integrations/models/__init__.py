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
from .panorama import DeviceGroup, DeviceGroupBinding
from .authentication import AuthenticationProfile
from .authentication_sequence import AuthenticationSequence
from .certificates import Certificate, CertificateProfile, SslTlsServiceProfile
from .interface_management_profile import InterfaceManagementProfile
from .ike import IkeCryptoProfile, IkeGateway
from .interfaces import Interface
from .management_interface import (
    ManagementInterface,
    ManagementService,
    SERVICE_NAMES,
    PermittedSource,
    parse_permitted_source,
)
from .normalization import NormalizationIssue
from .admin_user import AdminUser, ROLE_KEYS
from .server_profile import ServerProfile
from .log_settings import (
    ALL_FORWARDING_LOG_TYPES_MISSING,
    ALL_PANORAMA_LOG_TYPES_MISSING,
    ALL_SYSTEM_SEVERITIES_MISSING,
    FORWARDING_PROFILE_LOG_TYPES,
    LogServerTarget,
    PANORAMA_FORWARDABLE_LOG_TYPES,
    SYSTEM_LOG_SEVERITIES,
    VsysLogForwarding,
)
from .authentication_settings import AuthenticationSettings
from .login_banner import LoginBanner
from .management_tls import ManagementTlsBinding
from .management_ssh import ManagementSshSettings
from .high_availability import HighAvailabilityConfig
from .panorama_registration import PanoramaRegistration
from .master_key import MasterKey
from .wildfire_settings import WildfireSettings
from .services_settings import LoggingSettings, UpdateServerSettings
from .device_services import NtpSettings, SnmpSettings, SystemIdentity
from .password_complexity import PasswordComplexityPolicy
from .password_profile import PasswordProfile, expiration_weakens
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
    SecurityProfile,
    SecurityProfileDecoder,
    SecurityProfileDnsSignatureSource,
    SecurityProfileApplicationOverride,
    SecurityProfileInlineDetector,
    SecurityProfileMlModel,
    SecurityProfileWildfireRule,
    SecurityProfileGroup,
    SecurityProfileCategoryVerdict,
    SecurityProfileSeverityVerdict,
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
    SecurityRuleProfileVerdict,
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
    "DeviceGroup",
    "DeviceGroupBinding",
    "ManagementStation",
    "Interface",
    "AuthenticationProfile",
    "AuthenticationSequence",
    "AdminUser",
    "ServerProfile",
    "ALL_FORWARDING_LOG_TYPES_MISSING",
    "ALL_PANORAMA_LOG_TYPES_MISSING",
    "ALL_SYSTEM_SEVERITIES_MISSING",
    "FORWARDING_PROFILE_LOG_TYPES",
    "LogServerTarget",
    "PANORAMA_FORWARDABLE_LOG_TYPES",
    "SYSTEM_LOG_SEVERITIES",
    "VsysLogForwarding",
    "ROLE_KEYS",
    "AuthenticationSettings",
    "LoggingSettings",
    "LoginBanner",
    "ManagementTlsBinding",
    "HighAvailabilityConfig",
    "ManagementSshSettings",
    "PanoramaRegistration",
    "MasterKey",
    "NtpSettings",
    "SnmpSettings",
    "SystemIdentity",
    "UpdateServerSettings",
    "PasswordComplexityPolicy",
    "PasswordProfile",
    "expiration_weakens",
    "Certificate",
    "CertificateProfile",
    "InterfaceManagementProfile",
    "IkeCryptoProfile",
    "IkeGateway",
    "SslTlsServiceProfile",
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
    "SecurityProfile",
    "SecurityProfileDecoder",
    "SecurityProfileDnsSignatureSource",
    "SecurityProfileApplicationOverride",
    "SecurityProfileInlineDetector",
    "SecurityProfileMlModel",
    "SecurityProfileWildfireRule",
    "WildfireSettings",
    "SecurityProfileGroup",
    "SecurityProfileCategoryVerdict",
    "SecurityProfileSeverityVerdict",
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
    "SecurityRuleProfileVerdict",
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
