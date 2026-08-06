"""Shared policy-object model primitives."""

from __future__ import annotations

from django.db import models

from ..provenance import ProvenancedMixin


CONFIG_SOURCE_CHOICES = [
    ("local", "Local"),
    ("pushed_pre", "Pushed Pre-Rulebase"),
    ("pushed_post", "Pushed Post-Rulebase"),
    ("default", "Default"),
]


class PolicyObjectNamespace(models.TextChoices):
    LOCAL_VSYS = "local_vsys", "Local VSYS"
    LOCAL_SHARED = "local_shared", "Local Shared"
    PANORAMA_SHARED = "panorama_shared", "Panorama Shared"
    PANORAMA_DEVICE_GROUP = "panorama_device_group", "Panorama Device Group"
    PUSHED_VSYS_EFFECTIVE = "pushed_vsys_effective", "Pushed VSYS Effective"
    BUILTIN = "builtin", "Built-In"
    PREDEFINED = "predefined", "Predefined"


class PolicyObjectPrecedence:
    """MEASURED WRONG - a four-level ladder PAN-OS does not implement. Do not extend.

    Established against a Panorama-managed PA-5220 (11.1.13-h3, multi-vsys) and a PA-VM
    (11.2.3, single-vsys), 2026-08, by reading compiled policy
    (`show running security-policy-addresses`) rather than configuration - configuration
    reads report every definition as-is and never name a winner.

    PAN-OS has **two** scopes, and scope is the only precedence axis:

        vsys-specific  >  shared

    Ownership (firewall-local vs Panorama-pushed) is provenance, not precedence. Two
    owners cannot occupy the same scope under one name - PAN-OS rejects the configuration
    instead of choosing a winner.

    The ranks below are wrong twice over:

    1. LOCAL_SHARED (20) ahead of PUSHED_VSYS_EFFECTIVE (30) is INVERTED. A pushed
       device-group object is vsys-scoped and beats a firewall-local shared object;
       measured, pushed-DG 10.221.1.1 beat local-shared 10.222.1.1 in compiled policy.
    2. Ranks 10/30 and 20/40 model coexistence for pairs PAN-OS REJECTS - states that
       cannot exist on a device.

    The ladder reproduced every earlier observation, which is why it survived: those
    observations could not distinguish it from the two-scope model. It was
    underdetermined, not supported.

    The seven PolicyObjectNamespace values remain useful *provenance* and should be kept;
    only their use as an ordering is unsound. Note also that
    `normalization/security_rules.py::literal_namespace` hardcodes 10 and 30 rather than
    reading this class, so changing the values here does not reach every site.

    See CLAUDE.md, "Object scope resolution (PAN-OS)".
    """

    LOCAL_VSYS = 10
    LOCAL_SHARED = 20
    PUSHED_VSYS_EFFECTIVE = 30
    PANORAMA_SHARED = 40
    PANORAMA_DEVICE_GROUP = 50
    BUILTIN = 90
    PREDEFINED = 95


class PolicyObjectBase(ProvenancedMixin, models.Model):
    name = models.CharField(max_length=255)
    namespace_type = models.CharField(max_length=64, choices=PolicyObjectNamespace.choices)
    namespace_value = models.CharField(max_length=255)
    precedence_rank = models.PositiveIntegerField()

    class Meta:
        abstract = True

    @property
    def namespace_key(self) -> str:
        return f"{self.namespace_type}:{self.namespace_value}"

