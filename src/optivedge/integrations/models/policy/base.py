"""Shared policy-object model primitives."""

from __future__ import annotations

from django.db import models


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


class PolicyObjectPrecedence:
    LOCAL_VSYS = 10
    LOCAL_SHARED = 20
    PUSHED_VSYS_EFFECTIVE = 30
    PANORAMA_SHARED = 40
    PANORAMA_DEVICE_GROUP = 50
    BUILTIN = 90


class PolicyObjectBase(models.Model):
    name = models.CharField(max_length=255)
    provenance = models.CharField(max_length=128, blank=True)
    namespace_type = models.CharField(max_length=64, choices=PolicyObjectNamespace.choices)
    namespace_value = models.CharField(max_length=255)
    precedence_rank = models.PositiveIntegerField()

    class Meta:
        abstract = True

    @property
    def namespace_key(self) -> str:
        return f"{self.namespace_type}:{self.namespace_value}"

