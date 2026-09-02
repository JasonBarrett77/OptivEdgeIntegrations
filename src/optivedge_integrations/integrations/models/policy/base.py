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


class PolicyObjectScope:
    """The axis PAN-OS actually resolves object names over.

    Established against a Panorama-managed PA-5220 (11.1.13-h3, multi-vsys) and a PA-VM
    (11.2.3, single-vsys), 2026-08, by reading compiled policy
    (`show running security-policy-addresses`). Configuration reads report every
    definition as-is and never name a winner, so they cannot answer this.

    There are TWO scopes, and scope is the only precedence axis:

        VSYS  >  SHARED

    Ownership - firewall-local versus Panorama-pushed - is **provenance, not precedence**.
    A pushed device-group object is vsys-scoped and beats a firewall-local *shared*
    object; measured, pushed-DG 10.221.1.1 beat local-shared 10.222.1.1.

    Two owners cannot occupy the same scope under one name: PAN-OS rejects the
    configuration rather than choosing. So within one scope a name has at most one
    definition, and two candidates in one scope means our collection is wrong - not that
    a tie needs breaking.

    VENDOR covers builtin/predefined objects. Its position below user configuration remains
    an assumption FOR POLICY OBJECTS, and it is now an assumption known to be wrong for other
    object types rather than merely unmeasured. Two have been measured, 2026-09-02, and
    neither behaves the way this rung describes:

        region                    a custom definition EXTENDS its predefined namesake -
                                  both sets of ranges apply. See resolve-object-name.md.
        ssl-tls-service-profile   the PREDEFINED definition WINS. A custom entry written to
                                  /config/shared under the shipped name TLSv1.3_Default was
                                  accepted, committed, and then discarded whole - protocol
                                  settings and certificate alike.

    Neither is "the user object shadows the predefined one", which is what VENDOR below user
    configuration encodes. So name-collision behaviour is PER OBJECT TYPE and cannot be
    carried between types in either direction.

    The rank is deliberately NOT changed. Both measurements are on objects that do not
    resolve through this ladder, and altering address-object resolution on the strength of
    them would repeat the error recorded above about the four-level ladder - reproducing
    observations that could not distinguish it, which is underdetermined rather than
    supported. What is measured for policy objects proper is still nothing.

    The technique, which is the reusable part: a name-collision question is answerable only
    by BEHAVIOUR - configuration reads report every definition as-is and never name a winner -
    and it needs a uniquely-named control state alongside the colliding one. Without a state
    that must come back different, "the custom definition was ignored" and "the binding was
    never wired up" are the same reading.

    A four-level ladder (local-vsys > local-shared > pushed-vsys > pushed-shared) was
    believed and is wrong. It reproduced every observation available at the time because
    those observations could not distinguish it from this model - underdetermined, not
    supported.
    """

    VSYS = "vsys"
    SHARED = "shared"
    VENDOR = "vendor"

    #: Resolution order, most specific first. Iterate this rather than sorting.
    ORDER = (VSYS, SHARED, VENDOR)


#: Which scope each namespace occupies. Namespaces stay as PROVENANCE - they record where
#: a definition came from - while the scope is what decides which one wins.
SCOPE_BY_NAMESPACE = {
    # vsys scope: local and pushed alike. Ownership does not separate them.
    PolicyObjectNamespace.LOCAL_VSYS: PolicyObjectScope.VSYS,
    PolicyObjectNamespace.PUSHED_VSYS_EFFECTIVE: PolicyObjectScope.VSYS,
    PolicyObjectNamespace.PANORAMA_DEVICE_GROUP: PolicyObjectScope.VSYS,
    # shared scope: likewise.
    PolicyObjectNamespace.LOCAL_SHARED: PolicyObjectScope.SHARED,
    PolicyObjectNamespace.PANORAMA_SHARED: PolicyObjectScope.SHARED,
    # vendor-supplied, below user configuration (position assumed, not measured).
    PolicyObjectNamespace.BUILTIN: PolicyObjectScope.VENDOR,
    PolicyObjectNamespace.PREDEFINED: PolicyObjectScope.VENDOR,
}


class PolicyObjectPrecedence:
    """The numeric encoding of PolicyObjectScope, for `Meta.ordering` and the composite
    index. It is derived, never chosen - use `precedence_for()` rather than writing a
    literal, so the rank and the namespace cannot disagree.

    Equal ranks are meaningful: two objects sharing a name and a rank occupy one scope,
    which PAN-OS rejects. A tie is a collection or classification fault, not something to
    break arbitrarily.
    """

    VSYS = 10
    SHARED = 20
    BUILTIN = 90
    PREDEFINED = 95


_RANK_BY_SCOPE = {
    PolicyObjectScope.VSYS: PolicyObjectPrecedence.VSYS,
    PolicyObjectScope.SHARED: PolicyObjectPrecedence.SHARED,
}


def scope_for(namespace_type: str) -> str:
    """The scope a namespace occupies. Unknown namespaces raise rather than defaulting -
    a new namespace must state which scope it belongs to."""
    try:
        return SCOPE_BY_NAMESPACE[namespace_type]
    except KeyError:
        raise ValueError(
            f"no scope defined for namespace {namespace_type!r}; add it to SCOPE_BY_NAMESPACE"
        ) from None


def precedence_for(namespace_type: str) -> int:
    """The rank for a namespace, derived from its scope. The single source of the value."""
    if namespace_type == PolicyObjectNamespace.PREDEFINED:
        return PolicyObjectPrecedence.PREDEFINED
    if namespace_type == PolicyObjectNamespace.BUILTIN:
        return PolicyObjectPrecedence.BUILTIN
    return _RANK_BY_SCOPE[scope_for(namespace_type)]


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

