"""Policy object models shared across addresses, services, and similar families."""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from ..base import SyncTrackedModel
from ..collected import ApplianceGroup, EnforcementPoint, ManagementStation
from .base import CONFIG_SOURCE_CHOICES, PolicyObjectBase, PolicyObjectScope, scope_for


class ScopedPolicyObject(PolicyObjectBase, SyncTrackedModel):
    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
    )
    #: Owner follows the object's SCOPE, not the collection that produced it:
    #:
    #:     vsys scope    -> enforcement_point   (local-vsys, pushed device-group)
    #:     shared scope  -> appliance_group     (local-shared, Panorama-shared)
    #:     vendor        -> enforcement_point   (builtin/predefined, synthesized per point)
    #:
    #: Shared scope belongs to the appliance group because the group is the unit that
    #: holds ONE configuration - every vsys on it reads the same /config/shared and the
    #: same Panorama-Shared push. Storing it per enforcement point copied a single
    #: observation once per vsys: 264 objects became 1,320 rows on a five-vsys PA-5220.
    #:
    #: Exactly one owner is set. See owner_kwargs_for() in normalization/addresses.py.
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    appliance_group = models.ForeignKey(
        ApplianceGroup,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
    )
    config_source = models.CharField(max_length=32, choices=CONFIG_SOURCE_CHOICES)

    class Meta:
        abstract = True

    @property
    def owner(self):
        """The enforcement point or appliance group this object is scoped to."""
        return self.enforcement_point or self.appliance_group

    def clean(self) -> None:
        owner_count = int(self.enforcement_point_id is not None) + int(self.appliance_group_id is not None)
        if owner_count != 1:
            raise ValidationError(
                "Policy object must have exactly one owner: an enforcement point for "
                "vsys-scoped objects, or an appliance group for shared-scoped ones."
            )
        if scope_for(self.namespace_type) == PolicyObjectScope.SHARED:
            if self.appliance_group_id is None:
                raise ValidationError(
                    f"{self.namespace_type} is shared-scoped and must belong to an appliance group."
                )
        elif self.enforcement_point_id is None:
            raise ValidationError(
                f"{self.namespace_type} is not shared-scoped and must belong to an enforcement point."
            )

        if self.enforcement_point is not None and self.enforcement_point.management_station_id != self.management_station_id:
            raise ValidationError("Policy object must belong to the same management station as the enforcement point.")
        if self.appliance_group is not None and self.appliance_group.management_station_id != self.management_station_id:
            raise ValidationError("Policy object must belong to the same management station as the appliance group.")
        if self.enforcement_point is None:
            return

        if (
            self.source_snapshot.enforcement_point_id != self.enforcement_point_id
            and self.source_snapshot.appliance_id is None
            and self.source_snapshot.appliance_group_id is None
        ):
            raise ValidationError(
                "Policy object source snapshot must belong to the enforcement point or a related appliance/appliance group."
            )

        snapshot_station_id = (
            self.source_snapshot.management_station_id
            or getattr(self.source_snapshot.appliance, "management_station_id", None)
            or getattr(self.source_snapshot.appliance_group, "management_station_id", None)
            or getattr(self.source_snapshot.enforcement_point, "management_station_id", None)
        )
        if snapshot_station_id != self.management_station_id:
            raise ValidationError("Policy object source snapshot must belong to the same management station.")


class AddressObject(ScopedPolicyObject):

    #: Computed here: classifications of what the entry turned out to be. See ProvenancedMixin.DERIVED_FIELDS.
    #: The two resolved_* fields are collection outcomes of the EDL/FQDN cache refresh, not
    #: configuration - nothing in the config says them, so there is no provenance row to carry.
    DERIVED_FIELDS = (
        "is_missing",
        "is_any",
        "is_edl",
        "is_builtin",
        "is_synthetic",
        # Worked out from the address value - 2^(32-prefix) for a prefix, the interval total
        # for an EDL, FQDN or negated complement. No payload key carries it, so it can have no
        # provenance row. ipv4_start_int/ipv4_end_int are computed the same way and are not
        # declared; that is a pre-existing gap, not a statement that they are read.
        "num_hosts",
        "resolved_content_truncated",
        "resolved_content_source_total",
    )
    TYPE_BUILTIN_ANY = "builtin_any"
    TYPE_EDL = "edl"
    TYPE_IP_NETMASK = "ip_netmask"
    TYPE_FQDN = "fqdn"
    TYPE_IP_RANGE = "ip_range"
    TYPE_IP_WILDCARD = "ip_wildcard"
    TYPE_NEGATED_COMPLEMENT = "negated_complement"

    ADDRESS_TYPE_CHOICES = [
        (TYPE_BUILTIN_ANY, "Any"),
        (TYPE_EDL, "External Dynamic List"),
        (TYPE_IP_NETMASK, "IP Netmask"),
        (TYPE_FQDN, "FQDN"),
        (TYPE_IP_RANGE, "IP Range"),
        (TYPE_IP_WILDCARD, "IP Wildcard"),
        (TYPE_NEGATED_COMPLEMENT, "Negated Complement (system-generated)"),
    ]

    SYNTHETIC_KIND_RULE_LITERAL = "rule_literal"
    SYNTHETIC_KIND_NEGATED_COMPLEMENT = "negated_complement"
    SYNTHETIC_KIND_CHOICES = [
        (SYNTHETIC_KIND_RULE_LITERAL, "Rule Literal Address"),
        (SYNTHETIC_KIND_NEGATED_COMPLEMENT, "Negated Complement"),
    ]

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="address_objects",
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="address_objects",
        null=True,
        blank=True,
    )
    appliance_group = models.ForeignKey(
        ApplianceGroup,
        on_delete=models.CASCADE,
        related_name="address_objects",
        null=True,
        blank=True,
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="address_objects",
    )
    address_type = models.CharField(max_length=32, choices=ADDRESS_TYPE_CHOICES)
    value = models.TextField(blank=True)
    normalized_value = models.TextField(blank=True)
    ipv4_start_int = models.BigIntegerField(null=True, blank=True)
    ipv4_end_int = models.BigIntegerField(null=True, blank=True)
    num_hosts = models.BigIntegerField(null=True, blank=True)
    is_any = models.BooleanField(default=False)
    is_edl = models.BooleanField(default=False)
    is_builtin = models.BooleanField(default=False)
    is_synthetic = models.BooleanField(default=False)
    synthetic_kind = models.CharField(max_length=32, choices=SYNTHETIC_KIND_CHOICES, blank=True, default="")
    edl_list_type = models.CharField(max_length=16, blank=True, default="")
    #: True when resolved_entries hold only part of what the device reported for this object.
    #: An object whose resolved content is truncated must NOT be read as a complete set: an
    #: address in the discarded tail is indistinguishable from an address the list excludes,
    #: so "not in this EDL" is unanswerable while this is True.
    resolved_content_truncated = models.BooleanField(default=False)
    #: What the device said the list holds, which is what truncation is measured against.
    #: Null means never refreshed, or a kind that has no such count (FQDN).
    resolved_content_source_total = models.BigIntegerField(null=True, blank=True)
    description = models.TextField(blank=True)
    raw_object = models.JSONField(default=dict, blank=True)

    @property
    def size_known(self) -> bool:
        """Whether this object's size was established. Mirrors the search layer's
        `num_hosts__isnull` inverted, so a control can both FILTER on the field and read it back
        when presenting the finding - the findings sheet refuses a tested field the model can
        neither store nor compute, which is how PAN-COV-001 broke the coverage page."""
        return self.num_hosts is not None

    @property
    def collection_attempted(self) -> bool:
        """Whether the DEVICE ever answered about this object's content.

        True and still unsized means the device could not resolve the list - a fault on the
        device, reported by PAN-POL-023. False means nobody asked yet, which is the gap
        PAN-COV-001 reports. The two are identical in `num_hosts` and must not be conflated.
        """
        return self.resolved_content_source_total is not None

    class Meta:
        ordering = ["name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "name", "precedence_rank"]),
            models.Index(fields=["appliance_group", "name", "precedence_rank"]),
            models.Index(fields=["enforcement_point", "normalized_value"]),
            models.Index(fields=["enforcement_point", "namespace_type", "namespace_value"]),
            models.Index(fields=["enforcement_point", "is_any"]),
            models.Index(fields=["enforcement_point", "ipv4_start_int"]),
            models.Index(fields=["enforcement_point", "ipv4_end_int"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_address_object_per_point_namespace",
            ),
            models.UniqueConstraint(
                fields=["enforcement_point"],
                condition=models.Q(is_any=True),
                name="integrations_single_any_address_object_per_point",
            ),
            models.CheckConstraint(
                condition=models.Q(is_any=False) | models.Q(is_builtin=True),
                name="integrations_any_address_object_must_be_builtin",
            ),
            models.CheckConstraint(
                condition=~models.Q(address_type="edl") | models.Q(is_edl=True),
                name="integrations_edl_address_object_flag",
            ),
            models.CheckConstraint(
                condition=~models.Q(address_type="builtin_any")
                | (models.Q(is_any=True) & models.Q(is_builtin=True)),
                name="integrations_builtin_any_address_object_flags",
            ),
            models.CheckConstraint(
                condition=models.Q(synthetic_kind="") | models.Q(is_synthetic=True),
                name="integrations_synthetic_kind_requires_is_synthetic",
            ),
            models.CheckConstraint(
                condition=~models.Q(address_type="negated_complement") | models.Q(is_synthetic=True),
                name="integrations_negated_complement_must_be_synthetic",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} / {self.namespace_key} / {self.name}"

    def clean(self) -> None:
        super().clean()
        if self.is_any and not self.is_builtin:
            raise ValidationError("Address objects marked is_any must also be marked is_builtin.")

        if self.is_edl and self.address_type != self.TYPE_EDL:
            raise ValidationError("Address objects marked is_edl must use the edl address type.")

        if self.address_type == self.TYPE_BUILTIN_ANY and (not self.is_any or not self.is_builtin):
            raise ValidationError("Built-in any address objects must set both is_any and is_builtin.")

        if self.address_type == self.TYPE_EDL and not self.is_edl:
            raise ValidationError("EDL address objects must set is_edl.")

        if self.synthetic_kind and not self.is_synthetic:
            raise ValidationError("Address objects with a synthetic_kind must set is_synthetic.")

        if self.address_type == self.TYPE_NEGATED_COMPLEMENT and not self.is_synthetic:
            raise ValidationError("Negated-complement address objects must set is_synthetic.")


class AddressObjectTag(models.Model):
    address_object = models.ForeignKey(
        AddressObject,
        on_delete=models.CASCADE,
        related_name="tags",
    )
    value = models.CharField(max_length=255)
    prov = models.CharField(max_length=128, blank=True)
    position = models.PositiveIntegerField()

    class Meta:
        ordering = ["position", "id"]

    def __str__(self) -> str:
        return self.value


class AddressObjectResolvedEntry(models.Model):
    """A merged, disjoint IPv4 interval resolved at runtime for an EDL(ip)/FQDN AddressObject.

    Populated only by the explicit "Refresh EDL/FQDN cache" action, never by regular
    config normalization - this is operational/cached state (EDL download cache, DNS
    resolution cache), not committed configuration, and can go stale independently of
    address_object.last_synced_at. An EDL/FQDN object with zero rows here has simply
    never been refreshed (or resolved to nothing), and is excluded from IP-semantic
    matching exactly like it is today.
    """

    address_object = models.ForeignKey(
        AddressObject,
        on_delete=models.CASCADE,
        related_name="resolved_entries",
    )
    ipv4_start_int = models.BigIntegerField()
    ipv4_end_int = models.BigIntegerField()
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="address_object_resolved_entries",
    )
    collected_at = models.DateTimeField()

    class Meta:
        ordering = ["ipv4_start_int", "id"]
        indexes = [
            models.Index(fields=["address_object", "ipv4_start_int", "ipv4_end_int"]),
        ]

    def __str__(self) -> str:
        return f"{self.address_object} / {self.ipv4_start_int}-{self.ipv4_end_int}"


class AddressGroup(ScopedPolicyObject):

    #: Computed here: referenced but never defined. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
    )
    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="address_groups",
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="address_groups",
        null=True,
        blank=True,
    )
    appliance_group = models.ForeignKey(
        ApplianceGroup,
        on_delete=models.CASCADE,
        related_name="address_groups",
        null=True,
        blank=True,
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="address_groups",
    )
    dynamic_filter = models.TextField(blank=True)
    raw_group = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "name", "precedence_rank"]),
            models.Index(fields=["appliance_group", "name", "precedence_rank"]),
            models.Index(fields=["enforcement_point", "namespace_type", "namespace_value"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_address_group_per_point_namespace",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} / {self.namespace_key} / {self.name}"

    def clean(self) -> None:
        super().clean()


class AddressGroupTag(models.Model):
    address_group = models.ForeignKey(
        AddressGroup,
        on_delete=models.CASCADE,
        related_name="tags",
    )
    value = models.CharField(max_length=255)
    prov = models.CharField(max_length=128, blank=True)
    position = models.PositiveIntegerField()

    class Meta:
        ordering = ["position", "id"]

    def __str__(self) -> str:
        return self.value


class AddressGroupMember(models.Model):
    address_group = models.ForeignKey(
        AddressGroup,
        on_delete=models.CASCADE,
        related_name="members",
    )
    value = models.CharField(max_length=255)
    prov = models.CharField(max_length=128, blank=True)
    position = models.PositiveIntegerField()

    class Meta:
        ordering = ["position", "id"]

    def __str__(self) -> str:
        return self.value


class Region(ScopedPolicyObject):
    """A PAN-OS custom Region object (Objects > Regions), collected as a named
    reference only — no member IP ranges or geo-location, since rule resolution
    only needs to know the region exists and which object it is."""

    #: Computed here: referenced but never defined. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
    )

    management_station = models.ForeignKey(
        ManagementStation,
        on_delete=models.CASCADE,
        related_name="regions",
    )
    enforcement_point = models.ForeignKey(
        EnforcementPoint,
        on_delete=models.CASCADE,
        related_name="regions",
        null=True,
        blank=True,
    )
    appliance_group = models.ForeignKey(
        ApplianceGroup,
        on_delete=models.CASCADE,
        related_name="regions",
        null=True,
        blank=True,
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="regions",
    )
    raw_region = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name", "precedence_rank", "id"]
        indexes = [
            models.Index(fields=["enforcement_point", "name", "precedence_rank"]),
            models.Index(fields=["appliance_group", "name", "precedence_rank"]),
            models.Index(fields=["enforcement_point", "namespace_type", "namespace_value"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point", "name", "namespace_type", "namespace_value"],
                name="integrations_unique_region_per_point_namespace",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.enforcement_point} / {self.namespace_key} / {self.name}"

    def clean(self) -> None:
        super().clean()
