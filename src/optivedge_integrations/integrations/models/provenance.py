"""Field-level provenance tracking for normalized PAN-OS configuration objects."""

from __future__ import annotations

from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.db import models


class ProvenancedMixin(models.Model):
    """A GenericRelation to FieldProvenance, and the model's own account of its computed fields.

    `DERIVED_FIELDS` names the columns normalization WORKED OUT rather than read: a verdict over
    several keys, a count, a value resolved through another object. They have no payload key, so
    they can never have a provenance row, and without being declared they are indistinguishable
    from a field nobody tracks.

    Declared here rather than recorded as rows because derived-ness belongs to the FIELD and
    never varies by object: 885 security rules would otherwise carry 885 identical copies of a
    static fact. It was hand-kept per SHEET in the xlsx prototype, which put it a repository
    away from the field it describes; `test_declared_derived_fields` holds it honest by failing
    if a declared field turns out to have a stored row.
    """

    #: Column names this model computes. Every one must exist on the model.
    DERIVED_FIELDS: tuple[str, ...] = ()

    field_provenance = GenericRelation(
        "integrations.FieldProvenance",
        related_query_name="%(app_label)s_%(class)s",
    )

    class Meta:
        abstract = True

    def provenance_for(self, field_name: str):
        """One answer for any field, so a consumer never has to interpret a blank.

        Returns the stored row; an UNSAVED FieldProvenance typed `derived` for a computed
        column; or None, which now means only that nothing tracks this field.
        """
        row = self.field_provenance.filter(field_name=field_name).first()
        if row is not None:
            return row
        if field_name in self.DERIVED_FIELDS:
            return FieldProvenance(
                content_type=ContentType.objects.get_for_model(type(self)),
                object_id=self.pk, field_name=field_name,
                provenance_type=FieldProvenance.ProvenanceType.DERIVED)
        return None


class FieldProvenance(models.Model):
    """Provenance record for a single field (or entry) on a normalized configuration object.

    One row per tracked field per object. field_name "__entry__" records the object's
    own entry-level provenance (e.g., the @ptpl on a named PAN-OS entry).

    WHAT A MISSING ROW MEANS CHANGED ON 2026-09-21. It used to mean "the key was absent from the
    payload", which made three situations look identical: a key absent with PAN-OS supplying a
    known default, a key absent with the stored value being OUR inference, and a field
    normalization does not track at all. Consumers could only guess between them, and the xlsx
    prototype was guessing per MODEL - `absent_provenance="PAN-OS default"` on a whole sheet -
    while implicit values are per KEY and point opposite ways inside one node: `disable-http`
    absent means the service is ON, `enable-log-high-dp-load` absent means it is OFF.

    So an absent key now records a row too, and a missing row means only that the field is not
    tracked.

    THE SAME CORRECTION REACHED `__entry__` ON 2026-10-05. An unmarked entry is a LOCALLY
    DEFINED object, and some normalizers wrote nothing for it - so absence meant both "defined
    on the device" and "nothing tracks this", which no consumer can tell apart. 25 of the lab's
    26 administrator accounts and half its interface management profiles were local and recorded
    nothing. An unmarked entry now records LOCAL. A missing `__entry__` row means only that the
    model does not track entry provenance - true of the `deviceconfig/system` settings models,
    which are nodes rather than named entries and carry their provenance per field.

    An OVERRIDE also leaves an entry unmarked, and LOCAL is correct there: the override replaced
    the object, so the device-side copy is what is in force and is where a change has to be
    made. What is lost is the history, not the destination.

    `@ptpl` names a template OR a template stack, and a stack has its own config layer that
    overrides its templates - `raw_value` is stored as given and not disambiguated.

    The five types that describe a value's origin:

      LOCAL / TEMPLATE / DEVICE_GROUP / PANORAMA   the key was PRESENT; this is where it came
                                                   from, read off the payload's own marker
      PAN_OS_DEFAULT   the key was ABSENT and PAN-OS's own default applies. The stored value is
                       that default, and the claim is backed by a measurement - `raw_value`
                       carries the value, and the citation lives with the declaration in
                       `normalization.common.Implicit`, in code, where it is reviewable and
                       cannot drift from the value it justifies
      ASSUMED_DEFAULT  the key was ABSENT and the stored value is OUR INFERENCE, not a measured
                       vendor fact. A consumer must not render this as a vendor default
      NOT_CONFIGURED   the key was ABSENT and normalization stored NOTHING - the field is null,
                       because assuming a value here would be worse than admitting ignorance.
                       `log-start` and `log-end` on a security rule are the case this exists
                       for: `read-a-security-rule.md` says their defaults are unmeasured and
                       must not be assumed, PAN-POL-009 asserts log-end, and the rule normalizer
                       has always stored null rather than False. Without this type that null
                       would have had to be described as a default of "no", which is the exact
                       fabrication the split above exists to prevent

    The split between the last two is the whole point and is not a formality. Jason, 2026-09-21:
    "It's critical that we get this right, we can't afford mistakes here." An assumed default
    presented as a vendor default is a fabricated fact about a customer's firewall.
    """

    class ProvenanceType(models.TextChoices):
        LOCAL           = "local",           "Local"
        TEMPLATE        = "template",        "Template"
        DEVICE_GROUP    = "device_group",    "Device Group"
        PANORAMA        = "panorama",        "Panorama"
        #: Key absent, PAN-OS supplies this value, and we have measured that it does.
        PAN_OS_DEFAULT  = "pan_os_default",  "PAN-OS default"
        #: Key absent, the stored value is our inference. NOT a vendor fact.
        ASSUMED_DEFAULT = "assumed_default", "Assumed default"
        #: Key absent and nothing stored - the field is null and we say why.
        NOT_CONFIGURED  = "not_configured",  "Not configured"
        #: No payload key at all: normalization computed this column. Never stored as a row -
        #: see ProvenancedMixin.DERIVED_FIELDS for why it is a declaration instead.
        DERIVED         = "derived",         "Derived"
        UNKNOWN         = "unknown",         "Unknown"

    #: The types that mean "this key was absent from the payload". A consumer asking "was this
    #: configured" asks this, rather than listing the two and falling behind a third.
    DEFAULTED_TYPES = ("pan_os_default", "assumed_default")

    #: Every type meaning "the payload did not carry this key". A consumer asking "did anyone
    #: configure this" asks this one; the three differ only in what we could say about it.
    ABSENT_TYPES = ("pan_os_default", "assumed_default", "not_configured")

    content_type   = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id      = models.PositiveIntegerField()
    content_object = GenericForeignKey("content_type", "object_id")

    field_name       = models.CharField(max_length=64)
    provenance_type  = models.CharField(max_length=32, choices=ProvenanceType.choices)
    raw_key          = models.CharField(max_length=32, blank=True)
    raw_value        = models.CharField(max_length=128, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["content_type", "object_id"]),
            models.Index(fields=["content_type", "object_id", "field_name"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["content_type", "object_id", "field_name"],
                name="integrations_unique_field_provenance_per_field",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.content_type} #{self.object_id} [{self.field_name}] = {self.provenance_type}"
