"""Delete FieldProvenance rows whose model no longer exists.

`FieldProvenance` is a generic relation, so dropping a model leaves its rows behind: nothing
cascades, because there is no foreign key to cascade from. `DeviceConfigurationProfile` was
split into seven models and deleted, and left 28 rows in the lab database pointing at a
content type with no class - 7 of them `template`, which is how they were noticed, while
counting which templates push what.

Rows pointing at a DELETED OBJECT are a different question and were measured at zero: object
provenance is rewritten correctly on every renormalization. This migration is only about the
dropped model.

`apps.get_model` here is the REAL app registry rather than the migration's historical one, on
purpose: "does this model still exist in the code" is exactly the question, and a historical
registry answers it as of this migration rather than as of now.
"""

from django.apps import apps as global_apps
from django.db import migrations


def prune_orphaned_provenance(apps, schema_editor):
    FieldProvenance = apps.get_model("integrations", "FieldProvenance")
    ContentType = apps.get_model("contenttypes", "ContentType")

    orphaned_ids = []
    for content_type_id in (
        FieldProvenance.objects.values_list("content_type_id", flat=True).distinct()
    ):
        content_type = ContentType.objects.filter(pk=content_type_id).first()
        if content_type is None:
            orphaned_ids.append(content_type_id)
            continue
        try:
            global_apps.get_model(content_type.app_label, content_type.model)
        except LookupError:
            orphaned_ids.append(content_type_id)

    if orphaned_ids:
        FieldProvenance.objects.filter(content_type_id__in=orphaned_ids).delete()


def noop(apps, schema_editor):
    """Irreversible in substance - the rows described a model that no longer exists - but
    reversible as a migration, so an unrelated rollback is not blocked by it."""


class Migration(migrations.Migration):

    dependencies = [
        ("integrations", "0064_device_group"),
        ("contenttypes", "0002_remove_content_type_name"),
    ]

    operations = [
        migrations.RunPython(prune_orphaned_provenance, noop),
    ]
