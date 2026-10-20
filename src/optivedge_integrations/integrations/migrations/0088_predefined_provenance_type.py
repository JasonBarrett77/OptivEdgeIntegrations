"""A PROVENANCE TYPE FOR AN OBJECT PAN-OS SHIPPED: `predefined`.

Choices-only: `provenance_type` is already `max_length=32` and `predefined` is ten characters,
so this alters no column and moves no data. Django records the new choice list because
`choices` lives in the field's deconstruction, not because the database needs anything.

WHAT AN EXISTING ROW HOLDS AFTER THIS MIGRATION: exactly what it held before. Nothing is
backfilled and nothing can be - the fact that distinguishes a predefined entry from a local one
is the SCOPE it was collected from, which lives in the payload and not in the row. The rows that
should say `predefined` today say `local` (predefined SSL/TLS service profiles and certificates,
via certificates.py) or do not exist at all (the built-in `any` and the predefined EDLs, whose
normalizer passed an empty provenance list). Both are corrected by re-normalizing the appliance;
until then a `local` row on a predefined-scope object is the old answer, not a new one.

No control reads `provenance_type` for these objects today, so nothing changes verdict here.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0087_antivirus_rule_assertions'),
    ]

    operations = [
        migrations.AlterField(
            model_name='fieldprovenance',
            name='provenance_type',
            field=models.CharField(choices=[('local', 'Local'), ('template', 'Template'), ('device_group', 'Device Group'), ('panorama', 'Panorama'), ('predefined', 'Predefined'), ('pan_os_default', 'PAN-OS default'), ('assumed_default', 'Assumed default'), ('not_configured', 'Not configured'), ('derived', 'Derived'), ('unknown', 'Unknown')], max_length=32),
        ),
    ]
