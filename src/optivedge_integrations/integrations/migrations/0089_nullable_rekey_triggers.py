"""The three SSH session-rekey triggers become NULLABLE, because their defaults are unmeasured.

`rekey_interval_seconds`, `rekey_data_mb` and `rekey_packets_exponent` stored 0 for an absent
`session-rekey` key. 0 is also a value an administrator can configure, and what it MEANS when
configured is documented per trigger (no time limit, the cipher's own data limit, 2^28 packets,
Help p.905) - so the stand-in and a deliberate 0 were the same number, and the permissive one.
The module has said since it was written that these defaults are unmeasured. They now store
nothing and carry a `not_configured` row saying why, which is the shape `host_key_bits` on this
same model already took on 2026-10-06 for the same reason.

WHAT AN EXISTING ROW HOLDS AFTER THIS MIGRATION: 0, unchanged. The column only becomes capable
of NULL; no row is rewritten and no backfill is attempted, because 0 in an existing row is
ambiguous in exactly the way this change exists to end - nothing in the row says whether it was
read off a `session-rekey` node or supplied by the old helper. Only re-normalizing can tell them
apart, and it will: an appliance with no SSH profile, or a profile with no `session-rekey` node,
comes back NULL with a row, and one that configures a trigger comes back with the configured
number and the marker's own provenance.

No control and no template reads these three fields (grep, 2026-10-20: the model, this
normalizer, migration 0055 and the tests), so NULL reaches no consumer that would have to
interpret it. Jason will migrate and re-normalise; no backward compatibility is required.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0088_predefined_provenance_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='managementsshsettings',
            name='rekey_interval_seconds',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AlterField(
            model_name='managementsshsettings',
            name='rekey_data_mb',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AlterField(
            model_name='managementsshsettings',
            name='rekey_packets_exponent',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
    ]
