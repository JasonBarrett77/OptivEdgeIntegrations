"""The three preferred-value flags default to the FIRING value, and existing rows are marked
not-yet-computed.

0057 added these columns to rows that already existed, and a migration does not compute a derived
column - so every row sat at the old default of False, which for these three means COMPLIANT. On
a database migrated and reseeded but not re-normalized, PAN-MCR-001, 002 and 003 therefore
reported a clean estate: not an error, not an empty page, three controls quietly passing every
device. Proved on a copy of the lab with only the re-normalize differing - 0 of 3 firing before,
2 of 3 after, same queries and same devices.

The data step below sets existing rows to the firing value, so a database that has not been
re-normalized since 0057 reports loudly instead of silently. Re-normalizing replaces all three
with the measured answer and contacts no device; the reverse step is a no-op because the honest
prior state of these columns is "not computed", which is what forward already says.
"""

from django.db import migrations, models


def mark_not_yet_computed(apps, schema_editor):
    apps.get_model("integrations", "ManagementSshSettings").objects.update(
        ciphers_below_preferred=True, kex_below_preferred=True, macs_below_preferred=True)


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0058_ntpsettings_snmpsettings_systemidentity'),
    ]

    operations = [
        migrations.AlterField(
            model_name='managementsshsettings',
            name='ciphers_below_preferred',
            field=models.BooleanField(default=True),
        ),
        migrations.AlterField(
            model_name='managementsshsettings',
            name='kex_below_preferred',
            field=models.BooleanField(default=True),
        ),
        migrations.AlterField(
            model_name='managementsshsettings',
            name='macs_below_preferred',
            field=models.BooleanField(default=True),
        ),
        migrations.RunPython(mark_not_yet_computed, migrations.RunPython.noop),
    ]
