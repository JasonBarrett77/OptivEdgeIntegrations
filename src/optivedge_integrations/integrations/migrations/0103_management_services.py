"""The `management-services` domain's columns and its two new appliance-grained models.

Three columns added to models that already exist and are SHARED with other domains - do not
re-type or rename anything else on them - and two new models for facts about the management
PLANE rather than about a surface on it.

EVERY NEW COLUMN HERE DEFAULTS TO ITS FIRING VALUE, and that is deliberate rather than
incidental: a row the migration creates and nothing has yet re-normalized must report rather
than reassure. `is_management_surface` True lets PAN-MGT-003 through, `floor_below_minimum` True
says the management TLS floor has not been shown to meet the minimum, `unbound_exposure_class`
holds the worst of its three classes, `address_is_globally_routable` True and `exposure_posture`
`routable_address` report PAN-MGT-004 at its top grade, and `approved_cryptography_mode` False
reports PAN-MGT-012. Six of those are the OPPOSITE of what a reader would pick for a field
default. The alternative in each case reports the catalogue's preferred state for every
unmigrated row, with nothing erroring and nothing rendering empty.

NO BACKFILL, and nothing is owed one: each default IS the value stage 5 declares for the window
between this migration and the next normalization pass, so a `RunPython` would only write the
value the column already holds.

THE DEPENDENCY LINE IS EXPECTED TO BE REWRITTEN. This was built in a concurrent wave of four
stage 7 runs, each in its own worktree and each declaring the same head, so at merge there are
four leaves and Django refuses that. Re-chaining them into a line is the orchestrator's, not
this run's - which is also why the number is 0103 and not the next free one.
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0100_decryption_policy'),
    ]

    operations = [
        migrations.AddField(
            model_name='interfacemanagementprofile',
            name='unbound_exposure_class',
            field=models.CharField(choices=[('unencrypted_administrative_login', 'Would permit an unencrypted administrative login'), ('encrypted_administrative_login', 'Would permit an encrypted administrative login'), ('monitoring_or_nothing', 'Would permit monitoring or reachability only')], default='unencrypted_administrative_login', max_length=32),
        ),
        migrations.AddField(
            model_name='managementinterface',
            name='is_management_surface',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='managementtlsbinding',
            name='floor_below_minimum',
            field=models.BooleanField(default=True),
        ),
        migrations.CreateModel(
            name='ApplianceOperationalMode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('operational_mode', models.CharField(blank=True, max_length=32)),
                ('approved_cryptography_mode', models.BooleanField(default=False)),
                ('appliance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='appliance_operational_modes', to='integrations.appliance')),
                ('appliance_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='appliance_operational_modes', to='integrations.appliancegroup')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='appliance_operational_modes', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='appliance_operational_modes', to='integrations.snapshot')),
            ],
            options={
                'indexes': [models.Index(fields=['appliance'], name='integration_applian_8ab9d9_idx')],
                'constraints': [models.UniqueConstraint(fields=('appliance',), name='unique_appliance_operational_mode_per_appliance')],
            },
        ),
        migrations.CreateModel(
            name='ManagementPlaneAddressing',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('allocation_mode', models.CharField(choices=[('static', 'Static'), ('dhcp-client', 'DHCP client')], default='static', max_length=16)),
                ('management_ip_address', models.CharField(blank=True, max_length=64, null=True)),
                ('static_default_gateway', models.CharField(blank=True, max_length=64, null=True)),
                ('address_is_globally_routable', models.BooleanField(default=True)),
                ('exposure_posture', models.CharField(choices=[('routable_address', 'On a globally routable address'), ('private_with_default_route', 'Private, with a static default route'), ('private_no_default_route', 'Private, with no static default route'), ('dynamically_allocated', 'Dynamically allocated - the configuration holds neither')], default='routable_address', max_length=32)),
                ('appliance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='management_plane_addressings', to='integrations.appliance')),
                ('appliance_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='management_plane_addressings', to='integrations.appliancegroup')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='management_plane_addressings', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='management_plane_addressings', to='integrations.snapshot')),
            ],
            options={
                'indexes': [models.Index(fields=['appliance'], name='integration_applian_c10b5f_idx')],
                'constraints': [models.UniqueConstraint(fields=('appliance',), name='unique_management_plane_addressing_per_appliance')],
            },
        ),
    ]
