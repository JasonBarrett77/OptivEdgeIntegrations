"""The two `ha-panorama` models - `HighAvailabilityConfig` and `PanoramaRegistration`.

ADDITIVE ONLY: two new tables, no column touched on any existing model. The one shared module
this domain changed is `platforms/pan_os/normalization/common.py`, which gained a helper and
lost nothing, so no other domain's normalization or query behaviour moves with this migration.

THE FILE NUMBER IS 0094 AND THE DEPENDENCY IS 0092, WHICH IS DELIBERATE AND TEMPORARY. This was
built in a git worktree alongside three other stage 7 runs, all four depending on the same head
(`0092_ike_crypto`, the only leaf in this worktree on 2026-10-29). The number was assigned per
run so the four could not collide on a filename; the gap at 0093 belongs to another run. At
merge there will be four leaves and Django will refuse that, and re-chaining them into a line is
the orchestrator's, not this run's - so expect this `dependencies` line to be rewritten.

EVERY NEW COLUMN A CONTROL COMPARES IS NON-NULLABLE AND DEFAULTS TO ITS FIRING VALUE. That is
the rule `0089_nullable_rekey_triggers` broke in the other direction and
`LoggingSettings.central_store_delivery_healthy` was corrected for: the search layer has no
is-null operator, so a positive comparison over NULL matches nothing and the control silently
stops firing - which is the unsafe direction, a reading nobody can make reported as compliant.
The nullable booleans on `HighAvailabilityConfig` and `PanoramaRegistration` are display and
derivation inputs that no clause compares; they are listed in each model's docstring with that
prohibition attached.

NO CONTROL IN OPTIVEDGEASSESSMENTS READS EITHER TABLE YET. Checked by grep of that repo on
2026-10-29: neither model name appears in `search/registry.py`'s `MODEL_REGISTRY`, in any
per-model compiler, or in the shipped catalog - so nothing can be taken from matching to not
matching by this migration. Stage 8 is what registers them, and whoever writes that owes the
nullability grep in THIS direction.
"""


import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0092_ike_crypto'),
    ]

    operations = [
        migrations.CreateModel(
            name='HighAvailabilityConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('ha_config_collected', models.BooleanField(default=False)),
                ('ha_runtime_state_collected', models.BooleanField(default=False)),
                ('ha_enabled', models.BooleanField(default=False)),
                ('cluster_participation_enabled', models.BooleanField(blank=True, default=None, null=True)),
                ('ha_mode', models.CharField(blank=True, default='', max_length=32)),
                ('config_sync_enabled', models.BooleanField(blank=True, default=None, null=True)),
                ('state_sync_enabled', models.BooleanField(blank=True, default=None, null=True)),
                ('ha1_encryption_enabled', models.BooleanField(blank=True, default=None, null=True)),
                ('ha1_encryption_key_imported', models.BooleanField(blank=True, default=None, null=True)),
                ('ha1_backup_port', models.CharField(blank=True, default='', max_length=32)),
                ('peer_ip_backup', models.CharField(blank=True, default='', max_length=64)),
                ('heartbeat_backup_enabled', models.BooleanField(blank=True, default=None, null=True)),
                ('link_monitoring_enabled', models.BooleanField(default=True)),
                ('path_monitoring_enabled', models.BooleanField(default=True)),
                ('link_monitoring_failure_condition', models.CharField(blank=True, default='', max_length=16)),
                ('path_monitoring_failure_condition', models.CharField(blank=True, default='', max_length=16)),
                ('monitored_link_groups', models.JSONField(blank=True, default=list)),
                ('monitored_link_group_count', models.PositiveIntegerField(default=0)),
                ('no_live_redundant_peer', models.BooleanField(default=True)),
                ('ha_monitors_nothing', models.BooleanField(default=True)),
                ('ha_monitoring_state', models.CharField(default='unknown', max_length=32)),
                ('no_independent_second_keepalive_path', models.BooleanField(default=True)),
                ('second_keepalive_path_state', models.CharField(default='unknown', max_length=48)),
                ('ha1_control_link_not_encrypted', models.BooleanField(default=True)),
                ('ha1_control_link_exposure', models.CharField(default='unencrypted-port-unknown', max_length=48)),
                ('appliance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='high_availability_configs', to='integrations.appliance')),
                ('appliance_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='high_availability_configs', to='integrations.appliancegroup')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='high_availability_configs', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='high_availability_configs', to='integrations.snapshot')),
            ],
            options={
                'indexes': [models.Index(fields=['appliance'], name='integration_applian_d65e4e_idx'), models.Index(fields=['ha_config_collected'], name='integration_ha_conf_bd7848_idx'), models.Index(fields=['no_live_redundant_peer'], name='integration_no_live_0b4bf8_idx'), models.Index(fields=['ha_monitors_nothing'], name='integration_ha_moni_7a9020_idx')],
                'constraints': [models.UniqueConstraint(fields=('appliance',), name='unique_high_availability_config_per_appliance')],
            },
        ),
        migrations.CreateModel(
            name='PanoramaRegistration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('management_config_collected', models.BooleanField(default=False)),
                ('panorama_server_primary', models.CharField(blank=True, default='', max_length=255)),
                ('panorama_server_secondary', models.CharField(blank=True, default='', max_length=255)),
                ('secure_panorama_communication_enabled', models.BooleanField(blank=True, default=None, null=True)),
                ('check_server_identity_enabled', models.BooleanField(blank=True, default=None, null=True)),
                ('client_certificate_type', models.CharField(blank=True, default='', max_length=16)),
                ('client_certificate_name', models.CharField(blank=True, default='', max_length=64)),
                ('management_estate_is_a_pair', models.BooleanField(default=True)),
                ('panorama_address_in_force_unverified', models.BooleanField(default=True)),
                ('management_channel_not_hardened', models.BooleanField(default=True)),
                ('appliance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='panorama_registrations', to='integrations.appliance')),
                ('appliance_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='panorama_registrations', to='integrations.appliancegroup')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='panorama_registrations', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='panorama_registrations', to='integrations.snapshot')),
            ],
            options={
                'indexes': [models.Index(fields=['appliance'], name='integration_applian_cf52f5_idx'), models.Index(fields=['management_config_collected'], name='integration_managem_035087_idx'), models.Index(fields=['panorama_server_secondary'], name='integration_panoram_3130b5_idx'), models.Index(fields=['management_channel_not_hardened'], name='integration_managem_3846a5_idx')],
                'constraints': [models.UniqueConstraint(fields=('appliance',), name='unique_panorama_registration_per_appliance')],
            },
        ),
    ]
