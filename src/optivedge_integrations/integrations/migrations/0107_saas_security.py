"""SaaS security - PAN-SAS-001 to 005. Four new models, twenty-two new columns.

NUMBERED 0107 AGAINST A HEAD OF 0104, WHICH IS DELIBERATE AND NOT A MISTAKE. This landed in a
wave of four concurrent stage 7 runs, each assigned a filename so that two could not pick the
same number, and all four declare the same dependency - the head each one found. Four leaves in
one app is a state Django refuses outright, so expect this `dependencies` line to be rewritten
when the wave is merged; the four touch different models, so the order carries no meaning beyond
the filenames they were assigned.

EVERY COLUMN A CONTROL COMPARES IS NON-NULLABLE AND DEFAULTS TO ITS FIRING VALUE, and on this
domain three of those defaults are tokens rather than booleans:
`SaasUrlFilteringPosture.consumer_storage_category_treatment` defaults to
`in-no-restricting-list`, `SaasApplicationPolicyPosture.effective_action_for_function_apps` to
`no-rule`, and `CloudAppEngineSetting.ace_failure_reason` to `unread`. A row this migration
creates and nothing has yet renormalized therefore FIRES on four of the five controls. That is
the prescribed direction - a missing reading reported as compliant is a customer told they are
safe on the strength of nothing - and it means the window between this migration and the first
collection over-reports rather than reporting a clean estate.

TWO COLUMNS ARE NULLABLE AND NEITHER IS COMPARED BY A CONTROL. `CloudAppEngineSetting.ace_disabled`
is nullable in exactly one state, a merged snapshot carrying no `deviceconfig/setting` subtree, so
that "unread" is distinguishable from the absent key the assumed default covers - and
`cloudapp_node_read` beside it is what a control reads instead of scoring the null as a value.
`cloudapp_server_address` is nullable because stage 5's declaration for it is `stores: null` with
`rests_on: not_assumed`: store nothing, because the absence was never measured.

THE IDENTITY CONSTRAINT IS ONE ROW PER ENFORCEMENT POINT for the three vsys-scoped models and one
row per APPLIANCE for the engine setting. Stage 5's identity named `appliance` plus `vsys_name`
for the first three and predicted two rows for one synchronised HA configuration; an
`EnforcementPoint` is held once per Panorama-managed pair, so a synchronised configuration
produces ONE row here. That is the same correction `0100_decryption_policy` records, and
`appliance` and `vsys_name` are reachable through the foreign key rather than duplicated.
"""


import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    # RE-CHAINED WHEN WAVE 4 WAS MERGED, 2026-10-29. All four runs were told to depend on the
    # head they found, `0104_network_hardening`; four leaf nodes is a state Django refuses, so they were put
    # in a line at merge time. They touch different models.
    # SO THE `dependencies` LINE BELOW IS NOT WHAT THE RUN WROTE: it was rewritten from
    # `0104_network_hardening` to `0106_platform_lifecycle` here, at merge time.
    dependencies = [
        ('integrations', '0106_platform_lifecycle'),
    ]

    operations = [
        migrations.CreateModel(
            name='CloudAppEngineSetting',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('ace_disabled', models.BooleanField(blank=True, default=False, null=True)),
                ('cloudapp_node_read', models.BooleanField(default=False)),
                ('ace_not_operational', models.BooleanField(default=True)),
                ('ace_failure_reason', models.CharField(default='unread', max_length=48)),
                ('cloudapp_server_address', models.CharField(blank=True, max_length=255, null=True)),
                ('appliance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='cloud_app_engine_settings', to='integrations.appliance')),
                ('appliance_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='cloud_app_engine_settings', to='integrations.appliancegroup')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='cloud_app_engine_settings', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='cloud_app_engine_settings', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['appliance', 'id'],
                'indexes': [models.Index(fields=['appliance'], name='integration_applian_9481a6_idx'), models.Index(fields=['management_station'], name='integration_managem_b2caa5_idx'), models.Index(fields=['ace_not_operational'], name='integration_ace_not_5737c8_idx'), models.Index(fields=['ace_failure_reason'], name='integration_ace_fai_f9f639_idx')],
                'constraints': [models.UniqueConstraint(fields=('appliance',), name='integrations_unique_cloud_app_engine_setting_per_appliance')],
            },
        ),
        migrations.CreateModel(
            name='SaasApplicationPolicyPosture',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('function_app_rule_count', models.PositiveIntegerField(default=0)),
                ('function_apps_are_refused', models.BooleanField(default=False)),
                ('effective_action_for_function_apps', models.CharField(default='no-rule', max_length=16)),
                ('cloud_app_filter_count', models.PositiveIntegerField(default=0)),
                ('cloud_app_selection_is_refused', models.BooleanField(default=False)),
                ('cloud_app_selection_excludes_approved', models.BooleanField(default=False)),
                ('enforcement_point', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saas_application_policy_postures', to='integrations.enforcementpoint')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saas_application_policy_postures', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saas_application_policy_postures', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['enforcement_point', 'id'],
                'indexes': [models.Index(fields=['enforcement_point'], name='integration_enforce_6e713a_idx'), models.Index(fields=['management_station'], name='integration_managem_4a107b_idx'), models.Index(fields=['function_apps_are_refused'], name='integration_functio_b7dd09_idx'), models.Index(fields=['effective_action_for_function_apps'], name='integration_effecti_babedd_idx'), models.Index(fields=['cloud_app_selection_is_refused'], name='integration_cloud_a_92537e_idx')],
                'constraints': [models.UniqueConstraint(fields=('enforcement_point',), name='integrations_unique_saas_app_policy_posture_per_point')],
            },
        ),
        migrations.CreateModel(
            name='SaasUrlFilteringPosture',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('url_filtering_profiles_read', models.BooleanField(default=False)),
                ('header_insertion_type_entry_count', models.PositiveIntegerField(default=0)),
                ('tenant_restriction_in_force', models.BooleanField(default=False)),
                ('tenant_header_without_value_count', models.PositiveIntegerField(default=0)),
                ('rule_bound_tenant_list_count', models.PositiveIntegerField(default=0)),
                ('consumer_storage_category_treatment', models.CharField(default='in-no-restricting-list', max_length=32)),
                ('consumer_storage_categories_are_restricted', models.BooleanField(default=False)),
                ('enforcement_point', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saas_url_filtering_postures', to='integrations.enforcementpoint')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saas_url_filtering_postures', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saas_url_filtering_postures', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['enforcement_point', 'id'],
                'indexes': [models.Index(fields=['enforcement_point'], name='integration_enforce_b3a2ae_idx'), models.Index(fields=['management_station'], name='integration_managem_d07dae_idx'), models.Index(fields=['tenant_restriction_in_force'], name='integration_tenant__f45ca2_idx'), models.Index(fields=['consumer_storage_category_treatment'], name='integration_consume_310e45_idx'), models.Index(fields=['consumer_storage_categories_are_restricted'], name='integration_consume_f372ae_idx')],
                'constraints': [models.UniqueConstraint(fields=('enforcement_point',), name='integrations_unique_saas_url_filtering_posture_per_point')],
            },
        ),
        migrations.CreateModel(
            name='SanctionedApplicationMarking',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('sanctioned_application_count', models.PositiveIntegerField(default=0)),
                ('marked_application_names', models.JSONField(blank=True, default=list)),
                ('appliance_is_multi_vsys', models.BooleanField(default=True)),
                ('marking_is_inconsistent_across_vsys', models.BooleanField(default=True)),
                ('enforcement_point', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sanctioned_application_markings', to='integrations.enforcementpoint')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sanctioned_application_markings', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sanctioned_application_markings', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['enforcement_point', 'id'],
                'indexes': [models.Index(fields=['enforcement_point'], name='integration_enforce_d7c666_idx'), models.Index(fields=['management_station'], name='integration_managem_725f46_idx'), models.Index(fields=['sanctioned_application_count'], name='integration_sanctio_9b62df_idx'), models.Index(fields=['marking_is_inconsistent_across_vsys'], name='integration_marking_fef4d8_idx')],
                'constraints': [models.UniqueConstraint(fields=('enforcement_point',), name='integrations_unique_sanctioned_app_marking_per_point')],
            },
        ),
    ]
