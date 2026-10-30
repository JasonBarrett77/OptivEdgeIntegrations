"""The updates domain's schema - PAN-UPD-001 to PAN-UPD-006.

TWO NEW MODELS AND NO COLUMN ON ANY SHIPPED ONE. Both nodes were checked for prior coverage under
another class name before either was written, which is what ruling P374a asks of a new model:
`grep -rn 'update-schedule' src/` returns nothing, and the two classes that sound closest cover
different reads entirely - `FirewallContentStreams` holds the content a firewall HAS INSTALLED
(versions and release dates off `show system info`) and `LicenceInventory` holds the entitlement
verdict off `request license info`. This domain holds what the appliance has ARRANGED TO FETCH.

- `ContentUpdateSchedule`, one row per APPLIANCE over `deviceconfig/system/update-schedule`, with
  all five content types on one row. Fifteen columns. A ROW PER HA PEER and not per pair: the
  update schedule does not sync across peers, and the two lab PA-5220s hold different content
  types to prove it.
- `ContentDeploymentSchedule`, one row per MANAGEMENT STATION and a verdict over every
  `deployment-update-schedule` entry on it. Eight columns. The grain cuts against the object's own
  shape - stage 4 measured it as a collection - because the commonest failing state is NO ENTRY AT
  ALL and an entry-grained row cannot report that it does not exist.

TEN TEXT COLUMNS ARE NON-NULLABLE AND DEFAULT TO THE EMPTY STRING, AND THAT IS THE FIRING SIDE OF
EVERY CONTROL THAT NAMES THEM. Each cadence and action column holds `""` for an appliance nobody
read and `none` for one that was read and has nothing scheduled; every clause in this domain is a
negated equality, so `""` satisfies all of them and an unread appliance REPORTS rather than
passing. A nullable column would have been invisible to both polarities, and a boolean set would
have defaulted false and read as compliant.

THE TWO INTEGER COLUMNS ARE NULLABLE, WHICH IS THE OPPOSITE CHOICE AND IS ALSO STAGE 5's. What an
absent `threshold` or `new-app-threshold` does is UNMEASURED, so nothing is stored. The cost is
recorded rather than worked around: a NULL is unreachable by every operator the query grammar has,
so both columns read as COMPLIANT when nobody looked, and `update_schedule_collected` is the
declared companion that carries the unknown. PAN-UPD-003 is discharged `engineer_answers` on both
its records, so no query reads either column today.

`ContentDeploymentSchedule.source_snapshot` IS THE ONE NULLABLE SNAPSHOT FK HERE, following
`DeviceGroup`. There is no station-scoped snapshot an estate is guaranteed to have, and a station
nobody collected must still get a row - otherwise an uncollected estate and a standalone one with
no management station at all are both absent from every query and indistinguishable.

NO FINDING IS RAISED FROM ANY COLUMN OF `ContentDeploymentSchedule`. Jason, 2026-10-27: "own
panorama is still out of scope (values that effect the panorama appliance only)". PAN-UPD-006's
first record is discharged `not_in_configuration` on that ruling and its second is discharged
`engineer_answers`, so the table exists to hand an engineer `rollout_staging_shape`,
`installing_schedule_count` and `schedules` and not to be claused on.

DEPENDENCY AND NUMBER. Cut against `0115_one_telemetry_model`, the head of `stage7/wave-5` plus
ruling P374a, which is the head this worktree holds. Every run in this wave depends on that same
head, so the leaves are re-chained into a line by the orchestrator after hand-back.

RE-CHAINED AT MERGE, FROM `0115_one_telemetry_model` TO `0118_logging`. All five stage 7 runs of wave 6
read `0115` as the head in their own worktrees and wrote it as their dependency, which is four
leaves and not a line; Django refuses that. The wave was landed as 0116 globalprotect-gateway,
0117 vulnerability-protection, 0118 logging, 0120 here, and this file's dependency is the only
thing about it that the merge changed. **0119 IS DELIBERATELY UNUSED**: it was assigned to
`mgmt-crypto`, whose run needed no new model, no new column and no migration at all - 28 of its
29 declared columns already existed and the 29th was a second field over a leaf a shipped field
already answers. The gap is that result, not a lost file.
"""

import django.core.validators
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0118_logging'),
    ]

    operations = [
        migrations.CreateModel(
            name='ContentDeploymentSchedule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('scope', models.CharField(default='panorama-own', max_length=32)),
                ('deployment_schedule_read', models.BooleanField(default=False)),
                ('central_schedule_state', models.CharField(blank=True, choices=[('enabled', 'At least one schedule entry is enabled'), ('all_disabled', 'Entries exist and every one is disabled'), ('none', 'No schedule entry exists at all')], default='', max_length=32)),
                ('enabled_schedule_count', models.PositiveIntegerField(default=0)),
                ('installing_schedule_count', models.PositiveIntegerField(default=0)),
                ('rollout_staging_shape', models.CharField(blank=True, choices=[('none', 'No installing schedule'), ('single', 'One installing schedule'), ('multiple_disjoint', 'Several, over disjoint device lists'), ('multiple_overlapping', 'Several, and not demonstrably disjoint')], default='', max_length=32)),
                ('schedules', models.JSONField(blank=True, default=list)),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='content_deployment_schedules', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='content_deployment_schedules', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['management_station__hostname', 'pk'],
                'indexes': [models.Index(fields=['management_station'], name='integration_managem_47f854_idx')],
                'constraints': [models.UniqueConstraint(fields=('management_station',), name='unique_content_deployment_schedule_per_station')],
            },
        ),
        migrations.CreateModel(
            name='ContentUpdateSchedule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_synced_at', models.DateTimeField(blank=True, null=True)),
                ('is_missing', models.BooleanField(default=False)),
                ('missing_since', models.DateTimeField(blank=True, null=True)),
                ('scope', models.CharField(default='device-local', max_length=32)),
                ('update_schedule_collected', models.BooleanField(default=False)),
                ('threats_threshold_hours', models.PositiveIntegerField(blank=True, null=True, validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(336)])),
                ('threats_new_app_threshold_hours', models.PositiveIntegerField(blank=True, null=True, validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(336)])),
                ('av_recurrence', models.CharField(blank=True, default='', max_length=32)),
                ('av_action', models.CharField(blank=True, default='', max_length=32)),
                ('threats_recurrence', models.CharField(blank=True, default='', max_length=32)),
                ('threats_action', models.CharField(blank=True, default='', max_length=32)),
                ('wildfire_recurrence', models.CharField(blank=True, default='', max_length=32)),
                ('wildfire_action', models.CharField(blank=True, default='', max_length=32)),
                ('gp_datafile_recurrence', models.CharField(blank=True, default='', max_length=32)),
                ('gp_datafile_action', models.CharField(blank=True, default='', max_length=32)),
                ('gp_clientless_vpn_recurrence', models.CharField(blank=True, default='', max_length=32)),
                ('gp_clientless_vpn_action', models.CharField(blank=True, default='', max_length=32)),
                ('appliance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='content_update_schedules', to='integrations.appliance')),
                ('appliance_group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='content_update_schedules', to='integrations.appliancegroup')),
                ('last_sync_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='%(app_label)s_%(class)ss', to='integrations.integrationrun')),
                ('management_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='content_update_schedules', to='integrations.managementstation')),
                ('source_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='content_update_schedules', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['appliance__hostname', 'pk'],
                'indexes': [models.Index(fields=['appliance'], name='integration_applian_ce09b0_idx'), models.Index(fields=['management_station'], name='integration_managem_c08725_idx')],
                'constraints': [models.UniqueConstraint(fields=('appliance',), name='unique_content_update_schedule_per_appliance')],
            },
        ),
    ]
