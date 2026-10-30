"""The logging domain's one new column - PAN-LOG-001's count half.

ONE COLUMN AND NO NEW MODEL. The logging domain's three models all ship already
(`0090_log_settings`, `0091_logging_delivery_fires`) and stage 5 declares three of its four
subjects `existing_unchanged`; the fourth, `appliance-logging-posture`, is `new_columns` for
exactly this one column, which `probe.model_brief` confirmed as the whole `TO ADD` bucket across
all three models.

WHY A COUNT AND NOT THE BOOLEAN ALREADY THERE. `LoggingSettings.syslog_destination_in_use` folds
BOTH halves of PAN-LOG-001 into one verdict - a destination is defined AND a forwarding rule
names it - and stage 3 split the control deliberately, because `a destination nothing forwards
to` and `no destination at all` have the same outcome and DIFFERENT REMEDIATIONS. The boolean
also cannot carry stage 3's grading, whose three rungs are a count: none at all (high), one path
(medium), two or more (no finding). The two columns stand beside each other so a finding can say
which half failed.

DEFAULT ZERO, WHICH FIRES. The clause is `fewer than two`, so zero is both the convenient
default and the safe one: an appliance nobody has recomputed reports rather than passing, at the
assertion's own severity. That is the direction every unknown in this domain takes and it is
`rules.md`'s rule, not this migration's choice.

NO DATA MIGRATION IS OWED AND THAT WAS CHECKED. The column is in
`LoggingSettings.DERIVED_FIELDS`, so `provenance_for` synthesises a `derived` answer and no
`FieldProvenance` row is ever written for it - there is nothing for a backfill to carry. Existing
rows take the zero and the next normalization pass replaces it; between the two, every row reads
on the firing side rather than reporting coverage nobody counted.

THE INDEX IS BECAUSE PAN-LOG-001 CLAUSES ON THIS COLUMN TWICE - a threshold at two for the
assertion and an equality on one for the medium rung - which is the same reason
`LogServerTarget.profile_referrer_count` carries one.

DEPENDENCY. `0115_one_telemetry_model` is the head this worktree was cut at. Four of this wave's
runs depend on that same head, so at merge there are several leaves and Django refuses that;
re-chaining them is the orchestrator's after the wave, not this run's, and this `dependencies`
line is expected to be rewritten there.

RE-CHAINED AT MERGE, FROM `0115_one_telemetry_model` TO `0117_vulnerability_protection`. All five stage 7 runs of wave 6
read `0115` as the head in their own worktrees and wrote it as their dependency, which is four
leaves and not a line; Django refuses that. The wave was landed as 0116 globalprotect-gateway,
0117 vulnerability-protection, 0118 logging, 0118 here, and this file's dependency is the only
thing about it that the merge changed. **0119 IS DELIBERATELY UNUSED**: it was assigned to
`mgmt-crypto`, whose run needed no new model, no new column and no migration at all - 28 of its
29 declared columns already existed and the 29th was a second field over a leaf a shipped field
already answers. The gap is that result, not a lost file.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0117_vulnerability_protection'),
    ]

    operations = [
        migrations.AddField(
            model_name='loggingsettings',
            name='offbox_destination_count',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddIndex(
            model_name='loggingsettings',
            index=models.Index(fields=['offbox_destination_count'],
                               name='integration_offbox__cf608f_idx'),
        ),
    ]
