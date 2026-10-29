"""The nine `av-wildfire` columns: six aggregates on `SecurityProfile`, three on `WildfireSettings`.

ADDITIVE ONLY: no table is created, no column is removed, and no existing column's type,
nullability or default is touched. Every one of the nine is new. The four satellite models this
domain reads - `SecurityProfileDecoder`, `SecurityProfileApplicationOverride`,
`SecurityProfileMlModel` and `SecurityProfileWildfireRule` - need nothing at all: stage 5
declared them `existing_unchanged` and the code agrees, so their rows, their uniqueness
constraints and their columns are exactly as they were.

THE FILE NUMBER IS 0101 AND THE DEPENDENCY IS 0100, WHICH IS DELIBERATE AND TEMPORARY. This was
built in a git worktree alongside three other stage 7 runs, all four depending on the same head
(`0100_decryption_policy`, the only leaf in this worktree on 2026-10-29). The number was assigned
per run so the four could not collide on a filename. At merge there will be four leaves and
Django refuses that outright, and re-chaining them into a line is the orchestrator's job rather
than this run's - so expect this `dependencies` line to be rewritten.

EVERY COLUMN A CONTROL COMPARES DEFAULTS TO ITS FIRING VALUE, and three of the nine are the
OPPOSITE of the framework's own default:

    SecurityProfile.weakest_decoder_action                default 'allow'
    SecurityProfile.weakest_application_override_action   default 'allow'
    SecurityProfile.weakest_ml_model_state                default 'disable'
    WildfireSettings.size_limits_wholly_untuned           default True    <- not False
    WildfireSettings.verdict_reporting_gap                default 'both'  <- not ''
    SecurityProfile.direction_coverage                    default NULL    <- and nullable

The three `weakest_*` CharFields take a VALUE rather than the empty string because what reads
them is a GRADING, which places values: an empty string matches no placement, and a row that
matches no placement falls back to the baseline severity with no calibration query naming it. The
value chosen is the weakest token of each collection, which is also what the measured implicit
says an untouched profile really holds - an absent decoder action is `allow` and an absent ML
model is `disable`. So a row nobody has recomputed is graded as though nothing were configured,
which is the firing side AND the honest reading of an unedited profile.

`size_limits_wholly_untuned` takes True, matching `size_limits_untuned` beside it, and that is
worth stating because the convention on THAT MODEL is no guide: `shares_full_session_info` was
added by `0080_wildfire_full_session_info` as `BooleanField(default=True)` with no backfill on a
column whose True side is the COMPLIANT one, so every row of that model has read as sharing full
session information with WildFire since, whether or not anybody ever looked.

`session_info_read` takes False, which fires, and it is the column that answers exactly that
defect: it is false on every pre-existing row and true only on a row this release's normalizer
wrote, so "we never asked" stops looking like "we asked and it was fine".

`verdict_reporting_gap` needed no choice at all. It is computed from two non-nullable booleans
that both default to False, so an un-recomputed row holds `both` - neither verdict reported,
which fires at the worse of the two severities. That is the one default on this domain that is
structural rather than argued.

ONE NULLABLE COLUMN IS ADDED AND THE NULL IS LOAD-BEARING. `direction_coverage` is null where no
rule of a WildFire analysis profile reaches either direction of travel, which is also what a row
nobody has recomputed holds - and both must be reported at the BASELINE severity rather than
graded as a direction, so conflating them costs nothing. It is nullable rather than
`blank=True, default=""` because the two states this column must not conflate are "no rule
reaches either direction" and "some rule does"; an empty string would also be the value a
positive comparison fails to match, and the clause that rests on this column is `eq both` written
as the passing condition with the sign inverted, which a null correctly fires against.
`IkeCryptoProfile.weakest_dh_group` is the precedent on this schema for a nullable CharField
holding a weakest-member aggregate for exactly that reason.

NO BACKFILL. Nine columns on two already-populated tables and every one of them is computed at
normalization from rows that are already stored, so the correct repair is a re-normalization and
not a data migration: a backfill would have to re-derive an aggregate from satellite rows inside
a historical-model context, and would then be a second implementation of the derivation that
could drift from the real one. Every default above was chosen so the window before that
re-normalization REPORTS rather than reassures.

WHAT MOVES FOR ANOTHER DOMAIN. `SecurityProfile` is shared by nine stage 5 subjects across seven
domains. All six columns added here are blank, False or null on every kind but `virus` and
`wildfire-analysis`, because the normalizer writes them only for those two kinds and the model
defaults stand otherwise - the same convention `file_blocking` and `data_filtering` already
follow on this model. The `kind` clause every query over this model carries is what keeps an
antivirus assertion off an anti-spyware row; nothing in the schema enforces that.

One change in this domain's normalization is a CORRECTION rather than an addition and no column
moves with it: `normalization/wildfire_settings.py::exclusions` read only a `<member>` list, and
the device stores the twelve session-information items as CHILD NODES each taking its own yes/no.
Measured on fw-core-tpa-a, serial 013201001475, 2026-10-29. Until that fix,
`session_info_excluded` was the empty list and `shares_full_session_info` was True on the one
appliance in the lab that withholds anything - the compliant side, on a firewall withholding a
username and a source address.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("integrations", "0100_decryption_policy"),
    ]

    operations = [
        migrations.AddField(
            model_name="securityprofile",
            name="weakest_decoder_action",
            field=models.CharField(blank=True, default="allow", max_length=32),
        ),
        migrations.AddField(
            model_name="securityprofile",
            name="weakest_application_override_action",
            field=models.CharField(blank=True, default="allow", max_length=32),
        ),
        migrations.AddField(
            model_name="securityprofile",
            name="weakest_ml_model_state",
            field=models.CharField(blank=True, default="disable", max_length=32),
        ),
        migrations.AddField(
            model_name="securityprofile",
            name="submits_all_file_types",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="securityprofile",
            name="covers_all_applications",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="securityprofile",
            name="direction_coverage",
            field=models.CharField(blank=True, default=None, max_length=16, null=True),
        ),
        migrations.AddField(
            model_name="wildfiresettings",
            name="size_limits_wholly_untuned",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="wildfiresettings",
            name="session_info_read",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="wildfiresettings",
            name="verdict_reporting_gap",
            field=models.CharField(default="both", max_length=16),
        ),
    ]
