"""`SecurityProfileWildfireRule.direction` and `.analysis` become NULLABLE, and the blanks
already stored become NULL.

WHAT THIS CORRECTS. Stage 5 declared both columns `default.stores: null`,
`rests_on: not_assumed` - stage 4 could not settle what the device does with an absent
`direction`, and declined to promote the schema's `public-cloud` for an absent `analysis`. The
built columns stored the EMPTY STRING for that case instead. Recorded as two of the seven
`default_implemented` failures the stage 7 validator raised on `av-wildfire`, 2026-10-29, and the
only two of the seven that were a defect in this repo.

WHY IT IS NOT COSMETIC. `is_empty` compiles to `filter(field="")`, which matches `''` and does
NOT match NULL. So a clause written against stage 5's declaration and one written against the
blank column find DIFFERENT ROWS, and whichever way round that falls one of them is quietly
wrong. Both columns are `not_searchable` today - their model is in no field registry, so no
clause can name them yet - which is why this is a correction and not an incident.

THE BACKFILL IS SAFE AND IT DOES NOT READ A DEVICE. `''` was only ever the absent case: the
device REFUSES `<direction></direction>` and `<analysis></analysis>` at the write, so an empty
element is unreachable and no stored blank can mean anything else. Measured by stage 4 on
pan-fw-111 (PA-VM 11.2.3), recorded in stage5-av-wildfire.json under
`subjects.wildfire-analysis-rule`. The reverse puts the blanks back, so a downgrade lands where it
started.

NOTHING ELSE MOVES. No other column's type or nullability is touched, no row is added or
removed, and `covers_both_directions` was already nullable and already NULL for this case.
"""

from django.db import migrations, models


def blanks_to_null(apps, schema_editor):
    rule = apps.get_model("integrations", "SecurityProfileWildfireRule")
    rule.objects.filter(direction="").update(direction=None)
    rule.objects.filter(analysis="").update(analysis=None)


def null_to_blanks(apps, schema_editor):
    rule = apps.get_model("integrations", "SecurityProfileWildfireRule")
    rule.objects.filter(direction__isnull=True).update(direction="")
    rule.objects.filter(analysis__isnull=True).update(analysis="")


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0109_user_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='securityprofilewildfirerule',
            name='direction',
            field=models.CharField(blank=True, max_length=16, null=True),
        ),
        migrations.AlterField(
            model_name='securityprofilewildfirerule',
            name='analysis',
            field=models.CharField(blank=True, max_length=16, null=True),
        ),
        migrations.RunPython(blanks_to_null, null_to_blanks),
    ]
