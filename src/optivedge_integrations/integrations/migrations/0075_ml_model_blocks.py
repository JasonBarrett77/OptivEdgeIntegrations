"""`mlav-policy-action` has three values, so running and blocking are two questions.

Enumerated from the device with `action=complete` on 2026-10-08: `enable`,
`enable(alert-only)`, `disable`. The normalizer wrote `enabled = (action == "enable")`, which
records an alert-only model as DISABLED - wrong, because it does run and does alert, it just
does not stop the file.

THE BACKFILL IS EXACT, not a guess. Every pre-existing row was written by that same
`== "enable"` test, so `enabled` is true on exactly the rows whose action was the literal
`enable` - which is exactly the set that blocks. Leaving `blocks` at its False default instead
would mark every already-normalized model as non-blocking and fire PAN-AVW-002 on every
profile in the estate until something re-normalized.
"""

from django.db import migrations, models


def blocks_follows_enabled(apps, schema_editor):
    model = apps.get_model("integrations", "SecurityProfileMlModel")
    model.objects.filter(enabled=True).update(blocks=True)


def noop(apps, schema_editor):
    """Nothing to undo: removing the column discards it."""


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0074_security_profile_wildfire_analysis_kind'),
    ]

    operations = [
        migrations.AddField(
            model_name='securityprofilemlmodel',
            name='blocks',
            field=models.BooleanField(default=False),
        ),
        migrations.RunPython(blocks_follows_enabled, noop),
    ]
