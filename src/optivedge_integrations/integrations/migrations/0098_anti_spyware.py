"""The anti-spyware domain's store: PAN-SPY-001 to PAN-SPY-005.

Four changes and one new table.

`SecurityProfile.cloud_inline_analysis` - the Inline Cloud Analysis tab's own enable, positive
polarity. FALSE is the default and the firing side, so every existing row reads as un-enabled
until the normalizer runs, which is the direction a new column on a populated model has to point.

`SecurityProfileInlineDetector.local_deep_learning` - blank on every row this estate holds, and
deliberately so. NOTHING ASSERTS IT: the column exists so that a reading taken off a grid column
that is in the DOM and not on the page has somewhere to land, and no clause may be written over it
until a surface an operator can see settles what a blank means.

`SecurityRule.spyware_profile_resolved` - the THIRD attachment state. `has_spyware_profile` is
true as soon as something names a spyware profile and says nothing about whether that name
resolves; this is the resolution. FALSE by default, which fires: a rule nobody has recomputed
reports as unresolved rather than passing.

`SecurityRuleProfileVerdict.grading_value` - the graded value beside a verdict, one column for
every assertion that has one, following `detail`. BLANK and not null: the search layer has no
is-null operator, so a positive clause over a nullable column never matches, and `is_empty` -
the one operator that is about absence - compiles to `filter(field="")` and reaches no NULL.

`SecurityProfileThreatException` - one row per per-signature override. The estate already held a
COUNT summed over five exception surfaces, which answers *does an exception exist* and cannot
answer *does an exception hand a critical signature back*. An exception's action set is the same
eight as a profile rule's, which is exactly why one can undo a severity verdict that passed.

DEPENDENCY: `0096_file_data_filtering`, the single leaf in this worktree when this was written.
Three sibling stage 7 runs depend on the same leaf at the same time, so re-chaining the four
leaves into a line happens after this lands and is not this migration's business.

RECOMPUTE OWED: `normalize_security_rule_profile_coverage` writes `spyware_profile_resolved` and
`grading_value`, and `normalize_security_profiles` writes the other three. Until both have run
again, the two boolean columns read their defaults - which are the firing side - and the two text
columns read blank, which matches no severity placement and so loses an escalation rather than a
finding.
"""

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    # RE-CHAINED WHEN WAVE 2 WAS MERGED, 2026-10-29. Built by one of four concurrent stage 7
    # runs, each told to depend on the head it found - `0096_file_data_filtering` for all four,
    # because none could see a sibling's work. Four leaf nodes is a state Django refuses outright,
    # so the four were put in a line at merge time; they touch different models, so the order
    # carries no meaning beyond the filenames they were assigned.
    # SO THE `dependencies` LINE BELOW IS NOT WHAT THE RUN WROTE: it was rewritten from
    # `0096_file_data_filtering` to `0097_admin_authentication` here, at merge time.
    dependencies = [
        ("integrations", "0097_admin_authentication"),
    ]

    operations = [
        migrations.AddField(
            model_name="securityprofile",
            name="cloud_inline_analysis",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="securityprofileinlinedetector",
            name="local_deep_learning",
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AddField(
            model_name="securityrule",
            name="spyware_profile_resolved",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="securityruleprofileverdict",
            name="grading_value",
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.CreateModel(
            name="SecurityProfileThreatException",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("threat_id", models.CharField(max_length=64)),
                ("action", models.CharField(default="default", max_length=32)),
                ("exempt_ip_count", models.PositiveIntegerField(default=0)),
                ("security_profile", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="threat_exceptions",
                    to="integrations.securityprofile")),
            ],
            options={
                "ordering": ["security_profile", "threat_id"],
            },
        ),
        migrations.AddConstraint(
            model_name="securityprofilethreatexception",
            constraint=models.UniqueConstraint(
                fields=("security_profile", "threat_id"),
                name="integrations_unique_threat_exception_per_profile"),
        ),
    ]
