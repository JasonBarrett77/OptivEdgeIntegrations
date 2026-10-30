"""The twelve columns the `auth-servers` domain needs, and the key one of them is computed with
- PAN-AAA-005, 007, 009, 010 and 012.

WHAT EACH ONE IS FOR, because a column list says nothing about why:

    SecretFingerprintKey                            one random value per management station, and
                                                    the only key material this package generates
                                                    rather than collects - see the model
    ServerProfile.secret_digests                    an EQUALITY-GROUP ID per server entry, which
                                                    is never the secret and never the form the
                                                    device stores it in
    ServerProfile.secret_shortest_stored_length     the shortest stored form's LENGTH, taken on
                                                    the way past and before the id is computed
    ServerProfile.secret_weakness                   the verdict a grading reads - PAN-AAA-005
    ServerProfile.message_signing_effective         the flag AND a certificate to sign with,
                                                    which live on two different objects - 009
    AuthenticationProfile.allow_list_width          `all` / `named_group` / `empty`, which no
                                                    clause can tell apart - PAN-AAA-010
    AuthenticationProfile.sso_realm                 the two keys that can hold a Kerberos
    AuthenticationProfile.kerberos_method_realm     realm, and the two verdicts over them, one
    AuthenticationProfile.kerberos_realm_configured of which is a CASE test that no clause can
    AuthenticationProfile.kerberos_realm_is_uppercase  make - every text operator in the
                                                    registry is case-insensitive - PAN-AAA-007
    AuthenticationProfile.saml_certificate_profile  the trust anchor the IdP profile's
                                                    validation switch needs - PAN-AAA-008
    AuthenticationProfile.saml_request_signing_certificate  what the firewall signs with - 009
    AuthenticationSequence.weakest_member_method    `none` graded apart from `local-database`,
                                                    which `has_local_member` merges - 012

NO COLUMN HERE HOLDS A SHARED SECRET, which is Jason's standing ruling and the shipped reading of
every other secret-shaped column in this package - `ike.py::IkeGateway` keeps a presence test and
says "No column holds the ciphertext", `device_services.py::SnmpSettings` keeps
`community_is_default` and lets the community string stay in the snapshot. `secret_digests` holds
`HMAC-SHA256(station key, stored form)` truncated to 32 hex characters, one per server entry: two
entries hold the same secret exactly when their ids match, and the id is not the secret and does
not become it. The key is KEYED rather than bare because PAN-OS's stored form is derivable from a
guessed plaintext for its first 33 characters, so a plain digest of it is brute-forceable from a
word list. `ServerProfile.clean()` refuses an entry that is not 32 characters wide, which is what
keeps a stored form out of the column by construction.

THE FOUR TEXT COLUMNS ARE NULLABLE AND THE REASON IS NOT COSMETIC. Stage 5 declared each of them
`default.stores: null`, `rests_on: not_assumed` - stage 4 held every one of those readings back,
two of them `not_reached` outright. `is_empty` compiles to `filter(field="")`, which matches a
blank and does NOT match NULL, so a blank column and a null one are found by different clauses and
whichever way round that falls, one of them is quietly wrong. The same correction 0110 made to two
columns that had already shipped as blanks.

TWO OF THE THREE NEW DERIVED COLUMNS ARE BACKFILLED HERE and the third cannot be. A new
BooleanField defaults to False and a new CharField to "", and for `allow_list_width` and
`weakest_member_method` that default reads as a real state - `""` matches no placement, so a
grading silently falls back to its baseline severity on every row until a normalization pass runs.
Both are derivable from JSON this store ALREADY HOLDS (`allow_list_members`, `member_methods`), so
they are computed here, in the same change as the column, exactly as stage 5 asked.

WHAT IS NOT BACKFILLED, AND IT IS NAMED RATHER THAN LEFT TO BE NOTICED:
`kerberos_realm_configured`, `kerberos_realm_is_uppercase`, `message_signing_effective` and
`secret_weakness` are derived from columns this migration CREATES, so there is nothing stored to
compute them from - no realm, no signing certificate and no secret has ever been collected. Until
a collection and normalization pass runs they read False, False, False and "". The first three are
the FIRING side (PAN-AAA-007 and 009 report rather than reassure) and the fourth matches no
placement, so the estate is not told it is safe on the strength of nothing - but PAN-AAA-007 and
009 should not be activated until that pass has run, because a finding on every profile in an
estate is still a wrong finding.

NOTHING EXISTING MOVES. No column's type or nullability is changed, no row is added or removed,
and the two backfills are reversible: the reverse puts both columns back to the field default,
which is where a plain AddField would have left them.
"""

# Generated by Django 6.0.6, then given its reasoning and its two backfills by hand.

import django.db.models.deletion
from django.db import migrations, models


def width_from_members(apps, schema_editor):
    """`allow_list_width` from `allow_list_members`, which the store already holds.

    THE EMPTY CASE IS PLACED EXPLICITLY. An empty allow list admits NOBODY - Help p.839 and the
    admin guide's p.288 step 6 - and `all` admits every principal the method can reach. Both are
    "no named group" and they mean opposite things, which is the whole reason this column exists.
    """
    profile = apps.get_model("integrations", "AuthenticationProfile")
    for row in profile.objects.all().only("id", "allow_list_members", "allow_list_width"):
        members = [str(m).strip() for m in (row.allow_list_members or [])]
        row.allow_list_width = ("all" if any(m.lower() == "all" for m in members)
                                else "empty" if not members else "named_group")
        row.save(update_fields=["allow_list_width"])


def weakest_from_methods(apps, schema_editor):
    """`weakest_member_method` from `member_methods`, which the store already holds.

    `none` first because the vendor's own description of it is that it performs no
    authentication at all, where `local-database` checks a credential the firewall holds.
    """
    sequence = apps.get_model("integrations", "AuthenticationSequence")
    for row in sequence.objects.all().only("id", "member_methods", "weakest_member_method"):
        methods = [str(m) for m in (row.member_methods or [])]
        row.weakest_member_method = next(
            (m for m in ("none", "local-database") if m in methods), "")
        row.save(update_fields=["weakest_member_method"])


def widths_back_to_the_field_default(apps, schema_editor):
    """Where a plain AddField would have left it, so a downgrade lands where it started."""
    apps.get_model("integrations", "AuthenticationProfile").objects.all().update(
        allow_list_width="")


def weakest_back_to_the_field_default(apps, schema_editor):
    apps.get_model("integrations", "AuthenticationSequence").objects.all().update(
        weakest_member_method="")


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0110_wildfire_rule_absence_is_null'),
    ]

    operations = [
        migrations.AddField(
            model_name='authenticationprofile',
            name='allow_list_width',
            field=models.CharField(blank=True, choices=[('all', 'All principals the method can reach'), ('named_group', 'A named group or user'), ('empty', 'Nobody - the list is empty')], max_length=16),
        ),
        migrations.AddField(
            model_name='authenticationprofile',
            name='kerberos_method_realm',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name='authenticationprofile',
            name='kerberos_realm_configured',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='authenticationprofile',
            name='kerberos_realm_is_uppercase',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='authenticationprofile',
            name='saml_certificate_profile',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name='authenticationprofile',
            name='saml_request_signing_certificate',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name='authenticationprofile',
            name='sso_realm',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name='authenticationsequence',
            name='weakest_member_method',
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AddField(
            model_name='serverprofile',
            name='message_signing_effective',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='serverprofile',
            name='secret_digests',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name='serverprofile',
            name='secret_shortest_stored_length',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='serverprofile',
            name='secret_weakness',
            field=models.CharField(blank=True, choices=[('reused_across_appliances', 'Reused across appliances'), ('below_sixteen_characters', 'Below sixteen characters'), ('meets_floor', 'Meets the floor')], max_length=32),
        ),
        migrations.CreateModel(
            name='SecretFingerprintKey',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key_hex', models.CharField(max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('management_station', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='secret_fingerprint_key', to='integrations.managementstation')),
            ],
            options={
                'verbose_name': 'secret fingerprint key',
                'verbose_name_plural': 'secret fingerprint keys',
            },
        ),
        # AFTER the AddFields, and only the two the store can already answer. See the module
        # docstring for the four that cannot be answered without a collection pass - one of
        # which is `secret_weakness`, whose input is an equality-group id nothing has computed
        # yet. NO BACKFILL COULD COMPUTE ONE: the ids are derived from a key this migration
        # creates, over a stored form no column has ever held.
        migrations.RunPython(width_from_members, widths_back_to_the_field_default),
        migrations.RunPython(weakest_from_methods, weakest_back_to_the_field_default),
    ]
