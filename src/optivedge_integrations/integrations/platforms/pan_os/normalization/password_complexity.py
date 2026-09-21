"""Minimum password complexity - PAN-AUTH-001 to 013.

Reads `/config/mgt-config/password-complexity`, which sits at the TOP of the merged config
beside `devices` and `shared` rather than under a device entry. `PasswordProfile` reads the node
next to it and is the OVERRIDE for the accounts it is applied to.

The parsing is `password_complexity_from_snapshot`, which already existed for
`DeviceConfigurationProfile` and is shared rather than copied - this normalizer exists to give
the values a row of their OWN, not to re-read them differently. While both models exist the two
write the same numbers from the same parse, so they cannot disagree; when
`DeviceConfigurationProfile` goes, its password fields go with it.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, FieldProvenance, PasswordComplexityPolicy)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT, classify_prov_type, provenance_raw_key,
    provenance_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot, password_complexity_from_snapshot)

#: The shared parser names every field `password_*`, because it was written for a model whose
#: other 34 fields needed the prefix to stay apart. On a model that IS the password policy the
#: prefix says nothing, so it comes off here - one place, rather than sixteen renamed keys in a
#: parser two models read.
_PREFIX = "password_"
RENAMED = {
    "password_complexity_enabled": "enabled",
    "password_minimum_length": "minimum_length",
    "password_minimum_uppercase": "minimum_uppercase",
    "password_minimum_lowercase": "minimum_lowercase",
    "password_minimum_numeric": "minimum_numeric",
    "password_minimum_special": "minimum_special",
    "password_block_username_inclusion": "block_username_inclusion",
    "password_new_differs_by_characters": "new_differs_by_characters",
    "password_history_count": "history_count",
    "password_block_repeated_characters": "block_repeated_characters",
    "password_change_on_first_login": "change_on_first_login",
    "password_change_period_block": "change_period_block",
    "password_expiration_period": "expiration_period",
    "password_expiration_warning_period": "expiration_warning_period",
    "password_post_expiration_admin_login_count": "post_expiration_admin_login_count",
    "password_post_expiration_grace_period": "post_expiration_grace_period",
}


def normalize_password_complexity(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"password_complexity_policies": 0}

    values, provenance = password_complexity_from_snapshot(snapshot)
    renamed = {RENAMED[k]: v for k, v in values.items()}

    content_type = ContentType.objects.get_for_model(PasswordComplexityPolicy)
    with transaction.atomic():
        obj, _ = PasswordComplexityPolicy.objects.update_or_create(
            appliance=appliance,
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": snapshot,
                **renamed,
            },
        )
        FieldProvenance.objects.filter(content_type=content_type, object_id=obj.pk).delete()
        for field, raw_key, raw_value in provenance:
            # An absent key produces NO row, which is what keeps "pushed", "written locally"
            # and "defaulted" three different facts instead of one blank. mgt-config is
            # template-managed - the users node on tpa-a arrives carrying @ptpl - so these
            # values really can be pushed.
            if raw_key is not ABSENT:
                FieldProvenance.objects.create(
                    content_type=content_type, object_id=obj.pk, field_name=RENAMED[field],
                    provenance_type=classify_prov_type(raw_key),
                    raw_key=provenance_raw_key(raw_key), raw_value=provenance_value(raw_key, raw_value))
    return {"password_complexity_policies": 1}
