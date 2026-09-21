"""Password profiles - PAN-AUTH-026.

Reads `/config/mgt-config/password-profile`, which sits at the TOP of the merged config beside
`devices` and `shared` rather than under a device entry - the same place password-complexity
lives, and the same trap: the obvious xpath is wrong.
"""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, FieldProvenance, PasswordProfile, Snapshot, expiration_weakens)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit,
    ABSENT, classify_prov_type, provenance_raw_key, provenance_value, entry_provenance, ensure_list, parse_integer_field)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot, password_complexity_from_snapshot)

#: model field -> the key under the profile's `password-change` node. The same four keys the
#: global policy carries, which is what makes a profile an override rather than a new setting.
PROFILE_FIELDS = (
    ("expiration_period", "expiration-period"),
    ("expiration_warning_period", "expiration-warning-period"),
    ("post_expiration_admin_login_count", "post-expiration-admin-login-count"),
    ("post_expiration_grace_period", "post-expiration-grace-period"),
)


def _entries(snapshot: Snapshot) -> list[dict[str, Any]]:
    payload = snapshot.payload or {}
    config = payload.get("config") if isinstance(payload, dict) else None
    if not isinstance(config, dict):
        return []
    node = config.get("mgt-config")
    if not isinstance(node, dict):
        return []
    profiles = node.get("password-profile")
    if not isinstance(profiles, dict):
        return []
    return [e for e in ensure_list(profiles.get("entry")) if isinstance(e, dict)]


def normalize_password_profiles(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"password_profiles": 0}

    # The global policy this profile would override, from the SAME snapshot - so the comparison
    # is between two facts collected together rather than two facts collected at two times.
    global_values, _ = password_complexity_from_snapshot(snapshot)
    global_expiration = global_values.get("password_expiration_period", 0)

    content_type = ContentType.objects.get_for_model(PasswordProfile)
    seen = []
    with transaction.atomic():
        for entry in _entries(snapshot):
            name = str(entry.get("@name") or "").strip()
            if not name:
                continue
            change = entry.get("password-change")
            if not isinstance(change, dict):
                change = {}
            values, provenance = {}, []
            for field, key in PROFILE_FIELDS:
                values[field], raw_key, raw_value = parse_integer_field(
                    change.get(key),
                    implicit=Implicit.assumed(
                        0,
                        "the password-complexity form was measured, this object's "
                        "password-change node was not. 0 matches that neighbour, where it "
                        "means the rule is not enforced"))
                provenance.append((field, raw_key, raw_value))

            obj, _ = PasswordProfile.objects.update_or_create(
                appliance=appliance, name=name,
                defaults={
                    "management_station": appliance.management_station,
                    "appliance_group": appliance.appliance_group,
                    "source_snapshot": snapshot,
                    "global_expiration_period": global_expiration,
                    "weakens_global_expiration": expiration_weakens(
                        values["expiration_period"], global_expiration),
                    **values,
                },
            )
            seen.append(obj.pk)

            FieldProvenance.objects.filter(
                content_type=content_type, object_id=obj.pk).delete()
            raw_key, raw_value = entry_provenance(entry)
            if raw_key is not ABSENT:
                FieldProvenance.objects.create(
                    content_type=content_type, object_id=obj.pk, field_name="__entry__",
                    provenance_type=classify_prov_type(raw_key),
                    raw_key=provenance_raw_key(raw_key), raw_value=provenance_value(raw_key, raw_value))
            for field, rk, rv in provenance:
                if rk is not ABSENT:
                    FieldProvenance.objects.create(
                        content_type=content_type, object_id=obj.pk, field_name=field,
                        provenance_type=classify_prov_type(rk),
                        raw_key=provenance_raw_key(rk), raw_value=provenance_value(rk, rv))

        # A profile gone from the device must not linger: PAN-AUTH-026 is a hygiene control and
        # a stale row is a finding about something that no longer exists.
        PasswordProfile.objects.filter(appliance=appliance).exclude(pk__in=seen).delete()
    return {"password_profiles": len(seen)}
