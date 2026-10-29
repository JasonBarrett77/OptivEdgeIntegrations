"""The scoped-administrator-role posture of one appliance - PAN-AUTH-023.

Two counts over `/config/shared/admin-role` and over the accounts that name an entry in it. The
row is the APPLIANCE, because the commonest failing state is NO ROLE AT ALL and there is then no
entry to hang a row on - measured on three of the four lab appliances, where the collection is
absent in all three config views.

NO EARLY RETURN WHEN THE COLLECTION IS ABSENT. An appliance with no `admin-role` node still gets
a row, holding 0 and 0, because 0 is the finding: "this firewall has no scoped administrator
role in use". Returning without writing would leave the appliance with no row, which reports
nothing at all and is the one answer this control must never give.

THE SECOND COUNT IS AN INTERSECTION, not a tally of role references. `custom_role_profile` may
name a PREDEFINED role - completing that leaf on a device with no custom roles at all returned
`auditadmin`, `securityadmin` and `cryptoadmin` - and a predefined role is not a scoped role
anybody here defined. So only names that are also entries of this appliance's shared collection
are counted, which is the reverse traversal stage 5 specifies and nothing wider.

ROLE DEFINITIONS LIVE ONLY AT SHARED SCOPE, so there is no vsys walk. That the node is INVALID
under a vsys is the project's own record carried forward and was NOT re-measured by this run; a
per-vsys role, if one can exist, is invisible to these counts.

THE USERS WALK IS `admin_users._entries` RATHER THAN A SECOND COPY. One parse of
`mgt-config/users`, so this module and `normalize_admin_users` cannot disagree about which
entries exist - the same reason `password_complexity_from_snapshot` is shared.
"""

from __future__ import annotations

from typing import Any

from django.db import transaction

from optivedge_integrations.integrations.models import AdminRolePosture, Appliance, Snapshot
from optivedge_integrations.integrations.platforms.pan_os.normalization.admin_users import (
    _entries as user_entries)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ensure_list, merged_shared, scalar_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    write_node_row)


def shared_role_names(snapshot: Snapshot) -> list[str]:
    """Every custom administrator role this appliance defines at shared scope, by name.

    An absent `admin-role` node, a present-but-empty one and a node whose entries carry no
    `@name` all answer with the empty list, which is the finding value rather than an error.
    """
    payload = snapshot.payload or {}
    shared = merged_shared(payload) if isinstance(payload, dict) else {}
    roles = shared.get("admin-role")
    if not isinstance(roles, dict):
        # A template push of an empty node leaves `{"admin-role": None}` behind, which is not
        # an error and is not a role either.
        return []
    names = []
    for entry in ensure_list(roles.get("entry")):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("@name") or "").strip()
        if name:
            names.append(name)
    return names


def role_names_in_use(snapshot: Snapshot) -> set[str]:
    """The role names some account on this appliance NAMES, from the users walk.

    Reads `permissions/role-based/custom/profile`, which is the only place an account points at
    a role definition. The names are returned unfiltered - whether each one is a role THIS
    appliance defines is the caller's intersection, because a predefined role reaches this leaf
    too and is not a scoped role anybody here created.
    """
    named: set[str] = set()
    for entry in user_entries(snapshot):
        permissions = entry.get("permissions")
        role_based = permissions.get("role-based") if isinstance(permissions, dict) else None
        custom = role_based.get("custom") if isinstance(role_based, dict) else None
        if not isinstance(custom, dict):
            continue
        profile, _, _ = scalar_value(custom.get("profile"))
        profile = profile.strip()
        if profile:
            named.add(profile)
    return named


def admin_role_posture_from_snapshot(snapshot: Snapshot) -> dict[str, Any]:
    """The two counts, so a caller can assert them without a database."""
    defined = shared_role_names(snapshot)
    in_use = role_names_in_use(snapshot)
    return {
        "scoped_role_count": len(set(defined)),
        "scoped_roles_in_use_count": len({name for name in defined if name in in_use}),
    }


def normalize_admin_role_posture(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"admin_role_postures": 0}

    values = admin_role_posture_from_snapshot(snapshot)
    with transaction.atomic():
        # `provenance=()` writes no FieldProvenance row, which is what a model whose every
        # column is in DERIVED_FIELDS wants - a derived field may never carry one.
        write_node_row(AdminRolePosture, appliance, snapshot, values, provenance=())
    return {"admin_role_postures": 1}
