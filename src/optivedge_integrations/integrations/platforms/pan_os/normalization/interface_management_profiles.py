"""Normalize every interface management profile on an appliance, bound or not.

The "or not" is the reason this exists. `ManagementInterface` has a row only where a
profile is bound to something, so a profile bound to nothing leaves no trace anywhere - and
"is this profile unused" cannot be asked of a model that only records the used ones.

Bindings are counted from `Interface` rows, which is where the binding is recorded. An
earlier version re-walked the payload here, which meant the walk ran twice per appliance and
left the interface model - built to BE the join that PAN-OS does not provide - out of the
one join that needed it.

That makes this normalizer depend on interfaces having run first for the same snapshot, so
it checks rather than assumes: with no interface rows every profile would count zero
bindings and every one of them would be reported unused, which is a page of false findings
rather than a visible failure.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance,
    FieldProvenance,
    Interface,
    InterfaceManagementProfile,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ENTRY_PROVENANCE_ATTRIBUTES,
    ensure_list,
    entry_provenance_record,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot,
    latest_merged_snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_interfaces import (
    profile_service_states,
)

#: The entry-level provenance record, as FieldProvenance documents it: the `@ptpl` on a
#: named PAN-OS entry rather than on one of its fields.
ENTRY_FIELD = "__entry__"

#: The two services whose presence makes the counterfactual an UNENCRYPTED administrative
#: login. Keyed to the two controls stage 3 named when it placed this class one grade above
#: the row's baseline: "attaching it creates in ONE ACTION the exposure PAN-MGT-001 (telnet)
#: and PAN-MGT-002 (http) exist to report". The same pair is `INSECURE_SERVICES` in
#: OptivEdgeAssessments' presentation layer.
_UNENCRYPTED_ADMINISTRATIVE = ("telnet", "http")
#: The two that give real administrative reach over a sound transport - the baseline class.
_ENCRYPTED_ADMINISTRATIVE = ("https", "ssh")


def classify_unbound_exposure(profile_entry: dict) -> str:
    """What attaching this profile WOULD permit, as one of three classes.

    Strict precedence, which is what makes it a classification rather than three tests: an
    unencrypted administrative service beats an encrypted one beats everything else.

    `snmp` IS DELIBERATELY NOT AN ADMINISTRATIVE LOGIN HERE, and it IS one for
    `ManagementInterface.is_management_surface` - the two columns genuinely differ, and the
    difference is in their inputs rather than a slip:

    - `is_management_surface` asks "does this surface offer a way to administer the device at
      all", over `ADMINISTRATIVE_SERVICE_NAMES`, which is the five-member set
      OptivEdgeAssessments' search layer declares and whose docstring calls them services that
      "accept an administrative session or management protocol exchange". SNMP is one.
    - this column grades an administrative LOGIN, and its third class is named
      `monitoring_or_nothing`: "attaching it makes the interface answerable but not
      administrable". SNMP is monitoring - a community-string read, not a login - and it is
      neither of the two controls the worst class is keyed to, nor administrative reach over a
      sound transport.

    So a profile enabling SNMP alone makes a surface administrable and grades at the mildest
    class. Both readings are defensible and nothing upstream settles it: stage 5's
    `unbound_exposure_class` value set is three tokens it minted out of stage 3's three ranks
    and says nothing about SNMP, while stage 5's `is_management_surface.stores` says "the five
    administrative services" explicitly. The asymmetry is recorded rather than smoothed over,
    because smoothing it would mean changing one of those two readings without saying which.
    The lab exercises exactly this case - an snmp-only profile bound to one loopback.
    """
    states = profile_service_states(profile_entry)
    if any(states.get(name, (False, None, None))[0]
           for name in _UNENCRYPTED_ADMINISTRATIVE):
        return InterfaceManagementProfile.EXPOSURE_UNENCRYPTED
    if any(states.get(name, (False, None, None))[0]
           for name in _ENCRYPTED_ADMINISTRATIVE):
        return InterfaceManagementProfile.EXPOSURE_ENCRYPTED
    # The mildest class, and stage 3's one unplaced case is folded in here: a profile that
    # permits NOTHING AT ALL grades the same as one permitting only monitoring, because the
    # hygiene claim is identical and the row's severity is already the lowest that fires.
    return InterfaceManagementProfile.EXPOSURE_MONITORING


#: Attributes that state where an entry came from. Measured 2026-08-31: a template-pushed
#: profile carries `@ptpl` on the entry AND on each service leaf; a locally-created one carries
#: none.
#:
#: LOCAL used to be the absence of a row. That made absence mean two things - "defined on the
#: device" and "nothing tracks this" - and a consumer cannot tell them apart, so a locally
#: defined profile was presented as unrecorded. Four of the lab's eight profiles are in that
#: state. An unmarked entry now gets a row SAYING local, which is the same correction
#: normalization made for FIELDS on 2026-09-21.
#:
#: An override also leaves an entry unmarked, and local is the right answer there too: the
#: override replaced the object, so the device-side copy is what is in force and is where a
#: change has to be made. What is lost is the history, not the destination.
def _entry_provenance(entry: dict) -> tuple[str, str, str]:
    return entry_provenance_record(entry)


def _profile_entries(device_entry: dict) -> list[dict]:
    node = (((device_entry.get("network") or {}).get("profiles") or {})
            .get("interface-management-profile") or {})
    if not isinstance(node, dict):
        return []
    return [entry for entry in ensure_list(node.get("entry")) if isinstance(entry, dict)]


def normalize_interface_management_profiles(
    appliance: Appliance,
) -> list[InterfaceManagementProfile]:
    """Replace every profile for one appliance. Returns what was written."""
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        raise ValueError(f"no merged config snapshot for appliance {appliance.pk}")
    device_entry = device_entry_from_snapshot(snapshot)

    interface_rows = list(
        Interface.objects.filter(appliance=appliance, source_snapshot=snapshot)
        .values_list("name", "management_profile_name")
    )
    if not interface_rows:
        raise ValueError(
            f"appliance {appliance.pk} has no normalized interfaces for snapshot "
            f"{snapshot.pk}, so profile bindings cannot be counted. Every profile would "
            f"otherwise be reported unused. Normalize interfaces first."
        )

    bindings: dict[str, list[str]] = {}
    for interface_name, profile_name in interface_rows:
        if profile_name:
            bindings.setdefault(profile_name, []).append(interface_name)

    written: list[InterfaceManagementProfile] = []
    with transaction.atomic():
        content_type = ContentType.objects.get_for_model(InterfaceManagementProfile)
        FieldProvenance.objects.filter(
            content_type=content_type,
            object_id__in=list(
                InterfaceManagementProfile.objects.filter(appliance=appliance)
                .values_list("pk", flat=True)),
        ).delete()
        InterfaceManagementProfile.objects.filter(appliance=appliance).delete()

        seen: set[str] = set()
        for entry in _profile_entries(device_entry):
            name = str(entry.get("@name") or "").strip()
            if not name or name in seen:
                # A profile with no name cannot be bound by anything, and a duplicate name
                # is not expressible in PAN-OS. Neither is silently dropped: they surface
                # as the interface normalizer's issues against the same payload.
                continue
            seen.add(name)
            bound = sorted(set(bindings.get(name, [])))
            profile = InterfaceManagementProfile.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                source_snapshot=snapshot,
                name=name,
                bound_interface_names=bound,
                bound_interface_count=len(bound),
                # Counterfactual and computed for EVERY profile, bound or not. PAN-MGT-013
                # grades only the unbound ones, but storing it on all of them keeps the column
                # meaningful rather than leaving a null that means two things, and the keys are
                # already in hand from this same entry.
                unbound_exposure_class=classify_unbound_exposure(entry),
            )
            provenance_type, raw_key, raw_value = _entry_provenance(entry)
            FieldProvenance.objects.create(
                content_type=content_type, object_id=profile.pk,
                field_name=ENTRY_FIELD, provenance_type=provenance_type,
                raw_key=raw_key, raw_value=raw_value[:128],
            )
            written.append(profile)
    return written
