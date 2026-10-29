"""One appliance's channel to its central management estate - PAN-HAP-005.

TWO NODES ON ONE SCREEN, both device-wide `deviceconfig`:

  - `system/panorama/local-panorama` - the two address slots.
  - `setting/management/secure-conn-client` - the certificate choice and the per-surface
    switches, of which only `enable-secure-panorama-communication` and `check-server-identity`
    are this control's.

And one operational read, `show panorama-status`, which is the only firewall-side instrument for
whether the registration WORKS. It feeds `panorama_address_in_force_unverified` and no column of
its own.

THE REPLY IS A PLAIN STRING. Every other collected reply in this estate parses to a dict; this
one arrives as pre-formatted text and is split by line and label. The parser is deliberately
tolerant and FAILS CLOSED: a shape nobody has seen leaves the registration unverified, which is
the firing side, rather than being read as a working connection.

THREE NODES CAN HOLD A PANORAMA ADDRESS ON ONE APPLIANCE and only one is the live setting -
`local-panorama`, `setting/management/initcfg/panorama-server`, and a pushed template's copy.
Measured on this estate 2026-10-29: pan-fw-201 holds an `initcfg/panorama-server` with the same
address as the live setting, pan-fw-111 holds an `initcfg` with no panorama-server at all, and
the two PA-5220s hold neither. So a predicate over the configured slot alone reports a firewall
as managed when its only address is a stale bootstrap value, and that is why the verification
column exists and why nothing clauses on it yet.

WHAT THIS MODULE CANNOT ANSWER, named here rather than left to be discovered: whether the
management STATION accepts the vendor's shipped certificate from anybody. That is
`secure-conn-server`/`check-client-identity` on Panorama, which `rules.md` puts out of scope. A
firewall-only reading can say what the firewall is configured to present and can never say the
channel is authenticated.
"""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, FieldProvenance, PanoramaRegistration, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    Implicit,
    choice_child,
    classify_prov_type,
    parse_text_field,
    parse_yes_no_field,
    provenance_raw_key,
    provenance_value,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    device_entry_from_snapshot, latest_merged_snapshot)

#: An absent SECOND slot asserts the firewall names NO secondary management appliance. The one
#: measured implicit on this subject, paid in BOTH directions on fw-core-tpa-a 2026-10-26:
#: staged 192.0.2.1 left `show panorama-status` showing one server block, commit job 540 added
#: `Panorama Server 2 : 192.0.2.1 / Connected: no`, and deleting the leaf with commit job 541
#: removed it, with all three config views returning to their pre-experiment answers.
#:
#: STORED AS BLANK AND NOT NULL. Stage 5 declared it a materialised NULL; `is_empty` in the
#: consumer compiles to `filter(field="")`, so a NULL would take PAN-HAP-005[0] from firing on
#: every appliance in this estate to never firing anywhere. The MEANING stage 5 declared -
#: nothing is bound, and that is the finding side - is what the blank carries, and the
#: provenance row records it as a measured vendor default rather than as an unread field.
NO_SECONDARY_SLOT = Implicit.measured(
    "",
    "stage4-ha-panorama.json, firewall-panorama-servers field `panorama-server-2`: positive "
    "control paid in both directions on fw-core-tpa-a 2026-10-26, commit jobs 540 and 541, "
    "against `show panorama-status`, which gained and lost a `Panorama Server 2` block with it")

PRIMARY_SLOT_UNMEASURED = Implicit.not_assumed(
    "deleting a firewall's only Panorama address is the one write the measuring run would not "
    "make, because every read in the wave was proxied through it, and no appliance in the "
    "estate lacks the key - so the absent state was never available to read")
SECURE_PANORAMA_UNMEASURED = Implicit.not_assumed(
    "nothing on the firewall reports the value: `show system state filter *panorama*` answers "
    "NO_MATCHES and `show panorama-status` reports the address and the connection state and "
    "nothing about which certificate the connection used, so no positive control is payable "
    "from the firewall at all. The CLI grammar's help text reads \"Default setting : 'no'\" and "
    "Help p.710 lists `None (default)`, which is the vendor saying so and not a measurement")
CHECK_SERVER_IDENTITY_UNMEASURED = Implicit.not_assumed(
    "no firewall-side oracle reports whether peer-name validation is in force, so no positive "
    "control is payable. An absent key that means 'the firewall does not check who it is "
    "talking to' is a finding, and materialising `no` on the strength of the vendor's text "
    "would report a measurement nobody took")
CERTIFICATE_TYPE_UNMEASURED = Implicit.not_assumed(
    "Help p.710 verbatim: 'None (default) - No device certificate is configured and the default "
    "predefined certificate is used', and three of the four lab appliances hold no "
    "`certificate-type` at all. Documented, not measured. Recorded for the SHAPE rather than "
    "the value: `none` is a SETTABLE BRANCH as well as the documented default, so an absent key "
    "and an explicit `none` are two stored states with one meaning")
CERTIFICATE_NAME_UNMEASURED = Implicit.not_assumed(
    "the behavioural consequence of binding nothing needs a TLS observation. The completion "
    "pool at this position says only which certificates the device would ACCEPT here - four "
    "different pools from one request shape across four appliances, and ZERO on pan-fw-201 - "
    "not what it does with none bound")

#: What `show panorama-status` labels each field. Compared case-insensitively on the part before
#: the colon, because the reply pads labels to a fixed width.
_SERVER_LABEL = "panorama server"
_CONNECTED_LABEL = "connected"
_HA_STATE_LABEL = "ha state"


def latest_panorama_status_snapshot(appliance: Appliance) -> Snapshot | None:
    """The newest `show panorama-status` reply for this appliance, or None.

    None until the collector runs, which `panorama_address_in_force_unverified` reports as
    unverified. Same shape as `log_settings.latest_logging_status_snapshot`.
    """
    return (
        Snapshot.objects.filter(appliance=appliance, source_type="show_panorama_status")
        .order_by("-collected_at", "-pk")
        .first()
    )


def parse_panorama_status(snapshot: Snapshot | None) -> list[dict[str, str]]:
    """One dict per server slot from the reply's pre-formatted text, in the order it lists them.

    Each slot carries `address`, `connected` ("yes"/"no"/"") and `ha_state`. Measured on all
    four lab appliances 2026-10-29:

        Panorama Server 1 : 20.185.152.225
            Connected     : yes
            HA state      : Unknown
        Panorama Server 2 : 192.0.2.1
            Connected     : no
            HA state      : disconnected

    Returns [] for a missing snapshot AND for a reply this cannot read, which the caller must
    treat as "not verified" rather than as "no servers". Those two are distinguished by the
    snapshot's existence, which the caller already has.
    """
    if snapshot is None:
        return []
    payload = snapshot.payload if isinstance(snapshot.payload, dict) else {}
    result = ((payload.get("response") or {}).get("result")
              if isinstance(payload.get("response"), dict) else None)
    if isinstance(result, dict):
        # Some op replies wrap their text; take any string the result holds rather than failing.
        result = next((v for v in result.values() if isinstance(v, str)), None)
    if not isinstance(result, str):
        return []
    slots: list[dict[str, str]] = []
    for line in result.splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        label = " ".join(label.split()).lower()
        value = value.strip()
        if label.startswith(_SERVER_LABEL):
            slots.append({"address": value, "connected": "", "ha_state": ""})
        elif not slots:
            continue
        elif label == _CONNECTED_LABEL:
            slots[-1]["connected"] = value.lower()
        elif label == _HA_STATE_LABEL:
            slots[-1]["ha_state"] = value
    return slots


def normalize_panorama_registration(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"panorama_registrations": 0}
    entry = device_entry_from_snapshot(snapshot)
    collected = isinstance(entry, dict)
    deviceconfig = (entry.get("deviceconfig") or {}) if collected else {}
    system = deviceconfig.get("system") if isinstance(deviceconfig.get("system"), dict) else {}
    panorama = system.get("panorama") if isinstance(system.get("panorama"), dict) else {}
    local_panorama = (panorama.get("local-panorama")
                      if isinstance(panorama.get("local-panorama"), dict) else {})
    setting = deviceconfig.get("setting") if isinstance(deviceconfig.get("setting"), dict) else {}
    management = setting.get("management") if isinstance(setting.get("management"), dict) else {}
    secure = (management.get("secure-conn-client")
              if isinstance(management.get("secure-conn-client"), dict) else {})
    initcfg = management.get("initcfg") if isinstance(management.get("initcfg"), dict) else {}

    primary, primary_rk, primary_rv = parse_text_field(
        local_panorama.get("panorama-server"), implicit=PRIMARY_SLOT_UNMEASURED)
    secondary, secondary_rk, secondary_rv = parse_text_field(
        local_panorama.get("panorama-server-2"), implicit=NO_SECONDARY_SLOT)
    secure_panorama, secure_rk, secure_rv = parse_yes_no_field(
        secure.get("enable-secure-panorama-communication"),
        implicit=SECURE_PANORAMA_UNMEASURED)
    check_identity, check_rk, check_rv = parse_yes_no_field(
        secure.get("check-server-identity"), implicit=CHECK_SERVER_IDENTITY_UNMEASURED)
    cert_type, cert_body = choice_child(
        secure.get("certificate-type"), PanoramaRegistration.CERTIFICATE_TYPE_CHOICES)
    cert_type_rk = CERTIFICATE_TYPE_UNMEASURED if not cert_type else None
    cert_name, cert_name_rk, cert_name_rv = parse_text_field(
        cert_body.get("certificate") if cert_type == PanoramaRegistration.CERTIFICATE_TYPE_LOCAL
        else None,
        implicit=CERTIFICATE_NAME_UNMEASURED)

    slots = parse_panorama_status(latest_panorama_status_snapshot(appliance))
    status_collected = bool(slots)

    # --- the verdicts -----------------------------------------------------------------------
    # WHETHER THE ESTATE IS A PAIR cannot be computed from a firewall. The station's own
    # `deviceconfig/high-availability` is out of scope, so no collector exists and none may, and
    # the engineer's answer is what should override this. TRUE is the APPLYING side: a false
    # would suppress PAN-HAP-005's redundancy half on every firewall, which is the reassuring
    # failure an applicability clause makes look careful.
    #
    # `show panorama-status`'s own `HA state` token is the nearest firewall-side reading and it
    # does NOT settle it: `Unknown` on the connected slot of all four lab appliances cannot tell
    # "not a pair" from "not established". It is read here only so that a later run finds the
    # attempt recorded rather than repeating it.
    management_estate_is_a_pair = True

    # The configured primary slot is the address IN FORCE only if the reply names it and reports
    # it connected. An `initcfg/panorama-server` that differs from the live setting is the
    # stale-bootstrap case stage 4 measured, and it leaves this unverified.
    initcfg_address = str(initcfg.get("panorama-server") or "").strip()
    live_addresses = {s["address"] for s in slots if s.get("connected") == "yes"}
    address_in_force_unverified = not bool(
        status_collected
        and primary
        and primary in live_addresses
        and (not initcfg_address or initcfg_address == primary)
    )

    # Hardening needs all three on the firewall's side: a LOCAL certificate bound, the Panorama
    # surface switched to use it, and the server-identity check on. The explicit `none` branch
    # and an absent key both mean no customer certificate, which is why the test is on the
    # `local` branch and a resolved name rather than on the key's presence.
    not_hardened = not (
        cert_type == PanoramaRegistration.CERTIFICATE_TYPE_LOCAL
        and bool(cert_name)
        and secure_panorama is True
        and check_identity is True
    )

    content_type = ContentType.objects.get_for_model(PanoramaRegistration)
    with transaction.atomic():
        row, _ = PanoramaRegistration.objects.update_or_create(
            appliance=appliance,
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": snapshot,
                "management_config_collected": collected,
                "panorama_server_primary": primary[:255],
                "panorama_server_secondary": secondary[:255],
                "secure_panorama_communication_enabled": secure_panorama,
                "check_server_identity_enabled": check_identity,
                "client_certificate_type": cert_type[:16],
                "client_certificate_name": cert_name[:64],
                "management_estate_is_a_pair": management_estate_is_a_pair,
                "panorama_address_in_force_unverified": address_in_force_unverified,
                "management_channel_not_hardened": not_hardened,
            },
        )
        FieldProvenance.objects.filter(content_type=content_type, object_id=row.pk).delete()
        entries = [
            ("panorama_server_primary", primary_rk, primary_rv),
            ("panorama_server_secondary", secondary_rk, secondary_rv),
            ("secure_panorama_communication_enabled", secure_rk, secure_rv),
            ("check_server_identity_enabled", check_rk, check_rv),
            ("client_certificate_type", cert_type_rk, None),
            ("client_certificate_name", cert_name_rk, cert_name_rv),
        ]
        FieldProvenance.objects.bulk_create([
            FieldProvenance(
                content_type=content_type, object_id=row.pk, field_name=field_name,
                provenance_type=classify_prov_type(rk),
                raw_key=provenance_raw_key(rk), raw_value=provenance_value(rk, rv)[:128])
            for field_name, rk, rv in entries if rk is not ABSENT])
    return {"panorama_registrations": 1}
