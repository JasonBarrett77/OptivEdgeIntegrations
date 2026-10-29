"""The management interface's SSL/TLS binding - PAN-MGT-010 and PAN-CRT-006.

Resolves the bound name over `SslTlsServiceProfile` ROWS rather than over the payload, which is
the whole change from the aggregate: a binding that points at a row cannot disagree with it. It
therefore has to run AFTER `normalize_certificate_objects` has written this appliance's profile
rows, and `APPLIANCE_OBJECT_NORMALIZERS` orders it so.

The resolution rule is the measured one, now applied to rows: PREDEFINED FIRST, then shared, and
never a vsys - `deviceconfig/system` cannot reference a vsys profile at all. Predefined rows exist
only when the predefined catalog was collected; without it a predefined name resolves nowhere,
which is the same answer the payload-based resolver gave and the same NormalizationIssue says why.

The certificate TRUST is still computed from the certificate payloads, because predefined
certificates are not rows and the chain walk needs them. What changed is where the certificate
NAME comes from: the profile row, so the name the verdict is about is the name the profile has.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.db import transaction

from optivedge_integrations.integrations.models import (
    Appliance, FieldProvenance, ManagementTlsBinding, NormalizationIssue, SslTlsServiceProfile)
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    ABSENT,
    Implicit,
    parse_text_field, classify_prov_type, provenance_raw_key, provenance_value, scalar_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    SSL_TLS_ISSUE_KIND, device_entry_from_snapshot, latest_merged_snapshot,
    latest_predefined_certificate_snapshot, predefined_certificates, resolve_certificate,
    shared_certificates)

#: Resolution order over rows. Predefined first - see the module docstring.
_ORDER = (ManagementTlsBinding.SCOPE_PREDEFINED, ManagementTlsBinding.SCOPE_SHARED)

#: NOTHING IS ASSUMED, and the reason is an instruction rather than an omission: writing this
#: leaf was forbidden, because a wrong value here is a management-interface lockout and on a
#: Panorama-managed appliance the recovery is a console session. So the positive control - the
#: third point of the five-point bar - was never paid and the status cannot be `measured`.
#:
#: What IS held: the config is silent in every view on two appliances; the key is absent by
#: construction on both, which have never held it; a second oracle is paid in full by the WIRE
#: TEST, which is behavioural and independent of every config read - an unbound interface
#: refuses TLS 1.0 and ACCEPTS 1.1, 1.2 and 1.3, measured on four appliances; and no sibling
#: moves the reading.
#:
#: It was declared `Implicit.measured(None, '... an absent key binds no profile')`, which is
#: wrong the same way the SSL/TLS profile's `certificate` was: a `measured` Implicit whose value
#: is None has `stores_nothing` true, so it persists as `not_configured` - the declaration
#: claiming a vendor fact while the row records "nobody configured it", and nothing notices.
#: The vendor's own Help ("If you select none (default), the firewall or Panorama uses a
#: predefined certificate") is a LEAD and not evidence, and it was measured WRONG in one
#: direction: the certificate an unbound interface presents is NOT the one in
#: /config/predefined/certificate.
#:
#: EMPTY IS A STATE AND NOT A GAP. It is the COMMONEST FAILING STATE in the estate - two of the
#: four lab appliances - which is why the row is keyed on the appliance: keyed on the profile
#: there would be no row at all for it, and the most common failure would be unreportable.
BINDING_IMPLICIT = Implicit.not_assumed(
    "deviceconfig/system/ssl-tls-service-profile holds a NAME and an absent key binds no "
    "profile - but the positive control was never paid, writing this leaf being forbidden, so "
    "nothing is assumed about the absence beyond the wire test's reading that such an "
    "interface accepts TLS 1.1")


def resolve_profile_row(appliance: Appliance, name: str):
    """(scope, row) for the bound name, or (UNRESOLVED, None).

    PREDEFINED FIRST. Measured 2026-09-02: a custom entry written to /config/shared under the
    predefined name `TLSv1.3_Default` was accepted, committed, and then ignored completely - the
    device kept negotiating TLS 1.3 and kept serving the predefined certificate, while a second
    profile with a UNIQUE name and the same custom certificate took effect immediately. So the
    custom entry was not merely outranked on protocol settings, it was discarded whole.

    The OPPOSITE of `region`, where a custom definition extends its predefined namesake - name
    collision behaviour is per object type and each has to be measured separately.

    The vsys scope is deliberately absent: `deviceconfig/system` cannot reference a vsys profile
    at all. Measured the same day with `action=complete` on the binding field, which lists valid
    target names - writing a vsys profile to the candidate did not add it.

    This rule was applied to payload dicts by `resolve_ssl_tls_profile` until that resolver was
    deleted with `DeviceConfigurationProfile` on 2026-09-11. It is applied to ROWS here.
    """
    rows = {row.scope: row for row in SslTlsServiceProfile.objects.filter(
        appliance=appliance, name=name, scope__in=_ORDER)}
    for scope in _ORDER:
        if scope in rows:
            return scope, rows[scope]
    return ManagementTlsBinding.SCOPE_UNRESOLVED, None


def normalize_management_tls(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"management_tls_bindings": 0}

    entry = device_entry_from_snapshot(snapshot)
    deviceconfig = entry.get("deviceconfig") if isinstance(entry, dict) else None
    system = deviceconfig.get("system") if isinstance(deviceconfig, dict) else None
    system = system if isinstance(system, dict) else {}
    # PAN-MGT-010 fires when nothing is bound, so "no key" is the finding and has to be
    # recorded as a state rather than left as a gap in the table.
    name, name_rk, name_rv = parse_text_field(
        system.get("ssl-tls-service-profile"), implicit=BINDING_IMPLICIT)

    scope, row = ("", None)
    trust, cert_scope, issuer = "", "", ""
    if name:
        scope, row = resolve_profile_row(appliance, name)
        if row is not None and row.certificate_name:
            cert_scope, trust, issuer = resolve_certificate(
                row.certificate_name,
                predefined=predefined_certificates(
                    latest_predefined_certificate_snapshot(appliance)),
                shared=shared_certificates(snapshot),
            )
    else:
        # NOTHING IS BOUND, and the measured truth is sharper than a blank. An unbound
        # management interface presents an RSA-2048, sha256WithRSAEncryption, one-year,
        # SELF-SIGNED certificate whose common name is the chassis serial, on all four lab
        # appliances - so classifying it is reporting what the device does rather than guessing.
        #
        # It is NOT the predefined certificate, which is the obvious wrong answer and was
        # measured apart from it: /config/predefined/certificate's TLSv1.3_Default is EC
        # prime256v1, ecdsa-with-SHA256 and valid ten years, and the two were generated four
        # seconds apart at first boot with identical subject DNs.
        #
        # THE EVIDENCE COLUMNS STAY BLANK AND THAT IS THE POINT: the certificate the interface
        # actually serves is in NO configuration namespace reachable from the appliance -
        # `show config running` carries one BEGIN CERTIFICATE block and it is a leftover,
        # "Palo Alto Networks" appears nowhere in it, `request certificate show` answers
        # "Command succeeded with no output" for four plausible names including the chassis
        # serial, and `show system state filter *cert*` is NO_MATCHES. So there is no scope to
        # record and no issuer to print, and inventing either would be the invention this
        # classification exists to avoid.
        #
        # The baseline clause `is not ca_issued` matched the blank too, so the finding fired
        # either way - but by the accident of a negated equality rather than by design, and the
        # SEVERITY the grading places depended on that accident. Changed 2026-10-29.
        trust = ManagementTlsBinding.TRUST_SELF_SIGNED

    content_type = ContentType.objects.get_for_model(ManagementTlsBinding)
    with transaction.atomic():
        binding, _ = ManagementTlsBinding.objects.update_or_create(
            appliance=appliance,
            defaults={
                "management_station": appliance.management_station,
                "appliance_group": appliance.appliance_group,
                "source_snapshot": snapshot,
                "profile_name": name,
                "profile_scope": scope,
                "ssl_tls_service_profile": row,
                "certificate_trust": trust,
                # A certificate that resolved nowhere reports its scope as unresolved, which is
                # evidence worth keeping; one that was never looked up has no scope at all.
                "certificate_scope": cert_scope,
                "certificate_issuer": issuer,
            },
        )
        # Only the BINDING has provenance. The resolved values live on another object and carry
        # no @ptpl of their own, so a provenance line under them would be an invention.
        FieldProvenance.objects.filter(content_type=content_type, object_id=binding.pk).delete()
        if name_rk is not ABSENT:
            FieldProvenance.objects.create(
                content_type=content_type, object_id=binding.pk, field_name="profile_name",
                provenance_type=classify_prov_type(name_rk),
                raw_key=provenance_raw_key(name_rk), raw_value=provenance_value(name_rk, name_rv))

        NormalizationIssue.objects.filter(appliance=appliance, kind=SSL_TLS_ISSUE_KIND).delete()
        if scope == ManagementTlsBinding.SCOPE_UNRESOLVED:
            NormalizationIssue.objects.create(
                management_station=appliance.management_station,
                appliance=appliance,
                appliance_group=appliance.appliance_group,
                kind=SSL_TLS_ISSUE_KIND,
                name=name,
                severity=NormalizationIssue.Severity.WARNING,
                disposition=NormalizationIssue.Disposition.KEPT,
                reason=(
                    f"deviceconfig/system binds SSL/TLS service profile {name!r}, which matches "
                    "no predefined or shared SslTlsServiceProfile row on this appliance. Most "
                    "often the predefined catalog has not been collected - it does not travel "
                    "in `show config merged` and needs its own read - rather than the reference "
                    "being genuinely dangling. The binding is kept as recorded; its protocol "
                    "floor cannot be read, so PAN-MGT-010 reports it rather than passing it."),
            )
    return {"management_tls_bindings": 1}
