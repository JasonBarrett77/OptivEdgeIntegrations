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
    ABSENT, classify_prov_type, scalar_value)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    SSL_TLS_ISSUE_KIND, device_entry_from_snapshot, latest_merged_snapshot,
    latest_predefined_certificate_snapshot, predefined_certificates, resolve_certificate,
    shared_certificates)

#: Resolution order over rows. Predefined first - see the module docstring.
_ORDER = (ManagementTlsBinding.SCOPE_PREDEFINED, ManagementTlsBinding.SCOPE_SHARED)


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
    name, name_rk, name_rv = scalar_value(system.get("ssl-tls-service-profile"))

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
                raw_key=name_rk or "", raw_value=name_rv or "")

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
