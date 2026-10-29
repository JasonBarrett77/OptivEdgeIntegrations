"""Device > Setup > Management - the channel a firewall uses to reach its management estate.

PAN-HAP-005's subject, from `stage5-ha-panorama.json`'s `firewall-management-channel`.

ONE ROW PER APPLIANCE. Both nodes are device-wide `deviceconfig` - `system/panorama/local-panorama`
and `setting/management/secure-conn-client` - so one row per appliance however many vsys it
carries. On an HA pair this yields TWO rows for one configuration and nothing deduplicates them;
unlike the HA model beside it these two ARE expected to agree, and this estate measured that
directly on 2026-10-29: `panorama-server-2`, written on fw-core-tpa-a alone, is present on BOTH
members, carried there by the pair's configuration synchronisation with nothing ever addressed to
the peer.

THE SUBJECT IS THE FIREWALL'S HALF OF THE HANDSHAKE AND ONLY THAT HALF. What the firewall
presents and what it checks are here; whether the management appliance ACCEPTS the shipped
certificate from anybody is `secure-conn-server`/`check-client-identity` on the station, which
`rules.md` puts out of scope. So a row with every column on this model on the hardened side still
does not say the channel is authenticated, and `management_channel_not_hardened` says so in its
own comment rather than leaving it to be discovered.

THE DIRECTION OF `check_server_identity_enabled` MATTERS AND IS EASY TO GET BACKWARDS. It is the
firewall checking the station's certificate common name against the configured address. The
control's own words say "client identity verification", which is the APPLIANCE checking the
FIREWALL and lives on Panorama - a stage reading this leaf for the control's words reports the
wrong direction of trust as satisfied.

TEXT COLUMNS ARE BLANK RATHER THAN NULL, and `panorama_server_secondary` is the one that matters:
PAN-HAP-005[0]'s assertion clause is `panorama_server_secondary is empty`, and MEASURED
2026-10-29 `is_empty` compiles to `filter(field="")` in every per-model compiler in
`OptivEdgeAssessments/src/assessments/search/*/compiler.py`. A NULL matches nothing, so storing
the absence as NULL would take the control from "fires on every appliance in this estate" to
"never fires anywhere" with nothing erroring. See `HighAvailabilityConfig` for the same decision
and the companion-column mechanism that carries "nobody looked".
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class PanoramaRegistration(ProvenancedMixin, SyncTrackedModel):
    """One appliance's registration with its central management estate, and what it presents."""

    #: `certificate-type` is a CHOICE NODE - the device stores which child exists, not a text
    #: value. Three children on all four lab appliances by `action=complete`. `none` IS A
    #: SETTABLE BRANCH as well as the documented default, so "the key is absent" and "the key
    #: says none" are two different stored states with the same meaning, and anything reading
    #: this column has to treat them alike.
    CERTIFICATE_TYPE_LOCAL = "local"
    CERTIFICATE_TYPE_SCEP = "scep"
    CERTIFICATE_TYPE_NONE = "none"
    CERTIFICATE_TYPE_CHOICES = (
        CERTIFICATE_TYPE_LOCAL, CERTIFICATE_TYPE_SCEP, CERTIFICATE_TYPE_NONE)

    #: Computed here: the collection flag, the estate-shape applicability predicate and the two
    #: verdicts. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "management_config_collected",
        "management_estate_is_a_pair",
        "panorama_address_in_force_unverified",
        "management_channel_not_hardened",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="panorama_registrations")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="panorama_registrations")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="panorama_registrations", null=True, blank=True)
    #: The MERGED CONFIG snapshot. `show panorama-status` is a second snapshot and is not
    #: referenced here - it carries no column of its own and feeds
    #: `panorama_address_in_force_unverified` only.
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="panorama_registrations")

    #: FALSE MEANS NOBODY LOOKED. True where the merged-config read returned a device entry for
    #: this appliance, including where neither node exists on it - an absence is a reading.
    management_config_collected = models.BooleanField(default=False)

    #: `local-panorama/panorama-server`. Blank means the firewall names no management appliance
    #: at all and is unmanaged. 255 characters because Help p.709 permits an FQDN and a column
    #: sized for an address truncates a hostname; stage 4 measured no maxLength, so the length
    #: is this layer's proposal and not a reconciliation.
    panorama_server_primary = models.CharField(max_length=255, blank=True, default="")
    #: `local-panorama/panorama-server-2`. BLANK IS A MEASURED READING, not an absence of one:
    #: an absent second slot asserts the firewall names NO secondary appliance, paid in both
    #: directions on fw-core-tpa-a (commit jobs 540 and 541, 2026-10-26) against
    #: `show panorama-status`, which gained and lost a `Panorama Server 2` block with it.
    #: THIS IS THE FINDING SIDE for PAN-HAP-005's redundancy half.
    panorama_server_secondary = models.CharField(max_length=255, blank=True, default="")

    #: `secure-conn-client/enable-secure-panorama-communication`. NULL AND NOT FALSE: nothing on
    #: the firewall reports the value - `show system state filter *panorama*` answers NO_MATCHES
    #: and `show panorama-status` reports the address and the connection state and nothing about
    #: which certificate the connection used - so no positive control is payable from the
    #: firewall at all. The CLI grammar's help text and Help p.710 both say the default is off;
    #: `rules.md` ranks that `documented`, which is not a measurement, so it is not materialised.
    secure_panorama_communication_enabled = models.BooleanField(
        null=True, blank=True, default=None)
    #: `secure-conn-client/check-server-identity` - the FIREWALL checking the STATION. Null for
    #: the same reason as its neighbour: no firewall-side oracle reports whether peer-name
    #: validation is in force.
    check_server_identity_enabled = models.BooleanField(null=True, blank=True, default=None)
    #: `secure-conn-client/certificate-type`, read as WHICH CHILD is present. Blank where the key
    #: is absent, which MEANS THE SAME THING as the explicit `none` branch and is stored
    #: differently - measured on this estate, where three appliances hold no key and
    #: pan-fw-201 holds `certificate-type/none`.
    client_certificate_type = models.CharField(max_length=16, blank=True, default="")
    #: `secure-conn-client/certificate-type/local/certificate`. Blank means nothing is bound and
    #: the appliance falls back to the vendor's predefined certificate pair.
    #:
    #: A REFERENCE NOTHING RESOLVES HERE. The name points at
    #: `/config/shared/certificate/entry[@name='...']` and the per-vsys certificate collections,
    #: which no subject of this domain models. An unresolvable name means the firewall presents
    #: no customer certificate - and because a null join sits on the compliant side of a plain
    #: comparison and is silently dropped, the hardening verdict is computed at normalization
    #: instead of being left to a query.
    client_certificate_name = models.CharField(max_length=64, blank=True, default="")

    #: WHETHER THE MANAGEMENT ESTATE IS A REDUNDANT PAIR - the applicability PAN-HAP-005's
    #: redundancy half turns on, because a second address slot has nothing to point at on a
    #: single-appliance estate.
    #:
    #: TRUE BY DEFAULT AND FALSE BY NOTHING, AND A REVIEWER SHOULD SEE WHY. The answer lives on
    #: the management station's own `deviceconfig/high-availability`, which `rules.md` puts out
    #: of scope - so there is no subject, no collector and no column for it, and the engineer's
    #: answer is the only thing that can set this. True is the APPLYING side: a false here would
    #: SUPPRESS the control on every firewall, which is the reassuring failure an applicability
    #: clause makes look careful. The consequence is explicit: on a single-Panorama estate -
    #: which is what this lab MEASURES, the station's HA node being absent in all three config
    #: views - PAN-HAP-005 fires on every managed firewall and its remediation is wrong, because
    #: there is no second appliance to point at.
    #:
    #: THE NEAREST FIREWALL-SIDE READING DOES NOT CLOSE IT. `show panorama-status` carries an
    #: `HA state` token per slot, measured 2026-10-29 as `Unknown` for the connected slot on all
    #: four lab appliances and `disconnected` for the unreachable one. `Unknown` cannot tell "not
    #: a pair" from "not established", so it is an unknown and not an answer.
    management_estate_is_a_pair = models.BooleanField(default=True)
    #: WHETHER THE REGISTRATION HAS NOT BEEN SHOWN TO BE THE LIVE, WORKING ONE - true is the
    #: finding side. THREE different nodes can hold a Panorama address on one appliance and only
    #: one is the live setting, so the answer is a precedence decision across nodes rather than a
    #: comparison - measured on this estate: pan-fw-201 holds `initcfg/panorama-server` with the
    #: same address as the live setting, pan-fw-111 holds an `initcfg` with no panorama-server at
    #: all, and the two PA-5220s hold neither.
    #:
    #: NO CONTROL CLAUSES ON THIS. It exists to discharge a question stage 4 recorded and to stop
    #: a later stage writing PAN-HAP-005 against the configured slot alone, which would report a
    #: firewall as managed when its only address is a stale bootstrap value.
    panorama_address_in_force_unverified = models.BooleanField(default=True)
    #: WHETHER THE MANAGEMENT CHANNEL IS NOT HARDENED to the customer's own certificate material
    #: with peer-name validation - true is the finding side. True unless a local certificate is
    #: bound AND the Panorama surface is switched to use it AND the server-identity check is on.
    #:
    #: THE HALF THIS COLUMN CANNOT HOLD: even all three true on the firewall does not make the
    #: channel authenticated, because the station may still accept the shipped certificate from
    #: anybody. That switch is on the management appliance and on no firewall. Stage 3 routes it
    #: to an engineer and this column does not pretend to answer it.
    management_channel_not_hardened = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_panorama_registration_per_appliance"),
        ]
        indexes = [
            models.Index(fields=["appliance"]),
            models.Index(fields=["management_config_collected"]),
            models.Index(fields=["panorama_server_secondary"]),
            models.Index(fields=["management_channel_not_hardened"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} management channel"
