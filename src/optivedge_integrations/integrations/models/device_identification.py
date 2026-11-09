"""Device-ID / IoT device identification - PAN-IOT-001 to PAN-IOT-004's subjects.

TWO GRAINS, ONE DOMAIN, and they are different on purpose:

`DeviceIdentificationState` is ONE ROW PER APPLIANCE. All three readings behind it are
device-wide - the license table, `show system info` and `deviceconfig/setting/iot/edge` -
so nothing here is scoped to an enforcement point. On an HA pair both peers hold their own
license table and their own content, so the pair yields TWO rows for what an operator
thinks of as one firewall and the two can legitimately differ: a license is per serial.

`RulebaseDeviceMatchVerdict` is ONE ROW PER ENFORCEMENT POINT. It is a conclusion about
the rule SET rather than about any rule, because "no rule names what a device is" cannot be
said of a particular rule - 182 of 188 rules measured in the lab carry neither device
element, so keying on the rule would multiply the failure rather than locate it.

A ROW EXISTS EVEN WHERE THE READ NEVER ARRIVED, following `MasterKey`: the companion
booleans (`licence_read_taken`, `device_dictionary_release_date_known`) are false in that
case and the controls fire on them, because "we never asked" must not look like "we asked
and it was fine".

NO `FieldProvenance` ROWS ARE WRITTEN FOR EITHER MODEL. Two of the three readings behind
the appliance row are operational replies, which carry no `@ptpl`, `@loc` or `@src`
decoration of any kind; the third - the edge node - was read with neither marker on any of
the four lab appliances. Every column of the verdict model is computed. Both models carry
`ProvenancedMixin` so the computed columns can be DECLARED in `DERIVED_FIELDS`, which is
what `provenance_for()` answers from; declaring them is the only thing that separates
"we worked this out" from "nothing tracks this field".
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


class DeviceIdentificationState(ProvenancedMixin, SyncTrackedModel):
    """One appliance's device-identification service state.

    Three unrelated instruments land on this one row, and a reader has to be able to tell
    which of them answered. The license table and `show system info` are operational
    commands with no xpath at any scope; the edge-service address is a configuration leaf
    in the merged view.
    """

    #: Computed here: verdicts over the licence table, the two companion "was this read"
    #: flags, values parsed out of a free-text reply, and the age arithmetic. None of them
    #: is a payload key. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "device_id_licensed",
        "licence_read_taken",
        "device_dictionary_version",
        "device_dictionary_release_date",
        "device_dictionary_release_date_known",
        "device_dictionary_age_days",
        "icd_build_version",
        "icd_built_at",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation",
        on_delete=models.CASCADE,
        related_name="device_identification_states",
    )
    appliance = models.ForeignKey(
        "integrations.Appliance",
        on_delete=models.CASCADE,
        related_name="device_identification_states",
    )
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup",
        on_delete=models.CASCADE,
        related_name="device_identification_states",
        null=True,
        blank=True,
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="device_identification_states",
    )

    #: True only where the licence table holds a row for the device-identification feature
    #: AND that row reports `expired: no`. False is the state of the whole lab and the state
    #: PAN-IOT-001's first half fires on.
    #:
    #: THE ONE INPUT NORMALIZATION CANNOT SUPPLY IS THE FEATURE STRING. No appliance in the
    #: lab holds the entitlement, so no run has read the literal the vendor uses for it, and
    #: a match against a string nobody has seen can never be true. The failure direction is
    #: the safe one - a wrong or absent string leaves this false, which FIRES - but it fires
    #: on every appliance in every estate until the string is right. The candidate set is in
    #: the normalizer as IOT_SECURITY_FEATURE_NAMES, where it can be corrected in one place.
    device_id_licensed = models.BooleanField(default=False)

    #: Whether `request license info` answered for this appliance at all, as against the
    #: appliance holding no entitlement. The two are INDISTINGUISHABLE in the payload: an
    #: appliance with nothing licensed answers `{"licenses": None}`, which is what an
    #: appliance nobody asked also produces. This column is the only thing that separates
    #: them, and the search layer has no is-null operator to ask with - the same shape as
    #: `ManagementSshSettings.defaults_measured`.
    licence_read_taken = models.BooleanField(default=False)

    #: `deviceconfig/setting/iot/edge/address`, verbatim. BLANK MEANS POINTED AT NOTHING,
    #: which is the state of all four lab appliances before anything was written, and a
    #: populated value says the WIRING exists and nothing about whether the service answers:
    #: a `.invalid` hostname that cannot resolve committed clean on a lab firewall.
    #:
    #: Blank rather than NULL deliberately. The stage-5 contract asked for "no stored guess"
    #: and blank stores no guess either, while a NULL would stop the shipped `is empty`
    #: clause matching at all - the search layer compiles a positive comparison and SQL
    #: answers no for a NULL, so the reading that must FIRE would silently pass.
    edge_service_address = models.CharField(max_length=255, blank=True)

    #: `show system info`'s `device-dictionary-version` - a two-part "<major>-<minor>"
    #: string. IT IS NOT A DATE and no currency grading can be computed from it alone:
    #: 249-772 on both PA-VMs against 82-406 on both PA-5220s says which is older and not
    #: by how long.
    device_dictionary_version = models.CharField(max_length=64, blank=True)

    #: `show system info`'s `device-dictionary-release-date`, verbatim, which is a LOCAL
    #: timestamp with a timezone ABBREVIATION rather than an offset. Blank where the reply
    #: omits the key, measured on both PA-5220s - where the three sibling release-date keys
    #: vanish from the same reply.
    #:
    #: The string is not comparable across appliances and is not stable on one: the same
    #: content instant read on 2026-10-26 as "2026/10/23 22:35:51 EDT" read on 2026-10-29
    #: as "2026/10/24 02:35:51 GMT", because the appliance's own timezone setting moved.
    #: Grade on `device_dictionary_age_days`, never on this.
    device_dictionary_release_date = models.CharField(max_length=64, blank=True)

    #: Whether this appliance reported a release date at all. False covers BOTH states that
    #: leave the column above blank - a reply that omits the key, and an appliance nobody
    #: read - and both mean the same thing to the control: the currency of this appliance's
    #: classification data could not be established.
    device_dictionary_release_date_known = models.BooleanField(default=False)

    #: Whole days between the installed content's own reported release date and the
    #: appliance's own clock at collection. It is the AGE of what is installed and NOT the
    #: distance behind what the vendor is currently publishing - nothing on a firewall
    #: carries the second.
    #:
    #: NULL where no release date was reported, and the null PASSES every threshold, which
    #: is why the control's graded group carries an applicability clause on
    #: `device_dictionary_release_date_known` and a second query that fires on it at false.
    #: A zero here would score the appliance that reports nothing as the freshest in the
    #: estate.
    device_dictionary_age_days = models.PositiveIntegerField(null=True, blank=True)

    #: `show iot icd version`'s Version line. A SECOND, INCOMMENSURABLE statement about the
    #: same installed data, carried so a reader of a staleness finding can see the instrument
    #: that disagrees: its values (13.pan_h1_r3, 14_1275212e43, 5.pan_r6) do not map onto
    #: the content version at all.
    icd_build_version = models.CharField(max_length=64, blank=True)

    #: `show iot icd version`'s TimeBuilt line - the only date either instrument gives for
    #: all four lab appliances, and the one that MUST NOT be graded on: it ranks the two
    #: appliances 167 content releases behind as the freshest in the estate.
    icd_built_at = models.CharField(max_length=64, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"],
                name="unique_device_identification_state_per_appliance",
            ),
        ]
        indexes = [models.Index(fields=["appliance"])]

    def __str__(self) -> str:
        return f"{self.appliance} device identification"

    def clean(self) -> None:
        """The two companion flags have to agree with the values they vouch for.

        A `release_date_known` of true beside a blank date would tell a reader the currency
        was established on an appliance that reported nothing, and the applicability clause
        built on it would then silence exactly the rows it exists to surface.
        """
        if self.device_dictionary_release_date_known != bool(self.device_dictionary_release_date):
            raise ValidationError(
                "device_dictionary_release_date_known must be true exactly when a release "
                "date is stored."
            )
        if self.device_dictionary_age_days is not None and not self.device_dictionary_release_date:
            raise ValidationError(
                "device_dictionary_age_days cannot be computed without a release date."
            )
        if self.device_id_licensed and not self.licence_read_taken:
            raise ValidationError(
                "device_id_licensed cannot be true when the license read was never taken."
            )


class RulebaseDeviceMatchVerdict(ProvenancedMixin, SyncTrackedModel):
    """One enforcement point's verdict about whether its rule set names what a device IS.

    The rule set of an enforcement point is THREE reads and not one - the firewall-local
    vsys rulebase, the Panorama pre- and post-rulebases pushed to it, and the vendor's two
    predefined default rules - and a verdict computed over any two of them is a verdict
    about the wrong rule set. It is therefore computed over the STORED `SecurityRule` rows,
    which already carry all three with `config_source` telling them apart, rather than over
    a payload this model would have to re-read and could read short.

    NO SCOPE COLUMN, and the consequence is a remediation one: the verdict cannot say which
    of the three rulebases the absence spans, so an estate whose policy is pushed from
    Panorama would be told to edit a vsys rulebase the firewall will not accept rules into.
    The distinction IS stored, on `SecurityRule.config_source`; joining back to it is a
    presentation question and not this row's.
    """

    #: Computed here: a verdict across the point's whole rule set and two counts. No payload
    #: key carries any of them. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "has_no_rule_matching_on_device",
        "rules_matching_on_device_count",
        "device_object_count",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation",
        on_delete=models.CASCADE,
        related_name="rulebase_device_match_verdicts",
    )
    enforcement_point = models.ForeignKey(
        "integrations.EnforcementPoint",
        on_delete=models.CASCADE,
        related_name="rulebase_device_match_verdicts",
    )
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot",
        on_delete=models.CASCADE,
        related_name="rulebase_device_match_verdicts",
    )

    #: True when this enforcement point evaluates NO rule that permits traffic and names a
    #: device object - the verdict, in the direction that FIRES. True is the state of the
    #: whole lab, and it is also what a point nobody recomputed holds, so the migration
    #: window announces itself rather than reporting a clean estate.
    #:
    #: WHAT THIS CANNOT YET TELL APART is a device object from a GlobalProtect HIP profile.
    #: One `source-hip` member list holds a device object, a HIP profile, and the bare
    #: keywords any/no-hip/quarantine, all as plain strings, so the only discriminator is
    #: resolving the member against the device-object namespace - which is what the
    #: normalizer does. A HIP profile sharing a name with a device object would be counted
    #: as a device match. No HIP profile exists anywhere in the lab, so the gap is inert
    #: here and wrong on the first estate that uses host posture.
    has_no_rule_matching_on_device = models.BooleanField(default=True)

    #: How many rules this point evaluates that name a device object in either device
    #: element, with NO action filter - the reachable form of the verdict beside it, so a
    #: finding can print a number. It counts a `deny` rule that names a device, which the
    #: verdict above deliberately does not.
    rules_matching_on_device_count = models.PositiveIntegerField(default=0)

    #: How many device objects this point could resolve a rule member against, across vsys,
    #: firewall-local shared and Panorama-pushed scope. ZERO MEANS NO RULE COULD NAME A
    #: DEVICE even if somebody wrote one, which is a different remediation from "no rule
    #: names one", and it is the state of this whole estate bar one vsys.
    device_object_count = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["enforcement_point"],
                name="unique_rulebase_device_match_verdict_per_point",
            ),
        ]
        indexes = [models.Index(fields=["enforcement_point"])]

    def __str__(self) -> str:
        return f"{self.enforcement_point} device-match verdict"

    def clean(self) -> None:
        """The verdict and the count it is taken over must not contradict each other.

        A false verdict with a zero count would say "some rule names a device" beside "no
        rule does", and the query reads the boolean.
        """
        if not self.has_no_rule_matching_on_device and self.rules_matching_on_device_count == 0:
            raise ValidationError(
                "has_no_rule_matching_on_device cannot be false while no rule names a "
                "device object."
            )
        if self.rules_matching_on_device_count and not self.device_object_count:
            raise ValidationError(
                "a rule cannot name a device object where this point resolves none."
            )
