"""Device > Setup > WildFire. The device-wide settings. PAN-AVW-004 and PAN-AVW-005.

ONE MODEL, TWO CONTROLS, because they are one screen and one config node - and because the
distinction that matters is not between them but between this node and a WildFire ANALYSIS
PROFILE. A profile decides what is ASKED FOR; this decides what the platform actually
forwards. A file type a profile names is never analysed if it exceeds its per-type limit
here, which is why PAN-AVW-003's description points at this node rather than claiming more
than it can.

Measured on the lab 2026-10-09 and 2026-10-10.

**The UI is INVERTED relative to the config on session information**, and reading it the
other way round gets PAN-AVW-005 exactly backwards. `session-info-select` holds twelve
`exclude-*` members, so the config stores what is WITHHELD and a ticked checkbox means the
exclusion is ABSENT. An empty list is FULL sharing and the desirable state - the opposite of
this codebase's usual rule that an absent key is the weaker end.

**The size limits look configured and mostly are not what they appear.** A value can come
from a member template, from the template STACK, or from the platform, and all three report
`@src: tpl`. Only `@ptpl` names the source. Getting that wrong produced a wrong defaults
table that shipped for a day - see the comments on the version table below.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


#: THE DEFAULTS ARE PER PAN-OS VERSION, which a single table could never have expressed.
#:
#: Established 2026-10-10 from a device where NOTHING sets them - the only oracle, since such
#: a device shows no node at all in configuration and the UI is the only place the values
#: appear. A PA-5220 on 11.1.13-h3, whose template stack holds no wildfire node, gave the
#: 11.1 table.
#:
#: 11.2 ADDED `eml`: the key set is ten on 11.1 and eleven on 11.2, confirmed by completing
#: the node on all three lab appliances. So a table keyed by nothing would assert a file type
#: that does not exist on half the estate.
#:
#: HOW THIS REPLACED A WRONG TABLE. An earlier version recorded ten values as "the" defaults.
#: They were the template STACK's configuration on one lab - found when a member template set
#: `pe: 8`, the push succeeded, and the limits did not move because stack config overrides
#: member templates. `@src` reads `tpl` for both, so it cannot tell them apart; `@ptpl` names
#: the source. See the payload contract's wildfire-device-settings node.
DEFAULT_SIZE_LIMITS_BY_VERSION = {
    "11.1": {"pe": 16, "apk": 10, "pdf": 3072, "ms-office": 16384, "jar": 5, "flash": 5,
             "MacOSX": 10, "archive": 50, "linux": 50, "script": 20},
}

#: 11.2 IS NOT IN THE TABLE, deliberately. Only `eml` is established there - set by nothing on
#: pan-fw-111 and the UI shows 5 MB. The other ten are supplied by that device's template
#: stack, which re-asserts the 11.1 values EXCEPT ms-office, where it holds 16385 against
#: 11.1's 16384. That one difference cannot be read: either 11.2's default is 16385 and the
#: stack asserts defaults, or it is 16384 and someone moved it by 1 KB. Settling it needs an
#: 11.2 device with nothing set, and the lab has none.
#:
#: A device whose version is absent here REPORTS, naming the version, rather than passing.
#: "We have no table for this release" must not render as "nothing to tune here".
VERSIONS_NOT_ESTABLISHED_NOTE = (
    "the PAN-OS defaults for this release are not established, so whether these limits were "
    "sized for the estate cannot be decided")

#: `eml` cannot be set from a TEMPLATE even on 11.2 - measured 2026-10-09, the write refused
#: with `eml 'eml' is not a valid reference` and a template's key set is ten where the
#: device's is eleven. On a Panorama-managed estate its only remediation is a device-local
#: override, so asserting it would make the control unsatisfiable.
TEMPLATE_UNSETTABLE = ("eml",)


def defaults_for_version(software_version: str) -> dict[str, int] | None:
    """The per-type defaults for this release, or None where none is established.

    Matches on major.minor: PAN-OS ships these in the platform, and a maintenance release
    has never been observed to change them. A release this does not know returns None, which
    the caller reports rather than treats as "nothing is untuned".
    """
    parts = (software_version or "").split(".")
    if len(parts) < 2:
        return None
    table = DEFAULT_SIZE_LIMITS_BY_VERSION.get(f"{parts[0]}.{parts[1]}")
    if table is None:
        return None
    return {k: v for k, v in table.items() if k not in TEMPLATE_UNSETTABLE}


class WildfireSettings(ProvenancedMixin, SyncTrackedModel):
    """`deviceconfig/setting/wildfire`, per appliance."""

    #: What PAN-OS supplies when nobody has touched the value, established 2026-10-09 - see
    #: the payload contract's `wildfire-device-settings` node for how. PAN-AVW-004 is a TUNING
    #: check (Jason, 2026-10-09): a value still at its default means nobody sized it for this
    #: estate, and a value moved off it is taken as evidence that somebody did.
    #:
    #: THE UNITS ARE NOT UNIFORM - the UI renders pe as MB and pdf as KB - so a value is only
    #: ever compared against its OWN default, never against another type's.
    #:
    #: NOT CONFIRMED ON A SECOND PLATFORM. Both PA-5220s were disconnected when this was
    #: measured and they sit behind a different template stack. If their values differ, either
    #: these are not defaults or the defaults are platform-dependent, and this table would
    #: have to become one table per platform.
    #: Re-exported from module level; see the comments there.
    DEFAULT_SIZE_LIMITS_BY_VERSION = DEFAULT_SIZE_LIMITS_BY_VERSION
    TEMPLATE_UNSETTABLE = TEMPLATE_UNSETTABLE

    #: The twelve exclusions PAN-OS offers, enumerated 2026-10-09. A profile's file types are a
    #: different and larger set; these are session ATTRIBUTES.
    SESSION_INFO_EXCLUSIONS = (
        "exclude-app-name", "exclude-dest-ip", "exclude-dest-port", "exclude-email-recipient",
        "exclude-email-sender", "exclude-email-subject", "exclude-filename", "exclude-src-ip",
        "exclude-src-port", "exclude-url", "exclude-username", "exclude-vsys-id",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="wildfire_settings")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="wildfire_settings")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="wildfire_settings", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="wildfire_settings")

    #: {file type: limit as configured}. A type absent here is at its default, and the model
    #: does NOT fill it in - absent and "set to the default value" are different facts about
    #: who did what, even though PAN-AVW-004 treats them the same way.
    size_limits = models.JSONField(default=dict, blank=True)
    #: Which types are still at their default. DETAIL ONLY, for the same reason as
    #: `session_info_excluded`; the searchable form is `size_limits_untuned` below.
    untuned_file_types = models.JSONField(default=list, blank=True)
    #: PAN-AVW-004's verdict. True when NO type has been moved off its default.
    size_limits_untuned = models.BooleanField(default=True)

    #: The `exclude-*` members in force. EMPTY IS THE GOOD STATE - it means nothing is
    #: withheld from a sample. See the class docstring on the inversion.
    #:
    #: DETAIL ONLY. A control may not rest on a JSON column - a JSON lookup is unindexed and
    #: matches NOTHING when the vendor renames a key, so a control resting on one stops
    #: finding anything instead of failing. The searchable form is the boolean below.
    session_info_excluded = models.JSONField(default=list, blank=True)
    #: The same fact as `session_info_excluded == []`, stored because that is the one a
    #: control can search. Written at normalization beside the list it summarises.
    shares_full_session_info = models.BooleanField(default=True)
    #: The Inline Session Information Settings block, same twelve members. Collected because
    #: it is the same fact about a second engine; PAN-AVW-005 asserts the main block only.
    inline_session_info_excluded = models.JSONField(default=list, blank=True)

    #: Implicit NO both: absent on pan-fw-111 and both boxes render unticked, measured
    #: 2026-10-09. PAN-AVW-005 wants both `yes`.
    report_benign_file = models.BooleanField(default=False)
    report_grayware_file = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["appliance"], name="unique_wildfire_settings_per_appliance"),
        ]
        indexes = [models.Index(fields=["appliance"])]

    @property
    def reports_all_verdicts(self) -> bool:
        """Both benign and grayware reported. PAN-AVW-005 asserts both (Jason, 2026-10-09)."""
        return self.report_benign_file and self.report_grayware_file

    @property
    def session_info_gaps(self) -> list[str]:
        """What PAN-AVW-005 has to say, in the terms the screen uses."""
        gaps = []
        if self.session_info_excluded:
            gaps.append("session information withheld: "
                        + ", ".join(sorted(self.session_info_excluded)))
        if not self.report_benign_file:
            gaps.append("benign verdicts not reported")
        if not self.report_grayware_file:
            gaps.append("grayware verdicts not reported")
        return gaps

    @property
    def tuning_detail(self) -> str:
        """What PAN-AVW-004 has to say: which types nobody has sized for this estate.

        Two different findings share this column and the text separates them. A release with
        no established table cannot be assessed at all, which is not the same as being
        untuned - and saying so is the difference between "nobody sized this" and "we cannot
        tell", which have different next steps.
        """
        defaults = defaults_for_version(self.appliance.software_version)
        if defaults is None:
            return (f"PAN-OS {self.appliance.software_version or 'unknown'}: "
                    f"{VERSIONS_NOT_ESTABLISHED_NOTE}")
        if not self.untuned_file_types:
            return ""
        return ("still at the PAN-OS default: "
                + ", ".join(f"{t} ({defaults.get(t, '?')})"
                            for t in self.untuned_file_types))

    @property
    def defaults_established(self) -> bool:
        """Is there a measured defaults table for this appliance's release?"""
        return defaults_for_version(self.appliance.software_version) is not None

    def __str__(self) -> str:
        return f"{self.appliance} WildFire settings"
