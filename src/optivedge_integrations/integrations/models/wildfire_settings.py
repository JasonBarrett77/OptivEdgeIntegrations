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


#: PAN-OS'S OWN DECLARED DEFAULTS, from two agreeing vendor sources: Help pages 774-776 and
#: Panorama's Size Limit tooltip, which state identical ranges and defaults.
#:
#:     type        range            default    Help's best-practice recommendation
#:     pe          1 - 50 MB        16 MB      16 MB
#:     apk         1 - 50 MB        10 MB      10 MB
#:     pdf         100 - 51200 KB   3072 KB    3072 KB
#:     ms-office   200 - 51200 KB   16384 KB   16384 KB
#:     jar         1 - 20 MB        5 MB       5 MB
#:     flash       1 - 10 MB        5 MB       5 MB
#:     MacOSX      1 - 50 MB        10 MB      1 MB   <- the only disagreement
#:     archive     1 - 50 MB        50 MB      50 MB  <- default IS the maximum
#:     linux       1 - 50 MB        50 MB      50 MB  <- default IS the maximum
#:     script      10 - 4096 KB     20 KB      20 KB
#:
#: THE DEFAULT IS THE VENDOR'S BEST PRACTICE for nine of ten, which decides what a finding
#: about them MEANS. An estate at defaults is at the recommended STARTING POINT, not below
#: it - Help p.775 calls them "a good starting place for setting effective limits that don't
#: overtax firewall resources" and says to increase them "if more buffer space is available".
#: So PAN-AVW-004 reports that nobody has evaluated this platform's headroom, NOT that the
#: estate is below best practice. Saying otherwise in a finding would be false.
#:
#: THE VENDOR SAYS THESE MOVE. p.776: the values "might differ based on the current version
#: of PAN-OS or the content release", and the tooltip is the live authority. A CONTENT
#: release can change them, not just a PAN-OS version - so this table is a snapshot by the
#: vendor's own account, which is why `defaults_for_version` keeps its argument.
#:
#: TWO EARLIER TABLES HERE WERE WRONG and both inferred defaults from a DEVICE - one took a
#: template stack's configuration for the platform's, the other read one device and covered
#: one release. Both were avoidable: p.775 states the defaults outright and was in this
#: project's own doc index the whole time. The search returned p.774, p.774 was read, and
#: p.774 ends mid-sentence.
DEFAULT_SIZE_LIMITS = {
    "pe": 16, "apk": 10, "pdf": 3072, "ms-office": 16384, "jar": 5, "flash": 5,
    "MacOSX": 10, "archive": 50, "linux": 50, "script": 20,
}

#: The permitted range per type. This project twice recorded that the maxima were not
#: discoverable, because an absurd value is refused with `size-limit '999999999' is invalid.
#: Invalid limit` and no range. True of the write probe, false of the question: Help p.775
#: lists every one.
SIZE_LIMIT_RANGE = {
    "pe": (1, 50), "apk": (1, 50), "pdf": (100, 51200), "ms-office": (200, 51200),
    "jar": (1, 20), "flash": (1, 10), "MacOSX": (1, 50), "archive": (1, 50),
    "linux": (1, 50), "script": (10, 4096),
}

#: The Help's own best-practice recommendation per type. Identical to the default for nine of
#: ten; MacOSX is the exception, recommended at 1 MB against a default of 10 MB. Every other
#: bullet restates its own default and 1 MB is also the range minimum, so that reads like a
#: documentation error - recorded as the Help states it, and not acted on.
BEST_PRACTICE_SIZE_LIMITS = dict(DEFAULT_SIZE_LIMITS, MacOSX=1)

#: `eml` EXISTS ONLY ON 11.2+ and is not in the declared set above - the key set is ten on
#: 11.1.13-h3 and eleven on 11.2.3-h3, completed on all three lab appliances. It is also
#: unsettable from a TEMPLATE: the write is refused with `eml 'eml' is not a valid reference`,
#: so on a Panorama-managed estate its only remediation would be a device-local override.
#:
#: Excluded on both counts, which is why the ASSERTED set is release-invariant and this table
#: needs no version key. Its default is 5 MB where it exists, observed on pan-fw-111 where
#: nothing sets it.
TEMPLATE_UNSETTABLE = ("eml",)


def defaults_for_version(software_version: str = "") -> dict[str, int]:
    """The per-type defaults this control asserts against.

    Release-invariant: the only per-release difference is `eml`, which 11.2 adds and which is
    excluded anyway. The argument is kept so a release that DOES change a default has one
    obvious place to branch, and so callers need not know that today it does not matter.
    """
    return {k: v for k, v in DEFAULT_SIZE_LIMITS.items() if k not in TEMPLATE_UNSETTABLE}


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
    DEFAULT_SIZE_LIMITS = DEFAULT_SIZE_LIMITS
    SIZE_LIMIT_RANGE = SIZE_LIMIT_RANGE
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
        if not self.untuned_file_types:
            return ""
        return ("still at the PAN-OS default: "
                + ", ".join(f"{t} ({defaults.get(t, '?')})"
                            for t in self.untuned_file_types))

    @property
    def defaults_established(self) -> bool:
        """Always true now that the defaults come from the vendor rather than a device.

        Kept so the finding builder need not change if a release ever does diverge.
        """
        return True

    def __str__(self) -> str:
        return f"{self.appliance} WildFire settings"
