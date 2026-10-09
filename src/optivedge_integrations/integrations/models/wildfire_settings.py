"""Device > Setup > WildFire. The device-wide settings. PAN-AVW-004 and PAN-AVW-005.

ONE MODEL, TWO CONTROLS, because they are one screen and one config node - and because the
distinction that matters is not between them but between this node and a WildFire ANALYSIS
PROFILE. A profile decides what is ASKED FOR; this decides what the platform actually
forwards. A file type a profile names is never analysed if it exceeds its per-type limit
here, which is why PAN-AVW-003's description points at this node rather than claiming more
than it can.

Measured on pan-fw-111 (PA-VM 11.2.3), 2026-10-09.

**The UI is INVERTED relative to the config on session information**, and reading it the
other way round gets PAN-AVW-005 exactly backwards. `session-info-select` holds twelve
`exclude-*` members, so the config stores what is WITHHELD and a ticked checkbox means the
exclusion is ABSENT. An empty list is FULL sharing and the desirable state - the opposite of
this codebase's usual rule that an absent key is the weaker end.

**The size limits look configured and are not.** Every entry on pan-fw-111 reports
`@src: tpl`, but `temp-stck-jb-rg` is a template STACK and none of the six templates holds a
wildfire node - verified by writing a value into one and watching it appear and vanish, after
two malformed xpaths had already produced false negatives that day. So nothing sets them and
they are what PAN-OS supplies.
"""

from __future__ import annotations

from django.db import models

from .base import SyncTrackedModel
from .provenance import ProvenancedMixin


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
    DEFAULT_SIZE_LIMITS = {
        "pe": 16, "apk": 10, "pdf": 3072, "ms-office": 16385, "jar": 5, "flash": 5,
        "MacOSX": 10, "archive": 50, "linux": 50, "script": 20, "eml": 5,
    }
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
        """What PAN-AVW-004 has to say: which types nobody has sized for this estate."""
        if not self.untuned_file_types:
            return ""
        return ("still at the PAN-OS default: "
                + ", ".join(f"{t} ({self.DEFAULT_SIZE_LIMITS.get(t, '?')})"
                            for t in self.untuned_file_types))

    def __str__(self) -> str:
        return f"{self.appliance} WildFire settings"
