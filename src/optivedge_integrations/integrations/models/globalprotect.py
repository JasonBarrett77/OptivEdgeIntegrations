"""GlobalProtect portal models - the `globalprotect-portal` domain's three subjects.

PAN-GPP-001 to PAN-GPP-006. Three grains, because three different things are being asserted
and a finding has to be able to name the thing an engineer edits:

    GlobalProtectPortal               one portal entry of one vsys of one appliance
    GlobalProtectPortalClientAuthRow  one row of that portal's client-authentication table
    GlobalProtectEnforcementPoint     one vsys, as a VERDICT over its GlobalProtect objects

THE THIRD GRAIN EXISTS BECAUSE THE DEFECT IS SOMETIMES AN ABSENCE. A vsys holding clientless
application definitions that no portal publishes has no portal row to be named on, and a vsys
with no portal at all is where PAN-GPP-006's `latent` state lives. A control written on the
portal could report neither.

EVERY COLUMN A CONTROL COMPARES DEFAULTS TO ITS FIRING VALUE, which on this domain means some
defaults are the opposite of the framework's own: `tls_profile_binding_missing` defaults True,
`clientless_vpn_state` and `admission_demand` default to `unknown` rather than to a real state,
and both app-setting postures default to the `no_agent_configuration` sentinel. The rule behind
it is OptivEdgeProbe `pipeline/rules.md`: a missing reading reported as compliant is a customer
told they are safe on the strength of nothing.

THREE TRI-STATE VOCABULARIES HERE ARE THIS PIPELINE'S AND NOT THE DEVICE'S -
`clientless_vpn_state`, `admission_demand`, `clientless_vpn_feature_state` and the two
`*_posture` sentinels. The device offers no such value and a boolean would have defaulted
`False`, which excludes exactly the rows nobody read. Each one's `unknown` member is what keeps
an unread row inside the comparison instead of quietly outside it.

WHAT IS NOT MODELLED HERE, recorded because the absence is deliberate: the GlobalProtect
gateway, the portal's satellite configuration, the clientless application and application-group
definitions as objects (only their COUNTS, on the enforcement point), the login response page's
content, and the SSL/TLS service profile and certificate profile a portal binds - those two are
other domains' subjects and ship as `SslTlsServiceProfile` and `CertificateProfile`. A portal's
binding is stored here as a NAME and resolving it is a cross-domain join nothing here makes.
"""


from django.core.exceptions import ValidationError
from django.db import models

from .base import ApplianceScopedObject, SyncTrackedModel
from .provenance import ProvenancedMixin


#: The three states a portal's clientless-vpn branch can be reported in. `unknown` is the
#: migration default and the only one that keeps an unrecomputed row inside PAN-GPP-006's
#: comparison - its applicability clause is written `is not absent`.
CLIENTLESS_VPN_PRESENT = "present"
CLIENTLESS_VPN_ABSENT = "absent"
CLIENTLESS_VPN_UNKNOWN = "unknown"
CLIENTLESS_VPN_STATE_CHOICES = [
    (CLIENTLESS_VPN_PRESENT, "The portal carries a clientless-vpn branch"),
    (CLIENTLESS_VPN_ABSENT, "The portal carries no clientless-vpn branch"),
    (CLIENTLESS_VPN_UNKNOWN, "Not recomputed, or the portal arrived incomplete"),
]

#: `client-upgrade`'s five values, read off the device's own dictionary at
#: /config/predefined/dynamic-schema/gp-app-config/config - regex
#: ^(prompt|disabled|manual|transparent|internal)$ with form default `prompt`, identical on
#: 11.1.13-h3/PA-5220 and 11.2.5/PA-VM. THE REGEX IS ADVISORY: the device accepted a value
#: outside it into the member list without comment, so this column can hold a sixth thing and
#: the choices list is documentation rather than enforcement.
UPGRADE_PROMPT = "prompt"
UPGRADE_DISABLED = "disabled"
UPGRADE_MANUAL = "manual"
UPGRADE_TRANSPARENT = "transparent"
UPGRADE_INTERNAL = "internal"

#: The three states a single value cannot express. `no_agent_configuration` is the migration
#: default and the measured state of the estate's one pre-existing portal; it behaves like the
#: worst of the five, because nothing will move an endpoint and there is no configuration to
#: edit. `not_set` must not be collapsed onto the form default `prompt`, which is an acceptable
#: rank - that collapse turns "this portal says nothing about upgrades" into a pass.
#: `several_members` is reachable because a second write APPENDS rather than replaces.
POSTURE_NO_AGENT_CONFIGURATION = "no_agent_configuration"
POSTURE_NOT_SET = "not_set"
POSTURE_SEVERAL_MEMBERS = "several_members"

UPGRADE_POSTURE_CHOICES = [
    (UPGRADE_PROMPT, "Allow with Prompt"),
    (UPGRADE_DISABLED, "Disallow"),
    (UPGRADE_MANUAL, "Allow Manually"),
    (UPGRADE_TRANSPARENT, "Allow Transparently"),
    (UPGRADE_INTERNAL, "Internal"),
    (POSTURE_NO_AGENT_CONFIGURATION, "The portal hands out no agent configuration"),
    (POSTURE_NOT_SET, "An agent configuration exists and carries no client-upgrade setting"),
    (POSTURE_SEVERAL_MEMBERS, "The member list holds more than one value"),
]

#: `save-user-credentials`, as the device's own NUMERIC STRINGS and not integers and not labels -
#: written `0`, read back {'#text': '0'}. THE STORED ORDER IS NOT THE EXPOSURE ORDER: the column
#: runs 0,1,2,3 and the exposure runs 0 < 2 < 3 < 1, so any threshold comparison on this column
#: is wrong and a grading has to place the four values individually.
SAVED_CREDENTIALS_CHOICES = [
    ("0", "No"),
    ("1", "Yes - username and password"),
    ("2", "Save Username Only"),
    ("3", "Only with User Fingerprint"),
    (POSTURE_NO_AGENT_CONFIGURATION, "The portal hands out no agent configuration"),
    (POSTURE_NOT_SET, "An agent configuration exists and carries no save-user-credentials key"),
]

#: What one client-authentication row demands, resolved from the portal's certificate-profile
#: binding and the row's own and/or switch TOGETHER. Neither raw column can carry the grading:
#: `yes` on the switch is one rank where a certificate profile is bound and a worse one where
#: none is, and a clause has no second field slot.
ADMISSION_PASSWORD_ONLY = "password_only"
ADMISSION_PASSWORD_OR_CERTIFICATE = "password_or_certificate"
ADMISSION_PASSWORD_AND_CERTIFICATE = "password_and_certificate"
ADMISSION_UNKNOWN = "unknown"
ADMISSION_DEMAND_CHOICES = [
    (ADMISSION_PASSWORD_ONLY, "A password alone admits an endpoint"),
    (ADMISSION_PASSWORD_OR_CERTIFICATE, "A password OR a client certificate admits an endpoint"),
    (ADMISSION_PASSWORD_AND_CERTIFICATE, "Both a password AND a client certificate are required"),
    (ADMISSION_UNKNOWN, "Either input is missing, so the demand cannot be resolved"),
]

#: How much of the Clientless VPN feature is present in one vsys. `latent` is the state the
#: enforcement-point grain exists for: definitions that no portal publishes, which is a
#: configuration one edit from being live and has no portal row to be reported on.
FEATURE_LIVE = "live"
FEATURE_LATENT = "latent"
FEATURE_ABSENT = "absent"
FEATURE_UNKNOWN = "unknown"
CLIENTLESS_VPN_FEATURE_STATE_CHOICES = [
    (FEATURE_LIVE, "A portal publishes applications and definitions exist"),
    (FEATURE_LATENT, "Definitions or groups exist and no portal publishes them"),
    (FEATURE_ABSENT, "Neither a publishing portal nor a definition"),
    (FEATURE_UNKNOWN, "The reads that would answer it did not all arrive"),
]

#: Whether the appliance reported a GlobalProtect Portal licence. `unknown` is kept APART from
#: `no`: {'licenses': None} arrives with status=success on an appliance that holds nothing, and
#: a count of zero cannot tell "asked and holds none" from "never asked".
LICENSED_YES = "yes"
LICENSED_NO = "no"
LICENSED_UNKNOWN = "unknown"
PORTAL_LICENSED_CHOICES = [
    (LICENSED_YES, "A GlobalProtect Portal licence is installed"),
    (LICENSED_NO, "A populated licence list does not carry it"),
    (LICENSED_UNKNOWN, "The appliance reported no licences at all, or was never asked"),
]


class GlobalProtectPortal(ApplianceScopedObject):
    """One GlobalProtect portal entry of one virtual system. PAN-GPP-001, 003, 004, 005, 006.

    `ApplianceScopedObject` is the base because the portal's real scopes are a member of its
    `SCOPE_CHOICES`: a portal exists only under a vsys entry - there is no shared portal and no
    predefined one, measured - so every row of this model is `scope=vsys`. The base's `name`
    IS the portal name, exposed as `portal_name` below because that is what the spec, the
    finding and the artifact layer call it.

    THE PORTAL NAME'S NAMESPACE IS THE APPLIANCE AND NOT THE VSYS, measured and unusual for a
    vsys-scoped object: writing a name into one vsys while the same name existed in another was
    refused at the write, code=12, "already in use". So the constraint below is wider than the
    device's own rule rather than narrower, which is the safe direction - it can never merge two
    device objects into one row.

    WHAT A ROW CANNOT SAY, and both are in the stage 5 artifact's `not_stored`: whether the TLS
    floor the portal actually negotiates is acceptable (the binding is a NAME, and on a
    template-managed appliance the profile it names is not in the same payload), and whether the
    authentication profile a row beneath it binds is a PROFILE or a SEQUENCE.
    """

    #: Everything the normalizer worked out rather than read. See ProvenancedMixin.DERIVED_FIELDS.
    #: `is_missing` is SyncTrackedModel's and is set by collection rather than by a payload key.
    DERIVED_FIELDS = (
        "is_missing",
        "mandatory_keys_present",
        "tls_profile_binding_missing",
        "clientless_vpn_state",
        "clientless_vpn_floor_known",
        "client_auth_row_count",
        "upgrade_posture",
        "saved_credentials_posture",
    )

    #: Whether this row carries all four keys the device refuses to commit a portal without -
    #: portal-config/local-address, ssl-tls-service-profile, custom-login-page and
    #: custom-home-page. IT IS THE ONLY THING THAT TELLS AN ABSENT KEY APART FROM A READ THAT
    #: DID NOT CARRY ONE: an absent node and a path a collector never asked for arrive as the
    #: same nothing, so no column can separate them unless the collector records that it ASKED.
    #: False until something proves otherwise, and false is the firing side.
    mandatory_keys_present = models.BooleanField(default=False)

    #: The NAME of the SSL/TLS service profile this portal binds. A name and nothing else: what
    #: the profile PERMITS is PAN-CRT-005's subject and is not in this column. Non-nullable with
    #: an empty default, because the key is MANDATORY on a committed portal - an empty string
    #: here is always a read that did not carry it, never a device state, and `is_empty` is the
    #: only absence operator the query layer offers.
    ssl_tls_service_profile = models.CharField(max_length=64, blank=True, default="")

    #: The verdict in the direction that fires: true when no transport-profile name is bound.
    #: Default True - a portal nobody has looked at has not been shown to bind one.
    tls_profile_binding_missing = models.BooleanField(default=True)

    #: The NAME of the certificate profile this portal binds, which decides whether a client
    #: certificate can be demanded of any endpoint class at all. NULL IS A REAL COMMITTED STATE
    #: AND IT IS THE PERMISSIVE ONE - the estate's one pre-existing portal binds none. Nullable
    #: because nothing compares this column: the reading is carried by
    #: `GlobalProtectPortalClientAuthRow.certificate_profile_bound` and `admission_demand`.
    certificate_profile = models.CharField(max_length=64, null=True, blank=True)

    #: What this portal serves a browser that asks for its login page: `Disable` means no page
    #: at all, `factory-default` names the page the platform ships, and any other value is an
    #: imported response page. NO `None` STATE EXISTS ON A DEVICE - the vendor Help names one
    #: and calls it this field's default, and the device refuses to write it in either
    #: capitalisation - so the comparison is total over three states.
    #: Non-nullable: the key is mandatory on a committed portal, so an empty string is evidence
    #: about the READ and `mandatory_keys_present` is the column that reports it.
    custom_login_page = models.CharField(max_length=64, blank=True, default="")

    #: Whether this portal publishes internal web applications for browser access.
    #: THERE IS NO OFF SWITCH TO READ: ten children under `clientless-vpn` and not one of them
    #: is a boolean, measured on three builds, so `absent OR disabled` collapses to "the element
    #: exists or it does not" - and reading that absence as `off` would report every portal with
    #: the feature configured as compliant.
    clientless_vpn_state = models.CharField(
        max_length=16, choices=CLIENTLESS_VPN_STATE_CHOICES, default=CLIENTLESS_VPN_UNKNOWN)

    #: The weakest TLS version the browser sessions carrying this portal's published web
    #: applications may negotiate. THIS IS THE CLIENTLESS VPN'S OWN TRANSPORT AND NOT THE
    #: PORTAL'S: it is configured independently of the SSL/TLS service profile and is the weaker
    #: of the two in every respect - four values with no tls1-3 at all, against the profile's
    #: tls1-0 through tls1-3, and a schema default of tls1-0 against the profile's tls1-2.
    #: Nullable, because the key is OPTIONAL and nothing measured what an absent floor enforces.
    clientless_vpn_min_version = models.CharField(max_length=16, null=True, blank=True)

    #: Whether that branch carries a min-version AT ALL, as against a branch that exists and
    #: leaves the floor unwritten. It exists because a NULL matches no comparison, so the clause
    #: `min_version is not tls1-2` passes a portal that never wrote one - this column is what a
    #: control clauses on instead. Default False, which is the side that reports.
    clientless_vpn_floor_known = models.BooleanField(default=False)

    #: The strongest version those sessions may negotiate, carried for a reader rather than for
    #: a finding: nothing asserts a ceiling, and its top token `max` resolves to nothing this
    #: project has established - the enum it sits in stops at tls1-2, so it is either that or
    #: "whatever the build's highest is", and those differ the day a build adds one.
    clientless_vpn_max_version = models.CharField(max_length=16, null=True, blank=True)

    #: How many client-authentication rows this portal holds. ZERO IS A LEGAL COMMITTED STATE
    #: and it is weaker than every rank PAN-GPP-002 grades - a portal with an empty
    #: authentication table demands nothing at all. Carried here and claused by nothing: a
    #: control's queries all compile against ONE model, and that control's finding names a row.
    client_auth_row_count = models.PositiveIntegerField(default=0)

    #: The ordered agent configuration list as collected, kept so a remediation can name WHICH
    #: configuration to edit. THE ORDER IS THE SEMANTICS AND A CONSUMER THAT SORTS DESTROYS IT:
    #: the collection is a flat entry list with no priority key, so the order is the DOCUMENT
    #: order and the portal delivers the FIRST match and stops. A finding may not rest on it -
    #: the two posture columns beside it carry the reading.
    agent_configurations = models.JSONField(null=True, blank=True)

    #: What this portal tells an endpoint to do when a new GlobalProtect app version appears,
    #: read off the FIRST agent configuration an endpoint would match. One of the five values
    #: the vendor's dictionary permits, or one of three sentinels for the states a single value
    #: cannot express.
    upgrade_posture = models.CharField(
        max_length=32, choices=UPGRADE_POSTURE_CHOICES,
        default=POSTURE_NO_AGENT_CONFIGURATION)

    #: What this portal permits the app to keep on an endpoint, from that same first matching
    #: configuration. THE HARDENED VALUE DOES NOT BY ITSELF PRODUCE A PROMPT PER CONNECTION:
    #: the authentication-override cookie is a neighbouring node on the same agent configuration
    #: and pre-empts re-entry of credentials. This column is about what is STORED on the
    #: endpoint, which is what the node decides.
    saved_credentials_posture = models.CharField(
        max_length=32, choices=SAVED_CREDENTIALS_CHOICES,
        default=POSTURE_NO_AGENT_CONFIGURATION)

    class Meta:
        ordering = ["appliance__hostname", "vsys_name", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "name"],
                name="integrations_unique_gp_portal_per_scope"),
        ]
        indexes = [
            models.Index(fields=["appliance", "vsys_name"]),
            models.Index(fields=["appliance", "clientless_vpn_state"]),
            models.Index(fields=["management_station"]),
        ]

    @property
    def portal_name(self) -> str:
        """The base's `name`, under the name the spec and the finding use.

        Not only a convenience: the artifact layer resolves a control's tested fields against
        the subject model and accepts a name the model either stores or COMPUTES, so a search
        field named `portal_name` needs an attribute of that name to exist. A second CharField
        holding the same string would be two columns that can disagree.
        """
        return self.name

    def clean(self) -> None:
        super().clean()
        # A portal exists only under a vsys entry. Stated rather than assumed, because the base
        # inherits a `predefined` member this object type has no instance of.
        if self.scope != self.SCOPE_VSYS:
            raise ValidationError("A GlobalProtect portal is always vsys-scoped.")
        # The verdict is derived from the name beside it, so the two cannot be allowed to
        # disagree - the guard `CertificateProfile.checks_revocation` carries.
        if self.tls_profile_binding_missing != (not self.ssl_tls_service_profile):
            raise ValidationError(
                "tls_profile_binding_missing must follow ssl_tls_service_profile.")


class GlobalProtectPortalClientAuthRow(ApplianceScopedObject):
    """One row of one portal's client-authentication table. PAN-GPP-002.

    The table is KEYED BY `os` - `Any`, `Browser` or `Satellite` - so a portal can demand both
    factors of one endpoint class and neither of another. The row's own name is
    OPERATOR-CHOSEN and carries no meaning, measured; it is here because it is what tells two
    rows of one portal apart and what a finding has to print to name the row to edit.

    THE PORTAL IS CARRIED TWICE, as a foreign key and as its name. The FK is the join a reader
    follows; `portal_name` is part of the row's IDENTITY and is what a finding prints, and a
    uniqueness constraint over a nullable FK and a name would not be the identity stage 5
    declared. They are written from one source in one place and cannot diverge.

    `certificate_profile_bound` IS THE OWNING PORTAL'S FACT, carried down onto the row because
    the and/or switch beside it says nothing without it: `yes` means "a password OR a client
    certificate will do", and where no certificate profile is bound there is no second factor
    for the OR to reach.
    """

    DERIVED_FIELDS = (
        "is_missing",
        "portal_name",
        "certificate_profile_bound",
        "admission_demand",
    )

    #: The portal this row sits inside. SET_NULL rather than CASCADE so a row is never silently
    #: deleted by a portal rewrite: the normalizer owns removal, and a dangling row with its
    #: portal name still set is visible where a vanished one is not.
    portal = models.ForeignKey(
        "integrations.GlobalProtectPortal", on_delete=models.SET_NULL,
        related_name="client_auth_rows", null=True, blank=True)

    #: The owning portal's name, from the subtree this row was read at. Part of the identity:
    #: `name` alone is not unique within a vsys, because two portals of one vsys routinely use
    #: the same row name - measured, four portals of vsys4 each carrying a row called `r1`.
    portal_name = models.CharField(max_length=64)

    #: Which class of endpoint this row applies to. The leaf ALSO references a predefined list
    #: of ELEVEN per-platform names, so this column can hold a value the three generic buckets
    #: do not list - which is why no `choices` is declared on it.
    os = models.CharField(max_length=32, blank=True, default="")

    #: The NAME this row binds as its first factor. It may be a PROFILE or a SEQUENCE - two
    #: different objects, both shipped downstream - AND THIS COLUMN CANNOT SAY WHICH. A sequence
    #: is tried member by member until one succeeds, so a portal bound to one whose last member
    #: is the firewall's own local user database accepts a locally held password whenever the
    #: identity service is unreachable. Resolved against the VSYS first, then shared, measured.
    authentication_profile = models.CharField(max_length=64, blank=True, default="")

    #: The device's own key, WITH THE VENDOR'S POLARITY KEPT: `yes` means a password OR a client
    #: certificate will do, which is the PERMISSIVE state, and `no` means both are required,
    #: which is the hardened one. The device's own help strings carry it: no -> "No (User
    #: Credentials AND Client Certificate Required)". A reviewer who clauses `equals yes`
    #: believing they have selected the hardened rows has selected exactly the permissive ones.
    #: Nullable: the key is OPTIONAL on a committed row, measured, and its MEANING is not
    #: measured - the two candidate answers are the two ENDS of PAN-GPP-002's grading, so
    #: materialising either would report a rank nobody read.
    user_credential_or_client_cert_required = models.CharField(
        max_length=8, null=True, blank=True)

    #: Whether the PORTAL this row belongs to binds a certificate profile at all. Default False,
    #: which is both the firing side and the state measured on the estate's one pre-existing
    #: portal.
    certificate_profile_bound = models.BooleanField(default=False)

    #: What this row demands of an endpoint, resolved from the pair above TOGETHER.
    #: THE FAILING CONDITION IS A DISJUNCTION - no profile bound, OR one bound with a permissive
    #: switch - and a clause list is one conjunction with no OR, which is the other reason this
    #: is a column rather than a predicate over the two.
    admission_demand = models.CharField(
        max_length=32, choices=ADMISSION_DEMAND_CHOICES, default=ADMISSION_UNKNOWN)

    class Meta:
        ordering = ["appliance__hostname", "vsys_name", "portal_name", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "portal_name", "name"],
                name="integrations_unique_gp_portal_client_auth_row"),
        ]
        indexes = [
            models.Index(fields=["appliance", "vsys_name", "portal_name"]),
            models.Index(fields=["appliance", "admission_demand"]),
            models.Index(fields=["management_station"]),
        ]

    @property
    def row_name(self) -> str:
        """The base's `name`, under the name the spec uses. See `GlobalProtectPortal.portal_name`."""
        return self.name

    def clean(self) -> None:
        super().clean()
        if self.scope != self.SCOPE_VSYS:
            raise ValidationError("A GlobalProtect portal client-auth row is always vsys-scoped.")
        if not self.portal_name:
            raise ValidationError("A client-auth row must name the portal it was read inside.")


class GlobalProtectEnforcementPoint(ProvenancedMixin, SyncTrackedModel):
    """One virtual system, as a verdict over its GlobalProtect objects AS A WHOLE. PAN-GPP-003, 006.

    THE VSYS IS THE ROW AND NOT THE PORTAL, for the same reason `VsysLogForwarding` is keyed on
    the vsys: the gap these two controls are about is sometimes the ABSENCE of a portal, of a
    posture matcher or of a published application, and nothing that does not exist can carry a
    row. One row per vsys of every appliance collected, including a vsys with no `global-protect`
    node at all - that is a real and graded state, not a row to skip.

    NODE PRESENCE IS THE WRONG TEST AND AN ENTRY COUNT IS THE RIGHT ONE, measured: deleting the
    last entry leaves the container present and empty, deleting the container leaves
    `global-protect` present and empty, and an appliance in this estate carries exactly that -
    `global-protect` -> `global-protect-portal` -> null, committed and undecorated. Every level
    of that residue is truthy under `action=get`, and a staged-and-deleted container parses to a
    dict of @admin/@dirtyId/@time while a committed empty one parses to None, so `if node:`
    gives opposite wrong answers from one test.

    CARRIES NO PER-FIELD PROVENANCE, and that is a real `false` rather than a lapse: every
    column is computed. The limit it leaves is that a control whose finding turned on whether a
    definition was PUSHED could not be written against this subject.
    """

    #: The one scope a row of this model has. Borrowed from `ApplianceScopedObject` rather than
    #: re-spelled, so the token and the choices list cannot drift apart - this model does not
    #: inherit that base, because it has no `name`: a vsys is not a named entry.
    SCOPE_VSYS = ApplianceScopedObject.SCOPE_VSYS

    DERIVED_FIELDS = (
        "is_missing",
        "portal_count",
        "clientless_app_count",
        "clientless_app_group_count",
        "portals_publishing_clientless_apps",
        "hip_objects_testing_client_version",
        "hip_client_version_criteria",
        "clientless_vpn_feature_state",
        "licence_reply_collected",
        "licence_entry_count",
        "globalprotect_portal_licensed",
        "licence_excludes_globalprotect",
    )

    management_station = models.ForeignKey(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="globalprotect_enforcement_points")
    appliance = models.ForeignKey(
        "integrations.Appliance", on_delete=models.CASCADE,
        related_name="globalprotect_enforcement_points")
    appliance_group = models.ForeignKey(
        "integrations.ApplianceGroup", on_delete=models.CASCADE,
        related_name="globalprotect_enforcement_points", null=True, blank=True)
    source_snapshot = models.ForeignKey(
        "integrations.Snapshot", on_delete=models.CASCADE,
        related_name="globalprotect_enforcement_points")

    #: Always `vsys` for the four configuration collections this row is a verdict over. Carried
    #: as a column because stage 5 declares it part of the identity, and because the licence
    #: columns beside it are device-wide and have no scope of their own - the store's enum has no
    #: `device-local` member, so they are reported at the vsys grain or not at all.
    scope = models.CharField(
        max_length=16, choices=ApplianceScopedObject.SCOPE_CHOICES,
        default=ApplianceScopedObject.SCOPE_VSYS)

    #: The vsys's own name, enumerated from the device's own config and never from a list the
    #: collector chooses: a PA-5220 in this estate reports eight firewall-local vsys under
    #: action=show and a ninth under action=get.
    vsys_name = models.CharField(max_length=64)

    #: How many GlobalProtect portals this vsys holds - the test for whether the firewall
    #: terminates a portal here at all. ABSENCE OF A PORTAL IS NOT A PASS AND NOT A FAILURE FOR
    #: MOST OF THIS DOMAIN: for PAN-GPP-005 and 006 it SATISFIES the control, and for
    #: PAN-GPP-001 to 004 it makes the control inapplicable by producing no row at all.
    portal_count = models.PositiveIntegerField(default=0)

    #: How many clientless application definitions this vsys holds - one internal web
    #: application published for browser access.
    clientless_app_count = models.PositiveIntegerField(default=0)

    #: How many clientless application GROUPS it holds. BESIDE THE COUNT ABOVE RATHER THAN
    #: INSTEAD OF IT: the vendor's own sentence names two screens, and for an assertion whose
    #: content is ABSENCE an application reachable only through a group would make the estate
    #: look clean.
    clientless_app_group_count = models.PositiveIntegerField(default=0)

    #: How many portals in this vsys carry a clientless-vpn branch - the portal side of the
    #: feature's presence test.
    portals_publishing_clientless_apps = models.PositiveIntegerField(default=0)

    #: How many HIP objects in this vsys carry a client-version criterion at all - the only
    #: configured mechanism by which this estate could notice an outdated GlobalProtect app.
    #: "BELOW THE DOCUMENTED VERSION FLOOR" IS NOT SOMETHING THIS OBJECT CAN SAY: the matcher
    #: has exactly three children - contains, is, is-not - every one a string match, with no
    #: numeric comparison anywhere beneath it. So this column asks only whether the version is
    #: tested, and a check written to look for a comparison would report the control
    #: unimplementABLE rather than unimplemented.
    hip_objects_testing_client_version = models.PositiveIntegerField(default=0)

    #: The operator and version string of every such criterion, so a remediation can name what
    #: is currently matched. FOR A READER, NOT FOR A FINDING - the count beside it carries the
    #: reading.
    hip_client_version_criteria = models.JSONField(null=True, blank=True)

    #: How much of the Clientless VPN feature is present here. WHAT IS GRADED IS PRESENCE, so
    #: there is no acceptable RANK: the acceptable state is the absence of every rank below it,
    #: which is a shape no single device key holds.
    clientless_vpn_feature_state = models.CharField(
        max_length=16, choices=CLIENTLESS_VPN_FEATURE_STATE_CHOICES, default=FEATURE_UNKNOWN)

    #: Whether the appliance's licence reply was obtained AT ALL, as against an appliance that
    #: answered with an empty list. These two are indistinguishable from the reply - {'licenses':
    #: None} arrives with status=success - so the normalizer has to record that it ASKED.
    licence_reply_collected = models.BooleanField(default=False)

    #: How many licence entries the appliance reported. ZERO DOES NOT MEAN UNLICENSED FOR
    #: GLOBALPROTECT; it means the question has no answer on that appliance yet, which is
    #: exactly why the boolean above exists beside it.
    licence_entry_count = models.PositiveIntegerField(default=0)

    #: Whether a GlobalProtect Portal licence is installed. THE JOIN IS ON A PROSE STRING -
    #: `GlobalProtect Portal` matched against a vendor label that nothing guarantees stable
    #: across releases - which is the whole fragility, and why `unknown` is a member.
    globalprotect_portal_licensed = models.CharField(
        max_length=8, choices=PORTAL_LICENSED_CHOICES, default=LICENSED_UNKNOWN)

    #: Whether this appliance has been ASKED about its licences and answered NO to GlobalProtect.
    #: TRUE ONLY where a POPULATED list carries no GlobalProtect feature; false both where it
    #: does and where the appliance reported nothing.
    #:
    #: THIS IS THE APPLICABILITY TRAP, ON THIS FIELD. An `applies_when` clause reading
    #: "unlicensed, so there was never a choice" SUPPRESSES the control where the answer is no -
    #: and on two appliances of this estate the answer is not no, it is UNKNOWN. So the column is
    #: BUILT to be false on an unknown and the control fires. Do not re-point a clause at
    #: `globalprotect_portal_licensed` to get the same effect: that column's `unknown` and `no`
    #: are both "not yes", and a negated clause over it would suppress on both.
    licence_excludes_globalprotect = models.BooleanField(default=False)

    class Meta:
        ordering = ["appliance__hostname", "vsys_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name"],
                name="integrations_unique_gp_enforcement_point_per_vsys"),
        ]
        indexes = [
            models.Index(fields=["appliance", "vsys_name"]),
            models.Index(fields=["appliance", "clientless_vpn_feature_state"]),
            models.Index(fields=["management_station"]),
        ]

    def __str__(self) -> str:
        return f"{self.appliance} / {self.vsys_name} GlobalProtect"

    def clean(self) -> None:
        super().clean()
        # The two licence verdicts are derived from the same reply, so they cannot disagree:
        # `licence_excludes_globalprotect` is true ONLY on a populated list that lacks the
        # feature, which is the shape the applicability trap above turns on.
        expected = (self.licence_reply_collected
                    and self.licence_entry_count > 0
                    and self.globalprotect_portal_licensed == LICENSED_NO)
        if self.licence_excludes_globalprotect != expected:
            raise ValidationError(
                "licence_excludes_globalprotect must follow the licence reply it came from.")
