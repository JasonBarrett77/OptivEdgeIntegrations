"""GlobalProtect models - the `globalprotect-portal` and `globalprotect-gateway` domains.

PAN-GPP-001 to PAN-GPP-006 and PAN-GPG-001 to PAN-GPG-007. Six grains, because six different
things are being asserted and a finding has to be able to name the thing an engineer edits:

    GlobalProtectPortal               one portal entry of one vsys of one appliance
    GlobalProtectPortalClientAuthRow  one row of that portal's client-authentication table
    GlobalProtectEnforcementPoint     one vsys, as a VERDICT over its GlobalProtect objects
    GlobalProtectGateway              one gateway entry of one vsys of one appliance
    GlobalProtectGatewayClientAuth    one row of that gateway's client-authentication table
    GlobalProtectGatewayAgentConfig   one row of that gateway's Agent > Client Settings table

THE PORTAL AND THE GATEWAY ARE SIBLING NODES UNDER ONE `global-protect` CONTAINER and they are
separate classes because they are separate objects an engineer opens on separate screens - but
`client-auth` is a leaf name BOTH of them carry, under different parents, and the two
client-auth classes here are not interchangeable. `GlobalProtectPortalClientAuthRow` reads
`global-protect-portal/entry/portal-config/client-auth`; `GlobalProtectGatewayClientAuth` reads
`global-protect-gateway/entry/client-auth`. Reading one with the other's normalizer returns
nothing and reports no admission path at all.

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

WHAT IS NOT MODELLED HERE, recorded because the absence is deliberate: the portal's satellite
configuration, the clientless application and application-group definitions as objects (only
their COUNTS, on the enforcement point), the login response page's content, the gateway's
`roles` collection and its `ip-pool`/`max-user` networking leaves, the GlobalProtect IPSec app
crypto profile as an object (the gateway stores the bound NAME and the head of the proposal
list it resolves to), and the SSL/TLS service profile and certificate profile either object
binds - those two are other domains' subjects and ship as `SslTlsServiceProfile` and
`CertificateProfile`. A portal's binding is stored here as a NAME and resolving it is a
cross-domain join nothing here makes; a GATEWAY's bindings are resolved onto the gateway row,
because PAN-GPG-001, 002 and 006 each assert something about the thing the name reaches rather
than about the name.
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
        # The host-posture pipeline, added by the `globalprotect-gateway` domain for PAN-GPG-005.
        "hip_object_count",
        "hip_profile_count",
        "rules_referencing_a_hip_profile_count",
        "posture_referenced_in_policy",
        "automatic_quarantine_action_present",
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

    # ----------------------------------------------------------------- host posture
    # PAN-GPG-005's subject, added to THIS class rather than to a second per-vsys model by
    # ruling P374a (OptivEdgeProbe, 2026-10-29): one model per PAN-OS node. The
    # `globalprotect-gateway` stage 5 artifact declares a `GlobalProtectPosturePipeline` with
    # the identity ["appliance", "scope", "vsys_name"] - this class's own constraint, over
    # `profiles/hip-objects`, which `hip_objects_testing_client_version` above already counts a
    # SUBSET of. Two models at one grain over one node is two findings that can disagree about
    # what an absence means, which is what P374a was decided on.

    #: How many HIP objects define a posture criterion of ANY kind on this enforcement point -
    #: the superset of `hip_objects_testing_client_version` above, which counts only the ones
    #: carrying a client-version matcher. Both are kept: PAN-GPP-003 asks whether the app
    #: version is tested and PAN-GPG-005 asks whether posture is defined at all, and a vsys
    #: with posture objects that test everything except the version answers the two opposite
    #: ways.
    #:
    #: ZERO IS THE FIRING SIDE AND ALSO THE REAL STATE of most of this estate, and this column
    #: cannot tell them apart on its own. `posture_referenced_in_policy` below is the verdict a
    #: finding rests on; this count is what a remediation prints.
    hip_object_count = models.PositiveIntegerField(default=0)

    #: How many HIP PROFILES exist here - the layer security policy actually consumes, and NOT
    #: the object layer PAN-GPG-005's own asserted path names. The vendor is explicit that HIP
    #: objects are building blocks for the profiles a policy can use, so a vsys with objects and
    #: no profile enforces nothing while looking configured.
    hip_profile_count = models.PositiveIntegerField(default=0)

    #: How many LOCAL security rules of this vsys match on host posture through `source-hip` or
    #: `destination-hip`, counting only a member that resolves to a HIP profile of this vsys.
    #:
    #: THE THREE BARE KEYWORDS ARE NOT REFERENCES - `any`, `no-hip` and `quarantine`, which
    #: `normalization/device_identification.py::HIP_KEYWORDS` measured at the write path - and
    #: `any` is the commonest member in this estate and constrains nothing. A count of populated
    #: member lists would report the whole lab as matching on posture.
    #:
    #: LOCAL ONLY, and it under-reports on a Panorama-managed estate by exactly the pushed pre-
    #: and post-rulebases. The under-report lands on the firing side of the verdict below, which
    #: is the safe direction; a profile referenced only from the authentication, decryption, QoS
    #: or network-packet-broker rulebase is missed the same way.
    rules_referencing_a_hip_profile_count = models.PositiveIntegerField(default=0)

    #: Whether host posture decides anything at all here - true ONLY where a HIP object exists,
    #: a HIP profile exists, and at least one rule names that profile. The whole apparatus costs
    #: licence, agent and administrative effort and changes no outcome unless a rule references
    #: it, so false is the firing side and the default.
    posture_referenced_in_policy = models.BooleanField(default=False)

    #: Whether any shared HIP Match log setting carries the built-in `quarantine` action - the
    #: one automatic route onto the quarantine list that needs no security policy attached to
    #: it. The vendor's own words: "Unlike a log forwarding profile, you do not need to attach
    #: this log setting to a security policy for it to take effect."
    #:
    #: DEVICE-WIDE CONTENT AT THE VSYS GRAIN, like the licence columns above: the node is
    #: `/config/shared/log-settings/hipmatch`, so one appliance-level cause is replicated onto
    #: every vsys row of that appliance - nine of them on a PA-5220 here. The log-forwarding-
    #: profile route to the same action is NOT read: it lives on a profile that must then be
    #: attached to a rule, so an appliance quarantining that way reads as having no automation.
    automatic_quarantine_action_present = models.BooleanField(default=False)

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
        # The posture verdict is a conjunction over the three counts beside it, so the four
        # cannot be allowed to disagree - the same guard `licence_excludes_globalprotect` above
        # carries, and the reason PAN-GPG-005's finding can print the counts and rest on the
        # boolean without the two contradicting each other.
        posture = (self.hip_object_count > 0
                   and self.hip_profile_count > 0
                   and self.rules_referencing_a_hip_profile_count > 0)
        if self.posture_referenced_in_policy != posture:
            raise ValidationError(
                "posture_referenced_in_policy must follow the three posture counts.")


# ===========================================================================
# The `globalprotect-gateway` domain. PAN-GPG-001 to PAN-GPG-007.
# ===========================================================================

#: The feature string `request license info` reports for the GATEWAY entitlement, lowercased for
#: comparison. A SEPARATE FEATURE from the portal's: 691665AC334B458 names both and a control
#: asserting "a GlobalProtect licence" has to say which. The same prose-label fragility as
#: `GLOBALPROTECT_PORTAL_FEATURE` above - a vendor rename moves a row to `unknown` rather than to
#: `no`, which is the direction that keeps the control reporting.
GLOBALPROTECT_GATEWAY_FEATURE = "globalprotect gateway"

#: The three unit branches a gateway's `login-lifetime` container may carry, and EXACTLY ONE
#: ever exists: writing a second branch REPLACES the first rather than adding to it, measured by
#: stage 4 on four appliances across two models and three PAN-OS builds. A normalizer storing
#: three nullable columns and summing them is wrong in a way nothing catches.
#:
#: The order is the order `common.py::choice_child` tests in, and it does not matter here
#: because the device's own schema permits only one.
LOGIN_LIFETIME_BRANCHES = ("days", "hours", "minutes")

#: How many hours one unit of each branch is worth. The three branches describe ONE range in
#: three units on this leaf - 1-30 days, 2-720 hours and 120-43200 minutes are all 2 to 720
#: hours - so every severity band is reachable through some branch and the only hazard is which
#: branch a reader looks in.
LOGIN_LIFETIME_HOURS_PER_UNIT = {"days": 24, "hours": 1, "minutes": 1 / 60}

#: The three unit branches an agent configuration's `cookie-lifetime` container may carry, with
#: the device's own element names. THERE IS NO WEEKS BRANCH, which the vendor documents twice -
#: a write of `lifetime-in-weeks` is refused - and the MINUTES branch, which the vendor documents
#: nowhere, holds the most compliant value the field can take.
COOKIE_LIFETIME_BRANCHES = (
    "lifetime-in-days", "lifetime-in-hours", "lifetime-in-minutes")

#: Hours per unit for each cookie branch. UNLIKE THE LOGIN LIFETIME these three do NOT describe
#: one range in three units: minutes reach 59, hours reach 72 and days reach 365, all measured by
#: write refusals. So the hours branch alone cannot express a week and the days branch can
#: express most of a year, which is why the conversion exists at all - the control's two worst
#: severity bands are unreachable through the hours leaf the assertion names.
COOKIE_LIFETIME_HOURS_PER_UNIT = {
    "lifetime-in-days": 24, "lifetime-in-hours": 1, "lifetime-in-minutes": 1 / 60}

#: The authentication back ends a GlobalProtect gateway can honour a second factor through, as
#: the element names under an authentication profile's `method`.
#:
#: WHAT A TRUE HERE DOES NOT SAY is that the identity service DEMANDS a second factor. The
#: firewall holds the name of the service and nothing about the policy behind it. The node a
#: reader of the control's own wording would reach for - the profile's `multi-factor-auth` with
#: its `mfa-enable` child - is the one the vendor says is NEVER ENFORCED for GlobalProtect, so a
#: column over it would report a correctly configured RADIUS gateway as failing and an MFA-free
#: RADIUS gateway as passing. Deliberately not modelled.
SECOND_FACTOR_CAPABLE_BACKENDS = frozenset({"radius", "saml-idp"})

#: The encryption proposal a hardened GlobalProtect IPSec crypto profile offers FIRST. The ORDER
#: IS THE SEMANTICS - the vendor states the firewall applies the proposals in the order they are
#: listed - and the query grammar has `includes` and `intersects` over a member list with no way
#: to ask which member comes first, which is why the head of the list is a column.
APP_CRYPTO_PREFERRED_FIRST_ENCRYPTION = "aes-256-gcm"


class GlobalProtectGateway(ApplianceScopedObject):
    """One GlobalProtect gateway entry of one vsys. PAN-GPG-001, 002, 004, 005, 006, 007.

    ONE DIALOG, TWO SUBTREES, AND THE JOIN IS THE ENTRY NAME. Network > GlobalProtect >
    Gateways writes a vsys-scoped entry under `global-protect/global-protect-gateway` AND a
    device-local entry of the SAME NAME under `network/tunnel/global-protect-gateway`. The
    second carries the transport - `ipsec/enable`, `ipsec/ipsec-crypto-profile`,
    `client/exclude-video-traffic/enabled` - and a check that retrieves the gateway entry gets
    the first half and silently misses the second. Stage 4 measured the join: commit job 260
    aborted naming the VSYS ENTRY'S OWN NAME as the thing it could not find in the network
    level, which contradicts the `remote-user-tunnel` leaf stage 2 had named as the only
    candidate. `networking_half_present` is the column that reports an unjoined row, and a row
    whose join failed reports FALSE rather than nothing.

    THE ROW IS STORED AT THE VSYS SCOPE and the device-local half is merged onto it. That is a
    fact a remediation needs rather than a convenience: the two halves can be owned by different
    people, their Panorama wrappers differ - one takes a vsys layer and the other a device layer
    - and a template that pushes one need not push the other. The store's scope enum has no
    `device-local` member, so there is nowhere else to put it.

    `ApplianceScopedObject` is the base because a gateway exists ONLY under a vsys entry:
    stage 4 measured the shared and device-local spellings of the vsys half both answering
    code=6 "Invalid sequence", so `/config/shared/global-protect/global-protect-gateway` - which
    `probe.cli_index` DERIVES from the CLI's set shorthand - is not a position at all. A
    collector carrying that derived path across would read an absence that is a path error and
    report "no gateway" on every appliance in the estate including the ones that have one.

    THE BASE'S `name` IS THE GATEWAY NAME, exposed as `entry_name` below because that is what
    the stage 5 artifact, the finding and the artifact layer call it - the same shape
    `GlobalProtectPortal.portal_name` carries, and for the same reason: a second CharField
    holding the same string would be two columns that can disagree.

    FIVE COLUMNS HERE ARE RESOLVED THROUGH A NAME onto another model's row -
    `bound_tls_min_version`, `tls_profile_resolves_to_an_explicit_floor`,
    `bound_certificate_profile_blocks_unauthenticated_cert`, `bound_app_crypto_first_encryption`
    and `app_crypto_offers_gcm_first`. The query grammar has no edge to walk and no second field
    slot, so the traversal is normalization's work or it is nobody's. Each one's default sits on
    the side that FIRES, so a row nobody has recomputed reports itself.

    WHAT NO ROW OF THIS MODEL CAN SAY: whether the value was PUSHED. Stage 4 measured the
    asymmetry on this very path - `network/interface` carries @ptpl and @src on the same
    appliance where NO element of this object carries either - so the reliable derivation is
    membership of the committed-local config, which costs a read nothing issues today.
    """

    #: Everything the normalizer worked out rather than read. See ProvenancedMixin.DERIVED_FIELDS.
    #: `is_missing` is SyncTrackedModel's and is set by collection rather than by a payload key.
    DERIVED_FIELDS = (
        "is_missing",
        "bound_tls_min_version",
        "tls_profile_resolves_to_an_explicit_floor",
        "networking_half_present",
        "bound_app_crypto_first_encryption",
        "bound_certificate_profile_blocks_unauthenticated_cert",
        "any_client_auth_row_permits_either_or",
        "automatic_quarantine_path_exists",
        "globalprotect_gateway_licensed",
        "licence_state_known",
        "login_lifetime_unit",
        "login_lifetime_as_entered",
        "login_lifetime_hours",
        "inactivity_logout_minutes",
        "login_lifetime_known",
        "inactivity_logout_known",
        "ipsec_enabled_known",
        "client_certificate_is_a_second_factor",
        "app_crypto_offers_gcm_first",
    )

    # ------------------------------------------------- the TLS binding, PAN-GPG-001
    #: The SSL/TLS service profile this gateway binds, as the device spells it - a bare string
    #: naming an entry, not the profile's content.
    #:
    #: MANDATORY AT COMMIT, measured: `validate full` job 259 reported "global-protect-gateway ->
    #: <name> is missing ssl-tls-service-profile". So this CHANGES PAN-GPG-001's shape - a query
    #: written as "the binding is absent or empty" is dead code on every committed gateway in the
    #: estate. The empty string here is evidence about the READ and never about the device.
    ssl_tls_service_profile = models.CharField(max_length=64, blank=True)

    #: The minimum TLS version the bound profile will negotiate, copied onto this row so a
    #: finding about the gateway can print it. Empty where the name resolved to no definition the
    #: collection carries - and the commonest cause measured is that it resolves into
    #: /config/predefined, which no merge view and no superuser view carries. So the most
    #: plausible correctly-configured gateway is the one whose profile a collector cannot find.
    #:
    #: DO NOT COMPARE THIS TOKEN. It holds the DEVICE's spelling, not the catalogue's;
    #: `SslTlsServiceProfile.min_version_rank` is the comparison, and the verdict column below
    #: is what this domain's own assertion rests on.
    bound_tls_min_version = models.CharField(max_length=16, blank=True)

    #: Whether the protocol floor this gateway offers is a choice somebody made - true ONLY where
    #: the bound name resolved to a definition the collection carries AND that definition states
    #: a `protocol-settings/min-version` of its own.
    #:
    #: THREE LIMITS AT ONCE ARE WHY THIS IS A COLUMN: a traversal to another model's row, a
    #: comparison between two columns, and an OR between "the name resolved to nothing" and "the
    #: definition states no floor". False is the firing side and the migration default, so the
    #: window between the migration and the recompute announces itself.
    tls_profile_resolves_to_an_explicit_floor = models.BooleanField(default=False)

    # --------------------------------------------- the networking half, PAN-GPG-006
    #: Whether a same-named entry exists under `network/tunnel/global-protect-gateway`.
    #:
    #: FALSE READS AS "this gateway cannot be committed", which is the harsher side and the right
    #: one while nothing has been joined: an unresolved join means the transport, crypto and
    #: video-exclusion content was never read, so every column resting on the networking half is
    #: reading nothing. MEASURED: three of four lab appliances carry that collection PRESENT AND
    #: EMPTY and the fourth has no `network/tunnel` node at all, so a normalizer must treat the
    #: absent container and the empty one as one state or it reports two different things about
    #: one estate.
    networking_half_present = models.BooleanField(default=False)

    #: The gateway's own `tunnel-mode`, with the VENDOR'S POLARITY and nothing inverted: true
    #: where the gateway builds a tunnel for its endpoints, false where it logs them in and
    #: routes nothing.
    #:
    #: THE DEVICE REFUSES TO COMMIT A GATEWAY THAT OMITS IT - `validate full` job 259,
    #: "global-protect-gateway -> <name> is missing tunnel-mode" - so the failing state a query
    #: looks for is a stored FALSE and never an absence, and a column written as "absent or no"
    #: is half dead code. NULL only where the read did not carry the key at all.
    tunnel_mode = models.BooleanField(null=True)

    #: The networking half's `ipsec/enable`, with the vendor's polarity: true where the gateway
    #: offers IPSec and falls back to SSL, false where every endpoint gets the SSL transport.
    #:
    #: NULL ON AN ABSENT KEY AND THE NULL IS NOT A GUESS. Stage 4 recorded this implicit as
    #: UNMEASURED and declined to licence either reading: the vendor's help string reads like
    #: something a reader turns on, and the sibling pair on this very object type points the
    #: other way - `log-success` renders UNTICKED on a bare gateway and `log-fail` TICKED. A
    #: wrong number here would be worse than no number. `ipsec_enabled_known` beside it is what
    #: keeps a null inside the comparison, because `equals false` matches no null.
    ipsec_enabled = models.BooleanField(null=True)

    #: The GlobalProtect IPSec crypto profile the networking half binds.
    #:
    #: A NAME IN THE `global-protect-app-crypto-profiles` COLLECTION AND NOT IN THE SITE-TO-SITE
    #: `ipsec-crypto-profiles` COLLECTION BESIDE IT. The two hold a same-named `default` and are
    #: different objects; wave 5 measured `action=complete` at this leaf returning the app
    #: collection's single name where the satellite leaf returns the site-to-site collection's
    #: three, which is why `IpsecCryptoProfile` is NOT the join target - see
    #: `models/ipsec.py`'s own note on the same leaf.
    ipsec_crypto_profile_name = models.CharField(max_length=64, null=True, blank=True)

    #: Which encryption proposal the bound app crypto profile offers FIRST, copied onto this row.
    #: The vendor says the order is the order the firewall applies, so the head of the list is
    #: the algorithm most endpoints will negotiate. Empty where the gateway binds no profile or
    #: the name resolves to nothing the collection carries.
    bound_app_crypto_first_encryption = models.CharField(max_length=32, blank=True)

    #: Whether that first proposal is the 256-bit authenticated-encryption one the vendor names
    #: for highest security. A BOOLEAN BESIDE THE VALUE COLUMN BECAUSE THE VALUE CAN BE EMPTY and
    #: `is not aes-256-gcm` over an empty value answers nothing and so reports nothing; a
    #: materialised false turns that silence into a finding. False is also the real state of the
    #: only profile this estate holds.
    app_crypto_offers_gcm_first = models.BooleanField(default=False)

    # ------------------------------------- the second-factor question, PAN-GPG-002
    #: The certificate profile this gateway validates client certificates against - one per
    #: GATEWAY, not one per client-authentication row. NOT mandatory at commit, so an empty value
    #: is a real and common configuration rather than a collection failure.
    certificate_profile_name = models.CharField(max_length=64, null=True, blank=True)

    #: Whether that profile refuses a client certificate not issued to the device presenting it.
    #: FALSE WHERE THE PROFILE DOES NOT REFUSE IT AND FALSE WHERE NO PROFILE IS BOUND AT ALL -
    #: the two are collapsed deliberately, because a clause on the far row's column would drop
    #: every gateway that binds no profile, which is the weakest state there is.
    bound_certificate_profile_blocks_unauthenticated_cert = models.BooleanField(default=False)

    #: Whether ANY client-authentication row of this gateway permits a client certificate
    #: INSTEAD of credentials rather than in addition to them.
    #:
    #: DEFAULT TRUE, WHICH IS THE FIRING SIDE AND THE OPPOSITE OF THE FRAMEWORK'S OWN. An
    #: unrecomputed gateway reports that some path may accept a certificate instead of a
    #: password, which is the claim that has to be disproved rather than assumed. It also counts
    #: a row collected with the key ABSENT as permissive: stage 4 could not settle what an
    #: absence means and the schema default sits on the strict value, so if that is not also the
    #: implicit value then every gateway in an estate is weaker than a query written from the
    #: schema default would report.
    any_client_auth_row_permits_either_or = models.BooleanField(default=True)

    #: Whether a client certificate is a genuine SECOND factor here. True where no client
    #: certificate is in use at all, and true where one is in use AND the bound certificate
    #: profile refuses a certificate not issued to the authenticating device AND no client-auth
    #: row permits a certificate instead of credentials. False in every other case.
    #:
    #: THIS IS THE OR THE QUERY GRAMMAR CANNOT WRITE: the assertion fires when EITHER half
    #: fails, a clause list is one conjunction with no OR, and the applicability - "the gateway
    #: uses client certificates at all" - cannot be carried by an inverted conjunction either,
    #: because an applicability clause inside one fires on the rows it is meant to exclude. The
    #: two inputs stay stored so a finding can still say which half failed.
    #:
    #: "NO CLIENT CERTIFICATES IN USE" MEANS "NAMES NO CERTIFICATE PROFILE", and the error
    #: direction is suppression: there is no key saying a per-platform row ASKS for a
    #: certificate, so a gateway demanding one through a path this model cannot see would be
    #: passed. Recorded here rather than left in the code.
    client_certificate_is_a_second_factor = models.BooleanField(default=False)

    # ----------------------------------------------------- quarantine, PAN-GPG-005
    #: The gateway's own `block-quarantined-devices`, vendor polarity: true where the gateway
    #: refuses a login from a device on the quarantine list, false where the user is notified and
    #: connects anyway. NULL on an absent key, declined rather than guessed - stage 4 recorded
    #: the implicit as unmeasured and the sibling pair on this object points opposite ways.
    block_quarantined_devices = models.BooleanField(null=True)

    #: Whether anything on this appliance puts a failing device on the quarantine list
    #: automatically - true only where a shared HIP Match log setting carries the `quarantine`
    #: action, which is the one route that needs no security rule attached. The content is on
    #: `GlobalProtectEnforcementPoint` and copied here because a query is compiled against
    #: exactly one model with no join the model does not define.
    automatic_quarantine_path_exists = models.BooleanField(default=False)

    #: Whether this appliance's licence list carries an unexpired `GlobalProtect Gateway`
    #: feature - the subscription the vendor requires before any device can be added to the
    #: quarantine list at all.
    #:
    #: DELIBERATELY NOT CLAUSED ON, and the reason is the applicability trap: a clause on a "did
    #: we collect it" column SUPPRESSES the control when the answer is no, where an assertion
    #: clause on the same field would raise it. Two of the four lab appliances answer
    #: `{'licenses': None}`, which is the instrument saying nothing rather than saying
    #: unlicensed. The licence goes into the finding's WORDING instead.
    globalprotect_gateway_licensed = models.BooleanField(default=False)

    #: Whether the licence read answered at all for this appliance, as against answering with no
    #: GlobalProtect entry. The two are different facts and conflating them suppresses a control
    #: on a read that said nothing.
    licence_state_known = models.BooleanField(default=False)

    # ------------------------------------------------ session bounds, PAN-GPG-007
    #: Which unit branch the login lifetime was entered in - `days`, `hours` or `minutes`, from
    #: the role entry that yields the weakest bound. ONE COLUMN PLUS A UNIT IS THE SHAPE THE
    #: DEVICE REALLY HAS, and exactly one of the three branches ever exists.
    login_lifetime_unit = models.CharField(max_length=16, blank=True)

    #: The login lifetime as the administrator actually entered it, in the unit beside it -
    #: carried so a remediation can name the number on the screen rather than a converted one.
    login_lifetime_as_entered = models.PositiveIntegerField(null=True, blank=True)

    #: The WEAKEST login lifetime any of this gateway's role entries imposes, converted to hours
    #: before anything compares it. NULL where no role entry bounds the login at all - which is
    #: the state of every appliance stage 4 measured.
    #:
    #: THE NULL IS NOT A PASS AND IT LOOKS LIKE ONE. `is greater than 24` matches no null, so a
    #: gateway nobody could read passes the threshold in silence; `login_lifetime_known` beside
    #: it is false on exactly those rows and fires on its own. The vendor's documented 30-day
    #: default is NOT materialised here: its own field table on the same page states no default,
    #: and the device stores nothing when nobody sets it.
    login_lifetime_hours = models.PositiveIntegerField(null=True, blank=True)

    #: Whether a login lifetime was read at all, as against being absent on a row nobody could
    #: collect. There is no is-null operator in the query grammar, which is the whole reason this
    #: companion shape exists rather than being a convenience.
    login_lifetime_known = models.BooleanField(default=False)

    #: The weakest inactivity logout any of this gateway's role entries imposes, in minutes as
    #: the device stores it. NULL where no role entry sets one.
    #:
    #: ZERO IS NOT A SENTINEL ON THIS FIELD, and it is worth saying because the same spelling
    #: means UNLIMITED on other PAN-OS timeout leaves - the opposite end of the range from where
    #: a reader would put it. Stage 4 measured 0 REFUSED at the write ("should be equal to or
    #: between 5 and 43200"), so no stored row can hold it. The vendor's documented 180-minute
    #: default is not materialised either: it would already MEET this control, so materialising
    #: it would turn silence into a pass with a citation attached.
    inactivity_logout_minutes = models.PositiveIntegerField(null=True, blank=True)

    #: Whether an inactivity logout was read at all. Same companion shape, same reason.
    inactivity_logout_known = models.BooleanField(default=False)

    #: Whether the gateway's IPSec transport setting was read at all. Same companion shape: the
    #: networking half is a SEPARATE subtree at a different scope, so it is the half most likely
    #: to be missing while the gateway row itself exists.
    ipsec_enabled_known = models.BooleanField(default=False)

    # ------------------------------------------------- split tunnelling, PAN-GPG-004
    #: The networking half's `client/exclude-video-traffic/enabled`, vendor polarity: true where
    #: this gateway sends video traffic outside the tunnel for every endpoint it serves.
    #:
    #: PAN-GPG-004's FOURTH EXCLUSION AXIS AND THE ONLY ONE OUTSIDE THE SPLIT-TUNNEL CONTAINER,
    #: and it is GATEWAY-level where the other axes are per client-settings row - so the agent
    #: configuration's egress count has to reach across to this column. NULL on an absent key,
    #: declined: the entry could never be committed on the measured appliance and no rendering
    #: was reachable, so the reading stops at "the key is absent".
    video_traffic_excluded = models.BooleanField(null=True)

    class Meta:
        ordering = ["appliance__hostname", "vsys_name", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "name"],
                name="integrations_unique_gp_gateway_per_scope"),
        ]
        indexes = [
            models.Index(fields=["appliance", "vsys_name"]),
            models.Index(fields=["appliance", "tunnel_mode"]),
            models.Index(fields=["management_station"]),
        ]

    @property
    def entry_name(self) -> str:
        """The base's `name`, under the name the spec and the finding use.

        Not only a convenience: the artifact layer resolves a control's tested fields against the
        subject model and accepts a name the model either stores or COMPUTES, so a field named
        `entry_name` needs an attribute of that name to exist. A second CharField holding the
        same string would be two columns that can disagree. The same shape
        `GlobalProtectPortal.portal_name` carries.
        """
        return self.name

    def clean(self) -> None:
        super().clean()
        # Measured: the shared and device-local spellings of the vsys half both answer code=6
        # "Invalid sequence", so a gateway is always vsys-scoped. Stated rather than assumed,
        # because the base inherits a `predefined` member this object type has no instance of.
        if self.scope != self.SCOPE_VSYS:
            raise ValidationError("A GlobalProtect gateway is always vsys-scoped.")
        # The verdict is derived from the value column beside it, so the two cannot be allowed
        # to disagree - the guard `SslTlsServiceProfile.allows_sha1` carries.
        expected_gcm = (
            self.bound_app_crypto_first_encryption == APP_CRYPTO_PREFERRED_FIRST_ENCRYPTION)
        if self.app_crypto_offers_gcm_first != expected_gcm:
            raise ValidationError(
                "app_crypto_offers_gcm_first must follow bound_app_crypto_first_encryption.")
        # The two companions answer "was this read at all" about the columns beside them, and a
        # companion that disagrees with its own column is worse than no companion: it is the one
        # thing a reviewer checks instead of the null.
        for flag, value in (("login_lifetime_known", self.login_lifetime_hours),
                            ("inactivity_logout_known", self.inactivity_logout_minutes),
                            ("ipsec_enabled_known", self.ipsec_enabled)):
            if getattr(self, flag) != (value is not None):
                raise ValidationError(f"{flag} must be true exactly where its column is set.")


class GlobalProtectGatewayClientAuth(ApplianceScopedObject):
    """One row of one GlobalProtect gateway's client-authentication table. PAN-GPG-002.

    THE ROW IS THE SUBJECT AND NOT THE GATEWAY, because the commonest real defect on this
    control is PER PLATFORM: a Windows row pointed at a strong identity service and an `Any` row
    pointed at the firewall's own local database. A verdict over the rows would report one weak
    gateway without saying which platform to fix.

    NOT THE PORTAL'S CLIENT-AUTH TABLE. `client-auth` is a leaf name both objects carry, under
    different parents - see this module's docstring. `GlobalProtectPortalClientAuthRow` is the
    other one and the two normalizers are not interchangeable.

    THE ROW'S OWN NAME IS NOT THE OPERATING SYSTEM. `os` is a separate mandatory key and the
    entry name is free text, so a finding printing only the entry name tells a reader nothing
    about which platform it is about - which is why `client_os` is stored beside it.
    """

    #: See ProvenancedMixin.DERIVED_FIELDS. `authentication_backend_method` is RESOLVED through
    #: the row's own `authentication-profile` name onto another model's row, so it has no payload
    #: key of its own and can never carry a provenance row.
    DERIVED_FIELDS = (
        "is_missing",
        "gateway_name",
        "authentication_backend_method",
        "backend_can_deliver_a_second_factor",
    )

    #: The gateway this row was read inside. Plumbing rather than a declared column: the identity
    #: below is the name pair, and this FK is what lets a finding reach the gateway's own
    #: verdicts without a second lookup.
    gateway = models.ForeignKey(
        "integrations.GlobalProtectGateway", on_delete=models.CASCADE,
        related_name="client_auth_rows", null=True, blank=True)

    #: The parent gateway entry's own name, from the xpath this row was read at - a path element
    #: and not a key on this row, so a predicate has no edge to walk up a subtree for it. It is
    #: also the join to the networking half of that gateway.
    gateway_name = models.CharField(max_length=64)

    #: Which client platform this row applies to, from the device's own eleven-value set. `Any`
    #: IS A VALUE AND NOT A WILDCARD the store invents, and @default='yes' arrives on it without
    #: being an implicit value - the key is mandatory, so the field has no absent state for a
    #: default to describe. `X-Auth` is the third-party extended-authentication platform
    #: PAN-GPG-002's own applicability excludes.
    client_os = models.CharField(max_length=16, blank=True)

    #: The name this row points at for authentication - which may be an authentication PROFILE
    #: or an authentication SEQUENCE, because the leaf accepts both kinds and the stored string
    #: does not say which.
    #:
    #: THAT IS THE TRAP ON THIS COLUMN: a check resolving the name only among profiles finds
    #: NOTHING on a gateway naming a sequence and reports no identity service at all. Mandatory
    #: at commit, measured - "client-auth -> <row> is missing authentication-profile" - so this
    #: control's first half is never about an absent binding.
    authentication_profile_name = models.CharField(max_length=64, blank=True)

    #: The row's own `user-credential-or-client-cert-required` WITH THE VENDOR'S POLARITY and
    #: nothing inverted: TRUE means credentials OR a client certificate will do, which is the
    #: PERMISSIVE state, and FALSE means both are required, which is the hardened one.
    #:
    #: THE KEY IS NAMED AFTER THE PERMISSIVE SETTING, so a reader who fills a column called
    #: `certificate_required` from it stores the opposite of the truth. The polarity is kept here
    #: so the inversion has to be faced in a clause a reviewer reads rather than in a normalizer
    #: nobody looks at again. The device's own value descriptions, measured on three builds, are
    #: "No (User Credentials AND Client Certificate Required)" and "Yes (User Credentials OR
    #: Client Certificate Required)".
    #:
    #: NULL ON AN ABSENT KEY. The schema's @default='yes' sits on the value `no`, which IS the
    #: hardened state and this control's preferred value - so if the schema default is also the
    #: implicit value an unset row is compliant, and if it is not, every gateway in an estate is
    #: weaker than a query written from the schema default would report. Stage 4 declined to
    #: settle it and so does this.
    user_credential_or_client_cert_required = models.BooleanField(null=True)

    #: Which back end the thing this row names actually authenticates against - the element NAME
    #: under the profile's `method`, which is how the device models the choice. Empty where the
    #: name resolved to nothing the collection carries, WHICH INCLUDES EVERY ROW NAMING AN
    #: AUTHENTICATION SEQUENCE: a sequence can fall back to the firewall's own local database,
    #: and an unresolved back end reported as compliant would pass exactly that.
    #:
    #: `method` IS MODELLED AS WHICH CHILD EXISTS AND NOT AS TEXT on the device - an empty method
    #: is `{'none': None}` - so even reading the far side is a shape question.
    authentication_backend_method = models.CharField(max_length=16, blank=True)

    #: Whether the resolved back end is one the vendor says a GlobalProtect gateway can honour a
    #: second factor through at all. SET MEMBERSHIP OVER TWO VALUES, which the grammar cannot
    #: write: it has no `in` operator and a clause list is one conjunction, so two clauses would
    #: mean "the method is radius AND the method is saml-idp" and match nothing. False where the
    #: name resolved to nothing, which is the firing side.
    backend_can_deliver_a_second_factor = models.BooleanField(default=False)

    class Meta:
        ordering = ["appliance__hostname", "vsys_name", "gateway_name", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "gateway_name", "name"],
                name="integrations_unique_gp_gateway_client_auth_row"),
        ]
        indexes = [
            models.Index(fields=["appliance", "vsys_name", "gateway_name"]),
            models.Index(fields=["appliance", "client_os"]),
            models.Index(fields=["management_station"]),
        ]

    @property
    def entry_name(self) -> str:
        """The base's `name`, under the name the spec uses. See `GlobalProtectGateway.entry_name`."""
        return self.name

    def clean(self) -> None:
        super().clean()
        if self.scope != self.SCOPE_VSYS:
            raise ValidationError(
                "A GlobalProtect gateway client-auth row is always vsys-scoped.")
        if not self.gateway_name:
            raise ValidationError("A client-auth row must name the gateway it was read inside.")
        # The verdict is set membership over the column beside it, so they cannot disagree.
        expected = self.authentication_backend_method in SECOND_FACTOR_CAPABLE_BACKENDS
        if self.backend_can_deliver_a_second_factor != expected:
            raise ValidationError(
                "backend_can_deliver_a_second_factor must follow "
                "authentication_backend_method.")


class GlobalProtectGatewayAgentConfig(ApplianceScopedObject):
    """One agent client-settings row of one GlobalProtect gateway. PAN-GPG-003, PAN-GPG-004.

    The row an engineer opens at Agent > Client Settings to change a cookie lifetime or a
    split-tunnel inventory. It is the row a finding names because every remediation on this
    ground is a change to one of these rows - and because ABSENCE HERE IS THE SAFE DIRECTION: a
    gateway with no settings row accepts no cookie and excludes nothing, so there is no failing
    state with no row in it. Stage 4 measured that this entry has NO mandatory key at all, so a
    row carrying nothing but its name is legal and `validate full` accepts it.

    TWO COLUMNS ON THIS MODEL SUPPRESS RATHER THAN FIRE WHEN NOBODY HAS RECOMPUTED THEM, and
    that is stated rather than hidden: `accept_cookie_configured` and
    `authentication_override_configured` are APPLICABILITY inputs whose false is also the
    measured truth of every appliance in this lab, and `uninspected_egress_path_count` defaults
    to the zero a correctly configured full tunnel really holds. The migration owes the recompute
    before any finding is generated; `egress_inventory_computed` is what reports the window on
    the count.

    THE SIX SPLIT-TUNNEL COLUMNS ARE JSON AND NOTHING MAY CLAUSE ON THEM. A finding must rest on
    a column and not on a key inside a blob, and the consumer has a test that compiles every
    registered field to assert no JSON column is reachable from a query. They are stored for a
    reader; the count beside them is what a finding reads.
    """

    #: See ProvenancedMixin.DERIVED_FIELDS. The three container-presence columns have no payload
    #: key of their own - the posture is expressed by WHICH CHILDREN EXIST - and the count is an
    #: aggregate over eight axes, one of them on another model.
    DERIVED_FIELDS = (
        "is_missing",
        "gateway_name",
        "accept_cookie_configured",
        "authentication_override_configured",
        "cookie_lifetime_unit",
        "cookie_lifetime_as_entered",
        "cookie_lifetime_hours",
        "cookie_lifetime_known",
        "uninspected_egress_path_count",
        "egress_inventory_computed",
    )

    #: The gateway this row was read inside. Plumbing, as on the client-auth row.
    gateway = models.ForeignKey(
        "integrations.GlobalProtectGateway", on_delete=models.CASCADE,
        related_name="agent_configs", null=True, blank=True)

    #: The parent gateway entry's own name, from the xpath this row was read at.
    gateway_name = models.CharField(max_length=64)

    # --------------------------------------- authentication override, PAN-GPG-003
    #: The row's own `authentication-override/generate-cookie`, vendor polarity: true where this
    #: gateway ISSUES an authentication-override cookie to its endpoints.
    #:
    #: GENERATING AND ACCEPTING ARE DIFFERENT SETTINGS AND THE VENDOR SPLITS THEM ACROSS TWO
    #: DEVICES ON PURPOSE: the recommended two-factor arrangement generates the cookie on the
    #: PORTAL and accepts it on the gateway, so a gateway that generates none can still accept
    #: one. NULL on an absent key - reasoning from the control's wording is not a measurement.
    generate_cookie = models.BooleanField(null=True)

    #: Whether this row accepts a reconnection cookie at all - true where the
    #: `authentication-override/accept-cookie` subtree exists, which is the only thing that
    #: decides it. WHICH CHILDREN EXIST AND NOT ANY VALUE, so no measured column could point at
    #: a key: stage 4's field record has no entry for `accept-cookie` itself, only for the
    #: lifetime container beneath it.
    accept_cookie_configured = models.BooleanField(default=False)

    #: Whether this row uses authentication override AT ALL - true where the
    #: `authentication-override` subtree exists, whether it generates a cookie, accepts one, or
    #: both.
    #:
    #: A SECOND COLUMN BESIDE `accept_cookie_configured` RATHER THAN THE SAME ONE, because the
    #: cookie's LIFETIME only matters where the gateway ACCEPTS a cookie while the cookie's
    #: CERTIFICATE matters where it generates one too: stage 4 measured
    #: `cookie-encrypt-decrypt-cert` as a SIBLING of `accept-cookie` rather than a child, so one
    #: certificate serves both sides.
    authentication_override_configured = models.BooleanField(default=False)

    #: Which unit branch this row's cookie lifetime was entered in, as the device's own element
    #: name. EXACTLY THREE CHILDREN ON ALL FOUR APPLIANCES, and writing a second REPLACES the
    #: first - so a normalizer storing three nullable columns and summing them is wrong in a way
    #: nothing will catch.
    #:
    #: 24 AND NOT THE 16 STAGE 5 DECLARED, which is the one place this domain departs from a
    #: declared stored type. Stage 5's own MEASURED value set for this column is
    #: `lifetime-in-minutes`, `lifetime-in-hours` and `lifetime-in-days` - 19, 17 and 16
    #: characters - so a 16-character column truncates two of the three values it is declared to
    #: hold, silently, and `lifetime-in-minutes` becomes `lifetime-in-minu`. The truncation runs
    #: in the direction that matters: the minutes branch is the one holding the most compliant
    #: value the field can take, so a remediation would name a unit that does not exist. Caught
    #: by this domain's own tests, not by a gate.
    cookie_lifetime_unit = models.CharField(max_length=24, blank=True)

    #: The cookie lifetime as the administrator actually entered it, in the unit beside it.
    cookie_lifetime_as_entered = models.PositiveIntegerField(null=True, blank=True)

    #: How long this row will accept a reconnection cookie for, converted to HOURS before
    #: anything compares it - which is the only form in which this control's own severity bands
    #: can be applied at all. The asserted hours leaf caps at 72, so no value of it reaches the
    #: 169-hour band, while a lifetime set in days reaches 365 and reads ABSENT on that leaf.
    #:
    #: NULL WHERE NO BRANCH HELD A LIFETIME, and the null looks like a pass: `is greater than 24`
    #: matches no null. The applicability clause keeps rows accepting NO cookie out of the
    #: comparison; what it cannot keep out is a row that accepts one and bounds nothing, which is
    #: what `cookie_lifetime_known` is for.
    cookie_lifetime_hours = models.PositiveIntegerField(null=True, blank=True)

    #: Whether a cookie lifetime was read at all. Same companion shape as the gateway's two.
    cookie_lifetime_known = models.BooleanField(default=False)

    #: The certificate that encrypts and decrypts this row's reconnection cookie, as the device
    #: spells it.
    #:
    #: EMPTY MEANS NOTHING IS BOUND AND THAT IS A MEASURED VENDOR FACT rather than a gap in
    #: collection - measured 2026-10-26 on a PA-VM at 11.2.5 by config silence in candidate and
    #: running on an entry built to carry no child key at all, with the positive control paid on
    #: the REFERENCE POOL: completion at the leaf returns the appliance's certificate collection,
    #: so the leaf is a live reference and not an inert string. A CONSUMER MUST NOT RENDER THIS
    #: NULL AS "NOT COLLECTED". Whoever can forge or decrypt the cookie reconnects as any user of
    #: this gateway without authenticating and leaves nothing behind.
    cookie_encrypt_decrypt_cert = models.CharField(max_length=64, null=True, blank=True)

    # ----------------------------------------- the egress inventory, PAN-GPG-004
    #: The row's own `no-direct-access-to-local-network` WITH THE VENDOR'S POLARITY and nothing
    #: inverted: TRUE means direct access to the endpoint's own attached network is CLOSED, which
    #: is the hardened state. The key is named after what it FORBIDS, so a column called
    #: `local_network_access` filled from it would report every hardened gateway as permissive.
    #:
    #: NULL on an absent key, declined: the key's name is the negation of what it permits, so
    #: absent most likely means direct access IS allowed - the weaker state - but that is a
    #: reading of a name rather than a measurement.
    no_direct_access_to_local_network = models.BooleanField(null=True)

    #: Destinations this row sends OUTSIDE the tunnel by route - a member list mixing literal
    #: CIDR prefixes and address object names in ONE list. A query resolving every member as an
    #: address object name drops the literal prefixes silently, and one parsing every member as
    #: CIDR drops the names; both were accepted in one write and read back side by side.
    split_tunnel_exclude_access_routes = models.JSONField(null=True, blank=True)

    #: Destinations this row routes INTO the tunnel by route - which creates a split tunnel too,
    #: because a short include list sends everything else outside. THIS IS WHY THE ASSERTION IS
    #: ABOUT EVERY PATH rather than about how many exclusions there are: a gateway with zero
    #: exclusions and a narrow include list is a split tunnel an exclusion-only read calls full.
    split_tunnel_include_access_routes = models.JSONField(null=True, blank=True)

    #: Client applications this row sends outside the tunnel - free member strings the vendor
    #: describes as endpoint file paths.
    split_tunnel_exclude_applications = models.JSONField(null=True, blank=True)

    #: Client applications this row routes into the tunnel, where the literal `any` is an
    #: accepted member - measured at the write and stored verbatim.
    split_tunnel_include_applications = models.JSONField(null=True, blank=True)

    #: Domains this row sends outside the tunnel. AN ENTRY COLLECTION AND NOT A MEMBER LIST: the
    #: shape is list/entry[@name] with an optional `ports` key, so a normalizer written for a
    #: member list loses every port restriction and one written for a scalar loses the whole
    #: thing. Stored as the entry list so neither is lost.
    split_tunnel_exclude_domains = models.JSONField(null=True, blank=True)

    #: Domains this row routes into the tunnel - the same entry-collection shape as its twin.
    split_tunnel_include_domains = models.JSONField(null=True, blank=True)

    #: How many distinct paths this row leaves the firewall unable to inspect, over all EIGHT
    #: axes - the six split-tunnel lists, the endpoint's own local network, and the gateway's
    #: video exclusion, which is on ANOTHER MODEL at another scope.
    #:
    #: A COUNT COUNTS ROWS AND NOT EXPOSURE, and this column cannot fix that: one exclude member
    #: may be an ADDRESS GROUP, so one counted path can be a thousand subnets. The vendor's own
    #: caps are limits on rows and therefore not a measure of exposure either.
    #:
    #: ZERO IS THE REASSURING SIDE AND IT IS UNAVOIDABLE for a count whose honest empty value is
    #: zero: a row nobody recomputed looks exactly like a full tunnel with nothing excluded.
    #: `egress_inventory_computed` beside it is what closes that window.
    uninspected_egress_path_count = models.PositiveIntegerField(default=0)

    #: Whether the uninspected-egress inventory was computed at all, as against being zero on a
    #: row nobody could collect. A threshold comparison cannot tell those apart and there is no
    #: is-null operator to ask with.
    egress_inventory_computed = models.BooleanField(default=False)

    class Meta:
        ordering = ["appliance__hostname", "vsys_name", "gateway_name", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "gateway_name", "name"],
                name="integrations_unique_gp_gateway_agent_config"),
        ]
        indexes = [
            models.Index(fields=["appliance", "vsys_name", "gateway_name"]),
            models.Index(fields=["appliance", "uninspected_egress_path_count"]),
            models.Index(fields=["management_station"]),
        ]

    @property
    def entry_name(self) -> str:
        """The base's `name`, under the name the spec uses. See `GlobalProtectGateway.entry_name`."""
        return self.name

    def clean(self) -> None:
        super().clean()
        if self.scope != self.SCOPE_VSYS:
            raise ValidationError(
                "A GlobalProtect gateway agent configuration is always vsys-scoped.")
        if not self.gateway_name:
            raise ValidationError(
                "An agent configuration must name the gateway it was read inside.")
        # The companion answers "was this read at all" about the column beside it.
        if self.cookie_lifetime_known != (self.cookie_lifetime_hours is not None):
            raise ValidationError(
                "cookie_lifetime_known must be true exactly where cookie_lifetime_hours is set.")
        # A column derived from a JSON field gets a guard asserting the two agree - CLAUDE.md,
        # and the reason is that the count is what a finding reads while the lists are what a
        # reader sees. Only the SIX JSON axes are checked here: the other two inputs are a
        # boolean on this row and one on the gateway, and the gateway's is not reachable from a
        # `clean()` that may run before the parent row exists.
        json_axes = sum(1 for value in (
            self.split_tunnel_exclude_access_routes,
            self.split_tunnel_include_access_routes,
            self.split_tunnel_exclude_applications,
            self.split_tunnel_include_applications,
            self.split_tunnel_exclude_domains,
            self.split_tunnel_include_domains,
        ) if value)
        if self.uninspected_egress_path_count < json_axes:
            raise ValidationError(
                "uninspected_egress_path_count cannot be lower than the number of populated "
                "split-tunnel lists it counts.")
