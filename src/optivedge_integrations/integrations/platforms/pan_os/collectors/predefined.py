"""PAN-OS collector for predefined (vendor-shipped) address/URL list catalogs.

`show predefined` is appliance-wide, not vsys-scoped: predefined IP block lists and URL lists
(e.g. panw-known-ip-list, panw-highrisk-ip-list) are baked into the PAN-OS software/content
version, not user-configured, so there is exactly one catalog per appliance regardless of how
many vsys/enforcement points it hosts. This only returns the catalog of list names/descriptions
- not each list's actual member IPs/URLs, which PAN-OS does not expose the same way as
user-defined EDLs (see external_list.py).
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import (
    collect_config_response,
    collect_op_response,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSConfigRequest,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


SHOW_PREDEFINED_IP_BLOCK_LISTS_COMMAND = (
    "<show><predefined><xpath>/predefined/ip-block-list-v2</xpath></predefined></show>"
)
SHOW_PREDEFINED_URL_LISTS_COMMAND = (
    "<show><predefined><xpath>/predefined/url-predefined</xpath></predefined></show>"
)

#: THE URL CATEGORY CATALOGUE, which is NOT the URL LIST catalogue above - the constant beside
#: this one asks `/predefined/url-predefined`, the vendor's shipped URL LISTS, and nothing in
#: this package asked for the categories until PAN-URL-001 needed a denominator.
#:
#: It is the ONLY route to one. Nothing in any configuration view carries the catalogue:
#: measured 2026-10-29 on all four lab appliances, this command answers 90 entries on both
#: PA-VMs (11.2.5 and 11.2.3-h3) and 88 on both PA-5220s (11.1.13-h3), the two the PA-5220s
#: lack being `browser-runtime-attack` and `file-converter`. The difference is confounded
#: between platform, major version and the url-filtering content release, so the count is read
#: per appliance at run time and never written down as a number.
#:
#: WITHOUT IT every per-category verdict on a url-filtering profile reads as the failing side
#: and `category_catalogue_collected` is false on every row, because the profile's PERMIT SET
#: IS NOT IN THE PROFILE: `allow` is what the device omits for a predefined category, so the
#: permitted set is the catalogue minus the restricting lists and there is no catalogue to
#: subtract from.
#:
#: Appliance-wide and not vsys-scoped, like every `show predefined` read - one call per
#: appliance per collection.
#:
#: A SPELLING NOBODY HAS RECONCILED: this module's own docstring says `show predefined`'s
#: children are "application, url-categories, service and so on", while what answers is
#: `/predefined/pan-url-categories`. Both may be valid; only this one is measured.
SHOW_PREDEFINED_URL_CATEGORIES_COMMAND = (
    "<show><predefined><xpath>/predefined/pan-url-categories</xpath></predefined></show>"
)

#: NOT reachable by `show predefined`, despite the two lists above being. Measured 2026-09-02:
#: `show predefined` addresses the content/App-ID catalog - its children are application,
#: url-categories, service and so on - and asking it for /predefined/ssl-tls-service-profile
#: returns "No data found. Verify xpath and retry". The SSL/TLS profile lives in the config
#: tree's predefined branch, which is a different namespace with a similar name, and which
#: `show config merged` also omits. A direct config read is the only route.
PREDEFINED_SSL_TLS_SERVICE_PROFILE_XPATH = "/config/predefined/ssl-tls-service-profile"

#: The certificate a predefined profile points at, needed for the same reason as the profile.
#: Measured 2026-09-02 and not what the name suggests: /config/predefined/certificate's
#: TLSv1.3_Default entry is the DEVICE'S OWN factory certificate, common-name equal to the
#: chassis serial and self-signed. So it is "predefined" as a namespace, not as vendor-shared
#: content - it differs per appliance and must be collected per appliance.
PREDEFINED_CERTIFICATE_XPATH = "/config/predefined/certificate"


def collect_show_predefined_ip_block_lists(session: PANSession) -> PANOSCollectedResponse:
    request = PANOSOperationRequest(
        command_xml=SHOW_PREDEFINED_IP_BLOCK_LISTS_COMMAND,
        target=session.target,
        metadata={"command_name": "show predefined ip-block-list-v2"},
    )
    return collect_op_response(
        session,
        source_type="show_predefined_ip_block_lists",
        request=request,
    )


def collect_show_predefined_url_lists(session: PANSession) -> PANOSCollectedResponse:
    request = PANOSOperationRequest(
        command_xml=SHOW_PREDEFINED_URL_LISTS_COMMAND,
        target=session.target,
        metadata={"command_name": "show predefined url-predefined"},
    )
    return collect_op_response(
        session,
        source_type="show_predefined_url_lists",
        request=request,
    )


def collect_show_predefined_url_categories(session: PANSession) -> PANOSCollectedResponse:
    """The device's own URL category catalog - the denominator PAN-URL-001/002/003 need."""
    request = PANOSOperationRequest(
        command_xml=SHOW_PREDEFINED_URL_CATEGORIES_COMMAND,
        target=session.target,
        metadata={"command_name": "show predefined pan-url-categories"},
    )
    return collect_op_response(
        session,
        source_type="show_predefined_url_categories",
        request=request,
    )


def collect_predefined_ssl_tls_service_profiles(session: PANSession) -> PANOSCollectedResponse:
    """Collect the vendor-shipped SSL/TLS service profiles for one appliance.

    Needed because a predefined definition BEATS a same-named custom one - measured 2026-09-02
    by binding a custom `TLSv1.3_Default` with weaker settings and watching the device keep
    negotiating the predefined profile's TLS 1.3 and serve the predefined certificate. So a
    device bound to a predefined name cannot be assessed from the merged config at all, and
    `TLSv1.3_Default` is the shipped hardened profile an engineer is most likely to bind. The
    correctly configured device is precisely the one that would otherwise be unreadable.
    """
    request = PANOSConfigRequest(
        xpath=PREDEFINED_SSL_TLS_SERVICE_PROFILE_XPATH,
        target=session.target,
        metadata={"command_name": "config get predefined ssl-tls-service-profile"},
    )
    return collect_config_response(
        session,
        source_type="config_predefined_ssl_tls_service_profiles",
        request=request,
    )


def collect_predefined_certificates(session: PANSession) -> PANOSCollectedResponse:
    """Collect the vendor-namespace certificates for one appliance.

    Needed by the certificate-trust control. A device bound to the shipped TLSv1.3_Default
    profile is served TLSv1.3_Default's certificate, which lives here and nowhere else -
    `show config merged` carries shared/certificate but not this. Without it, the profile that
    satisfies the protocol floor is the one whose certificate cannot be assessed.
    """
    request = PANOSConfigRequest(
        xpath=PREDEFINED_CERTIFICATE_XPATH,
        target=session.target,
        metadata={"command_name": "config get predefined certificate"},
    )
    return collect_config_response(
        session,
        source_type="config_predefined_certificates",
        request=request,
    )


#: The vendor-shipped Log Forwarding profiles. The same namespace as the certificates and the
#: SSL/TLS profiles above - the config tree's predefined branch, which `show config merged` does
#: not carry and which `show predefined` does not address - so a direct config read is the only
#: route, and this is a new xpath on an existing pattern rather than a new mechanism.
PREDEFINED_LOG_FORWARDING_PROFILES_XPATH = "/config/predefined/log-settings/profiles"


def collect_predefined_log_forwarding_profiles(session: PANSession) -> PANOSCollectedResponse:
    """Collect the vendor-shipped Log Forwarding profiles for one appliance. PAN-LOG-005.

    Needed because a vsys CAN be covered by a profile nobody configured: `IoT Security Default
    Profile` ships with eight match lists, every one with filter `All Logs` and
    `send-to-panorama` yes, covering traffic, threat, wildfire, url, data, tunnel, auth and
    decryption. Read on all four lab appliances 2026-10-22, identical on each.

    WITHOUT THIS READ THE CONTROL OVER-REPORTS, and over-reporting here means telling an engineer
    that a correctly configured vsys has no log forwarding at all - a high-severity false finding
    on exactly the devices that are fine. `VsysLogForwarding.pushed_profile_sources_collected` is
    what keeps the control silent until this snapshot exists.
    """
    request = PANOSConfigRequest(
        xpath=PREDEFINED_LOG_FORWARDING_PROFILES_XPATH,
        target=session.target,
        metadata={"command_name": "config get predefined log-settings profiles"},
    )
    return collect_config_response(
        session,
        source_type="config_predefined_log_forwarding_profiles",
        request=request,
    )


#: Every predefined profile type in one read - anti-spyware and vulnerability for PAN-SPY-001 and
#: PAN-VLN-001, and antivirus, URL filtering, file blocking and WildFire for the controls after
#: them. About 16 KB on both lab platforms. Like the SSL/TLS profile this is the config tree's
#: predefined branch, which `show config merged` omits.
PREDEFINED_SECURITY_PROFILES_XPATH = "/config/predefined/profiles"


def collect_predefined_security_profiles(session: PANSession) -> PANOSCollectedResponse:
    """Collect the vendor-shipped security profiles - `default` and `strict` - for one appliance.

    Needed because a rule protected only by the shipped `default` profile is the commonest weak
    configuration there is, and that profile exists nowhere in the merged config.
    """
    request = PANOSConfigRequest(
        xpath=PREDEFINED_SECURITY_PROFILES_XPATH,
        target=session.target,
        metadata={"command_name": "config get predefined profiles"},
    )
    return collect_config_response(
        session,
        source_type="config_predefined_security_profiles",
        request=request,
    )


#: The vendor's own SSL decryption exclusion list. PAN-DEC-004's second half.
#:
#: AN OP READ AND NOT A CONFIG ONE, which is the opposite choice from the four `/config/
#: predefined/...` reads above and is measured rather than stylistic. On all four lab appliances,
#: 2026-10-29: `type=config&action=get` at /config/predefined/ssl-exclude-cert answers
#: `{"@total-count": "0", "@count": "0"}` - a well-formed, TRUTHY, EMPTY count envelope - for a
#: list this command returns 330 or 385 entries of, and `action=show` at the same xpath answers
#: `status=error, "No such node"`. So the config read a collector naturally reaches for is
#: silence that looks like data: `if result:` passes and a length check reports zero.
#:
#: This is the SET-DIFFERENCE right-hand side for
#: `SslDecryptionVendorExclusionOptOut.stale_disabled_vendor_exclusion_count`: a switched-off
#: entry the vendor no longer ships is residue that accumulates silently, and without this read
#: that column is zero on every row and the control reports nothing.
SHOW_PREDEFINED_SSL_EXCLUDE_CERT_COMMAND = (
    "<show><predefined><xpath>/predefined/ssl-exclude-cert</xpath></predefined></show>"
)

#: The snapshot source type the normalizer filters on. A constant beside the command because
#: nothing maps a source type to a reader - the normalizer that wants it writes its own
#: `latest_*_snapshot` helper and imports this.
PREDEFINED_SSL_EXCLUDE_CERT_SOURCE_TYPE = "show_predefined_ssl_exclude_cert"


def collect_show_predefined_ssl_exclude_cert(session: PANSession) -> PANOSCollectedResponse:
    """Collect the vendor-shipped SSL decryption exclusion list for one appliance. PAN-DEC-004.

    Appliance-wide, like every other predefined catalog. The count differs by appliance GROUP in
    this estate - 330 on both PA-5220s and 385 on both PA-VMs, measured twice - and nothing here
    can attribute that to a platform, a PAN-OS major version or a content release, because all
    three differ together between the two groups. So it is collected per appliance and never
    carried between them.
    """
    request = PANOSOperationRequest(
        command_xml=SHOW_PREDEFINED_SSL_EXCLUDE_CERT_COMMAND,
        target=session.target,
        metadata={"command_name": "show predefined ssl-exclude-cert"},
    )
    return collect_op_response(
        session,
        source_type=PREDEFINED_SSL_EXCLUDE_CERT_SOURCE_TYPE,
        request=request,
    )


#: The GlobalProtect APP-SETTING DICTIONARY: the value space of every setting a portal's agent
#: configuration can carry. Measured 2026-10-29 through Panorama's target= proxy on all four lab
#: appliances - 89 entries on both PA-5220s (11.1.13-h3) and 98 on both PA-VMs (11.2.3-h3 and
#: 11.2.5), the 89 a strict SUBSET of the 98 and every shared key identical - so it is read PER
#: APPLIANCE and never carried between them.
#:
#: REQUIRED AND LOAD-BEARING, not decoration. The portal stores an app setting as an entry NAME
#: and a MEMBER LIST, and validates neither: an entry named for no real setting was stored
#: without comment and `validate full` said nothing about it. Without this dictionary a reader
#: holds the name and the list and no way to know what either MEANS - no label, no permitted
#: set, no form default, and no way to tell a real setting from a typo. For `client-upgrade`,
#: the one setting a control in this domain asks about, it carries the regex
#: ^(prompt|disabled|manual|transparent|internal)$ and the form default `prompt`.
#:
#: `action=complete` IS NOT A SUBSTITUTE: completion at an ENTRY of this node is refused code=6
#: `Invalid sequence` on both builds while this ordinary config read returns the entry in full.
PREDEFINED_GP_APP_CONFIG_XPATH = "/config/predefined/dynamic-schema/gp-app-config/config"

#: The snapshot source type the normalizer filters on. A constant beside the xpath because
#: nothing maps a source type to a reader - see PREDEFINED_SSL_EXCLUDE_CERT_SOURCE_TYPE.
PREDEFINED_GP_APP_CONFIG_SOURCE_TYPE = "config_predefined_gp_app_config"


def collect_predefined_gp_app_config_dictionary(session: PANSession) -> PANOSCollectedResponse:
    """Collect the vendor's GlobalProtect app-setting dictionary for one appliance. PAN-GPP-003.

    The same mechanism and the same namespace as the predefined certificates and SSL/TLS
    profiles above - the config tree's predefined branch, which `show config merged` does not
    carry - so this is a new xpath on an existing pattern rather than a new mechanism.

    Appliance-wide and read-only; no lease is needed and none is taken.
    """
    request = PANOSConfigRequest(
        xpath=PREDEFINED_GP_APP_CONFIG_XPATH,
        target=session.target,
        metadata={"command_name": "config get predefined gp-app-config dictionary"},
    )
    return collect_config_response(
        session,
        source_type=PREDEFINED_GP_APP_CONFIG_SOURCE_TYPE,
        request=request,
    )


#: The App-ID catalogue, which is what makes "a rule names a function child application rather
#: than the base application" decidable at all. PAN-SAS-003's population.
#:
#: The config tree's predefined branch again, and NOT the namespace `show predefined` addresses -
#: so the same mechanism as the five reads above and a new xpath on an existing pattern.
#:
#: MEASURED COST, 2026-10-29, read read-only on three lab appliances: 3.6 MB and 5,051 entries on
#: the 11.1.13-h3 PA-5220, 7.2 MB and 5,552 on one PA-VM, 7.3 MB and 5,581 on the other, each in
#: about three seconds. Most of that is the inline base64 PNG icon on every entry. That is one
#: 7 MB JSON document in `Snapshot.payload` per appliance per collection - by far the largest read
#: in this package - and the normalizer needs four leaves of it. Recorded here because a reader
#: pricing this read from the entry count alone would be out by an order of magnitude.
#:
#: AND THE COUNT IS NOT STABLE. Stage 3 recorded 5,164 and 5,166 entries, stage 4 recorded 6,005
#: and 5,472, and the three measurements above are none of those: the catalogue arrives with
#: content updates and moves with no configuration change at all. So any count derived from it is
#: a reading of one day's content release, not a property of the estate.
PREDEFINED_APPLICATION_XPATH = "/config/predefined/application"

#: The snapshot source type the normalizer filters on. A constant beside the xpath because
#: nothing maps a source type to a reader - see PREDEFINED_SSL_EXCLUDE_CERT_SOURCE_TYPE.
PREDEFINED_APPLICATION_SOURCE_TYPE = "config_predefined_application"


def collect_predefined_applications(session: PANSession) -> PANOSCollectedResponse:
    """Collect the vendor's App-ID catalog for one appliance. PAN-SAS-003.

    Appliance-wide, like every other predefined catalog, and read-only; no lease is needed and
    none is taken. Per appliance rather than once and reused, because the entry count differs by
    appliance in this estate - 5,051 against 5,552 and 5,581, measured 2026-10-29 - which is the
    content release and not the platform.

    WHAT IT BUYS, and nothing else can: the parent/child relation between App-IDs. Measured at
    this xpath the same day, `dropbox-uploading` and `dropbox-downloading` carry
    `application-container: dropbox` and `use-applications/member: [dropbox-base]` with NO
    `parent-app` leaf, while `dropbox-delete` carries `parent-app: dropbox-base` as well - so
    `parent-app` is present on one function child of three and a derivation resting on it alone
    under-counts silently. Without this read the question has to be answered from the spelling of
    an application's name, which is a heuristic over a vendor catalog.
    """
    request = PANOSConfigRequest(
        xpath=PREDEFINED_APPLICATION_XPATH,
        target=session.target,
        metadata={"command_name": "config get predefined application"},
    )
    return collect_config_response(
        session,
        source_type=PREDEFINED_APPLICATION_SOURCE_TYPE,
        request=request,
    )
