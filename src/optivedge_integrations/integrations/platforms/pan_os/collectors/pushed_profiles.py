"""The Panorama-pushed security profiles, read on the FIREWALL from its own pushed tree.

WHY THIS IS NOT COVERED BY `show config pushed-shared-policy`. Two reads claim to answer "what
did Panorama push", and they DISAGREE PER PLATFORM. Measured 2026-10-27 and re-measured
2026-10-29 on both lab PA-VMs: a config get at

    /config/panorama/vsys/entry[@name='<vsys>']/profiles

returns the pushed file-blocking profile `zz_fileblock_shared` and the pushed data-filtering
profile `test_dlp_prof` on every appliance in the lab, while on the PA-5220 pair the
`pushed-shared-policy` op read is 57,809 bytes containing zero occurrences of either name. A
collector resting on the op read alone loses every pushed profile on that platform - and
`test_dlp_prof` is the ONLY data-filtering profile anything in the estate references.

ONE READ AT THE `profiles` PARENT, not one per kind. Measured on both PA-VMs on 2026-10-29: the
parent answers with every pushed profile collection under it - file-blocking, data-filtering,
url-filtering, spyware and the rest - in a single envelope, so a per-kind read would be N
requests for the same bytes. The caller's normalizer picks the kinds it knows.

EVERY ELEMENT ARRIVES DECORATED `@loc`, and @loc is what decides the namespace - never the path
this read used. The path says `vsys`; @loc on the lab's pushed profiles says `shared`, so these
rows land in `panorama_shared`. That is `pushed_entry_scope()`'s job and not this module's.
"""

from __future__ import annotations

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import (
    collect_config_response,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSConfigRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


#: The pushed tree's profile collections for one vsys, read on the firewall. `{vsys}` is
#: substituted by `build_pushed_vsys_profiles_xpath`.
PUSHED_VSYS_PROFILES_XPATH_TEMPLATE = "/config/panorama/vsys/entry[@name='{vsys}']/profiles"


def build_pushed_vsys_profiles_xpath(vsys_name: str) -> str:
    return PUSHED_VSYS_PROFILES_XPATH_TEMPLATE.format(vsys=vsys_name)


def collect_pushed_vsys_profiles(
    session: PANSession,
    *,
    vsys_name: str,
) -> PANOSCollectedResponse:
    """Collect the Panorama-pushed security profiles for one vsys, read on the firewall.

    One get per appliance per vsys. An unmanaged firewall answers with no `panorama` subtree,
    which the normalizer reads as "nothing is pushed" rather than as a failure.
    """
    request = PANOSConfigRequest(
        xpath=build_pushed_vsys_profiles_xpath(vsys_name),
        target=session.target,
        metadata={
            "command_name": "config get panorama vsys profiles",
            "vsys_name": vsys_name,
        },
    )
    return collect_config_response(
        session,
        source_type="config_pushed_vsys_profiles",
        request=request,
    )
