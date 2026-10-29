"""The appliance's certificate-hygiene settings - PAN-CRT-001's second half.

One leaf today, `deviceconfig/setting/management/enable-certificate-expiration-check`, and a
row for every appliance whether the leaf is there or not: the key is ABSENT on all four lab
appliances, so the commonest state - and the failing one - is the one with nothing to read. The
model docstring carries why this is its own model rather than a column on the neighbour that
already walks the same node.

The read is `show config merged`, which is issued on every appliance already. Nothing new is
asked of any device.
"""

from __future__ import annotations

from django.db import transaction

from optivedge_integrations.integrations.models import Appliance, CertificateSettings
from optivedge_integrations.integrations.platforms.pan_os.normalization.common import (
    Implicit, parse_yes_no_field)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_configuration import (
    latest_merged_snapshot, management_node)
from optivedge_integrations.integrations.platforms.pan_os.normalization.services_settings import (
    write_node_row)

#: Measured 2026-10-25 on pan-fw-201 (PA-VM 11.2.5), and the default FIRES, which is the right
#: side: an absent key means the firewall does NOT check its certificates' expiry.
#:
#: The project's earlier records carried stage 2's verb verbatim - "no implicit value
#: [implicit_needs_ui_toggle]", so nothing in any corpus said what an absent key meant. The
#: measurement that settled it: the General Settings checkbox renders UNTICKED on an appliance
#: where the key is absent from the configuration in candidate, running and `show config
#: running` on all FOUR appliances; the key is absent by construction on all four, which is a
#: natural experiment needing no write; and the positive control was paid ON THE ELEMENT -
#: written to `yes`, committed in job 149, the SAME panel re-read in the SAME browser session
#: showed the box TICKED, then deleted and committed in job 150 with the path returning to its
#: first reading. The reading was taken from the SCREENSHOT as well as the DOM, because this
#: panel's booleans carry their state in a CSS class and innerText is empty for a ticked and an
#: unticked box alike.
EXPIRY_CHECK_IMPLICIT = Implicit.measured(
    False,
    "payload contract, mgmt-settings.enable-certificate-expiration-check: implicit 'no' - the "
    "General Settings checkbox reads UNTICKED with the key absent in every config view, "
    "measured 2026-10-25 on pan-fw-201 with the positive control paid on the element "
    "(commit jobs 149 and 150)")


def normalize_certificate_settings(appliance: Appliance) -> dict[str, int]:
    snapshot = latest_merged_snapshot(appliance)
    if snapshot is None:
        return {"certificate_settings": 0}
    management = management_node(snapshot)

    enabled, raw_key, raw_value = parse_yes_no_field(
        management.get("enable-certificate-expiration-check"),
        implicit=EXPIRY_CHECK_IMPLICIT)

    with transaction.atomic():
        write_node_row(
            CertificateSettings, appliance, snapshot,
            {"expiry_check_enabled": enabled},
            [("expiry_check_enabled", raw_key, raw_value)])
    return {"certificate_settings": 1}
