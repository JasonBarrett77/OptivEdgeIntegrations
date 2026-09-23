"""PAN-OS collector for the external dynamic list (EDL) runtime cache.

This module stays PAN-OS-specific and should only own command definitions and collection
behavior for the external-list endpoint family.

`request system external-list show type ip name <value>` is vsys-scoped: verified directly
against a real device that this command requires a prior, separate
`set system setting target-vsys <vsys_name>` op-command on the same connection ("Please ensure
target-vsys is set" per the CLI's own completion hint) - it is not a parameter embedded in the
show command's XML. Also verified: target-vsys is connection-scoped, not account-scoped (a
second, independent SSH session showed `None` after a first had set it to a vsys name). That
means callers MUST issue set_target_vsys() on a session before calling
collect_show_external_list() on that same session, and MUST use a freshly-opened PANSession per
vsys - never reuse one session across two different vsys's EDL collection, and never mix EDL
collection with other collectors on the same session.
"""

from __future__ import annotations

from typing import Any

from optivedge_integrations.integrations.platforms.pan_os.collectors.base import collect_op_response
from optivedge_integrations.integrations.platforms.pan_os.collectors.types import (
    PANOSCollectedResponse,
    PANOSOperationRequest,
)
from optivedge_integrations.integrations.platforms.pan_os.session import PANSession


NUM_RECORDS_PER_PAGE = 10000


def _ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def build_set_target_vsys_command(vsys_name: str) -> str:
    return f"<set><system><setting><target-vsys>{vsys_name}</target-vsys></setting></system></set>"


def build_clear_target_vsys_command() -> str:
    return "<set><system><setting><target-vsys>none</target-vsys></setting></system></set>"


def build_show_external_list_command(
    *,
    name: str,
    anchor: int,
    num_records: int = NUM_RECORDS_PER_PAGE,
) -> str:
    return (
        "<request><system><external-list><show><type><ip>"
        f"<name>{name}</name><anchor>{anchor}</anchor><num-records>{num_records}</num-records>"
        "</ip></type></show></external-list></system></request>"
    )


def members_from_result(result: Any) -> list[str]:
    """The valid member addresses in one `external-list show` result.

    Only `valid-members` is read. The device reports `total-invalid` and `total-ignored`
    separately, and an entry it rejected is not something to resolve a rule against - the
    unreachable EDL on the lab answers `total-valid 0, total-invalid 1` with a cURL error, and
    that must stay empty rather than becoming an interval.
    """
    if not isinstance(result, dict):
        return []
    external_list = result.get("external-list")
    if not isinstance(external_list, dict):
        return []
    valid = external_list.get("valid-members")
    if not isinstance(valid, dict):
        return []
    return [member.strip() for member in _ensure_list(valid.get("member"))
            if isinstance(member, str) and member.strip()]


def set_target_vsys(session: PANSession, *, vsys_name: str) -> None:
    """Switch this connection's operational context to vsys_name.

    Must be called before collect_show_external_list() on the same session. Connection-scoped
    (confirmed against a real device), so this only ever affects calls made on this exact
    PANSession, not the station's API key/account generally.
    """
    session.op(build_set_target_vsys_command(vsys_name), target=session.target)


def clear_target_vsys(session: PANSession) -> None:
    """Reset this connection's target-vsys mode. Not safety-critical (connection-scoped, so a
    fresh session next time starts clean regardless) - cheap hygiene, not required."""
    session.op(build_clear_target_vsys_command(), target=session.target)


def collect_show_external_list(session: PANSession, *, name: str) -> PANOSCollectedResponse:
    """Collect every cached entry for one EDL, walking anchor-based pagination.

    Caller is responsible for having already called set_target_vsys() on this same session -
    this function only issues the "type ip" show command itself, since the vsys-scoping mode
    switch is a connection-level concern that may span several EDL names collected in one pass.

    Aggregates every page into a single PANOSCollectedResponse (one Snapshot per logical
    artifact, matching every other collector in this codebase), walking `anchor` forward until a
    page returns fewer than NUM_RECORDS_PER_PAGE entries.

    MEASURED 2026-09-22 on pan-fw-111, and the assumption this carried until then was wrong.
    A real response is not a list of entries under result["entry"]; it is:

        <result total-count="2776" count="100">
          <external-list>
            <vsys>vsys1</vsys><name>panw-highrisk-ip-list</name>
            <total-valid>2776</total-valid><total-ignored>0</total-ignored>
            <total-invalid>0</total-invalid>
            <valid-members><member>94.156.14.17</member>...</valid-members>

    Reading result["entry"] found nothing, so the loop below saw a zero-length page, stopped
    after one request, and stored an empty list - an EDL with 2,776 entries would have
    normalised to nothing at all, and silently, because an empty EDL is indistinguishable from
    one the device could not fetch.

    `count` versus `total-count` is why the paging matters: a request that does not ask for a
    page size gets 100. This asks for NUM_RECORDS_PER_PAGE and walks anchor forward until a
    short page arrives.
    """
    all_entries: list[str] = []
    anchor = 1
    while True:
        command_xml = build_show_external_list_command(name=name, anchor=anchor)
        request = PANOSOperationRequest(
            command_xml=command_xml,
            target=session.target,
            metadata={
                "command_name": "request system external-list show",
                "name": name,
                "anchor": anchor,
            },
        )
        collected = collect_op_response(session, source_type="show_external_list", request=request)
        response_root = collected.response.get("response", {})
        result = response_root.get("result", {}) if isinstance(response_root, dict) else {}
        page_members = members_from_result(result)
        all_entries.extend(page_members)
        if len(page_members) < NUM_RECORDS_PER_PAGE:
            break
        anchor += len(page_members)

    # Stored in the device's own shape rather than a shape of our own, so the normalizer reads
    # one payload whether it came from here or straight off a device.
    aggregated_response = {
        "response": {
            "@status": "success",
            "result": {
                "external-list": {
                    "name": name,
                    "total-valid": str(len(all_entries)),
                    "valid-members": {"member": all_entries},
                }
            },
        }
    }
    return PANOSCollectedResponse(
        source_type="show_external_list",
        request=PANOSOperationRequest(
            command_xml=build_show_external_list_command(name=name, anchor=1),
            target=session.target,
            metadata={"command_name": "request system external-list show", "name": name},
        ),
        response=aggregated_response,
    )
