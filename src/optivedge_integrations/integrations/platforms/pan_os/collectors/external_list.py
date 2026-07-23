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

    NOTE: the exact shape of a real `request system external-list show` response hasn't been
    verified against a live payload yet (only the command syntax has been confirmed against a
    real device). This assumes entries appear as a list under result["entry"], consistent with
    the xmltodict force_list=("entry", "member") convention already used everywhere in this
    codebase's session/response parsing. Revisit this assumption once a real payload is seen.
    """
    all_entries: list[dict[str, Any]] = []
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
        page_entries = [entry for entry in _ensure_list(result.get("entry")) if isinstance(entry, dict)]
        all_entries.extend(page_entries)
        if len(page_entries) < NUM_RECORDS_PER_PAGE:
            break
        anchor += len(page_entries)

    aggregated_response = {
        "response": {
            "@status": "success",
            "result": {"entry": all_entries},
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
