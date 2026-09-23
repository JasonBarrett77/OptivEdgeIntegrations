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

#: Hard ceiling on how many members we will keep for ONE list, across all pages.
#: A list longer than this is collected up to the ceiling and recorded as INCOMPLETE - see
#: collect_show_external_list. Deliberately equal to the page size, so the common case is a
#: single request and the ceiling costs nothing.
MAX_MEMBERS_COLLECTED = 10000


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


LIST_TYPE_CUSTOM = "ip"
LIST_TYPE_PREDEFINED = "predefined-ip"


def build_show_external_list_command(
    *,
    name: str,
    anchor: int,
    num_records: int = NUM_RECORDS_PER_PAGE,
    list_type: str = LIST_TYPE_CUSTOM,
) -> str:
    """One page of an EDL's cached content.

    MEASURED 2026-09-22 on pan-fw-111: `type ip` and `type predefined-ip` are strictly
    DISJOINT, and each rejects the other's names outright with api_code=17,
    "<name> is invalid name.Current target-vsys is <vsys>":

        type ip             panw-highrisk-ip-list   FAIL invalid name
        type ip             prod_west_edl           OK   0 valid / 1 invalid
        type predefined-ip  panw-highrisk-ip-list   OK   2,776 valid
        type predefined-ip  panw-known-ip-list      OK   4,000 valid
        type predefined-ip  prod_west_edl           FAIL invalid name

    The error names target-vsys, which reads like a scoping problem and is not one - the
    predefined lists are refused under `target-vsys none` and under `vsys1` alike. Only the
    type is wrong. So the caller must pick the type from the object, not from the vsys.
    """
    return (
        "<request><system><external-list><show><type>"
        f"<{list_type}>"
        f"<name>{name}</name><anchor>{anchor}</anchor><num-records>{num_records}</num-records>"
        f"</{list_type}>"
        "</type></show></external-list></system></request>"
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


def total_valid_from_result(result: Any) -> int | None:
    """How many valid members the DEVICE says the list holds, regardless of how many it sent.

    This is the number a truncated collection is measured against, so it is read from the
    device's own `total-valid` and never inferred from the members in hand.
    """
    if not isinstance(result, dict):
        return None
    external_list = result.get("external-list")
    if not isinstance(external_list, dict):
        return None
    try:
        return int(str(external_list.get("total-valid")).strip())
    except (TypeError, ValueError):
        return None


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


def collect_show_external_list(
    session: PANSession,
    *,
    name: str,
    list_type: str = LIST_TYPE_CUSTOM,
) -> PANOSCollectedResponse:
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

    Paging semantics, all measured 2026-09-22 against panw-known-ip-list (4,000 valid):

      * `num-records` IS the page size and is honoured exactly - ask 3, get 3; ask 100, get
        100. Omit it and the device gives 100, which is why a 2,776-entry list first looked
        like a 100-entry one.
      * Its accepted range is 1 to 4294967295 (`value=0 should be equal to or between 1 and
        4294967295`). Asking for more than the list holds is not an error and is not clamped to
        a page - the whole list comes back. So NUM_RECORDS_PER_PAGE is a ceiling on one
        response's size, not a limit the device imposes.
      * `anchor` is 1-BASED and is an offset into the member list, not a page number:
        anchor=2 returns the list from its second member. So walking it forward by the number
        of members received is right.
      * DO NOT drive the loop from the `count` attribute. Asking past the end
        (anchor=4001 of 4,000) answers `count="100"` with ZERO members - `count` reports what
        was asked for there, not what was sent, so a loop that trusted it would never
        terminate. This counts members.

    Proven live end to end: forced to a 100-member page, this walks anchors 1, 101, ... 3901,
    then 4001 which returns nothing, and returns all 4,000 members with no duplicates and no
    gaps.

    TRUNCATION: at most MAX_MEMBERS_COLLECTED members are kept. A longer list stops there and
    the aggregated payload carries the device's OWN `total-valid` rather than the number
    stored, which is what makes the shortfall visible - downstream, an EDL resolved from a
    truncated collection must not be read as a complete set, or an address in the discarded
    tail looks like an address the list does not contain.
    """
    all_entries: list[str] = []
    reported_total = None
    anchor = 1
    while True:
        command_xml = build_show_external_list_command(name=name, anchor=anchor, list_type=list_type)
        request = PANOSOperationRequest(
            command_xml=command_xml,
            target=session.target,
            metadata={
                "command_name": "request system external-list show",
                "name": name,
                "anchor": anchor,
                "list_type": list_type,
            },
        )
        collected = collect_op_response(session, source_type="show_external_list", request=request)
        response_root = collected.response.get("response", {})
        result = response_root.get("result", {}) if isinstance(response_root, dict) else {}
        if reported_total is None:
            reported_total = total_valid_from_result(result)
        page_members = members_from_result(result)
        all_entries.extend(page_members)
        if len(all_entries) >= MAX_MEMBERS_COLLECTED:
            del all_entries[MAX_MEMBERS_COLLECTED:]
            break
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
                    # The DEVICE's count, not len(all_entries). Overwriting it with what we
                    # kept would erase the only evidence that anything was dropped.
                    "total-valid": str(reported_total if reported_total is not None else len(all_entries)),
                    "valid-members": {"member": all_entries},
                }
            },
        }
    }
    return PANOSCollectedResponse(
        source_type="show_external_list",
        request=PANOSOperationRequest(
            command_xml=build_show_external_list_command(name=name, anchor=1, list_type=list_type),
            target=session.target,
            metadata={
                "command_name": "request system external-list show",
                "name": name,
                "list_type": list_type,
            },
        ),
        response=aggregated_response,
    )
