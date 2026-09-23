"""Build the collection package a consultant sends to a customer.

Three files go out: the PowerShell script, the `.cmd` that launches it past the execution
policy, and the instructions. They are read from this package rather than written here, so
what ships is the file that was tested - `ScriptedCollectionScriptTests` checks the same one
against the collector command set.

**CRLF is preserved deliberately.** The files are stored with Windows line endings (see the
`.gitattributes` beside them) and are read and written as BYTES here: a `.cmd` with bare LF
endings misbehaves under cmd.exe, and Python's text mode would silently rewrite them.

Substitution is by token rather than by template engine, so the source file is itself a
valid, runnable script. `__OPTIVEDGE_CLIENT_NAME__` left in place is what the script tests
for when deciding whether to name a client at all.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path

#: The directory a customer sees after extracting, so files do not scatter into their
#: Downloads folder.
BUNDLE_FOLDER = "OptivEdge-Collection"

SCRIPT_NAME = "Collect-OptivEdgeConfiguration.ps1"
LAUNCHER_NAME = "Collect-OptivEdgeConfiguration.cmd"
INSTRUCTIONS_NAME = "Instructions.txt"

CLIENT_NAME_TOKEN = "__OPTIVEDGE_CLIENT_NAME__"
GENERATED_ON_TOKEN = "__OPTIVEDGE_GENERATED_ON__"

_PACKAGE_DIR = Path(__file__).resolve().parent

#: A single quote would end the PowerShell string the token sits inside. Doubling it is how
#: PowerShell escapes one, so a client named "O'Brien Industries" produces a script that runs
#: rather than one that fails to parse.
def _powershell_literal(value: str) -> str:
    return value.replace("'", "''")


def _slug(value: str) -> str:
    """A file-name-safe form of the client name, for the download."""
    slug = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-")
    return slug or "client"


@dataclass(frozen=True)
class CollectionPackage:
    file_name: str
    content: bytes

    @property
    def size(self) -> int:
        return len(self.content)


def read_source(name: str) -> bytes:
    return (_PACKAGE_DIR / name).read_bytes()


def render_script(client_name: str, generated_on: date) -> bytes:
    script = read_source(SCRIPT_NAME).decode("utf-8")
    script = script.replace(CLIENT_NAME_TOKEN, _powershell_literal(client_name))
    script = script.replace(GENERATED_ON_TOKEN, generated_on.isoformat())
    return script.encode("utf-8")


def render_instructions(client_name: str, generated_on: date) -> bytes:
    """The instructions with a header naming who they were prepared for.

    Prepended rather than substituted: the source file is prose a person edits, and a token
    sitting in the middle of it would be one more thing to preserve by hand.
    """
    header = (
        f"Prepared for {client_name}\r\n"
        f"Generated {generated_on.isoformat()}\r\n"
        "\r\n"
    )
    return header.encode("utf-8") + read_source(INSTRUCTIONS_NAME)


def build_collection_package(
    client_name: str,
    *,
    generated_on: date | None = None,
) -> CollectionPackage:
    """The .zip to send, and the name to send it under."""
    client_name = (client_name or "").strip()
    if not client_name:
        raise ValueError("A client name is required so the customer can see who asked.")
    generated_on = generated_on or date.today()

    members = {
        SCRIPT_NAME: render_script(client_name, generated_on),
        LAUNCHER_NAME: read_source(LAUNCHER_NAME),
        INSTRUCTIONS_NAME: render_instructions(client_name, generated_on),
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            # A fixed timestamp would be tidier but lies about when this was produced; the
            # customer reading file dates should see the day it was generated for them.
            info = zipfile.ZipInfo(
                f"{BUNDLE_FOLDER}/{name}",
                date_time=(generated_on.year, generated_on.month, generated_on.day, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, content)

    file_name = f"OptivEdge-Collection-{_slug(client_name)}-{generated_on.isoformat()}.zip"
    return CollectionPackage(file_name=file_name, content=buffer.getvalue())
