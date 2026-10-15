"""What a receiver reads from a message (rust/PLAN.md 2.10, 7.4).

The semantic view of a message is what Python's ``email`` parser
(``policy.default``) gets from its bytes: the headers decoded and sorted,
without per-message and structural ones, and the MIME tree with decoded
bodies. The MIME byte form is free (parity contract); two messages that
arrive the same have the same view. Shared by the fixture generator
(``mime.json``), ``check_mime.py`` and the parity harness; standard library
only.
"""

from __future__ import annotations

import base64
import email
import email.header
import email.policy
import json
import re
from email.message import EmailMessage
from typing import Any

# Headers the semantic view leaves out: per-message values (Message-Id is
# checked against the response id, Date for presence) and MIME structure,
# which the tree carries.
SKIPPED = {"message-id", "date", "mime-version", "content-type", "content-transfer-encoding"}
ADDRESS_HEADERS = {"from", "to", "cc", "reply-to", "bcc"}


def parse(raw: bytes) -> EmailMessage:
    message = email.message_from_bytes(raw, policy=email.policy.default)
    assert isinstance(message, EmailMessage)
    return message


def defects(message: EmailMessage) -> list[str]:
    """Parser defects of the message, its headers and its parts. A part
    records transfer-encoding defects only when it is decoded."""
    found: set[str] = set()
    for part in message.walk():
        if not part.is_multipart():
            part.get_payload(decode=True)
        found.update(type(d).__name__ for d in part.defects)
        for name, _ in part.raw_items():
            try:
                found.update(type(d).__name__ for d in part[name].defects)
            except ValueError:
                found.add("ValueError")
    return sorted(found)


def _addresses(header: Any) -> list[list[str]]:
    return [[a.display_name, a.addr_spec] for a in header.addresses]


def _node(part: EmailMessage) -> dict[str, Any]:
    node: dict[str, Any] = {"type": part.get_content_type()}
    if part.is_multipart():
        node["parts"] = [_node(p) for p in part.iter_parts()]  # type: ignore[arg-type]
        return node
    disposition = part.get_content_disposition()
    if disposition is not None:
        node["disposition"] = disposition
        node["filename"] = part.get_filename()
    if part["Content-ID"] is not None:
        node["content_id"] = str(part["Content-ID"])
    if node["type"].startswith("text/") and disposition is None:
        node["charset"] = part.get_content_charset()
        text = part.get_content().replace("\r\n", "\n")
        node["text"] = text.removesuffix("\n")
    else:
        payload = part.get_payload(decode=True)
        assert isinstance(payload, bytes)
        node["data"] = base64.b64encode(payload).decode()
    return node


def semantic_message(raw: bytes) -> dict[str, Any]:
    """What a receiver's parser (``email``, ``policy.default``) reads from
    ``raw``: headers (decoded, sorted, without per-message and structural
    ones) and the MIME tree with decoded bodies (line endings normalised,
    one trailing newline dropped)."""
    message = parse(raw)
    headers: list[list[Any]] = []
    for name, value in message.raw_items():
        key = name.lower()
        if key in SKIPPED:
            continue
        try:
            parsed = message.policy.header_fetch_parse(name, value)
            decoded: Any = _addresses(parsed) if key in ADDRESS_HEADERS else str(parsed)
        except ValueError:
            # The registry refuses a display name with CR/LF (From, 200);
            # compare the decoded text instead.
            decoded = [
                "unparsable",
                str(email.header.make_header(email.header.decode_header(value))),
            ]
        headers.append([key, decoded])
    headers.sort(key=json.dumps)
    return {"headers": headers, "body": _node(message)}


def conformance(raw: bytes) -> list[str]:
    """RFC problems of a message as sent: not 7-bit, a bare CR or LF, no
    final CRLF, a line over 998 octets, a top-level encoded word over 75
    characters."""
    problems = []
    if not raw.isascii():
        problems.append("not 7-bit")
    lines = raw.split(b"\r\n")
    if lines[-1] != b"":
        problems.append("does not end with CRLF")
    for line in lines:
        if b"\r" in line or b"\n" in line:
            problems.append(f"bare CR or LF in {line[:60]!r}")
        if len(line) > 998:
            problems.append(f"line of {len(line)} octets")
    head = raw.split(b"\r\n\r\n", 1)[0].decode("ascii", "replace")
    for word in re.findall(r"=\?[^?\s]*\?[bBqQ]\?[^?\s]*\?=", head):
        if len(word) > 75:
            problems.append(f"encoded word of {len(word)} characters")
    return problems
