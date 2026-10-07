from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate

from mailgun_relay.headers import (
    HeaderInjectionError,
    parse_address_list,
    parse_header_address_list,
)


@dataclass(frozen=True)
class Attachment:
    filename: str
    content_type: str
    data: bytes
    content_id: str | None = None


@dataclass(frozen=True)
class MessageInput:
    from_address: str
    to: list[str]
    cc: list[str]
    bcc: list[str]
    subject: str
    text: str | None
    html: str | None
    amp_html: str | None
    custom_headers: dict[str, str]
    attachments: list[Attachment]
    inline: list[Attachment]
    public_host: str
    date: str | None = field(default=None)


_OCTET_STREAM = ("application", "octet-stream")

# Uploaded bytes are always wrapped as a single leaf part. A declared
# ``multipart/*`` or ``message/*`` type would produce a part with no boundary
# or embedded message, which recipients cannot parse, so those are downgraded
# to an opaque binary part.
_CONTAINER_MAINTYPES = frozenset({"multipart", "message"})


def _split_ct(content_type: str) -> tuple[str, str]:
    main, _, sub = content_type.partition("/")
    main = main.strip().lower()
    sub = sub.split(";", 1)[0].strip().lower()
    if not main or not sub or main in _CONTAINER_MAINTYPES:
        return _OCTET_STREAM
    return main, sub


def _content_id(inline_att: Attachment) -> str:
    """Return an RFC 2392 ``Content-ID`` (``<id>``) for an inline upload.

    Mailgun names inline parts after the uploaded filename, so HTML refers to
    them as ``cid:<filename>``. The header value must carry angle brackets for
    clients to match that reference.
    """
    if inline_att.content_id is not None:
        # An explicitly supplied id may already be in the bracketed form.
        name = inline_att.content_id.strip().removeprefix("<").removesuffix(">")
    else:
        # The uploaded filename is used as-is; it is never normalized, so a
        # malformed name is rejected rather than silently rewritten.
        name = inline_att.filename
    if (
        not name
        or name != name.strip()
        or any(ch in name for ch in "<>")
        or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name)
    ):
        raise HeaderInjectionError(f"invalid inline filename {inline_att.filename!r}")
    return f"<{name}>"


def _find_html_part(msg: EmailMessage) -> EmailMessage | None:
    if msg.get_content_type() == "text/html":
        return msg
    if msg.get_content_type() == "multipart/alternative":
        for part in msg.iter_parts():
            if part.get_content_type() == "text/html":
                assert isinstance(part, EmailMessage)
                return part
    return None


def _addr_only(values: list[str]) -> list[str]:
    return [a.addr_spec for a in parse_address_list(values)]


def build_message(payload: MessageInput) -> tuple[EmailMessage, str, list[str]]:
    """Construct an EmailMessage from validated form fields.

    Returns (message, message_id, envelope_recipients).
    BCC recipients are returned in envelope_recipients but NEVER added to the message headers.
    """
    if not payload.text and not payload.html:
        raise ValueError("at least one of text/html is required")

    msg = EmailMessage()
    [from_addr] = parse_address_list([payload.from_address])
    msg["From"] = from_addr
    to_list = parse_address_list(payload.to) if payload.to else []
    cc_list = parse_address_list(payload.cc) if payload.cc else []
    if to_list:
        msg["To"] = ", ".join(str(a) for a in to_list)
    if cc_list:
        msg["Cc"] = ", ".join(str(a) for a in cc_list)
    msg["Subject"] = payload.subject

    message_id = f"<{uuid.uuid4().hex}@{payload.public_host}>"
    msg["Message-Id"] = message_id
    msg["Date"] = payload.date or formatdate(localtime=False, usegmt=True)

    if payload.text and payload.html:
        msg.set_content(payload.text)
        msg.add_alternative(payload.html, subtype="html")
    elif payload.html:
        msg.set_content(payload.html, subtype="html")
    else:
        assert payload.text is not None
        msg.set_content(payload.text)

    if payload.amp_html:
        msg.add_alternative(payload.amp_html, subtype="x-amp-html")

    for name, value in payload.custom_headers.items():
        try:
            if name.lower() == "reply-to":
                # Reply-To may be a single address or a comma-separated list; use
                # the RFC 5322 list parser so quoted commas inside display names
                # ('"Doe, Jane" <jane@example>') are not shattered.
                reply_to = parse_header_address_list(value)
                msg["Reply-To"] = ", ".join(str(a) for a in reply_to)
            else:
                msg[name] = value
        except HeaderInjectionError:
            raise
        except ValueError as exc:
            # Map any residual email-package rejection (e.g. a duplicate
            # structural header) to a clean 400 instead of a 500.
            raise HeaderInjectionError(f"invalid header {name!r}: {exc}") from exc

    # Inline parts are grouped with the HTML body in multipart/related (the
    # structure Mailgun sends), so ``cid:`` references resolve. Without an HTML
    # body there is nothing to relate them to; they are then added to the
    # top-level multipart/mixed with ``Content-Disposition: inline``.
    html_part = _find_html_part(msg)
    for inline_att in payload.inline:
        main, sub = _split_ct(inline_att.content_type)
        cid = _content_id(inline_att)
        try:
            if html_part is not None:
                html_part.add_related(
                    inline_att.data,
                    maintype=main,
                    subtype=sub,
                    filename=inline_att.filename,
                    disposition="inline",
                    cid=cid,
                )
            else:
                msg.add_attachment(
                    inline_att.data,
                    maintype=main,
                    subtype=sub,
                    filename=inline_att.filename,
                    disposition="inline",
                    cid=cid,
                )
        except ValueError as exc:
            raise HeaderInjectionError(
                f"invalid inline file {inline_att.filename!r}: {exc}"
            ) from exc

    for att in payload.attachments:
        main, sub = _split_ct(att.content_type)
        try:
            msg.add_attachment(att.data, maintype=main, subtype=sub, filename=att.filename)
        except ValueError as exc:
            raise HeaderInjectionError(f"invalid attachment {att.filename!r}: {exc}") from exc

    envelope: list[str] = []
    envelope.extend(_addr_only(payload.to) if payload.to else [])
    envelope.extend(_addr_only(payload.cc) if payload.cc else [])
    envelope.extend(_addr_only(payload.bcc) if payload.bcc else [])
    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique_envelope: list[str] = []
    for addr in envelope:
        if addr not in seen:
            seen.add(addr)
            unique_envelope.append(addr)

    return msg, message_id, unique_envelope


__all__ = ["Attachment", "MessageInput", "build_message"]
