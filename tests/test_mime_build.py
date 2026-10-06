from __future__ import annotations

from email.message import EmailMessage

import pytest

from mailgun_relay.headers import HeaderInjectionError
from mailgun_relay.mime_build import Attachment, MessageInput, build_message


def _base_input(**overrides: object) -> MessageInput:
    defaults: dict[str, object] = {
        "from_address": "Alice <alice@example.test>",
        "to": ["bob@example.test"],
        "cc": [],
        "bcc": [],
        "subject": "hi",
        "text": "hello",
        "html": None,
        "amp_html": None,
        "custom_headers": {},
        "attachments": [],
        "inline": [],
        "public_host": "mailgun.home.xn--wersdrfer-47a.de",
    }
    defaults.update(overrides)
    return MessageInput(**defaults)  # type: ignore[arg-type]


def test_text_only_message() -> None:
    msg, message_id, recipients = build_message(_base_input())
    assert message_id.startswith("<") and message_id.endswith("@mailgun.home.xn--wersdrfer-47a.de>")
    assert msg["Message-Id"] == message_id
    assert msg["From"] == "Alice <alice@example.test>"
    assert msg["To"] == "bob@example.test"
    assert msg["Subject"] == "hi"
    assert msg.get_content_type() == "text/plain"
    assert msg.get_content().strip() == "hello"
    assert recipients == ["bob@example.test"]


def test_html_only_message() -> None:
    msg, _, _ = build_message(_base_input(text=None, html="<p>hi</p>"))
    assert msg.get_content_type() == "text/html"
    assert "<p>hi</p>" in msg.get_content()


def test_multipart_alternative_text_html() -> None:
    msg, _, _ = build_message(_base_input(html="<p>hi</p>"))
    assert msg.get_content_type() == "multipart/alternative"
    parts = list(msg.iter_parts())
    types = [p.get_content_type() for p in parts]
    assert "text/plain" in types
    assert "text/html" in types


def test_cc_in_headers_and_envelope() -> None:
    msg, _, recipients = build_message(_base_input(cc=["c@example.test"], to=["a@example.test"]))
    assert msg["Cc"] == "c@example.test"
    assert "a@example.test" in recipients and "c@example.test" in recipients


def test_bcc_in_envelope_not_headers() -> None:
    msg, _, recipients = build_message(
        _base_input(
            to=["a@example.test"],
            bcc=["secret@example.test", "secret2@example.test"],
        )
    )
    assert msg.get("Bcc") is None
    serialized = bytes(msg)
    assert b"secret@example.test" not in serialized
    assert b"secret2@example.test" not in serialized
    assert set(recipients) == {"a@example.test", "secret@example.test", "secret2@example.test"}


def test_reply_to_via_custom_header() -> None:
    msg, _, _ = build_message(_base_input(custom_headers={"Reply-To": "ops@example.test"}))
    assert msg["Reply-To"] == "ops@example.test"


def test_attachment_included() -> None:
    attachment = Attachment(
        filename="hello.txt",
        content_type="text/plain",
        data=b"hello attachment",
    )
    msg, _, _ = build_message(_base_input(attachments=[attachment]))
    parts = list(msg.walk())
    types = [p.get_content_type() for p in parts]
    assert "text/plain" in types
    found_attachment = False
    for part in parts:
        disp = part.get_content_disposition()
        if disp == "attachment":
            assert part.get_filename() == "hello.txt"
            assert part.get_payload(decode=True) == b"hello attachment"
            found_attachment = True
    assert found_attachment


def test_message_id_matches_response_id() -> None:
    msg, message_id, _ = build_message(_base_input())
    assert msg["Message-Id"] == message_id
    assert "@" in message_id and message_id.startswith("<") and message_id.endswith(">")


def test_display_name_in_from_preserved() -> None:
    msg, _, _ = build_message(
        _base_input(from_address="Python Podcast <noreply@mg.python-podcast.de>")
    )
    assert "noreply@mg.python-podcast.de" in str(msg["From"])
    assert "Python Podcast" in str(msg["From"])


def _png(name: str = "logo.png", content_id: str | None = None) -> Attachment:
    return Attachment(
        filename=name, content_type="image/png", data=b"\x89PNG\r\n", content_id=content_id
    )


def _parts_by_type(msg: EmailMessage) -> dict[str, list[EmailMessage]]:
    found: dict[str, list[EmailMessage]] = {}
    for part in msg.walk():
        assert isinstance(part, EmailMessage)
        found.setdefault(part.get_content_type(), []).append(part)
    return found


def test_inline_content_id_has_angle_brackets() -> None:
    msg, _, _ = build_message(_base_input(html='<img src="cid:logo.png">', inline=[_png()]))
    [image] = _parts_by_type(msg)["image/png"]
    assert image["Content-ID"] == "<logo.png>"
    assert image.get_content_disposition() == "inline"
    assert image.get_filename() == "logo.png"
    # The serialized header uses the RFC 2392 bracketed form too.
    assert "Content-ID: <logo.png>" in msg.as_string()


def test_inline_explicit_content_id_is_not_double_bracketed() -> None:
    msg, _, _ = build_message(_base_input(html="<p>x</p>", inline=[_png(content_id="<logo>")]))
    [image] = _parts_by_type(msg)["image/png"]
    assert image["Content-ID"] == "<logo>"


def test_inline_part_grouped_with_html_in_multipart_related() -> None:
    msg, _, _ = build_message(
        _base_input(
            html='<img src="cid:logo.png">',
            inline=[_png()],
            attachments=[Attachment("a.pdf", "application/pdf", b"%PDF")],
        )
    )
    assert msg.get_content_type() == "multipart/mixed"
    alternative, attachment = list(msg.iter_parts())
    assert alternative.get_content_type() == "multipart/alternative"
    assert attachment.get_content_type() == "application/pdf"
    plain, related = list(alternative.iter_parts())
    assert plain.get_content_type() == "text/plain"
    assert related.get_content_type() == "multipart/related"
    html, image = list(related.iter_parts())
    assert html.get_content_type() == "text/html"
    assert image.get_content_type() == "image/png"
    assert image["Content-ID"] == "<logo.png>"


def test_inline_with_html_only_body_builds_related_root() -> None:
    msg, _, _ = build_message(
        _base_input(text=None, html='<img src="cid:logo.png">', inline=[_png()])
    )
    assert msg.get_content_type() == "multipart/related"
    assert msg["Subject"] == "hi"
    html, image = list(msg.iter_parts())
    assert html.get_content_type() == "text/html"
    assert image["Content-ID"] == "<logo.png>"


def test_inline_with_amp_html_keeps_amp_alternative() -> None:
    msg, _, _ = build_message(
        _base_input(html="<p>x</p>", amp_html="<html amp4email></html>", inline=[_png()])
    )
    assert msg.get_content_type() == "multipart/alternative"
    types = [p.get_content_type() for p in msg.iter_parts()]
    assert types == ["text/plain", "multipart/related", "text/x-amp-html"]


def test_inline_with_text_only_message_still_builds() -> None:
    msg, _, _ = build_message(_base_input(inline=[_png()]))
    assert msg.get_content_type() == "multipart/mixed"
    plain, image = list(msg.iter_parts())
    assert plain.get_content_type() == "text/plain"
    assert image["Content-ID"] == "<logo.png>"
    assert image.get_content_disposition() == "inline"


@pytest.mark.parametrize(
    "filename",
    ["a\r\nb.png", "<logo.png>", "<logo.png", "logo.png>", "\tlogo.png", " logo.png", "a\x7f.png"],
)
def test_malformed_inline_filename_rejected(filename: str) -> None:
    with pytest.raises(HeaderInjectionError):
        build_message(_base_input(html="<p>x</p>", inline=[_png(filename)]))


@pytest.mark.parametrize("content_type", ["multipart/mixed", "message/rfc822", "Multipart/Related"])
def test_container_upload_types_become_octet_stream(content_type: str) -> None:
    msg, _, _ = build_message(
        _base_input(attachments=[Attachment("a.bin", content_type, b"payload")])
    )
    _, attachment = list(msg.iter_parts())
    assert attachment.get_content_type() == "application/octet-stream"
    assert attachment.get_content() == b"payload"
    assert attachment.get_filename() == "a.bin"


def test_container_inline_type_becomes_octet_stream() -> None:
    msg, _, _ = build_message(
        _base_input(html="<p>x</p>", inline=[Attachment("x.eml", "message/rfc822", b"hi")])
    )
    parts = _parts_by_type(msg)
    assert "message/rfc822" not in parts
    [inline] = parts["application/octet-stream"]
    assert inline["Content-ID"] == "<x.eml>"
