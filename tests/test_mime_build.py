from __future__ import annotations

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
