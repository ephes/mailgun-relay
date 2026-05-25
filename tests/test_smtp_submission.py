from __future__ import annotations

import asyncio
import smtplib
import socket
import threading
from collections.abc import Iterator
from email.message import EmailMessage
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from aiosmtpd.controller import Controller

from mailgun_relay.smtp_client import (
    FailureCategory,
    SmtpSubmitError,
    SmtpTransport,
    submit,
)


class _RecordingHandler:
    def __init__(self) -> None:
        self.mail_from: str | None = None
        self.rcpt_tos: list[str] = []
        self.content: bytes | None = None
        self.auth_user: str | None = None

    async def handle_MAIL(  # noqa: N802
        self,
        server: Any,
        session: Any,
        envelope: Any,
        address: str,
        mail_options: list[str],
    ) -> str:
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(  # noqa: N802
        self,
        server: Any,
        session: Any,
        envelope: Any,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:  # noqa: N802
        self.mail_from = envelope.mail_from
        self.rcpt_tos = list(envelope.rcpt_tos)
        self.content = envelope.content
        return "250 Message accepted"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def fake_smtp() -> Iterator[tuple[_RecordingHandler, int]]:
    handler = _RecordingHandler()
    port = _free_port()
    controller = Controller(handler, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        yield handler, port
    finally:
        controller.stop()


def _msg() -> EmailMessage:
    m = EmailMessage()
    m["From"] = "Alice <alice@example.test>"
    m["To"] = "bob@example.test"
    m["Subject"] = "hi"
    m["Message-Id"] = "<abc@example.test>"
    m.set_content("hello")
    return m


def test_submit_happy_path(fake_smtp: tuple[_RecordingHandler, int]) -> None:
    handler, port = fake_smtp
    transport = SmtpTransport(
        host="127.0.0.1",
        port=port,
        username=None,
        password=None,
        use_starttls=False,
        timeout_s=5.0,
    )
    submit(
        _msg(),
        envelope_sender="relay@example.test",
        recipients=["bob@example.test", "secret@example.test"],
        transport=transport,
    )
    assert handler.mail_from == "relay@example.test"
    assert set(handler.rcpt_tos) == {"bob@example.test", "secret@example.test"}
    assert handler.content is not None
    # BCC must NOT appear in the message bytes (only in envelope).
    assert b"secret@example.test" not in handler.content


def _make_mock_smtp_with_exc(exc: Exception) -> MagicMock:
    mock = MagicMock()
    instance = MagicMock()
    instance.send_message.side_effect = exc
    instance.starttls.return_value = (220, b"ok")
    instance.login.return_value = (235, b"ok")
    instance.has_extn.return_value = True
    instance.__enter__.return_value = instance
    instance.__exit__.return_value = False
    mock.return_value = instance
    return mock


def test_smtp_data_5xx_maps_to_permanent() -> None:
    err = smtplib.SMTPDataError(550, b"rejected")
    with patch("smtplib.SMTP", new=_make_mock_smtp_with_exc(err)):
        with pytest.raises(SmtpSubmitError) as ei:
            submit(
                _msg(),
                envelope_sender="x@x",
                recipients=["y@y"],
                transport=SmtpTransport("h", 25, None, None, False, 5.0),
            )
    assert ei.value.category is FailureCategory.PERMANENT


def test_smtp_data_4xx_maps_to_temporary() -> None:
    err = smtplib.SMTPDataError(421, b"busy")
    with patch("smtplib.SMTP", new=_make_mock_smtp_with_exc(err)):
        with pytest.raises(SmtpSubmitError) as ei:
            submit(
                _msg(),
                envelope_sender="x@x",
                recipients=["y@y"],
                transport=SmtpTransport("h", 25, None, None, False, 5.0),
            )
    assert ei.value.category is FailureCategory.TEMPORARY


def test_smtp_recipients_refused_maps_to_permanent() -> None:
    err = smtplib.SMTPRecipientsRefused({"y@y": (550, b"no")})
    with patch("smtplib.SMTP", new=_make_mock_smtp_with_exc(err)):
        with pytest.raises(SmtpSubmitError) as ei:
            submit(
                _msg(),
                envelope_sender="x@x",
                recipients=["y@y"],
                transport=SmtpTransport("h", 25, None, None, False, 5.0),
            )
    assert ei.value.category is FailureCategory.PERMANENT


def test_smtp_auth_failure_maps_to_auth() -> None:
    err = smtplib.SMTPAuthenticationError(535, b"bad creds")
    with patch("smtplib.SMTP", new=_make_mock_smtp_with_exc(err)):
        with pytest.raises(SmtpSubmitError) as ei:
            submit(
                _msg(),
                envelope_sender="x@x",
                recipients=["y@y"],
                transport=SmtpTransport("h", 25, "user", "pw", False, 5.0),
            )
    assert ei.value.category is FailureCategory.AUTH
    # The error message must not include the SMTP password.
    assert "pw" not in str(ei.value)


def test_smtp_connection_refused_maps_to_temporary() -> None:
    err = ConnectionRefusedError("refused")
    with patch("smtplib.SMTP", side_effect=err):
        with pytest.raises(SmtpSubmitError) as ei:
            submit(
                _msg(),
                envelope_sender="x@x",
                recipients=["y@y"],
                transport=SmtpTransport("h", 25, None, None, False, 5.0),
            )
    assert ei.value.category is FailureCategory.TEMPORARY


def test_smtp_timeout_maps_to_temporary() -> None:
    err = TimeoutError("timeout")
    with patch("smtplib.SMTP", side_effect=err):
        with pytest.raises(SmtpSubmitError) as ei:
            submit(
                _msg(),
                envelope_sender="x@x",
                recipients=["y@y"],
                transport=SmtpTransport("h", 25, None, None, False, 5.0),
            )
    assert ei.value.category is FailureCategory.TEMPORARY


# Silence unused-warning for asyncio/threading imports kept for future TLS tests.
_unused = (asyncio, threading)
