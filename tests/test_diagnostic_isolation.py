"""Post-submission cleanup and diagnostics cannot decide delivery outcomes."""

from __future__ import annotations

import hashlib
import logging
import smtplib
from dataclasses import replace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import FormData, UploadFile

from mailgun_relay import routes
from mailgun_relay.app import create_app
from mailgun_relay.config import Secrets, Settings, SmtpCredentials, TokenPolicy
from mailgun_relay.logging_setup import access_logger, service_logger
from mailgun_relay.routes import AppState
from mailgun_relay.smtp_client import submit
from tests.test_messages_endpoint import basic
from tests.test_smtp_submission import _make_ok_mock_smtp, _plain_transport

_TOKEN = "synthetic-diagnostic-token"
_PRIVATE = "synthetic-private-payload"
_PATH = "/v3/mg.example.test/messages"


@pytest.fixture
def diagnostic_state(app_state: AppState) -> AppState:
    return replace(
        app_state,
        settings=app_state.settings.model_copy(update={"smtp_max_concurrency": 1}),
        secrets=Secrets(
            smtp=SmtpCredentials(username="synthetic-user", password=_PRIVATE),
            tokens=(
                TokenPolicy(
                    label="synthetic",
                    token_sha256=hashlib.sha256(_TOKEN.encode()).hexdigest(),
                    mailgun_domains=frozenset({"mg.example.test"}),
                    allowed_from_domains=frozenset({"example.test"}),
                ),
            ),
        ),
        smtp_submit=submit,
        transport=_plain_transport(25),
    )


def _fields() -> dict[str, str]:
    return {
        "from": "sender@example.test",
        "to": "recipient@example.test",
        "cc": "other@example.test",
        "subject": _PRIVATE,
        "text": _PRIVATE,
    }


@pytest.mark.parametrize(
    "outcome", ["accepted", "partial", "strict", "temporary", "permanent", "invalid"]
)
@pytest.mark.parametrize("broken_sink", [False, True])
def test_upload_close_failure_preserves_outcome_and_attempts_every_upload(
    diagnostic_state: AppState,
    outcome: str,
    broken_sink: bool,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    mock, smtp = _make_ok_mock_smtp()
    expected = 200
    if outcome in {"partial", "strict"}:
        smtp.send_message.return_value = {"other@example.test": (550, _PRIVATE.encode())}
        if outcome == "strict":
            diagnostic_state = replace(
                diagnostic_state,
                settings=diagnostic_state.settings.model_copy(
                    update={"fail_on_partial_refusal": True}
                ),
            )
            expected = 502
    elif outcome in {"temporary", "permanent"}:
        code = 450 if outcome == "temporary" else 550
        smtp.send_message.side_effect = smtplib.SMTPRecipientsRefused(
            {"recipient@example.test": (code, _PRIVATE.encode())}
        )
        expected = 503 if code == 450 else 502
    fields = _fields()
    if outcome == "invalid":
        fields = {"unsupported": _PRIVATE, **fields}
        expected = 400

    closed: list[UploadFile] = []
    uploads: list[UploadFile] = []
    close = UploadFile.close
    parse = routes._parse_form

    def capture(form: FormData, settings: Settings) -> routes._ParsedForm:
        uploads.extend(v for _, v in form.multi_items() if isinstance(v, UploadFile))
        return parse(form, settings)

    async def failing_close(upload: UploadFile) -> None:
        closed.append(upload)
        await close(upload)
        if len(closed) == 1:
            raise OSError(_PRIVATE)

    monkeypatch.setattr(UploadFile, "close", failing_close)
    monkeypatch.setattr(routes, "_parse_form", capture)
    handler = _RaisingHandler()
    if broken_sink:
        service_logger().addHandler(handler)
    try:
        with (
            patch("smtplib.SMTP", new=mock),
            TestClient(create_app(app_state=diagnostic_state)) as client,
        ):
            response = client.post(
                _PATH,
                headers={"Authorization": basic("api", _TOKEN)},
                data=fields,
                files=[("attachment", (f"{i}.txt", b"synthetic")) for i in range(3)],
            )
        assert all(upload.file.closed for upload in uploads)
    finally:
        if broken_sink:
            service_logger().removeHandler(handler)
        for upload in uploads:
            upload.file.close()
    assert response.status_code == expected, response.text
    assert len(closed) == 3
    assert all(upload.file.closed for upload in closed)
    assert smtp.send_message.call_count == (0 if outcome == "invalid" else 1)
    records = [r for r in caplog.records if getattr(r, "event", None) == "upload_cleanup_failed"]
    if broken_sink:
        assert handler.events == ["upload_cleanup_failed"]
    else:
        assert len(records) == 1
        assert records[0].error_class == "OSError"  # type: ignore[attr-defined]
    assert _PRIVATE not in caplog.text
    if expected == 200:
        assert response.json()["id"]
    elif outcome == "strict":
        assert "sent to the others" in response.json()["message"]


class _RaisingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.events: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.events.append(str(getattr(record, "event", "")))
        raise RuntimeError(f"{_TOKEN} {_PRIVATE} raw diagnostic exception")


@pytest.mark.parametrize("outcome", ["accepted", "partial", "strict", "temporary", "permanent"])
@pytest.mark.parametrize("sink", ["access", "service", "both"])
@pytest.mark.parametrize("cleanup", ["ok", "quit", "close"])
def test_raising_diagnostic_handler_preserves_outcome_and_releases_capacity(
    diagnostic_state: AppState,
    outcome: str,
    sink: str,
    cleanup: str,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    mock, smtp = _make_ok_mock_smtp()
    expected = 200
    if outcome in {"partial", "strict"}:
        smtp.send_message.return_value = {"other@example.test": (550, _PRIVATE.encode())}
        if outcome == "strict":
            diagnostic_state = replace(
                diagnostic_state,
                settings=diagnostic_state.settings.model_copy(
                    update={"fail_on_partial_refusal": True}
                ),
            )
            expected = 502
    elif outcome in {"temporary", "permanent"}:
        code = 451 if outcome == "temporary" else 550
        smtp.send_message.side_effect = smtplib.SMTPDataError(code, _PRIVATE.encode())
        expected = 503 if code == 451 else 502
    if cleanup == "quit":
        smtp.quit.side_effect = smtplib.SMTPResponseException(500, _PRIVATE.encode())
    elif cleanup == "close":
        smtp.close.side_effect = OSError(_PRIVATE)

    handler = _RaisingHandler()
    logs = [access_logger()] if sink == "access" else [service_logger()]
    if sink == "both":
        logs = [access_logger(), service_logger()]
    for log in logs:
        caplog.set_level(logging.DEBUG, logger=log.name)
        log.addHandler(handler)
    try:
        with (
            patch("smtplib.SMTP", new=mock),
            TestClient(create_app(app_state=diagnostic_state)) as client,
        ):
            for number in range(2):
                response = client.post(
                    _PATH, headers={"Authorization": basic("api", _TOKEN)}, data=_fields()
                )
                assert response.status_code == expected, response.text
                assert smtp.send_message.call_count == number + 1
                assert smtp.close.call_count == number + 1
                if expected == 200:
                    assert response.json()["id"]
                elif outcome == "strict":
                    assert "sent to the others" in response.json()["message"]
    finally:
        for log in logs:
            log.removeHandler(handler)
    fallback = capfd.readouterr().err
    assert fallback == '{"event":"diagnostic_logging_failed"}\n' * len(handler.events)
    assert _TOKEN not in fallback
    assert _PRIVATE not in fallback


def test_unavailable_fallback_preserves_accepted_send(
    diagnostic_state: AppState,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def fail_write(fd: int, data: bytes) -> int:
        assert fd == 2
        assert data == b'{"event":"diagnostic_logging_failed"}\n'
        raise OSError(_PRIVATE)

    monkeypatch.setattr("mailgun_relay.logging_setup.os.write", fail_write)
    mock, smtp = _make_ok_mock_smtp()
    handler = _RaisingHandler()
    log = access_logger()
    caplog.set_level(logging.INFO, logger=log.name)
    log.addHandler(handler)
    try:
        with (
            patch("smtplib.SMTP", new=mock),
            TestClient(create_app(app_state=diagnostic_state)) as client,
        ):
            response = client.post(
                _PATH, headers={"Authorization": basic("api", _TOKEN)}, data=_fields()
            )
        assert response.status_code == 200
        smtp.send_message.assert_called_once()
        assert handler.events == ["request"]
    finally:
        log.removeHandler(handler)
