from __future__ import annotations

import smtplib
from dataclasses import replace
from typing import cast
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from mailgun_relay.app import create_app
from mailgun_relay.routes import AppState
from mailgun_relay.smtp_client import FailureCategory, SmtpSubmitError, submit
from tests.test_messages_endpoint import _minimum_form, basic
from tests.test_smtp_submission import _make_ok_mock_smtp, _msg, _plain_transport


@pytest.mark.parametrize("kind", ["recipient", "sender", "helo"])
@pytest.mark.parametrize("code", [421, 450, 451, 550])
def test_refusal_codes_through_submit_and_endpoint(
    kind: str, code: int, app_state: AppState, homepage_token: str
) -> None:
    if kind == "recipient":
        error: Exception = smtplib.SMTPRecipientsRefused(
            {"private@x.test": (code, b"private reply")}
        )
    elif kind == "sender":
        error = smtplib.SMTPSenderRefused(code, b"private reply", "private@x.test")
    else:
        error = smtplib.SMTPHeloError(code, b"private reply")
    mock, instance = _make_ok_mock_smtp()
    instance.send_message.side_effect = error
    category = FailureCategory.TEMPORARY if code < 500 else FailureCategory.PERMANENT
    with patch("smtplib.SMTP", new=mock):
        with pytest.raises(SmtpSubmitError) as caught:
            submit(
                _msg(), envelope_sender="x@x", recipients=["y@y"], transport=_plain_transport(25)
            )
        assert caught.value.category == category
        response = _post(app_state, homepage_token)
    assert response.status_code == (503 if code < 500 else 502)
    assert "id" not in response.json()
    assert "private" not in response.text


@pytest.mark.parametrize(
    "codes,temporary", [([450, 451], True), ([450, 550], True), ([550, 551], False), ([], False)]
)
def test_all_refused_classifies_every_reply(codes: list[int], temporary: bool) -> None:
    mock, instance = _make_ok_mock_smtp()
    instance.send_message.side_effect = smtplib.SMTPRecipientsRefused(
        {f"user{i}@x.test": (code, b"no") for i, code in enumerate(codes)}
    )
    with patch("smtplib.SMTP", new=mock), pytest.raises(SmtpSubmitError) as caught:
        submit(_msg(), envelope_sender="x@x", recipients=["y@y"], transport=_plain_transport(25))
    assert caught.value.category == (
        FailureCategory.TEMPORARY if temporary else FailureCategory.PERMANENT
    )


def _post(app_state: AppState, token: str) -> Response:
    state = replace(app_state, smtp_submit=submit, transport=_plain_transport(25))
    with TestClient(create_app(app_state=state)) as client:
        return cast(
            Response,
            client.post(
                "/v3/mg.wersdoerfer.de/messages",
                headers={"Authorization": basic("api", token)},
                data=_minimum_form(),
            ),
        )


@pytest.mark.parametrize("refused", [{}, {"nope@x.test": (550, b"private reply")}])
@pytest.mark.parametrize("strict", [False, True])
def test_quit_failure_preserves_endpoint_outcome(
    refused: dict[str, tuple[int, bytes]],
    strict: bool,
    app_state: AppState,
    homepage_token: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    mock, instance = _make_ok_mock_smtp()
    instance.send_message.return_value = refused
    instance.__exit__.side_effect = smtplib.SMTPResponseException(500, b"private cleanup reply")
    instance.quit.side_effect = instance.__exit__.side_effect
    state = replace(
        app_state,
        settings=app_state.settings.model_copy(update={"fail_on_partial_refusal": strict}),
    )
    with patch("smtplib.SMTP", new=mock):
        response = _post(state, homepage_token)
    assert response.status_code == (502 if strict and refused else 200)
    if response.status_code == 200:
        assert response.json()["message"] == "Queued. Thank you."
    else:
        assert "sent to the others" in response.json()["message"]
    instance.send_message.assert_called_once()
    instance.close.assert_called_once()
    records = [r for r in caplog.records if getattr(r, "event", None) == "smtp_cleanup_failed"]
    assert len(records) == 1
    assert records[0].error_class == "SMTPResponseException"  # type: ignore[attr-defined]
    assert "private" not in caplog.text


def test_data_failure_is_not_hidden_by_quit_failure(
    app_state: AppState, homepage_token: str
) -> None:
    mock, instance = _make_ok_mock_smtp()
    instance.send_message.side_effect = smtplib.SMTPDataError(451, b"private DATA reply")
    instance.__exit__.side_effect = smtplib.SMTPResponseException(500, b"private cleanup reply")
    instance.quit.side_effect = instance.__exit__.side_effect
    with patch("smtplib.SMTP", new=mock):
        response = _post(app_state, homepage_token)
    assert response.status_code == 503
    assert "id" not in response.json()
    instance.send_message.assert_called_once()


@pytest.mark.parametrize(
    "error",
    [
        smtplib.SMTPDataError(421, b"bye"),
        smtplib.SMTPServerDisconnected("closed"),
        TimeoutError("timeout"),
    ],
)
def test_already_closed_send_failure_does_not_warn_about_cleanup(
    error: Exception,
    caplog: pytest.LogCaptureFixture,
) -> None:
    mock, instance = _make_ok_mock_smtp()

    def fail_send(*args: object, **kwargs: object) -> None:
        instance.sock = None
        raise error

    instance.send_message.side_effect = fail_send
    with patch("smtplib.SMTP", new=mock), pytest.raises(SmtpSubmitError) as caught:
        submit(_msg(), envelope_sender="x@x", recipients=["y@y"], transport=_plain_transport(25))
    assert caught.value.category == FailureCategory.TEMPORARY
    instance.quit.assert_not_called()
    instance.close.assert_called_once()
    assert not [r for r in caplog.records if getattr(r, "event", None) == "smtp_cleanup_failed"]


@pytest.mark.parametrize("failure", ["reply", "close"])
def test_cleanup_reply_and_close_errors_preserve_acceptance(
    failure: str, caplog: pytest.LogCaptureFixture
) -> None:
    mock, instance = _make_ok_mock_smtp()
    if failure == "reply":
        instance.quit.return_value = (500, b"private reply")
    else:
        instance.close.side_effect = OSError("private close detail")
    with patch("smtplib.SMTP", new=mock):
        assert (
            submit(
                _msg(), envelope_sender="x@x", recipients=["y@y"], transport=_plain_transport(25)
            )
            == {}
        )
    instance.send_message.assert_called_once()
    instance.close.assert_called_once()
    assert (
        len([r for r in caplog.records if getattr(r, "event", None) == "smtp_cleanup_failed"]) == 1
    )
    assert "private" not in caplog.text
