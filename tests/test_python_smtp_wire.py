"""Retained Python transport, exercised against the synthetic parity SMTP peer."""

from __future__ import annotations

import base64
import dataclasses
import sys
from collections.abc import Iterator
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mailgun_relay.app import create_app
from mailgun_relay.routes import AppState
from mailgun_relay.smtp_client import SmtpSubmitError, SmtpTransport, submit
from tests.test_smtp_submission import _msg

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rust" / "parity"))
from smtp_fake import ScriptedSmtp, make_certificates, server_contexts


@pytest.fixture(scope="module")
def python_pki(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    return make_certificates(tmp_path_factory.mktemp("python-smtp-pki"))


@pytest.fixture
def python_smtp(python_pki: dict[str, str]) -> Iterator[ScriptedSmtp]:
    server = ScriptedSmtp(server_contexts(python_pki))
    try:
        yield server
    finally:
        server.close()
        assert not server.thread.is_alive()


def _transport(port: int, pki: dict[str, str]) -> SmtpTransport:
    return SmtpTransport(
        "127.0.0.1",
        port,
        "invented-user",
        "invented-password",
        True,
        5.0,
        ca_file=f"{pki['ca']}.pem",
    )


@pytest.mark.parametrize("bcc_only", [False, True])
def test_http_bcc_reaches_envelope_but_not_data(
    python_smtp: ScriptedSmtp,
    python_pki: dict[str, str],
    app_state: AppState,
    homepage_token: str,
    bcc_only: bool,
) -> None:
    sink = python_smtp.start()
    state = dataclasses.replace(
        app_state,
        transport=_transport(sink.port, python_pki),
        smtp_submit=submit,
    )
    form = {
        "from": "jochen-homepage@wersdoerfer.de",
        "bcc": "hidden@example.test",
        "subject": "synthetic BCC",
        "text": "invented body",
    }
    if not bcc_only:
        form.update(to="visible@example.test", cc="copied@example.test")
    try:
        with TestClient(create_app(app_state=state)) as client:
            response = client.post(
                "/v3/mg.wersdoerfer.de/messages",
                data=form,
                headers={
                    "Authorization": "Basic "
                    + base64.b64encode(f"api:{homepage_token}".encode()).decode()
                },
            )
        assert response.status_code == 200, response.text
        sink.settle()
        [session] = sink.take()
        assert session["state"] == "closed"
        expected = {"hidden@example.test"}
        if not bcc_only:
            expected.update({"visible@example.test", "copied@example.test"})
        assert {address for address, code in session["rcpt"] if code == 250} == expected
        assert set(session["data_for"]) == expected
        assert session["mail_from"] == app_state.settings.envelope_sender
        message = BytesParser(policy=policy.default).parsebytes(session["message"])
        assert message.get_all("Bcc") is None
        assert b"hidden@example.test" not in session["message"]
        assert message["To"] == (None if bcc_only else "visible@example.test")
        assert message["Cc"] == (None if bcc_only else "copied@example.test")
        assert message["Message-ID"] == response.json()["id"]
    finally:
        python_smtp.stop(sink)


@pytest.mark.parametrize("variant", ["good", "wrongname", "selfsigned", "no_starttls"])
def test_python_starttls_handshake_before_auth_and_data(
    python_smtp: ScriptedSmtp,
    python_pki: dict[str, str],
    variant: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = python_smtp.start(
        {"offer_starttls": variant != "no_starttls"},
        cert=variant if variant in {"wrongname", "selfsigned"} else "good",
    )
    transport = _transport(sink.port, python_pki)
    assert transport.password is not None
    try:
        if variant == "good":
            assert (
                submit(
                    _msg(),
                    envelope_sender="relay@example.test",
                    recipients=["bob@example.test"],
                    transport=transport,
                )
                == {}
            )
        else:
            with pytest.raises(SmtpSubmitError) as exc:
                submit(
                    _msg(),
                    envelope_sender="relay@example.test",
                    recipients=["bob@example.test"],
                    transport=transport,
                )
            assert transport.password not in str(exc.value)
        sink.settle()
        [session] = sink.take()
        assert session["state"] == "closed"
        if variant == "good":
            assert session["commands"] == [
                "EHLO",
                "STARTTLS",
                "EHLO",
                "AUTH",
                "MAIL",
                "RCPT",
                "DATA",
                "QUIT",
            ]
            assert session["tls"] is True
            assert session["auth_user"] == transport.username
            assert session["message"] is not None
        else:
            expected = ["EHLO", "QUIT"] if variant == "no_starttls" else ["EHLO", "STARTTLS"]
            assert session["commands"] == expected
            assert session["auth_user"] is None
            assert session["mail_from"] is None
            assert session["rcpt"] == []
            assert session["message"] is None
        assert transport.password not in caplog.text
    finally:
        python_smtp.stop(sink)
