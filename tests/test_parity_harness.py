"""The parity harness itself (rust/parity, rust/PLAN.md 7.4): the fake SMTP
server records what a client sends."""

from __future__ import annotations

import json
import smtplib
import ssl
import sys
from collections.abc import Iterator
from email.message import EmailMessage
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rust" / "parity"))
from smtp_fake import ScriptedSmtp, make_certificates, server_contexts, session_from_json


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    return make_certificates(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def smtp(pki: dict[str, str]) -> Iterator[ScriptedSmtp]:
    server = ScriptedSmtp(server_contexts(pki))
    yield server
    server.close()


def _message(text: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = "a@example.org"
    message["To"] = "b@example.org"
    message["Subject"] = "s"
    message["Message-ID"] = "<1@x.test>"
    message["Date"] = "Thu, 15 Oct 2026 12:00:00 +0000"
    message.set_content(text)
    return message


def test_fake_records_the_session(smtp: ScriptedSmtp, pki: dict[str, str]) -> None:
    sink = smtp.start({"rcpt": {"gone": 550}})
    context = ssl.create_default_context(cafile=f"{pki['ca']}.pem")
    with smtplib.SMTP("localhost", sink.port, timeout=5) as client:
        client.starttls(context=context)
        client.login("relay", "secret")
        refused = client.send_message(
            _message(".leading dot\n"),
            from_addr="relay@example.org",
            to_addrs=["b@example.org", "gone@example.org"],
        )
    assert refused == {"gone@example.org": (550, b"rcpt result")}
    sink.settle()
    [session] = sink.take()
    smtp.stop(sink)
    assert session["tls"] and session["auth_user"] == "relay"
    assert session["mail_from"] == "relay@example.org"
    assert session["rcpt"] == [["b@example.org", 250], ["gone@example.org", 550]]
    assert session["data_for"] == ["b@example.org"]
    # Dot-stuffing undone; the final CRLF is the client's, no extra line.
    assert session["message"].endswith(b"\r\n\r\n.leading dot\r\n")


def test_recording_sink_keeps_nothing_and_numbers_on(
    smtp: ScriptedSmtp, pki: dict[str, str], tmp_path: Path
) -> None:
    context = ssl.create_default_context(cafile=f"{pki['ca']}.pem")
    for run in range(2):  # the second sink is a restarted one
        sink = smtp.start(record_dir=tmp_path)
        with smtplib.SMTP("localhost", sink.port, timeout=5) as client:
            client.starttls(context=context)
            client.login("relay", "secret")
            client.send_message(_message(f"run {run}\n"))
        sink.settle()
        smtp.stop(sink)
        assert sink.sessions == [] and sink.tasks == set()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["000001.json", "000002.json"]
    first = session_from_json(json.loads((tmp_path / "000001.json").read_text()))
    assert first["message"].endswith(b"run 0\r\n") and first["data_for"] == ["b@example.org"]
