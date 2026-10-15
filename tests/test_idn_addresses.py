"""IDN domains travel as A-labels; non-ASCII (EAI) local parts are refused.

The relay never submits with SMTPUTF8. An IDN domain in any address is
written to the headers and the envelope as its A-label (punycode); an address
whose local part is not ASCII cannot be expressed that way and is a 400.
Recipients are attacker-chosen in practice (a password-reset form mails any
address a visitor types in), so these paths are reachable from outside.
"""

from __future__ import annotations

import hashlib
import socket
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from typing import Any

import pytest
from aiosmtpd.controller import Controller
from fastapi.testclient import TestClient

from mailgun_relay.app import create_app
from mailgun_relay.config import Secrets, Settings, TokenPolicy
from mailgun_relay.mime_build import MessageInput, build_message
from mailgun_relay.routes import AppState
from mailgun_relay.smtp_client import SmtpTransport, submit
from tests.conftest import _TEST_TOKEN_HOMEPAGE, RecordingSubmitter
from tests.test_messages_endpoint import _ENCODINGS, _minimum_form, _post_form, _with, basic

_A_LABEL = "xn--wersdrfer-47a.de"
_U_LABEL = "wersdörfer.de"

_IDN_TOKEN = "idn-domain-only-token"
_DOMAIN_ONLY_TOKEN = "domain-only-token"


def _policy(label: str, token: str, mailgun: str, from_domain: str) -> TokenPolicy:
    return TokenPolicy(
        label=label,
        token_sha256=hashlib.sha256(token.encode()).hexdigest(),
        mailgun_domains=frozenset({mailgun}),
        allowed_from_domains=frozenset({from_domain}),
        allowed_from_addresses=None,
    )


@pytest.fixture
def extended_state(app_state: AppState, test_secrets: Secrets) -> AppState:
    """The shared test policies plus two domain-only tokens (no address allowlist)."""
    secrets = replace(
        test_secrets,
        tokens=(
            *test_secrets.tokens,
            _policy("idn-domain-only", _IDN_TOKEN, _A_LABEL, _A_LABEL),
            _policy("domain-only", _DOMAIN_ONLY_TOKEN, "mg.wersdoerfer.de", "wersdoerfer.de"),
        ),
    )
    return replace(app_state, secrets=secrets)


@pytest.fixture
def ext_client(extended_state: AppState) -> Iterator[TestClient]:
    with TestClient(create_app(app_state=extended_state)) as tc:
        yield tc


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": basic("api", token)}


@pytest.fixture
def auth(homepage_token: str) -> dict[str, str]:
    return _auth(homepage_token)


# --- recipients ------------------------------------------------------------


@pytest.mark.parametrize("encoding", _ENCODINGS)
@pytest.mark.parametrize(
    "to",
    [
        f"foo@{_A_LABEL}",
        f"foo@{_U_LABEL}",
        f"foo@{_U_LABEL.upper()}",
        f"Jörg <foo@{_U_LABEL}>",
    ],
)
def test_idn_recipient_is_sent_as_a_label(
    client: TestClient,
    auth: dict[str, str],
    recording_smtp: RecordingSubmitter,
    to: str,
    encoding: str,
) -> None:
    form = _minimum_form() | {"to": [to]}
    r = _post_form(client, auth, form, encoding=encoding)
    assert r.status_code == 200, r.text
    sent = recording_smtp.calls[0]
    assert sent.recipients == [f"foo@{_A_LABEL}"]
    assert f"foo@{_A_LABEL}" in str(sent.message["To"])
    raw = bytes(sent.message)
    assert raw.isascii()
    assert f"foo@{_A_LABEL}".encode() in raw


def test_idn_cc_bcc_and_reply_to_are_a_labels(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    form = _with(
        {
            "cc": [f"Cc Person <cc@{_U_LABEL}>"],
            "bcc": ["hidden@bü.test"],
            "h:Reply-To": [f"Jörg <reply@{_U_LABEL}>, other@bü.test"],
        }
    )
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 200, r.text
    sent = recording_smtp.calls[0]
    assert sent.recipients == [
        "admin@wersdoerfer.de",
        f"cc@{_A_LABEL}",
        "hidden@xn--b-eha.test",
    ]
    assert f"cc@{_A_LABEL}" in str(sent.message["Cc"])
    reply_to = str(sent.message["Reply-To"])
    assert f"reply@{_A_LABEL}" in reply_to
    assert "other@xn--b-eha.test" in reply_to
    raw = bytes(sent.message)
    assert raw.isascii()
    assert b"hidden@" not in raw


def test_u_label_and_a_label_recipient_deduplicate(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    form = _minimum_form() | {"to": [f"foo@{_U_LABEL}"], "cc": [f"foo@{_A_LABEL}"]}
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 200, r.text
    assert recording_smtp.calls[0].recipients == [f"foo@{_A_LABEL}"]


@pytest.mark.parametrize("encoding", _ENCODINGS)
@pytest.mark.parametrize(
    "extra",
    [
        {"to": ["jörg@example.org"]},
        {"to": [f"Jörg <jörg@{_U_LABEL}>"]},
        {"cc": ["jörg@example.org"]},
        {"bcc": ["jörg@example.org"]},
        {"h:Reply-To": ["support@wersdoerfer.de, jörg@example.org"]},
    ],
)
def test_eai_local_part_in_recipient_fields_returns_400(
    client: TestClient,
    auth: dict[str, str],
    recording_smtp: RecordingSubmitter,
    extra: dict[str, list[str]],
    encoding: str,
) -> None:
    r = _post_form(client, auth, _with(extra), encoding=encoding)
    assert r.status_code == 400, r.text
    assert set(r.json()) == {"message"}
    assert recording_smtp.calls == []


@pytest.mark.parametrize(
    "domain,extra,status",
    [
        # Policy (step 5) comes before message construction.
        ("mg.python-podcast.de", {"to": ["jörg@example.org"]}, 403),
        ("mg.wersdoerfer.de", {"from": ["intruder@example.org"], "to": ["jörg@example.org"]}, 403),
        # Recipient count (step 8) comes before message construction.
        (
            "mg.wersdoerfer.de",
            {"to": ["jörg@example.org"] + [f"r{i}@wersdoerfer.de" for i in range(10)]},
            413,
        ),
    ],
)
def test_eai_recipient_keeps_decision_order(
    client: TestClient,
    auth: dict[str, str],
    recording_smtp: RecordingSubmitter,
    domain: str,
    extra: dict[str, list[str]],
    status: int,
) -> None:
    form = _minimum_form() | extra
    r = client.post(f"/v3/{domain}/messages", headers=auth, data=form)
    assert r.status_code == status, r.text
    assert recording_smtp.calls == []


# --- from and the sender policy ---------------------------------------------


@pytest.mark.parametrize("encoding", _ENCODINGS)
@pytest.mark.parametrize(
    "sender", [f"Jochen <jochen@{_U_LABEL}>", f"jochen@{_A_LABEL}", f"jochen@{_U_LABEL.upper()}"]
)
def test_idn_from_is_allowed_and_rendered_as_a_label(
    ext_client: TestClient, recording_smtp: RecordingSubmitter, sender: str, encoding: str
) -> None:
    form = _minimum_form() | {"from": [sender]}
    r = _post_form(ext_client, _auth(_IDN_TOKEN), form, encoding=encoding, domain=_A_LABEL)
    assert r.status_code == 200, r.text
    sent = recording_smtp.calls[0].message
    assert f"jochen@{_A_LABEL}" in str(sent["From"])
    assert bytes(sent).isascii()


def test_idn_from_outside_allowed_domains_is_still_403(
    ext_client: TestClient, recording_smtp: RecordingSubmitter
) -> None:
    # wersdörfer.de is not wersdoerfer.de: the A-label differs.
    form = _minimum_form() | {"from": [f"jochen@{_U_LABEL}"]}
    r = ext_client.post(
        "/v3/mg.wersdoerfer.de/messages", headers=_auth(_DOMAIN_ONLY_TOKEN), data=form
    )
    assert r.status_code == 403, r.text
    assert recording_smtp.calls == []


@pytest.mark.parametrize("encoding", _ENCODINGS)
@pytest.mark.parametrize(
    "token,domain,sender",
    [
        # Domain-only policies: the domain is allowed, the local part is not ASCII.
        (_DOMAIN_ONLY_TOKEN, "mg.wersdoerfer.de", "jörg@wersdoerfer.de"),
        (_DOMAIN_ONLY_TOKEN, "mg.wersdoerfer.de", "Jörg <jörg@wersdoerfer.de>"),
        (_IDN_TOKEN, _A_LABEL, f"jörg@{_U_LABEL}"),
        # Address allowlist: rejected as a malformed sender before the lookup.
        (_TEST_TOKEN_HOMEPAGE, "mg.wersdoerfer.de", "jöchen-homepage@wersdoerfer.de"),
    ],
)
def test_eai_from_returns_400(
    ext_client: TestClient,
    recording_smtp: RecordingSubmitter,
    token: str,
    domain: str,
    sender: str,
    encoding: str,
) -> None:
    form = _minimum_form() | {"from": [sender]}
    r = _post_form(ext_client, _auth(token), form, encoding=encoding, domain=domain)
    assert r.status_code == 400, r.text
    assert set(r.json()) == {"message"}
    assert recording_smtp.calls == []


def test_ascii_from_on_domain_only_policy_is_still_accepted(
    ext_client: TestClient, recording_smtp: RecordingSubmitter
) -> None:
    form = _minimum_form() | {"from": ["Anyone <anyone@wersdoerfer.de>"]}
    r = ext_client.post(
        "/v3/mg.wersdoerfer.de/messages", headers=_auth(_DOMAIN_ONLY_TOKEN), data=form
    )
    assert r.status_code == 200, r.text
    assert len(recording_smtp.calls) == 1


def test_eai_from_on_foreign_path_domain_is_403(
    ext_client: TestClient, recording_smtp: RecordingSubmitter
) -> None:
    # The path domain is checked before the sender is parsed.
    form = _minimum_form() | {"from": ["jörg@wersdoerfer.de"]}
    r = ext_client.post(
        "/v3/mg.python-podcast.de/messages", headers=_auth(_DOMAIN_ONLY_TOKEN), data=form
    )
    assert r.status_code == 403, r.text


# --- SMTP: no SMTPUTF8 on the wire -------------------------------------------


@dataclass
class _EnvelopeRecorder:
    mail_from: str | None = None
    mail_options: list[str] = field(default_factory=list)
    rcpt_tos: list[str] = field(default_factory=list)
    content: bytes | None = None

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:  # noqa: N802
        self.mail_from = envelope.mail_from
        self.mail_options = list(envelope.mail_options)
        self.rcpt_tos = list(envelope.rcpt_tos)
        self.content = envelope.original_content
        return "250 Message accepted"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def smtputf8_server() -> Iterator[tuple[_EnvelopeRecorder, int]]:
    """A server that offers SMTPUTF8, so smtplib would use it if it had to."""
    handler = _EnvelopeRecorder()
    port = _free_port()
    controller = Controller(handler, hostname="127.0.0.1", port=port, enable_SMTPUTF8=True)
    controller.start()
    try:
        yield handler, port
    finally:
        controller.stop()


def _transport(port: int) -> SmtpTransport:
    return SmtpTransport(
        host="127.0.0.1",
        port=port,
        username=None,
        password=None,
        use_starttls=False,
        timeout_s=5.0,
    )


def _real_smtp_client(
    app_state: AppState, port: int, settings: Settings | None = None
) -> TestClient:
    state = replace(
        app_state,
        settings=settings or app_state.settings,
        smtp_submit=submit,
        transport=_transport(port),
    )
    return TestClient(create_app(app_state=state))


def test_fixture_server_detects_smtputf8(smtputf8_server: tuple[_EnvelopeRecorder, int]) -> None:
    """Guard for the tests below: a U-label envelope does trigger SMTPUTF8 here."""
    handler, port = smtputf8_server
    msg, _, _ = build_message(
        MessageInput(
            from_address="a@example.test",
            to=["b@example.test"],
            cc=[],
            bcc=[],
            subject="s",
            text="t",
            html=None,
            amp_html=None,
            custom_headers={},
            attachments=[],
            inline=[],
            public_host="relay.example.test",
        )
    )
    submit(msg, envelope_sender="", recipients=[f"b@{_U_LABEL}"], transport=_transport(port))
    assert "SMTPUTF8" in handler.mail_options


@pytest.mark.parametrize("to", [f"visitor@{_U_LABEL}", f"visitor@{_A_LABEL}"])
def test_external_idn_recipient_end_to_end_without_smtputf8(
    app_state: AppState,
    homepage_token: str,
    smtputf8_server: tuple[_EnvelopeRecorder, int],
    to: str,
) -> None:
    """The allauth "unknown account" shape: plain recipient typed in by a visitor."""
    handler, port = smtputf8_server
    form = _minimum_form() | {"to": [to], "subject": ["Password reset"]}
    with _real_smtp_client(app_state, port) as client:
        r = client.post("/v3/mg.wersdoerfer.de/messages", headers=_auth(homepage_token), data=form)
    assert r.status_code == 200, r.text
    assert "SMTPUTF8" not in handler.mail_options
    assert handler.mail_from == "mailgun-relay@xn--wersdrfer-47a.de"
    assert handler.rcpt_tos == [f"visitor@{_A_LABEL}"]
    assert handler.content is not None
    assert handler.content.isascii()
    assert f"To: visitor@{_A_LABEL}".encode() in handler.content


def test_idn_envelope_sender_is_normalized_and_sent_without_smtputf8(
    app_state: AppState,
    test_settings: Settings,
    homepage_token: str,
    smtputf8_server: tuple[_EnvelopeRecorder, int],
) -> None:
    handler, port = smtputf8_server
    settings = Settings(**{**test_settings.model_dump(), "envelope_sender": f"relay@{_U_LABEL}"})
    assert settings.envelope_sender == f"relay@{_A_LABEL}"
    with _real_smtp_client(app_state, port, settings) as client:
        r = client.post(
            "/v3/mg.wersdoerfer.de/messages", headers=_auth(homepage_token), data=_minimum_form()
        )
    assert r.status_code == 200, r.text
    assert handler.mail_from == f"relay@{_A_LABEL}"
    assert "SMTPUTF8" not in handler.mail_options


def test_empty_envelope_sender_is_still_the_null_sender(
    app_state: AppState,
    test_settings: Settings,
    homepage_token: str,
    smtputf8_server: tuple[_EnvelopeRecorder, int],
) -> None:
    handler, port = smtputf8_server
    settings = Settings(**{**test_settings.model_dump(), "envelope_sender": ""})
    with _real_smtp_client(app_state, port, settings) as client:
        r = client.post(
            "/v3/mg.wersdoerfer.de/messages", headers=_auth(homepage_token), data=_minimum_form()
        )
    assert r.status_code == 200, r.text
    assert handler.mail_from == "<>"
    assert "SMTPUTF8" not in handler.mail_options
