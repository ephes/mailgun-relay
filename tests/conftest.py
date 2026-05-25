from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mailgun_relay.app import create_app
from mailgun_relay.config import Secrets, Settings, SmtpCredentials, TokenPolicy
from mailgun_relay.routes import AppState
from mailgun_relay.smtp_client import SmtpTransport


@dataclass
class RecordedSend:
    envelope_sender: str
    recipients: list[str]
    message: EmailMessage
    transport: SmtpTransport


@dataclass
class RecordingSubmitter:
    """Drop-in replacement for `smtp_client.submit` used in route tests."""

    raise_with: Exception | None = None
    calls: list[RecordedSend] = field(default_factory=list)

    def __call__(
        self,
        message: EmailMessage,
        *,
        envelope_sender: str,
        recipients: list[str],
        transport: SmtpTransport,
    ) -> None:
        self.calls.append(
            RecordedSend(
                envelope_sender=envelope_sender,
                recipients=list(recipients),
                message=message,
                transport=transport,
            )
        )
        if self.raise_with is not None:
            raise self.raise_with


_TEST_TOKEN_HOMEPAGE = "homepage-token-secret"
_TEST_TOKEN_PODCAST = "podcast-token-secret"


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@pytest.fixture
def homepage_token() -> str:
    return _TEST_TOKEN_HOMEPAGE


@pytest.fixture
def podcast_token() -> str:
    return _TEST_TOKEN_PODCAST


@pytest.fixture
def test_secrets() -> Secrets:
    return Secrets(
        smtp=SmtpCredentials(
            username="mailgun-relay@xn--wersdrfer-47a.de",
            password="not-a-real-password",
        ),
        tokens=(
            TokenPolicy(
                # Mirrors the shipped production policy: the Mailgun path
                # subdomain (mg.wersdoerfer.de) is distinct from the from-domain
                # (wersdoerfer.de) — this is the cross-domain case Anymail
                # uses for homepage. Tests exercise this shape end-to-end.
                label="homepage-staging",
                token_sha256=_sha(_TEST_TOKEN_HOMEPAGE),
                mailgun_domains=frozenset({"mg.wersdoerfer.de"}),
                allowed_from_domains=frozenset({"wersdoerfer.de"}),
                allowed_from_addresses=frozenset({"jochen-homepage@wersdoerfer.de"}),
            ),
            TokenPolicy(
                label="python-podcast-staging",
                token_sha256=_sha(_TEST_TOKEN_PODCAST),
                mailgun_domains=frozenset({"mg.python-podcast.de"}),
                allowed_from_domains=frozenset({"mg.python-podcast.de"}),
                allowed_from_addresses=frozenset({"noreply@mg.python-podcast.de"}),
            ),
        ),
    )


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    return Settings(
        bind_host="127.0.0.1",
        bind_port=8085,
        public_host="mailgun.home.xn--wersdrfer-47a.de",
        secrets_path=str(tmp_path / "unused-in-tests.yml"),
        smtp_host="127.0.0.1",
        smtp_port=12525,
        smtp_starttls=False,
        smtp_timeout_s=5.0,
        envelope_sender="mailgun-relay@xn--wersdrfer-47a.de",
        max_body_bytes=1_048_576,
        max_attachments=3,
        max_attachment_bytes=524_288,
        max_recipients=10,
        max_header_value_length=998,
        log_level="INFO",
    )


@pytest.fixture
def recording_smtp() -> RecordingSubmitter:
    return RecordingSubmitter()


@pytest.fixture
def app_state(
    test_settings: Settings, test_secrets: Secrets, recording_smtp: RecordingSubmitter
) -> AppState:
    transport = SmtpTransport(
        host=test_settings.smtp_host,
        port=test_settings.smtp_port,
        username=test_secrets.smtp.username,
        password=test_secrets.smtp.password,
        use_starttls=test_settings.smtp_starttls,
        timeout_s=test_settings.smtp_timeout_s,
    )
    return AppState(
        settings=test_settings,
        secrets=test_secrets,
        transport=transport,
        smtp_submit=recording_smtp,
    )


@pytest.fixture
def client(app_state: AppState) -> Iterator[TestClient]:
    app = create_app(app_state=app_state)
    with TestClient(app) as tc:
        yield tc
