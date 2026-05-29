from __future__ import annotations

from pathlib import Path

import pytest

from mailgun_relay.config import (
    InvalidPolicyError,
    Settings,
    TokenPolicy,
    load_secrets,
)


def write_secrets(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "secrets.yml"
    p.write_text(body)
    p.chmod(0o600)
    return p


_VALID_BODY = """
smtp:
  username: relay@example.test
  password: hunter2
tokens:
  - label: t
    token_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    mailgun_domains: [wersdoerfer.de]
    allowed_from_domains: [wersdoerfer.de]
"""


def test_load_secrets_minimal(tmp_path: Path) -> None:
    secrets = load_secrets(
        write_secrets(
            tmp_path,
            """
smtp:
  username: relay@example.test
  password: hunter2
tokens:
  - label: homepage-staging
    token_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    mailgun_domains: [wersdoerfer.de]
    allowed_from_domains: [wersdoerfer.de]
""",
        )
    )
    assert secrets.smtp.username == "relay@example.test"
    assert secrets.smtp.password == "hunter2"
    assert len(secrets.tokens) == 1
    policy = secrets.tokens[0]
    assert policy.label == "homepage-staging"
    assert policy.mailgun_domains == {"wersdoerfer.de"}
    assert policy.allowed_from_domains == {"wersdoerfer.de"}
    assert policy.allowed_from_addresses is None


def test_load_secrets_normalizes_idn_to_punycode(tmp_path: Path) -> None:
    secrets = load_secrets(
        write_secrets(
            tmp_path,
            """
smtp:
  username: relay@wersdörfer.de
  password: pw
tokens:
  - label: t
    token_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    mailgun_domains: [wersdörfer.de]
    allowed_from_domains: [Wersdörfer.de]
    allowed_from_addresses:
      - Some.User@wersdörfer.de
""",
        )
    )
    policy = secrets.tokens[0]
    assert policy.mailgun_domains == {"xn--wersdrfer-47a.de"}
    assert policy.allowed_from_domains == {"xn--wersdrfer-47a.de"}
    assert policy.allowed_from_addresses == {"some.user@xn--wersdrfer-47a.de"}


def test_load_secrets_rejects_empty_tokens(tmp_path: Path) -> None:
    with pytest.raises(InvalidPolicyError):
        load_secrets(
            write_secrets(
                tmp_path,
                """
smtp:
  username: a
  password: b
tokens: []
""",
            )
        )


def test_load_secrets_rejects_changeme(tmp_path: Path) -> None:
    with pytest.raises(InvalidPolicyError):
        load_secrets(
            write_secrets(
                tmp_path,
                """
smtp:
  username: relay@example.test
  password: CHANGEME
tokens:
  - label: t
    token_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    mailgun_domains: [wersdoerfer.de]
    allowed_from_domains: [wersdoerfer.de]
""",
            )
        )


def test_load_secrets_rejects_bad_sha256(tmp_path: Path) -> None:
    with pytest.raises(InvalidPolicyError):
        load_secrets(
            write_secrets(
                tmp_path,
                """
smtp:
  username: a@b
  password: c
tokens:
  - label: t
    token_sha256: not-a-hex
    mailgun_domains: [wersdoerfer.de]
    allowed_from_domains: [wersdoerfer.de]
""",
            )
        )


def test_load_secrets_rejects_duplicate_labels(tmp_path: Path) -> None:
    with pytest.raises(InvalidPolicyError):
        load_secrets(
            write_secrets(
                tmp_path,
                """
smtp:
  username: a@b
  password: c
tokens:
  - label: same
    token_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    mailgun_domains: [wersdoerfer.de]
    allowed_from_domains: [wersdoerfer.de]
  - label: same
    token_sha256: 1111111111111111111111111111111111111111111111111111111111111111
    mailgun_domains: [wersdoerfer.de]
    allowed_from_domains: [wersdoerfer.de]
""",
            )
        )


def test_load_secrets_rejects_missing_mailgun_domains(tmp_path: Path) -> None:
    with pytest.raises(InvalidPolicyError):
        load_secrets(
            write_secrets(
                tmp_path,
                """
smtp:
  username: a@b
  password: c
tokens:
  - label: t
    token_sha256: 0000000000000000000000000000000000000000000000000000000000000000
    mailgun_domains: []
    allowed_from_domains: [wersdoerfer.de]
""",
            )
        )


def test_token_policy_repr_does_not_leak_sha(tmp_path: Path) -> None:
    secrets = load_secrets(
        write_secrets(
            tmp_path,
            """
smtp:
  username: a@b
  password: c
tokens:
  - label: t
    token_sha256: deadbeef00000000000000000000000000000000000000000000000000000000
    mailgun_domains: [wersdoerfer.de]
    allowed_from_domains: [wersdoerfer.de]
""",
        )
    )
    policy = secrets.tokens[0]
    assert "deadbeef" not in repr(policy)
    assert "label='t'" in repr(policy) or "label=t" in repr(policy)


@pytest.mark.parametrize("mode", [0o644, 0o604, 0o666, 0o660, 0o620])
def test_load_secrets_rejects_world_access_or_group_write(tmp_path: Path, mode: int) -> None:
    p = write_secrets(tmp_path, _VALID_BODY)
    p.chmod(mode)
    with pytest.raises(InvalidPolicyError):
        load_secrets(p)


@pytest.mark.parametrize("mode", [0o600, 0o400, 0o640, 0o440])
def test_load_secrets_accepts_owner_and_group_read_modes(tmp_path: Path, mode: int) -> None:
    # 0640 is the deployment layout (root:service-group); 0600/0400 also fine.
    p = tmp_path / f"secrets-{mode:o}.yml"
    p.write_text(_VALID_BODY)
    p.chmod(mode)
    secrets = load_secrets(p)
    assert secrets.smtp.username == "relay@example.test"


def test_settings_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAILGUN_RELAY_BIND_HOST", "0.0.0.0")  # noqa: S104
    monkeypatch.setenv("MAILGUN_RELAY_BIND_PORT", "9000")
    monkeypatch.setenv("MAILGUN_RELAY_SECRETS_PATH", "/etc/foo/secrets.yml")
    monkeypatch.setenv("MAILGUN_RELAY_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("MAILGUN_RELAY_SMTP_PORT", "587")
    monkeypatch.setenv("MAILGUN_RELAY_ENVELOPE_SENDER", "relay@example.test")
    monkeypatch.setenv("MAILGUN_RELAY_PUBLIC_HOST", "mailgun.home.xn--wersdrfer-47a.de")
    s = Settings()
    assert s.bind_host == "0.0.0.0"  # noqa: S104
    assert s.bind_port == 9000
    assert s.secrets_path == "/etc/foo/secrets.yml"
    assert s.smtp_host == "smtp.example.test"
    assert s.smtp_port == 587
    assert s.envelope_sender == "relay@example.test"
    assert s.public_host == "mailgun.home.xn--wersdrfer-47a.de"


def test_token_policy_allowed_addresses_none_means_domain_only() -> None:
    p = TokenPolicy(
        label="x",
        token_sha256="0" * 64,
        mailgun_domains=frozenset({"wersdoerfer.de"}),
        allowed_from_domains=frozenset({"wersdoerfer.de"}),
        allowed_from_addresses=None,
    )
    assert p.allowed_from_addresses is None
