from __future__ import annotations

import os
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
    assert policy.allowed_from_addresses == frozenset({"some.user@xn--wersdrfer-47a.de"})


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


@pytest.mark.parametrize(
    "value,expected",
    [
        ("", ""),
        ("mailgun-relay@xn--wersdrfer-47a.de", "mailgun-relay@xn--wersdrfer-47a.de"),
        ("relay@wersdörfer.de", "relay@xn--wersdrfer-47a.de"),
        ("relay@WERSDÖRFER.DE", "relay@xn--wersdrfer-47a.de"),
    ],
)
def test_envelope_sender_is_ascii_after_startup(value: str, expected: str) -> None:
    assert Settings(envelope_sender=value).envelope_sender == expected


@pytest.mark.parametrize(
    "value", ["jörg@example.test", "jörg@wersdörfer.de", "wersdörfer", "a@-ö.de"]
)
def test_envelope_sender_that_needs_smtputf8_fails_startup(value: str) -> None:
    with pytest.raises(ValueError, match="envelope_sender"):
        Settings(envelope_sender=value)


def test_envelope_sender_from_env_fails_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAILGUN_RELAY_ENVELOPE_SENDER", "jörg@example.test")
    with pytest.raises(ValueError, match="envelope_sender"):
        Settings()


@pytest.mark.parametrize(
    "field,value",
    [
        ("smtp_timeout_s", value)
        for value in [float("nan"), float("inf"), float("-inf"), 0, -1, 1e10]
    ]
    + [(field, value) for field in ["smtp_port", "bind_port"] for value in [-1, 0, 65536]]
    + [
        (field, -1)
        for field in [
            "max_body_bytes",
            "max_attachments",
            "max_attachment_bytes",
            "max_recipients",
            "max_header_value_length",
        ]
    ],
)
def test_invalid_transport_settings_fail_before_app_start(
    monkeypatch: pytest.MonkeyPatch, field: str, value: float
) -> None:
    from mailgun_relay.app import create_app

    monkeypatch.setenv(f"MAILGUN_RELAY_{field.upper()}", str(value))
    monkeypatch.setattr(
        "mailgun_relay.app._app_state_from_settings",
        lambda *_: pytest.fail("invalid settings reached secret/transport initialization"),
    )
    with pytest.raises(ValueError, match=field):
        create_app()


def test_small_transport_boundaries_are_supported() -> None:
    settings = Settings(
        bind_port=1,
        smtp_port=65535,
        smtp_timeout_s=0.001,
        max_body_bytes=1,
        max_attachments=0,
        max_attachment_bytes=0,
        max_recipients=1,
        max_header_value_length=0,
    )
    assert settings.smtp_timeout_s == 0.001
    assert settings.max_attachments == 0


def test_secret_file_read_cap(tmp_path: Path) -> None:
    path = write_secrets(tmp_path, _VALID_BODY + "#" + "x" * 1_048_576)
    with pytest.raises(InvalidPolicyError, match="exceeds"):
        load_secrets(path)


def test_secret_file_special_files_and_symlinks(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    directory = tmp_path / "directory"
    directory.mkdir(mode=0o700)
    valid = write_secrets(tmp_path, _VALID_BODY)
    link = tmp_path / "link"
    link.symlink_to(valid)
    for path in (fifo, directory, link):
        with pytest.raises(InvalidPolicyError):
            load_secrets(path)
    valid.write_bytes(b"\xff")
    with pytest.raises(InvalidPolicyError, match="UTF-8"):
        load_secrets(valid)


def test_secret_file_validates_and_reads_the_open_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_secrets(tmp_path, _VALID_BODY)
    opened = os.open
    calls = []

    def replace_after_open(name: str | Path, flags: int) -> int:
        fd = opened(name, flags)
        calls.append(fd)
        path.rename(tmp_path / "original")
        path.write_text("smtp: {password: replacement-marker}")
        path.chmod(0o644)
        return fd

    monkeypatch.setattr(os, "open", replace_after_open)
    assert load_secrets(path).smtp.password == "hunter2"
    assert len(calls) == 1
    monkeypatch.setattr(os, "open", opened)
    with pytest.raises(InvalidPolicyError):
        load_secrets(path)


@pytest.mark.parametrize("reverse", [False, True])
def test_duplicate_normalized_token_digest_refused(tmp_path: Path, reverse: bool) -> None:
    digest = "ab" * 32
    first = _VALID_BODY.replace("0" * 64, f'"{digest}"')
    prefix, token = first.split("tokens:\n")
    other = (
        token.replace("label: t", "label: synthetic-label-marker")
        .replace(f'"{digest}"', f'"  {digest.upper()}  "')
        .replace("wersdoerfer.de", "example.test")
    )
    text = prefix + "tokens:\n" + (other + token if reverse else token + other)
    with pytest.raises(InvalidPolicyError, match="duplicate token digest") as caught:
        load_secrets(write_secrets(tmp_path, text))
    assert digest not in str(caught.value).lower()
    assert "synthetic-label-marker" not in str(caught.value)
