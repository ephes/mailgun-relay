from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from mailgun_relay.policy import normalize_address, normalize_domain


class InvalidPolicyError(ValueError):
    """Raised when the secrets file is malformed or unsafe to load."""


_FORBIDDEN_VALUES = {"CHANGEME", "changeme", "replace-me", ""}


@dataclass(frozen=True)
class TokenPolicy:
    label: str
    token_sha256: str = field(repr=False)
    mailgun_domains: frozenset[str]
    allowed_from_domains: frozenset[str]
    allowed_from_addresses: frozenset[str] | None = None


@dataclass(frozen=True)
class SmtpCredentials:
    username: str
    password: str = field(repr=False)


@dataclass(frozen=True)
class Secrets:
    smtp: SmtpCredentials
    tokens: tuple[TokenPolicy, ...]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MAILGUN_RELAY_",
        env_file=None,
        extra="ignore",
    )

    bind_host: str = "127.0.0.1"
    bind_port: int = 8085
    public_host: str = "mailgun.home.xn--wersdrfer-47a.de"
    secrets_path: str = "/etc/mailgun-relay/secrets.yml"

    smtp_host: str = "smtp.home.xn--wersdrfer-47a.de"
    smtp_port: int = 587
    smtp_starttls: bool = True
    smtp_timeout_s: float = 30.0
    # Optional CA bundle for verifying the SMTP server certificate. Empty means
    # "use the system trust store"; certificate verification is never disabled.
    smtp_ca_file: str = ""
    envelope_sender: str = ""

    max_body_bytes: int = 26_214_400
    max_attachments: int = 10
    max_attachment_bytes: int = 10_485_760
    max_recipients: int = 100
    max_header_value_length: int = 998

    log_level: str = Field(default="INFO")


def _reject_changeme(field_name: str, value: str) -> None:
    if value in _FORBIDDEN_VALUES:
        raise InvalidPolicyError(f"{field_name}: refuses placeholder/empty value")


_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _validate_sha256_hex(value: str) -> str:
    # Strict canonical form only. `int(value, 16)` would accept non-canonical
    # spellings (0x-prefix, +/- signs, underscore separators) that can never
    # equal a real hashlib hexdigest, masking a misconfigured (dead) token.
    value = value.strip().lower()
    if not _SHA256_HEX_RE.match(value):
        raise InvalidPolicyError("token_sha256 must be 64 lowercase hex chars (sha256)")
    return value


def _coerce_domain_set(field_name: str, raw: object) -> frozenset[str]:
    if not isinstance(raw, list) or not raw:
        raise InvalidPolicyError(f"{field_name} must be a non-empty list")
    normalized: set[str] = set()
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise InvalidPolicyError(f"{field_name}: entries must be non-empty strings")
        normalized.add(normalize_domain(item))
    return frozenset(normalized)


def _coerce_optional_address_set(raw: object) -> frozenset[str] | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise InvalidPolicyError("allowed_from_addresses must be a list when present")
    if not raw:
        return None
    normalized: set[str] = set()
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise InvalidPolicyError("allowed_from_addresses: entries must be non-empty strings")
        normalized.add(normalize_address(item))
    return frozenset(normalized)


def _load_policy_entry(raw: object) -> TokenPolicy:
    if not isinstance(raw, dict):
        raise InvalidPolicyError("each token entry must be a mapping")
    label = raw.get("label")
    if not isinstance(label, str) or not label.strip():
        raise InvalidPolicyError("token.label must be a non-empty string")
    _reject_changeme(f"token[{label}].label", label)

    token_sha256_raw = raw.get("token_sha256")
    if isinstance(token_sha256_raw, int):
        token_sha256_raw = format(token_sha256_raw, "064x")
    if not isinstance(token_sha256_raw, str):
        raise InvalidPolicyError(f"token[{label}].token_sha256 must be a hex string")
    _reject_changeme(f"token[{label}].token_sha256", token_sha256_raw)
    token_sha256 = _validate_sha256_hex(token_sha256_raw)

    mailgun_domains = _coerce_domain_set(
        f"token[{label}].mailgun_domains", raw.get("mailgun_domains")
    )
    allowed_from_domains = _coerce_domain_set(
        f"token[{label}].allowed_from_domains", raw.get("allowed_from_domains")
    )
    allowed_from_addresses = _coerce_optional_address_set(raw.get("allowed_from_addresses"))

    return TokenPolicy(
        label=label,
        token_sha256=token_sha256,
        mailgun_domains=mailgun_domains,
        allowed_from_domains=allowed_from_domains,
        allowed_from_addresses=allowed_from_addresses,
    )


def _load_smtp(raw: object) -> SmtpCredentials:
    if not isinstance(raw, dict):
        raise InvalidPolicyError("smtp section must be a mapping")
    username = raw.get("username")
    password = raw.get("password")
    if not isinstance(username, str) or not username.strip():
        raise InvalidPolicyError("smtp.username must be a non-empty string")
    if not isinstance(password, str):
        raise InvalidPolicyError("smtp.password must be a string")
    _reject_changeme("smtp.username", username)
    _reject_changeme("smtp.password", password)
    return SmtpCredentials(username=username, password=password)


# Permission bits that must NOT be set on the secrets file: any world access
# (r/w/x) and group write/execute. Group *read* is intentionally allowed so the
# deployment's `0640 root:<service-group>` layout works — the file is owned by
# root and the service reads it via its dedicated group.
_FORBIDDEN_SECRET_MODE_BITS = 0o037


def _check_secret_file_permissions(path: Path) -> None:
    """Refuse to load a secrets file that is world-accessible or group-writable.

    The file holds the SMTP password and token hashes; an over-permissive mode
    (e.g. ``0644`` or ``0660``) would expose or allow tampering with them. We
    require ``0640`` or stricter (``0600``/``0400`` also fine). POSIX only; the
    mode bits are not meaningful elsewhere. The error names only the path and
    mode — never the secret content.
    """
    if os.name != "posix":
        return
    mode = path.stat().st_mode
    if mode & _FORBIDDEN_SECRET_MODE_BITS:
        raise InvalidPolicyError(
            f"secrets file {str(path)!r} is world-accessible or group-writable "
            f"(mode {oct(mode & 0o777)}); restrict it to 0640 or stricter"
        )


def load_secrets(path: str | Path) -> Secrets:
    resolved = Path(path)
    _check_secret_file_permissions(resolved)
    data_text = resolved.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(data_text)
    except yaml.YAMLError as exc:
        raise InvalidPolicyError(f"secrets file is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise InvalidPolicyError("secrets file must be a top-level mapping")

    smtp = _load_smtp(data.get("smtp"))

    tokens_raw = data.get("tokens")
    if not isinstance(tokens_raw, list) or not tokens_raw:
        raise InvalidPolicyError("tokens must be a non-empty list")

    tokens: list[TokenPolicy] = []
    seen_labels: set[str] = set()
    for entry in tokens_raw:
        policy = _load_policy_entry(entry)
        if policy.label in seen_labels:
            raise InvalidPolicyError(f"duplicate token label: {policy.label}")
        seen_labels.add(policy.label)
        tokens.append(policy)

    return Secrets(smtp=smtp, tokens=tuple(tokens))
