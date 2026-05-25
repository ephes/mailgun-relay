from __future__ import annotations

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


def _validate_sha256_hex(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 64:
        raise InvalidPolicyError("token_sha256 must be 64 hex chars (sha256)")
    try:
        int(value, 16)
    except ValueError as exc:
        raise InvalidPolicyError("token_sha256 must be hex") from exc
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


def load_secrets(path: str | Path) -> Secrets:
    data_text = Path(path).read_text(encoding="utf-8")
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
