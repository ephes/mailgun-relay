from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mailgun_relay.policy import InvalidAddressError, normalize_address, normalize_domain


class InvalidPolicyError(ValueError):
    """Raised when the secrets file is malformed or unsafe to load."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader with duplicate mapping-key refusal, including merged keys."""

    def flatten_mapping(self, node: yaml.MappingNode) -> None:
        # This hook also visits nested merge sources before consuming markers.
        if sum(key.tag == "tag:yaml.org,2002:merge" for key, _ in node.value) > 1:
            raise InvalidPolicyError("secrets file: duplicate mapping key")
        super().flatten_mapping(node)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        seen: set[object] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in seen:
                    raise InvalidPolicyError("secrets file: duplicate mapping key")
                seen.add(key)
            except TypeError:
                raise InvalidPolicyError("secrets file: non-string mapping key") from None
        return super().construct_mapping(node, deep=deep)


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
    bind_port: int = Field(default=8085, ge=1, le=65535)
    public_host: str = "mailgun.home.xn--wersdrfer-47a.de"
    secrets_path: str = "/etc/mailgun-relay/secrets.yml"

    smtp_host: str = "smtp.home.xn--wersdrfer-47a.de"
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_starttls: bool = True
    smtp_timeout_s: float = Field(default=30.0, gt=0, le=1e9, allow_inf_nan=False)
    # Optional CA bundle for verifying the SMTP server certificate. Empty means
    # "use the system trust store"; certificate verification is never disabled.
    smtp_ca_file: str = ""
    # Upper bound on concurrent SMTP submissions (each runs in a worker
    # thread), including body/MIME preparation; excess sends receive 503.
    smtp_max_concurrency: int = Field(default=8, ge=1)
    envelope_sender: str = ""
    # When the SMTP server accepts the message for some recipients but refuses
    # others, the relay answers 200 by default (the message *was* sent, and a
    # client retry would duplicate it for the accepted recipients) and logs a
    # WARNING. Set this to answer 502 instead, for callers that prefer a hard
    # failure over a partially delivered message.
    fail_on_partial_refusal: bool = False

    max_body_bytes: int = Field(default=26_214_400, ge=1)
    max_attachments: int = Field(default=10, ge=0)
    max_attachment_bytes: int = Field(default=10_485_760, ge=0)
    max_recipients: int = Field(default=100, ge=1)
    max_header_value_length: int = Field(default=998, ge=0)

    log_level: str = Field(default="INFO")

    @field_validator("envelope_sender")
    @classmethod
    def _envelope_sender_ascii(cls, value: str) -> str:
        """Keep ``MAIL FROM`` ASCII so smtplib never switches to SMTPUTF8.

        Empty stays the null sender and an ASCII value is used unchanged. An
        IDN domain is converted to its A-label; a non-ASCII local part cannot
        be expressed without SMTPUTF8 and stops the process at startup.
        """
        if value.isascii():
            return value
        local, sep, domain = value.rpartition("@")
        if not sep or not local or not local.isascii():
            raise ValueError(
                "envelope_sender: only the domain may be non-ASCII (SMTPUTF8 is not used)"
            )
        return f"{local}@{normalize_domain(domain)}"


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
    for index, item in enumerate(raw):
        if not isinstance(item, str) or not item.strip():
            raise InvalidPolicyError(f"{field_name}: entries must be non-empty strings")
        try:
            normalized.add(normalize_domain(item))
        except InvalidAddressError:
            raise InvalidPolicyError(f"{field_name}[{index}]: invalid domain") from None
    return frozenset(normalized)


def _coerce_optional_address_set(raw: object, at: str) -> frozenset[str] | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise InvalidPolicyError(f"{at} must be a list when present")
    if not raw:
        return None
    normalized: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, str) or not item.strip():
            raise InvalidPolicyError(f"{at}[{index}]: entries must be non-empty strings")
        try:
            normalized.add(normalize_address(item))
        except InvalidAddressError:
            raise InvalidPolicyError(f"{at}[{index}]: invalid address") from None
    return frozenset(normalized)


def _check_keys(raw: dict[object, object], allowed: set[str], at: str) -> None:
    if any(not isinstance(key, str) or key not in allowed for key in raw):
        raise InvalidPolicyError(f"{at}: unknown or non-string field")


def _load_policy_entry(raw: object, at: str) -> TokenPolicy:
    if not isinstance(raw, dict):
        raise InvalidPolicyError(f"{at}: each token entry must be a mapping")
    _check_keys(
        raw,
        {
            "label",
            "token_sha256",
            "mailgun_domains",
            "allowed_from_domains",
            "allowed_from_addresses",
        },
        at,
    )
    label = raw.get("label")
    if not isinstance(label, str) or not label.strip():
        raise InvalidPolicyError(f"{at}.label must be a non-empty string")
    _reject_changeme(f"{at}.label", label)

    token_sha256_raw = raw.get("token_sha256")
    if isinstance(token_sha256_raw, int):
        token_sha256_raw = format(token_sha256_raw, "064x")
    if not isinstance(token_sha256_raw, str):
        raise InvalidPolicyError(f"{at}.token_sha256 must be a hex string")
    _reject_changeme(f"{at}.token_sha256", token_sha256_raw)
    token_sha256 = _validate_sha256_hex(token_sha256_raw)

    mailgun_domains = _coerce_domain_set(f"{at}.mailgun_domains", raw.get("mailgun_domains"))
    allowed_from_domains = _coerce_domain_set(
        f"{at}.allowed_from_domains", raw.get("allowed_from_domains")
    )
    allowed_from_addresses = _coerce_optional_address_set(
        raw.get("allowed_from_addresses"), f"{at}.allowed_from_addresses"
    )

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
    _check_keys(raw, {"username", "password"}, "smtp")
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


# One MiB, matching Rust; reject a final symlink, allow operator-owned parents.
MAX_SECRET_BYTES = 1_048_576


def _read_secret_file(path: Path) -> str:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise InvalidPolicyError(f"secrets file cannot be opened (errno {exc.errno})") from None
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise InvalidPolicyError("secrets file must be a regular file")
        if metadata.st_mode & _FORBIDDEN_SECRET_MODE_BITS:
            raise InvalidPolicyError(
                "secrets file is world-accessible or group-writable; restrict to 0640 or stricter"
            )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_SECRET_BYTES + 1)
    except OSError as exc:
        raise InvalidPolicyError(f"cannot read secrets file (errno {exc.errno})") from None
    finally:
        os.close(fd)
    if len(data) > MAX_SECRET_BYTES:
        raise InvalidPolicyError("secrets file exceeds 1048576 bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidPolicyError("secrets file is not valid UTF-8") from None


def load_secrets(path: str | Path) -> Secrets:
    data_text = _read_secret_file(Path(path))
    try:
        data = yaml.load(data_text, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except InvalidPolicyError:
        raise
    except yaml.YAMLError, ValueError, TypeError, OverflowError:
        raise InvalidPolicyError("secrets file is not valid YAML") from None
    if not isinstance(data, dict):
        raise InvalidPolicyError("secrets file must be a top-level mapping")

    _check_keys(data, {"smtp", "tokens"}, "root")
    smtp = _load_smtp(data.get("smtp"))

    tokens_raw = data.get("tokens")
    if not isinstance(tokens_raw, list) or not tokens_raw:
        raise InvalidPolicyError("tokens must be a non-empty list")

    tokens: list[TokenPolicy] = []
    seen_labels: set[str] = set()
    seen_digests: set[str] = set()
    for index, entry in enumerate(tokens_raw):
        policy = _load_policy_entry(entry, f"tokens[{index}]")
        if policy.label in seen_labels:
            raise InvalidPolicyError(f"tokens[{index}]: duplicate token label")
        if policy.token_sha256 in seen_digests:
            raise InvalidPolicyError(f"tokens[{index}]: duplicate token digest")
        seen_digests.add(policy.token_sha256)
        seen_labels.add(policy.label)
        tokens.append(policy)

    return Secrets(smtp=smtp, tokens=tuple(tokens))
