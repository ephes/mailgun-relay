from __future__ import annotations

import re
from email.headerregistry import Address
from email.utils import getaddresses

from email_validator import EmailNotValidError, validate_email


class HeaderInjectionError(ValueError):
    """Raised when a header value or address contains CR/LF or invalid characters."""


class HeaderTooLongError(ValueError):
    """Raised when a header value exceeds the configured maximum."""


class DangerousHeaderError(ValueError):
    """Raised when a custom header name is on the denylist (e.g. Bcc, Received)."""


_HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")

# Headers the relay manages itself or that are unsafe for callers to supply.
# All comparisons are case-insensitive.
_DANGEROUS_HEADER_NAMES = frozenset(
    {
        "bcc",
        "received",
        "return-path",
        "message-id",
        "date",
        "from",
        "to",
        "cc",
        "subject",
    }
)

_RESENT_PREFIX = "resent-"


def _is_dangerous(name: str) -> bool:
    lowered = name.lower()
    if lowered in _DANGEROUS_HEADER_NAMES:
        return True
    return lowered.startswith(_RESENT_PREFIX)


def _ensure_no_crlf(value: str) -> None:
    if "\r" in value or "\n" in value:
        raise HeaderInjectionError("header value contains CR/LF")


def validate_subject(value: str, *, max_length: int) -> str:
    stripped = value.strip()
    _ensure_no_crlf(stripped)
    if len(stripped) > max_length:
        raise HeaderTooLongError(f"subject exceeds {max_length} chars")
    return stripped


def validate_custom_headers(
    headers: dict[str, str],
    *,
    max_value_length: int,
) -> dict[str, str]:
    """Return a new dict of validated header name → value.

    - Names must match `^[A-Za-z][A-Za-z0-9-]*$`.
    - Names on the dangerous list (case-insensitive) raise DangerousHeaderError.
    - Values must not contain CR/LF and must be <= max_value_length characters.
    """
    cleaned: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        if not _HEADER_NAME_RE.match(raw_name):
            raise HeaderInjectionError(f"invalid header name: {raw_name!r}")
        if _is_dangerous(raw_name):
            raise DangerousHeaderError(f"header {raw_name!r} is not accepted from clients")
        if not isinstance(raw_value, str):  # pragma: no cover - upstream callers send strings
            raise HeaderInjectionError(f"header {raw_name!r} value must be a string")
        _ensure_no_crlf(raw_value)
        if len(raw_value) > max_value_length:
            raise HeaderTooLongError(f"header {raw_name!r} exceeds {max_value_length} chars")
        cleaned[raw_name] = raw_value
    return cleaned


def parse_address_list(values: list[str]) -> list[Address]:
    """Parse a list of RFC 5322 address strings (possibly with display names).

    Each value yields exactly one address. CR/LF anywhere is rejected. The
    addr-spec is validated via ``email_validator.validate_email`` (no DNS
    deliverability), so malformed domains (e.g. spaces, ``..``) are rejected
    rather than silently rewritten by ``email.utils.getaddresses``.
    """
    addresses: list[Address] = []
    for raw in values:
        _ensure_no_crlf(raw)
        parsed = getaddresses([raw])
        if len(parsed) != 1:
            raise HeaderInjectionError(f"expected one address per value, got {parsed!r}")
        display, addr = parsed[0]
        if not addr or "@" not in addr:
            raise HeaderInjectionError(f"invalid address: {raw!r}")
        # email_validator is strict about the addr-spec (rejects spaces, '..',
        # bare-IP without brackets, etc.) — that's what we want. We disable
        # DNS deliverability AND special-use-domain blocking because deciding
        # whether the backend will accept a domain is the SMTP backend's job,
        # not the relay's. `test_environment=True` is the upstream knob for
        # exactly that ("don't reject .test/.example/.localhost").
        try:
            result = validate_email(addr, check_deliverability=False, test_environment=True)
        except EmailNotValidError as exc:
            raise HeaderInjectionError(f"invalid address: {raw!r} ({exc})") from exc
        normalized = result.normalized
        local, _, domain = normalized.rpartition("@")
        if not local or not domain:
            raise HeaderInjectionError(f"invalid address: {raw!r}")
        addresses.append(Address(display_name=display, username=local, domain=domain))
    return addresses
