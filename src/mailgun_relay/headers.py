from __future__ import annotations

import re
from email.headerregistry import Address
from email.utils import getaddresses


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

    Rejects CR/LF anywhere, rejects entries that don't yield a usable address.
    Display names are kept verbatim (they will be encoded by the email library).
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
        local, _, domain = addr.rpartition("@")
        if not local or not domain:
            raise HeaderInjectionError(f"invalid address: {raw!r}")
        addresses.append(Address(display_name=display, username=local, domain=domain))
    return addresses
