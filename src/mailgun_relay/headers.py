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

# Characters that can break header framing, truncate a value, or be treated as
# a line break by a downstream parser. Tab (\x09) is permitted as legitimate
# folding whitespace; everything else in the C0/C1 control ranges (including
# CR, LF and NUL), DEL, and the Unicode line/paragraph separators is rejected.
_FORBIDDEN_CONTROL_RE = re.compile("[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029]")

# Headers the relay manages itself, that are structural (set by MIME
# construction), or that are unsafe for callers to supply because they let a
# caller spoof identity or exfiltrate receipts. All comparisons are
# case-insensitive.
_DANGEROUS_HEADER_NAMES = frozenset(
    {
        # Relay-managed / addressing headers.
        "bcc",
        "received",
        "return-path",
        "message-id",
        "date",
        "from",
        "to",
        "cc",
        "subject",
        # Identity headers a caller must not forge.
        "sender",
        # Structural MIME headers — set by build_message; a duplicate from a
        # caller would otherwise raise deep in the email package (HTTP 500).
        "mime-version",
        "content-type",
        "content-transfer-encoding",
        "content-disposition",
        "content-id",
        # Read-receipt / notification headers (exfiltration vector).
        "disposition-notification-to",
        "return-receipt-to",
    }
)

_RESENT_PREFIX = "resent-"


def _is_dangerous(name: str) -> bool:
    lowered = name.lower()
    if lowered in _DANGEROUS_HEADER_NAMES:
        return True
    return lowered.startswith(_RESENT_PREFIX)


def contains_forbidden_control_chars(value: str) -> bool:
    """Return True if ``value`` holds a control char unsafe in a header value.

    Shared so address validation (policy) applies the same definition as header
    validation, rather than maintaining a divergent injection rule.
    """
    return _FORBIDDEN_CONTROL_RE.search(value) is not None


def _ensure_no_crlf(value: str) -> None:
    if contains_forbidden_control_chars(value):
        raise HeaderInjectionError("header value contains control characters")


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


def _validate_addr(raw_label: str, display: str, addr: str) -> Address:
    """Apply syntactic validation to one (display, addr) pair from ``getaddresses``.

    ``raw_label`` is used only in error messages (the original header value).
    """
    if not addr or "@" not in addr:
        raise HeaderInjectionError(f"invalid address: {raw_label!r}")
    # email_validator is strict about the addr-spec (rejects spaces, '..',
    # bare-IP without brackets, etc.) — that's what we want. We disable
    # DNS deliverability AND special-use-domain blocking because deciding
    # whether the backend will accept a domain is the SMTP backend's job,
    # not the relay's. `test_environment=True` is the upstream knob for
    # exactly that ("don't reject .test/.example/.localhost").
    try:
        result = validate_email(addr, check_deliverability=False, test_environment=True)
    except EmailNotValidError as exc:
        raise HeaderInjectionError(f"invalid address: {raw_label!r} ({exc})") from exc
    normalized = result.normalized
    local, _, domain = normalized.rpartition("@")
    if not local or not domain:
        raise HeaderInjectionError(f"invalid address: {raw_label!r}")
    return Address(display_name=display, username=local, domain=domain)


def parse_address_list(values: list[str]) -> list[Address]:
    """Parse a list of single-address values.

    Each entry MUST contain exactly one RFC 5322 address (display name optional).
    For headers that may contain comma-separated lists in a single value (e.g.
    ``h:Reply-To``), use :func:`parse_header_address_list` instead — it handles
    quoted commas inside display names correctly.
    """
    addresses: list[Address] = []
    for raw in values:
        _ensure_no_crlf(raw)
        parsed = getaddresses([raw])
        if len(parsed) != 1:
            raise HeaderInjectionError(f"expected one address per value, got {parsed!r}")
        display, addr = parsed[0]
        addresses.append(_validate_addr(raw, display, addr))
    return addresses


def parse_header_address_list(raw: str) -> list[Address]:
    """Parse an RFC 5322 address-list header value (one or more addresses).

    Unlike :func:`parse_address_list`, this delegates to
    ``email.utils.getaddresses`` over the full raw string so quoted commas
    inside display names (e.g. ``"Doe, Jane" <jane@example.test>``) are
    parsed as a single address rather than split on the comma.
    """
    _ensure_no_crlf(raw)
    parsed = getaddresses([raw])
    if not parsed:
        raise HeaderInjectionError(f"invalid address list: {raw!r}")
    return [_validate_addr(raw, display, addr) for display, addr in parsed]
