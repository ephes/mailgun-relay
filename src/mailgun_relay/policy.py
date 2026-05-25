from __future__ import annotations

import idna
from email_validator import EmailNotValidError, validate_email


class PolicyError(ValueError):
    """Base for token/sender policy violations."""


class InvalidAddressError(PolicyError):
    """Raised when an address cannot be parsed."""


def normalize_domain(value: str) -> str:
    """Return the A-label (punycode) lowercase form of a domain.

    Accepts both U-labels (Unicode) and A-labels. Rejects empty or whitespace input.
    """
    stripped = value.strip().lower()
    if not stripped:
        raise InvalidAddressError("empty domain")
    try:
        return idna.encode(stripped, uts46=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise InvalidAddressError(f"invalid domain: {value!r}") from exc


def normalize_address(value: str) -> str:
    """Lowercase + normalize-domain on the right of '@'. Reject malformed."""
    stripped = value.strip()
    if "@" not in stripped:
        raise InvalidAddressError(f"address missing '@': {value!r}")
    local, _, domain = stripped.rpartition("@")
    if not local:
        raise InvalidAddressError(f"address missing local part: {value!r}")
    return f"{local.lower()}@{normalize_domain(domain)}"


def parse_email_strict(value: str) -> tuple[str, str]:
    """Validate a single email address (no display name).

    Returns (normalized_address, normalized_domain). Raises InvalidAddressError.
    """
    try:
        result = validate_email(value, check_deliverability=False)
    except EmailNotValidError as exc:
        raise InvalidAddressError(str(exc)) from exc
    addr = result.normalized.lower()
    _, _, domain = addr.rpartition("@")
    return addr, normalize_domain(domain)
