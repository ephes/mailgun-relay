from __future__ import annotations

from email.utils import parseaddr
from typing import TYPE_CHECKING

import idna
from email_validator import EmailNotValidError, validate_email

if TYPE_CHECKING:
    from mailgun_relay.config import TokenPolicy


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
    """Validate a single email address, optionally with a display name.

    Returns (normalized_addr_spec, normalized_domain). Raises InvalidAddressError.
    Accepts both ``addr@host`` and ``Display Name <addr@host>`` forms.
    """
    _, addr_spec = parseaddr(value)
    if not addr_spec:
        raise InvalidAddressError(f"invalid address: {value!r}")
    try:
        result = validate_email(addr_spec, check_deliverability=False)
    except EmailNotValidError as exc:
        raise InvalidAddressError(str(exc)) from exc
    addr = result.normalized.lower()
    _, _, domain = addr.rpartition("@")
    return addr, normalize_domain(domain)


def enforce_policy(
    policy: TokenPolicy,
    *,
    path_domain: str,
    from_address: str,
) -> None:
    """Raise PolicyError unless the request is allowed by the policy.

    Validates: path_domain ∈ policy.mailgun_domains, from-domain ∈ policy.allowed_from_domains,
    and (if allowed_from_addresses is not None) from-address ∈ allowed_from_addresses.
    """
    normalized_path = normalize_domain(path_domain)
    if normalized_path not in policy.mailgun_domains:
        raise PolicyError(f"token not allowed for path domain {normalized_path!r}")

    addr, from_domain = parse_email_strict(from_address)
    if from_domain not in policy.allowed_from_domains:
        raise PolicyError(f"token not allowed for from domain {from_domain!r}")

    if policy.allowed_from_addresses is not None and addr not in policy.allowed_from_addresses:
        raise PolicyError(f"token not allowed for from address {addr!r}")
