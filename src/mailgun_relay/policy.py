from __future__ import annotations

from email.utils import parseaddr
from typing import TYPE_CHECKING

import idna
from email_validator import EmailNotValidError, validate_email

from mailgun_relay.headers import contains_forbidden_control_chars

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
    # Reject CR/LF/NUL/control chars up front: `parseaddr` silently swallows
    # embedded newlines (extracting an address from a smuggled line), which
    # would turn a header-injection attempt into a confusing policy decision.
    if contains_forbidden_control_chars(value):
        raise InvalidAddressError(f"invalid address: {value!r}")
    _, addr_spec = parseaddr(value)
    if not addr_spec:
        raise InvalidAddressError(f"invalid address: {value!r}")
    try:
        # `test_environment=True` keeps syntactic checks (spaces, '..',
        # invalid characters) but allows reserved/special-use TLDs because
        # the SMTP backend is the authoritative deliverability decision.
        result = validate_email(addr_spec, check_deliverability=False, test_environment=True)
    except EmailNotValidError as exc:
        raise InvalidAddressError(str(exc)) from exc
    # `email_validator` returns the domain as a U-label (Unicode) for IDNs, but
    # the configured allowlist stores A-labels (punycode) via `normalize_address`.
    # Re-normalize the domain to the A-label form so the policy comparison is
    # apples-to-apples; otherwise every IDN sender would be wrongly rejected.
    local, _, domain = result.normalized.rpartition("@")
    normalized_domain = normalize_domain(domain)
    addr = f"{local.lower()}@{normalized_domain}"
    return addr, normalized_domain


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
