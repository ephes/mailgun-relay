from __future__ import annotations

import pytest

from mailgun_relay.config import TokenPolicy
from mailgun_relay.policy import (
    InvalidAddressError,
    PolicyError,
    enforce_policy,
    normalize_address,
    normalize_domain,
)


def _policy(
    *,
    mailgun_domains: set[str],
    allowed_from_domains: set[str],
    allowed_from_addresses: set[str] | None = None,
) -> TokenPolicy:
    return TokenPolicy(
        label="t",
        token_sha256="0" * 64,
        mailgun_domains=frozenset(mailgun_domains),
        allowed_from_domains=frozenset(allowed_from_domains),
        allowed_from_addresses=(
            frozenset(allowed_from_addresses) if allowed_from_addresses is not None else None
        ),
    )


def test_normalize_domain_punycode() -> None:
    assert normalize_domain("wersdörfer.de") == "xn--wersdrfer-47a.de"
    assert normalize_domain("XN--wersdrfer-47a.DE") == "xn--wersdrfer-47a.de"


def test_normalize_address_punycode_and_lowercase() -> None:
    assert normalize_address("Some.User@wersdörfer.de") == "some.user@xn--wersdrfer-47a.de"


def test_normalize_domain_empty_raises() -> None:
    with pytest.raises(InvalidAddressError):
        normalize_domain("")


def test_normalize_address_missing_at_raises() -> None:
    with pytest.raises(InvalidAddressError):
        normalize_address("noatsign")


def test_path_domain_match_ok() -> None:
    p = _policy(
        mailgun_domains={"wersdoerfer.de"},
        allowed_from_domains={"wersdoerfer.de"},
    )
    enforce_policy(p, path_domain="wersdoerfer.de", from_address="x@wersdoerfer.de")


def test_path_domain_idn_match_ok() -> None:
    p = _policy(
        mailgun_domains={"xn--wersdrfer-47a.de"},
        allowed_from_domains={"xn--wersdrfer-47a.de"},
    )
    enforce_policy(
        p,
        path_domain="wersdörfer.de",
        from_address="someone@wersdörfer.de",
    )


def test_path_domain_mismatch_raises() -> None:
    p = _policy(
        mailgun_domains={"wersdoerfer.de"},
        allowed_from_domains={"wersdoerfer.de"},
    )
    with pytest.raises(PolicyError):
        enforce_policy(p, path_domain="evil.test", from_address="x@wersdoerfer.de")


def test_from_domain_mismatch_raises() -> None:
    p = _policy(
        mailgun_domains={"wersdoerfer.de"},
        allowed_from_domains={"wersdoerfer.de"},
    )
    with pytest.raises(PolicyError):
        enforce_policy(p, path_domain="wersdoerfer.de", from_address="x@evil.test")


def test_from_address_in_allowlist_ok() -> None:
    p = _policy(
        mailgun_domains={"wersdoerfer.de"},
        allowed_from_domains={"wersdoerfer.de"},
        allowed_from_addresses={"jochen-homepage@wersdoerfer.de"},
    )
    enforce_policy(
        p,
        path_domain="wersdoerfer.de",
        from_address="Jochen-Homepage@wersdoerfer.de",
    )


def test_from_address_outside_allowlist_raises() -> None:
    p = _policy(
        mailgun_domains={"wersdoerfer.de"},
        allowed_from_domains={"wersdoerfer.de"},
        allowed_from_addresses={"jochen-homepage@wersdoerfer.de"},
    )
    with pytest.raises(PolicyError):
        enforce_policy(
            p,
            path_domain="wersdoerfer.de",
            from_address="someone-else@wersdoerfer.de",
        )


def test_invalid_from_address_raises() -> None:
    p = _policy(
        mailgun_domains={"wersdoerfer.de"},
        allowed_from_domains={"wersdoerfer.de"},
    )
    with pytest.raises(InvalidAddressError):
        enforce_policy(p, path_domain="wersdoerfer.de", from_address="not-an-email")
