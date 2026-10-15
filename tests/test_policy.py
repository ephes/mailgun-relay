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


def test_from_address_idn_allowlist_ok() -> None:
    """An IDN sender stored as an A-label must match a U-label request.

    Regression for the normalization mismatch where ``email_validator``
    returns the domain as a U-label but the allowlist stores A-labels.
    """
    p = _policy(
        mailgun_domains={"xn--wersdrfer-47a.de"},
        allowed_from_domains={"xn--wersdrfer-47a.de"},
        allowed_from_addresses={normalize_address("jochen@wersdörfer.de")},
    )
    enforce_policy(
        p,
        path_domain="wersdörfer.de",
        from_address="Jochen <jochen@wersdörfer.de>",
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


def test_from_address_with_crlf_raises_invalid_not_policy() -> None:
    """CRLF in `from` must be a parse/injection error, not silently reinterpreted.

    `parseaddr` would otherwise extract an address from a smuggled second line;
    the control-char guard turns that into InvalidAddressError (→ 400).
    """
    p = _policy(
        mailgun_domains={"wersdoerfer.de"},
        allowed_from_domains={"wersdoerfer.de"},
    )
    with pytest.raises(InvalidAddressError):
        enforce_policy(
            p,
            path_domain="wersdoerfer.de",
            from_address="ok@wersdoerfer.de\nBcc: evil@wersdoerfer.de",
        )


@pytest.mark.parametrize("allowed_addresses", [None, {normalize_address("jörg@wersdoerfer.de")}])
def test_non_ascii_local_part_in_from_is_invalid_not_policy(
    allowed_addresses: set[str] | None,
) -> None:
    """EAI senders are malformed (400), whatever the domain or address policy says."""
    p = _policy(
        mailgun_domains={"wersdoerfer.de"},
        allowed_from_domains={"wersdoerfer.de"},
        allowed_from_addresses=allowed_addresses,
    )
    with pytest.raises(InvalidAddressError):
        enforce_policy(p, path_domain="wersdoerfer.de", from_address="Jörg <jörg@wersdoerfer.de>")


def test_non_ascii_local_part_does_not_skip_the_path_domain_check() -> None:
    p = _policy(mailgun_domains={"wersdoerfer.de"}, allowed_from_domains={"wersdoerfer.de"})
    with pytest.raises(PolicyError) as caught:
        enforce_policy(p, path_domain="example.org", from_address="jörg@wersdoerfer.de")
    assert type(caught.value) is PolicyError


def test_idn_from_domain_is_compared_as_a_label() -> None:
    p = _policy(
        mailgun_domains={"xn--wersdrfer-47a.de"},
        allowed_from_domains={"xn--wersdrfer-47a.de"},
    )
    for sender in ("a@wersdörfer.de", "a@xn--wersdrfer-47a.de", "A <a@WERSDÖRFER.DE>"):
        enforce_policy(p, path_domain="xn--wersdrfer-47a.de", from_address=sender)
    with pytest.raises(PolicyError):
        enforce_policy(p, path_domain="xn--wersdrfer-47a.de", from_address="a@wersdoerfer.de")


# Production policy shapes (fix-403-diagnosis 1.3, after the 403 fix; no
# tokens) and boundary decisions the Rust port reproduces
# (rust/fixtures/domain.json, address.json, policy.json).

_HOMEPAGE = _policy(
    mailgun_domains={"mg.wersdoerfer.de"},
    allowed_from_domains={"wersdoerfer.de"},
    allowed_from_addresses={"jochen-homepage@wersdoerfer.de", "jochen-django@wersdoerfer.de"},
)
_PODCAST = _policy(
    mailgun_domains={"mg.python-podcast.de"},
    allowed_from_domains={"mg.python-podcast.de", "wersdoerfer.de"},
    allowed_from_addresses={"noreply@mg.python-podcast.de", "jochen-django@wersdoerfer.de"},
)


@pytest.mark.parametrize(
    ("policy", "path", "sender"),
    [
        (_HOMEPAGE, "mg.wersdoerfer.de", "Homepage <jochen-homepage@wersdoerfer.de>"),
        (_HOMEPAGE, "MG.WERSDOERFER.DE", "jochen-django@wersdoerfer.de"),
        (_HOMEPAGE, "mg.wersdoerfer.de", "Jochen-Django@WERSDOERFER.DE"),
        (_PODCAST, "mg.python-podcast.de", "Python Podcast <noreply@mg.python-podcast.de>"),
        # Cross-domain: the path domain and the from domain differ.
        (_PODCAST, "mg.python-podcast.de", "jochen-django@wersdoerfer.de"),
    ],
)
def test_production_shapes_accept(policy: TokenPolicy, path: str, sender: str) -> None:
    enforce_policy(policy, path_domain=path, from_address=sender)


@pytest.mark.parametrize(
    ("policy", "path", "sender", "message"),
    [
        (_HOMEPAGE, "mg.python-podcast.de", "jochen-django@wersdoerfer.de", "path domain"),
        (_HOMEPAGE, "wersdoerfer.de", "jochen-django@wersdoerfer.de", "path domain"),
        (_HOMEPAGE, "mg.wersdoerfer.de.", "jochen-django@wersdoerfer.de", "path domain"),
        (_HOMEPAGE, "mg.wersdoerfer.de", "noreply@mg.python-podcast.de", "from domain"),
        (_HOMEPAGE, "mg.wersdoerfer.de", "x@mg.wersdoerfer.de", "from domain"),
        (_HOMEPAGE, "mg.wersdoerfer.de", "someone-else@wersdoerfer.de", "from address"),
        (_PODCAST, "mg.python-podcast.de", "jochen-homepage@wersdoerfer.de", "from address"),
    ],
)
def test_production_shapes_refuse(
    policy: TokenPolicy, path: str, sender: str, message: str
) -> None:
    with pytest.raises(PolicyError) as caught:
        enforce_policy(policy, path_domain=path, from_address=sender)
    assert type(caught.value) is PolicyError
    assert f"token not allowed for {message} " in str(caught.value)


def test_idn_allowlist_matches_both_label_forms() -> None:
    p = _policy(
        mailgun_domains={normalize_domain("mg.wersdörfer.de")},
        allowed_from_domains={normalize_domain("wersdörfer.de")},
        allowed_from_addresses={normalize_address("Jochen@Wersdörfer.de")},
    )
    for path in ("mg.wersdörfer.de", "MG.XN--WERSDRFER-47A.DE"):
        for sender in ("jochen@wersdörfer.de", "Jochen <JOCHEN@xn--wersdrfer-47a.de>"):
            enforce_policy(p, path_domain=path, from_address=sender)
    with pytest.raises(PolicyError):
        enforce_policy(p, path_domain="mg.wersdörfer.de", from_address="jochen@wersdoerfer.de")


def test_ggs_default_sender_is_a_bad_request() -> None:
    with pytest.raises(InvalidAddressError):
        enforce_policy(
            _HOMEPAGE, path_domain="mg.wersdoerfer.de", from_address="webmaster@localhost"
        )


def test_quote_in_address_is_rendered_by_repr() -> None:
    with pytest.raises(PolicyError) as caught:
        enforce_policy(
            _HOMEPAGE, path_domain="mg.wersdoerfer.de", from_address="o'brien@wersdoerfer.de"
        )
    assert str(caught.value) == 'token not allowed for from address "o\'brien@wersdoerfer.de"'


@pytest.mark.parametrize(
    ("value", "a_label"),
    [
        ("WERSDÖRFER.DE", "xn--wersdrfer-47a.de"),
        ("ß.de", "xn--zca.de"),
        ("ⅻ.de", "xii.de"),
        ("mg.wersdoerfer.de.", "mg.wersdoerfer.de."),
        ("localhost", "localhost"),
        ("\x1c mg.wersdoerfer.de\x85", "mg.wersdoerfer.de"),
    ],
)
def test_normalize_domain_boundaries(value: str, a_label: str) -> None:
    assert normalize_domain(value) == a_label


@pytest.mark.parametrize("value", ["a_b.de", "xn--abc.de", "a..b", "-x.de", "☃.de", "a·b.de"])
def test_normalize_domain_refuses(value: str) -> None:
    with pytest.raises(InvalidAddressError):
        normalize_domain(value)


@pytest.mark.parametrize(
    "sender",
    ["a . b@wersdoerfer.de", "Jane <jochen-django@wersdoerfer.de", "grp: x@wersdoerfer.de;"],
)
def test_lax_python_forms_still_pass_the_strict_parse(sender: str) -> None:
    """Python's parser accepts these; the Rust port refuses them (PLAN.md D-11,
    fail closed). Pinned so a change on either side shows in review."""
    domain_only = _policy(mailgun_domains={"w.de"}, allowed_from_domains={"wersdoerfer.de"})
    enforce_policy(domain_only, path_domain="w.de", from_address=sender)
