from __future__ import annotations

import base64
import hashlib

import pytest

from mailgun_relay.auth import AuthError, authenticate
from mailgun_relay.config import TokenPolicy


def _policy(label: str, token: str) -> TokenPolicy:
    return TokenPolicy(
        label=label,
        token_sha256=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        mailgun_domains=frozenset({"wersdoerfer.de"}),
        allowed_from_domains=frozenset({"wersdoerfer.de"}),
        allowed_from_addresses=None,
    )


def _basic(user: str, password: str) -> str:
    raw = f"{user}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode("ascii")


def test_missing_header_raises() -> None:
    with pytest.raises(AuthError):
        authenticate(None, [_policy("h", "good-token")])


def test_wrong_scheme_raises() -> None:
    with pytest.raises(AuthError):
        authenticate("Bearer xyz", [_policy("h", "good-token")])


def test_wrong_username_raises() -> None:
    with pytest.raises(AuthError):
        authenticate(_basic("notapi", "good-token"), [_policy("h", "good-token")])


def test_unknown_token_raises() -> None:
    with pytest.raises(AuthError):
        authenticate(_basic("api", "wrong-token"), [_policy("h", "good-token")])


def test_matching_token_returns_policy() -> None:
    p = _policy("homepage-staging", "good-token")
    out = authenticate(_basic("api", "good-token"), [p])
    assert out is p


def test_matching_token_among_many() -> None:
    a = _policy("a", "token-a")
    b = _policy("b", "token-b")
    c = _policy("c", "token-c")
    out = authenticate(_basic("api", "token-b"), [a, b, c])
    assert out is b


def test_malformed_base64_raises() -> None:
    with pytest.raises(AuthError):
        authenticate("Basic !!!notbase64!!!", [_policy("h", "good-token")])


def test_basic_missing_colon_raises() -> None:
    raw = base64.b64encode(b"justuser").decode("ascii")
    with pytest.raises(AuthError):
        authenticate(f"Basic {raw}", [_policy("h", "good-token")])
