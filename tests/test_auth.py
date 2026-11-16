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


# Boundary decisions the Rust port reproduces (rust/fixtures/auth.json).

_API_T = base64.b64encode(b"api:t").decode("ascii")  # YXBpOnQ=


@pytest.mark.parametrize(
    "header",
    [
        f"Basic {_API_T}",
        "Basic YXBpOnR=",  # non-zero trailing bits decode like YXBpOnQ=
        f"Basic \t {_API_T} \x1c\x85\xa0",  # str.strip() whitespace
    ],
)
def test_accepted_credential_spellings(header: str) -> None:
    assert authenticate(header, [_policy("t", "t")]).label == "t"


@pytest.mark.parametrize(
    "header",
    [
        f"basic {_API_T}",  # the scheme is case-sensitive
        f"Basic\t{_API_T}",
        "Basic YXBpOnQ",  # padding is required
        "Basic YXBpOnQ==",  # and canonical
        f"Basic {_API_T}YQ==",  # nothing after the padding
        "Basic YXBp OnQ=",  # no whitespace inside
        "Basic YXBpOnQ-",  # standard alphabet only
        "Basic " + base64.b64encode(b"API:t").decode("ascii"),  # the username too
        "Basic " + base64.b64encode(b"api:\xff").decode("ascii"),  # strict UTF-8
    ],
)
def test_refused_credential_spellings(header: str) -> None:
    with pytest.raises(AuthError):
        authenticate(header, [_policy("t", "t")])


@pytest.mark.parametrize(
    "header", ["Basic \xe9YXBpOnQ=", "Basic YXBpOnQ=\xe9", "Basic YXBp\x80OnQ="]
)
def test_non_ascii_credentials_are_an_auth_error(header: str) -> None:
    """A header byte >= 0x80 (decoded as latin-1) used to escape as a plain
    ValueError from b64decode and answer 500."""
    with pytest.raises(AuthError):
        authenticate(header, [_policy("t", "t")])


def test_password_may_contain_colons_and_be_empty() -> None:
    policies = [_policy("colon", "a:b:c"), _policy("empty", "")]
    assert authenticate(_basic("api", "a:b:c"), policies).label == "colon"
    assert authenticate(_basic("api", ""), policies).label == "empty"


def test_duplicate_token_hashes_resolve_to_the_last_label() -> None:
    policies = [_policy("first", "shared"), _policy("second", "shared")]
    assert authenticate(_basic("api", "shared"), policies).label == "second"


@pytest.mark.parametrize("token", ["a" * 4092, "ü" * 2046])
def test_credential_byte_boundary_is_inclusive(token: str) -> None:
    policy = _policy("boundary", token)
    assert authenticate(_basic("api", token), [policy]) is policy


@pytest.mark.parametrize("extra", [1, 2, 3])
def test_oversize_credentials_are_refused_before_decode_or_hash(
    monkeypatch: pytest.MonkeyPatch, extra: int
) -> None:
    from unittest.mock import Mock

    token = "a" * (4092 + extra)
    policy = _policy("oversize", token)
    header = _basic("api", token)
    decode = Mock(side_effect=AssertionError("must not decode"))
    digest = Mock(side_effect=AssertionError("must not hash"))
    monkeypatch.setattr(base64, "b64decode", decode)
    monkeypatch.setattr(hashlib, "sha256", digest)
    with pytest.raises(AuthError):
        authenticate(header, [policy])
    decode.assert_not_called()
    digest.assert_not_called()


def test_authorization_padding_is_bounded_before_decode(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import Mock

    policy = _policy("t", "t")
    header = _basic("api", "t") + " " * 5464
    decode = Mock(side_effect=AssertionError("must not decode"))
    monkeypatch.setattr(base64, "b64decode", decode)
    with pytest.raises(AuthError):
        authenticate(header, [policy])
    decode.assert_not_called()


@pytest.mark.parametrize("kind", ["utf8", "non-ascii", "base64"])
def test_decoder_errors_leave_no_credential_bearing_exception_chain(kind: str) -> None:
    import traceback

    sentinel = "synthetic-private-credential"
    raw = b"api:" + sentinel.encode() + b"\xff"
    if kind == "utf8":
        header = "Basic " + base64.b64encode(raw).decode("ascii")
    elif kind == "non-ascii":
        header = "Basic " + sentinel + "é"
    else:
        header = "Basic " + sentinel + "!"
    with pytest.raises(AuthError) as caught:
        authenticate(header, [_policy("t", "t")])
    error = caught.value
    assert error.__cause__ is None
    assert error.__context__ is None
    for diagnostic in (str(error), repr(error), "".join(traceback.format_exception(error))):
        assert sentinel not in diagnostic
        assert repr(raw) not in diagnostic
        assert "UnicodeDecodeError" not in diagnostic
