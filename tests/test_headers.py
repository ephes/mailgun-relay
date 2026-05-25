from __future__ import annotations

import pytest

from mailgun_relay.headers import (
    DangerousHeaderError,
    HeaderInjectionError,
    HeaderTooLongError,
    parse_address_list,
    validate_custom_headers,
    validate_subject,
)


def test_validate_subject_ok() -> None:
    assert validate_subject("Hello there", max_length=998) == "Hello there"


def test_validate_subject_strips_whitespace() -> None:
    assert validate_subject("  Hello  ", max_length=998) == "Hello"


def test_validate_subject_rejects_lf() -> None:
    with pytest.raises(HeaderInjectionError):
        validate_subject("Hi\nBcc: evil@x.com", max_length=998)


def test_validate_subject_rejects_cr() -> None:
    with pytest.raises(HeaderInjectionError):
        validate_subject("Hi\rEvil", max_length=998)


def test_validate_subject_too_long() -> None:
    with pytest.raises(HeaderTooLongError):
        validate_subject("a" * 1000, max_length=998)


def test_custom_headers_accept_reply_to() -> None:
    out = validate_custom_headers({"Reply-To": "support@example.test"}, max_value_length=998)
    assert out == {"Reply-To": "support@example.test"}


def test_custom_headers_reject_bcc() -> None:
    with pytest.raises(DangerousHeaderError):
        validate_custom_headers({"Bcc": "evil@x.com"}, max_value_length=998)


def test_custom_headers_reject_bcc_mixed_case() -> None:
    with pytest.raises(DangerousHeaderError):
        validate_custom_headers({"bCc": "evil@x.com"}, max_value_length=998)


def test_custom_headers_reject_received() -> None:
    with pytest.raises(DangerousHeaderError):
        validate_custom_headers({"Received": "from spoofed"}, max_value_length=998)


def test_custom_headers_reject_return_path() -> None:
    with pytest.raises(DangerousHeaderError):
        validate_custom_headers({"Return-Path": "<evil@x.com>"}, max_value_length=998)


def test_custom_headers_reject_resent_from() -> None:
    with pytest.raises(DangerousHeaderError):
        validate_custom_headers({"Resent-From": "<evil@x.com>"}, max_value_length=998)


def test_custom_headers_reject_message_id() -> None:
    with pytest.raises(DangerousHeaderError):
        validate_custom_headers({"Message-Id": "<spoof@x>"}, max_value_length=998)


@pytest.mark.parametrize(
    "name",
    ["From", "To", "Cc", "Subject", "Date"],
)
def test_custom_headers_reject_relay_managed(name: str) -> None:
    with pytest.raises(DangerousHeaderError):
        validate_custom_headers({name: "spoofed"}, max_value_length=998)


def test_custom_headers_reject_crlf_in_value() -> None:
    with pytest.raises(HeaderInjectionError):
        validate_custom_headers({"X-Custom": "ok\nBcc: evil@x.com"}, max_value_length=998)


def test_custom_headers_reject_too_long_value() -> None:
    with pytest.raises(HeaderTooLongError):
        validate_custom_headers({"X-Long": "x" * 1000}, max_value_length=998)


def test_custom_headers_reject_bad_name() -> None:
    with pytest.raises(HeaderInjectionError):
        validate_custom_headers({"X Bad Name": "ok"}, max_value_length=998)


def test_parse_address_list_basic() -> None:
    out = parse_address_list(["a@x.test", "b@y.test"])
    assert [str(a) for a in out] == ["a@x.test", "b@y.test"]


def test_parse_address_list_display_name() -> None:
    out = parse_address_list(["Alice <alice@x.test>"])
    assert out[0].display_name == "Alice"
    assert out[0].addr_spec == "alice@x.test"


def test_parse_address_list_rejects_crlf() -> None:
    with pytest.raises(HeaderInjectionError):
        parse_address_list(["alice@x.test\nBcc: evil@y.test"])


def test_parse_address_list_rejects_invalid() -> None:
    with pytest.raises(HeaderInjectionError):
        parse_address_list(["not an address"])


@pytest.mark.parametrize(
    "bad",
    [
        "bad@bad domain",
        "a@x..test",
        "foo@",
        "@bar.com",
        "user@-.example.com",
        "no-at-sign",
    ],
)
def test_parse_address_list_rejects_malformed_domains(bad: str) -> None:
    with pytest.raises(HeaderInjectionError):
        parse_address_list([bad])
