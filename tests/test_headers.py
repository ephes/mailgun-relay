from __future__ import annotations

import pytest

from mailgun_relay.headers import (
    DangerousHeaderError,
    HeaderInjectionError,
    HeaderTooLongError,
    parse_address_list,
    parse_header_address_list,
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


@pytest.mark.parametrize(
    "payload",
    [
        "Hi\x00World",  # NUL truncation
        "Hi\x0bWorld",  # vertical tab
        "Hi\x0cWorld",  # form feed
        "Hi\x85World",  # NEL (C1)
        "Hi\u2028World",  # line separator
        "Hi\u2029World",  # paragraph separator
    ],
)
def test_validate_subject_rejects_control_and_unicode_separators(payload: str) -> None:
    with pytest.raises(HeaderInjectionError):
        validate_subject(payload, max_length=998)


def test_validate_subject_allows_tab() -> None:
    assert validate_subject("Hello\tthere", max_length=998) == "Hello\tthere"


@pytest.mark.parametrize(
    "name",
    [
        "Sender",
        "MIME-Version",
        "Content-Type",
        "Content-Transfer-Encoding",
        "Content-Disposition",
        "Content-ID",
        "Disposition-Notification-To",
        "Return-Receipt-To",
    ],
)
def test_custom_headers_reject_structural_and_spoof_headers(name: str) -> None:
    with pytest.raises(DangerousHeaderError):
        validate_custom_headers({name: "x@example.test"}, max_value_length=998)


def test_custom_headers_reject_nul_in_value() -> None:
    with pytest.raises(HeaderInjectionError):
        validate_custom_headers({"X-Thing": "a\x00b"}, max_value_length=998)


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


def test_header_address_list_quoted_comma_in_display_name() -> None:
    """Quoted comma inside the display name must not split the address."""
    out = parse_header_address_list('"Doe, Jane" <jane@example.test>')
    assert len(out) == 1
    assert out[0].addr_spec == "jane@example.test"
    assert "Doe, Jane" in out[0].display_name


def test_header_address_list_multiple_addresses() -> None:
    out = parse_header_address_list("a@x.test, b@y.test, Carol <c@z.test>")
    assert [str(addr.addr_spec) for addr in out] == ["a@x.test", "b@y.test", "c@z.test"]


def test_header_address_list_rejects_crlf() -> None:
    with pytest.raises(HeaderInjectionError):
        parse_header_address_list("a@x.test,\nb@y.test")


def test_header_address_list_rejects_invalid_in_middle() -> None:
    with pytest.raises(HeaderInjectionError):
        parse_header_address_list("a@x.test, bad@bad domain")
