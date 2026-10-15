"""Generate the shared fixtures of the Rust port from the Python code.

Python is the oracle for the contract and the policy decisions (rust/PLAN.md
section 7.2): every fixture is produced by calling the real Python code on a
fixed corpus. Only decisions and normalised values are stored, never message
texts. Cases where the decided behaviour of the Rust port differs (PLAN.md
section 3) carry ``"divergence": "D-n"`` and the Rust expectation; the
generator derives or checks that label, so the fixtures and the divergence
table cannot drift apart. The Rust tests load the files with
``include_str!``; ``tests/test_rust_fixtures.py`` regenerates them in memory
and fails when a committed file differs.

Usage::

    uv run python rust/fixtures/generate.py          # rewrite every file
    uv run python rust/fixtures/generate.py --check  # exit 1 on drift

Each slice adds its builders to ``GENERATORS``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import random
import sys
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from unittest import mock

import idna
import uvicorn.config
import yaml
from email_validator import EmailNotValidError, validate_email

from mailgun_relay import headers as headers_module
from mailgun_relay.auth import AuthError, authenticate
from mailgun_relay.config import Settings, TokenPolicy, load_secrets
from mailgun_relay.headers import (
    DangerousHeaderError,
    HeaderInjectionError,
    HeaderTooLongError,
    contains_forbidden_control_chars,
    parse_address_list,
    parse_header_address_list,
    validate_custom_headers,
    validate_subject,
)
from mailgun_relay.policy import (
    InvalidAddressError,
    PolicyError,
    enforce_policy,
    normalize_address,
    normalize_domain,
    parse_email_strict,
)

FIXTURES_DIR = Path(__file__).resolve().parent

# Look-alike characters, spelled out so the source stays unambiguous.
PAYPAL = f"p{chr(0x430)}ypal"  # Cyrillic small a: a mixed-script domain
NBSP = chr(0xA0)
LINE_SEPARATOR = chr(0x2028)
FULLWIDTH_A = chr(0xFF41)

# ------------------------------------------------------------ shared rules


def config_domain_ok(domain: str, a_label: str) -> bool:
    """Whether the Rust port accepts a configured domain Python accepted
    (D-10): the input and the Unicode form of the A-label stay within the
    character set of ``is_config_domain_char`` in ``rust/src/domain.rs``."""
    return _config_chars_ok(domain) and _config_chars_ok(idna.decode(a_label))


# The non-ASCII code points of ``is_config_domain_char`` in rust/src/domain.rs.
CONFIG_RANGES = [
    (0xC0, 0xD6),
    (0xD8, 0xF6),
    (0xF8, 0x24F),
    (0x250, 0x2AF),
    (0x300, 0x36F),
    (0x1E00, 0x1EFF),
]


def _config_char(char: str) -> bool:
    return char in "abcdefghijklmnopqrstuvwxyz0123456789-." or any(
        low <= ord(char) <= high for low, high in CONFIG_RANGES
    )


# ``is_combining_mark`` in rust/src/domain.rs: a domain may not start with one.
COMBINING_MARKS = {chr(c) for c in range(0x300, 0x370)}


def _config_chars_ok(domain: str) -> bool:
    return all(_config_char(char) for char in domain.strip().lower())


# The mailbox grammar of rust/src/address.rs (PLAN.md 2.6, D-11), mirrored
# here to derive the Rust expectation: a strict subset of what Python's
# parser accepts. The generator asserts that every value it accepts gives
# Python's result.

_WORD_EXCLUDED = set('()<>@,:;"[]\\')
_ADDR_EXCLUDED = set('()<>,:;"[]\\')
_COMMENT_EXCLUDED = set('()\\",')


class _GrammarError(Exception):
    pass


def _wsp(char: str) -> bool:
    return char in " \t"


def _word_char(char: str) -> bool:
    return not _wsp(char) and char not in _WORD_EXCLUDED


def _addr_char(char: str) -> bool:
    return not _wsp(char) and char not in _ADDR_EXCLUDED


class _Grammar:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def peek(self) -> str | None:
        return self.text[self.pos] if self.pos < len(self.text) else None

    def take(self, accept: Callable[[str], bool]) -> str:
        start = self.pos
        while self.pos < len(self.text) and accept(self.text[self.pos]):
            self.pos += 1
        return self.text[start : self.pos]

    def cfws(self, comments: list[str]) -> None:
        while (char := self.peek()) is not None:
            if _wsp(char):
                self.pos += 1
            elif char == "(":
                self.pos += 1
                text = self.take(lambda c: c not in _COMMENT_EXCLUDED)
                if self.peek() != ")":
                    raise _GrammarError
                self.pos += 1
                comments.append(text)
            else:
                return

    def quoted(self) -> str:
        self.pos += 1
        text = ""
        while True:
            char = self.peek()
            if char is None:
                raise _GrammarError
            if char == '"':
                self.pos += 1
                return text
            if char == "\\":
                if self.pos + 1 >= len(self.text):
                    raise _GrammarError
                text += self.text[self.pos + 1]
                self.pos += 2
            else:
                text += char
                self.pos += 1

    def mailbox(self) -> tuple[str, str]:
        """(display name, addr-spec token) of the whole text."""
        comments: list[str] = []
        self.cfws(comments)
        start = self.pos
        token = self.take(_addr_char)
        if "@" in token:
            self.cfws(comments)
            if self.peek() is not None:
                raise _GrammarError
            return " ".join(comments), token
        self.pos = start
        words = []
        while True:
            self.cfws(comments)
            char = self.peek()
            if char == '"':
                words.append(self.quoted())
            elif char is not None and _word_char(char):
                words.append(self.take(_word_char))
            elif char == "<":
                break
            else:
                raise _GrammarError
        display = " ".join(words)
        if comments:
            display += " (" + " ".join(comments) + ")"
        self.pos += 1
        self.take(_wsp)
        token = self.take(_addr_char)
        self.take(_wsp)
        if self.peek() != ">":
            raise _GrammarError
        self.pos += 1
        self.cfws([])
        if self.peek() is not None:
            raise _GrammarError
        return display, token


def _split_list(text: str) -> list[str]:
    parts, start, quoted, escaped = [], 0, False, False
    for i, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            parts.append(text[start:i])
            start = i + 1
    return [*parts, text[start:]]


Mailbox = tuple[str, str, str]  # display name, addr-spec, policy address


def _rust_token(display: str, token: str) -> Mailbox | None:
    """The addr-spec rules of ``validate`` in rust/src/address.rs: Python's
    ``email_validator`` decision, restricted to the Latin set (D-11)."""
    try:
        result = validate_email(
            token, check_deliverability=False, test_environment=True, allow_smtputf8=False
        )
    except EmailNotValidError:
        return None
    raw_domain = token.partition("@")[2]
    if raw_domain[:1] in COMBINING_MARKS:
        return None
    ascii_email = result.ascii_email or ""
    local, _, ascii_domain = ascii_email.rpartition("@")
    if not all(_config_char(c) for c in raw_domain.lower()):
        return None
    if not _config_chars_ok(idna.decode(ascii_domain)):
        return None
    return display, ascii_email, f"{local.lower()}@{ascii_domain}"


def rust_mailbox(value: str) -> Mailbox | None:
    """What ``address::parse_mailbox`` decides."""
    if contains_forbidden_control_chars(value):
        return None
    return _rust_mailbox(value)


def _rust_mailbox(value: str) -> Mailbox | None:
    try:
        display, token = _Grammar(value).mailbox()
    except _GrammarError:
        return None
    return _rust_token(display, token)


def rust_mailbox_list(value: str) -> list[Mailbox] | None:
    """What ``address::parse_mailbox_list`` decides."""
    if contains_forbidden_control_chars(value):
        return None
    mailboxes = [_rust_mailbox(part) for part in _split_list(value)]
    return None if None in mailboxes else [m for m in mailboxes if m is not None]


def rust_addr_spec(value: str) -> Mailbox | None:
    """What ``address::parse_addr_spec`` decides (ENVELOPE_SENDER, D-15)."""
    if not all(_addr_char(c) for c in value):
        return None
    return _rust_token("", value)


# -------------------------------------------------------------- config_env

PREFIX = "MAILGUN_RELAY_"
INT_FIELDS = (
    "max_body_bytes",
    "max_attachments",
    "max_attachment_bytes",
    "max_recipients",
    "max_header_value_length",
)
Env = list[tuple[str, str]]


def _python_start(env: Env) -> dict[str, Any] | None:
    """The configuration a Python process starts with, or ``None``.

    A start needs the ``__main__`` reads (``int()`` of ``BIND_PORT``,
    uvicorn's log level), ``Settings()``, ``logging``'s level, and a port
    uvicorn can bind. Bind host and port are the ``__main__`` values.
    """
    probe = logging.getLogger("mailgun_relay.fixture_probe")
    with mock.patch.dict(os.environ, dict(env), clear=True):
        try:
            host = os.environ.get(f"{PREFIX}BIND_HOST", "127.0.0.1")
            port = int(os.environ.get(f"{PREFIX}BIND_PORT", "8085"))
            uvicorn.config.LOG_LEVELS[os.environ.get(f"{PREFIX}LOG_LEVEL", "info").lower()]
            settings = Settings()
            probe.setLevel(settings.log_level.upper())
        except ValueError, KeyError:
            return None
        finally:
            probe.setLevel(logging.NOTSET)
    if not 0 <= port <= 65535:
        return None
    values = settings.model_dump()
    values.update(bind_host=host, bind_port=port, log_level=settings.log_level.upper())
    return values


def _rust_start(env: Env) -> tuple[dict[str, Any] | None, str | None]:
    """The decided Rust behaviour: Python's start with one reader per
    variable (D-7), then the range checks of D-18 and the domain set of
    D-10. Returns the result and the divergence that rejected it."""
    values = dict(env)
    canonical: Env = []
    for field in Settings.model_fields:
        exact = f"{PREFIX}{field.upper()}"
        names = [name for name, _ in env if name.lower() == exact.lower()]
        if len(names) > 1:
            return None, "D-7"
        if names:
            canonical.append((exact, values[names[0]]))
    result = _python_start(canonical)
    if result is None:
        return None, None
    if (
        result["bind_host"] == ""
        or not 0 <= result["smtp_port"] <= 65535
        or not 1 <= result["smtp_max_concurrency"] <= 2**32 - 1
        or not 0 <= result["smtp_timeout_s"] <= 1e9
        or not all(-(2**63) <= result[field] < 2**63 for field in INT_FIELDS)
    ):
        return None, "D-18"
    sender = dict(canonical).get(f"{PREFIX}ENVELOPE_SENDER", "")
    a_label = result["envelope_sender"].rpartition("@")[2]
    if not sender.isascii() and not config_domain_ok(sender.rpartition("@")[2], a_label):
        return None, "D-10"
    if result["envelope_sender"] and rust_addr_spec(result["envelope_sender"]) is None:
        return None, "D-15"
    return result, None


def _env_cases() -> list[tuple[str, Env]]:
    cases: list[tuple[str, Env]] = [
        ("defaults", []),
        (
            "production shape",
            [
                (f"{PREFIX}BIND_HOST", "127.0.0.1"),
                (f"{PREFIX}BIND_PORT", "8085"),
                (f"{PREFIX}PUBLIC_HOST", "mailgun.home.xn--wersdrfer-47a.de"),
                (f"{PREFIX}SECRETS_PATH", "/etc/mailgun-relay/secrets.yml"),
                (f"{PREFIX}SMTP_HOST", "smtp.home.xn--wersdrfer-47a.de"),
                (f"{PREFIX}SMTP_PORT", "587"),
                (f"{PREFIX}SMTP_STARTTLS", "true"),
                (f"{PREFIX}SMTP_TIMEOUT_S", "30"),
                (f"{PREFIX}ENVELOPE_SENDER", "mailgun-relay@xn--wersdrfer-47a.de"),
                (f"{PREFIX}MAX_BODY_BYTES", "26214400"),
                (f"{PREFIX}MAX_ATTACHMENTS", "10"),
                (f"{PREFIX}MAX_ATTACHMENT_BYTES", "10485760"),
                (f"{PREFIX}MAX_RECIPIENTS", "100"),
                (f"{PREFIX}MAX_HEADER_VALUE_LENGTH", "998"),
                (f"{PREFIX}LOG_LEVEL", "INFO"),
                ("PATH", "/usr/bin"),
            ],
        ),
        ("unknown prefixed variable ignored", [(f"{PREFIX}FOO", "x")]),
        ("empty strings are values", [(f"{PREFIX}PUBLIC_HOST", ""), (f"{PREFIX}SMTP_CA_FILE", "")]),
        ("ca file", [(f"{PREFIX}SMTP_CA_FILE", "/etc/ssl/private-ca.pem")]),
        ("empty bind host", [(f"{PREFIX}BIND_HOST", "")]),
        ("bind host name", [(f"{PREFIX}BIND_HOST", "localhost")]),
    ]
    bools = ["1", "on", "t", "true", "y", "yes", "0", "off", "f", "false", "n", "no"]
    bools += ["TRUE", "Yes", "oN", "F", " true", "true ", "", "2", "ye", "enabled"]
    cases += [(f"bool {v!r}", [(f"{PREFIX}SMTP_STARTTLS", v)]) for v in bools]
    cases += [
        (f"partial refusal {v!r}", [(f"{PREFIX}FAIL_ON_PARTIAL_REFUSAL", v)])
        for v in ["true", "No", "x"]
    ]
    ints = ["26214400", " 1 ", "\t7\n", "+5", "-1", "0", "0_1", "1_000", "007"]
    ints += ["8085.0", "8085.00", "-0.0", "+1.0", "8085.", "1 .0", "1\t.0", "1.5", "1.0_0"]
    ints += ["1__0", "_1", "1_"]
    ints += ["+_1", "0x10", "1e3", "", "٨", f"{NBSP}1", "\x1c1", "0000000000000000000000005"]
    ints += ["9223372036854775807", "-9223372036854775808", "9223372036854775808"]
    ints += ["99999999999999999999999"]
    cases += [(f"int {v!r}", [(f"{PREFIX}MAX_BODY_BYTES", v)]) for v in ints]
    cases += [
        (f"other int fields {v!r}", [(f"{PREFIX}{name}", v)])
        for name, v in [
            ("MAX_ATTACHMENTS", "-3"),
            ("MAX_ATTACHMENT_BYTES", "1_048_576"),
            ("MAX_RECIPIENTS", "0"),
            ("MAX_HEADER_VALUE_LENGTH", "78.0"),
        ]
    ]
    ports = ["9000", " 9000", "+9_000", "8085.0", "0", "65535", "65536", "-1", "x"]
    cases += [(f"bind port {v!r}", [(f"{PREFIX}BIND_PORT", v)]) for v in ports]
    cases += [
        (f"smtp port {v!r}", [(f"{PREFIX}SMTP_PORT", v)])
        for v in ["25", "465.0", "0", "65535", "65536", "-25"]
    ]
    floats = ["30", "30.0", " 2.5 ", "1e3", "1E2", ".5", "5.", "+7", "1_0.5", "1._5", "1_e1"]
    floats += ["0", "-0.0", "1e-400", "1__0", "_1", "1_", "0x10", "", "1e", "٣"]
    floats += ["inf", "-inf", "nan", "Infinity", "-1", "1e9", "1e10", "1.7976931348623157e309"]
    cases += [(f"float {v!r}", [(f"{PREFIX}SMTP_TIMEOUT_S", v)]) for v in floats]
    cases += [
        (f"concurrency {v!r}", [(f"{PREFIX}SMTP_MAX_CONCURRENCY", v)])
        for v in ["1", "0", "-1", "64", "4294967295", "4294967296"]
    ]
    levels = ["DEBUG", "info", "Warning", "error", "CRITICAL", "trace", "warn", "fatal"]
    levels += ["notset", "", " INFO", "INFO "]
    cases += [(f"log level {v!r}", [(f"{PREFIX}LOG_LEVEL", v)]) for v in levels]
    senders = ["", "relay@example.org", "Relay@Example.ORG", "not an address"]
    senders += ["relay@wersdörfer.de", "Relay@WERSDÖRFER.de", "jörg@example.org"]
    senders += ["@wersdörfer.de", "wersdörfer.de", "a@b@wersdörfer.de", "relay@wersdörfer..de"]
    senders += ["relay@Ⅻ.de", f"relay@{PAYPAL}.de", "relay@☃.de"]
    senders += ["relay@\u0140.de", "relay@xn--n3h.\u00fc", "relay@xn--wersdrfer-47a.\u00fc"]
    senders += ["relay@localhost", "relay@example", "relay@x.local", "relay@[192.0.2.1]"]
    senders += ["<relay@example.org>", "Relay <relay@example.org>", "relay @example.org"]
    senders += ["bounce@example.test", "a..b@example.org", "relay@exa_mple.org", "relay@"]
    senders += ["relay@wersdörfer.local", "relay@wersdörfer"]
    cases += [(f"envelope sender {v!r}", [(f"{PREFIX}ENVELOPE_SENDER", v)]) for v in senders]
    cases += [
        ("lower-case name", [("mailgun_relay_smtp_port", "25")]),
        ("mixed-case name", [("Mailgun_Relay_Max_Recipients", "5")]),
        ("lower-case bind port", [("mailgun_relay_bind_port", "9000")]),
        ("lower-case bind host", [("mailgun_relay_bind_host", "0.0.0.0")]),  # noqa: S104
        ("lower-case log level", [("mailgun_relay_log_level", "debug")]),
        ("lower-case log level warn", [("mailgun_relay_log_level", "warn")]),
        ("lower-case bad bind port", [("mailgun_relay_bind_port", "x")]),
        (
            "exact name before variant",
            [(f"{PREFIX}SMTP_PORT", "25"), ("mailgun_relay_smtp_port", "2525")],
        ),
        (
            "variant before exact name",
            [("mailgun_relay_smtp_port", "2525"), (f"{PREFIX}SMTP_PORT", "25")],
        ),
        (
            "exact name and invalid variant",
            [(f"{PREFIX}SMTP_PORT", "25"), ("mailgun_relay_smtp_port", "invalid")],
        ),
        ("unrelated non-ASCII name", [("aaaaaaaaaaaaa\u00fcx", "1")]),
        (
            "two variants",
            [("mailgun_relay_smtp_port", "25"), ("Mailgun_Relay_Smtp_Port", "2525")],
        ),
    ]
    return cases


def build_config_env() -> dict[str, Any]:
    cases = []
    for name, env in _env_cases():
        python = _python_start(env)
        expected, cause = _rust_start(env)
        case: dict[str, Any] = {"name": name, "env": [list(pair) for pair in env]}
        case["expected"] = expected
        if python != expected:
            if cause is None:
                # Only one reader per variable can explain this (D-7).
                assert any(not n.isupper() for n, _ in env), name
                cause = "D-7"
            case["divergence"] = cause
            case["python_starts"] = python is not None
        cases.append(case)
    return {
        "source": "mailgun_relay.config.Settings + mailgun_relay.__main__ reads",
        "cases": cases,
    }


# ---------------------------------------------------------- config_secrets

SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
SMTP = "smtp:\n  username: relay@example.test\n  password: hunter2\n"


def _doc(token: str = "", *, smtp: str = SMTP, extra: str = "") -> str:
    """A secrets document with one token; ``token`` overrides its fields."""
    fields = {
        "label": "homepage",
        "token_sha256": f'"{SHA}"',
        "mailgun_domains": "[mg.wersdoerfer.de]",
        "allowed_from_domains": "[wersdoerfer.de]",
    }
    lines = [line for line in token.splitlines() if line]
    for line in lines:
        key = line.split(":", 1)[0].strip()
        fields.pop(key, None)
    body = "".join(f"    {key}: {value}\n" for key, value in fields.items())
    body += "".join(f"    {line}\n" for line in lines)
    return f"{smtp}tokens:\n  - {body[4:]}{extra}"


def _secrets_cases() -> list[tuple[str, str, int, str | None]]:
    """(name, YAML text, file mode, divergence Python cannot reveal)."""
    ok = 0o640
    cases: list[tuple[str, str, int, str | None]] = [
        ("minimal", _doc(), ok, None),
        (
            "production shape",
            SMTP
            + "tokens:\n"
            + f"  - label: homepage\n    token_sha256: '{SHA}'\n"
            + "    mailgun_domains: [mg.wersdoerfer.de, mg.homepage.example]\n"
            + "    allowed_from_domains: [wersdoerfer.de, WERSDÖRFER.DE]\n"
            + "    allowed_from_addresses: [Info@Wersdörfer.de, noreply@wersdoerfer.de]\n"
            + f'  - label: python-podcast\n    token_sha256: "{SHA.upper()}"\n'
            + "    mailgun_domains:\n      - mg.python-podcast.de\n"
            + "    allowed_from_domains:\n      - python-podcast.de\n"
            + "    allowed_from_addresses:\n",
            ok,
            None,
        ),
        ("mode 0600", _doc(), 0o600, None),
        ("mode 0400", _doc(), 0o400, None),
        ("mode 0700", _doc(), 0o700, None),
        ("mode 0644", _doc(), 0o644, None),
        ("mode 0660", _doc(), 0o660, None),
        ("mode 0650", _doc(), 0o650, None),
        ("mode 0604", _doc(), 0o604, None),
        ("mode 0641", _doc(), 0o641, None),
        ("sha unquoted all digits", _doc(f"token_sha256: {'0' * 64}"), ok, None),
        ("sha boolean", _doc("token_sha256: yes"), ok, None),
        ("sha unquoted hex", _doc(f"token_sha256: {SHA}"), ok, None),
        ("sha uppercase with spaces", _doc(f'token_sha256: "  {SHA.upper()} "'), ok, None),
        ("sha too short", _doc(f'token_sha256: "{SHA[:63]}"'), ok, None),
        ("sha 0x prefix", _doc(f'token_sha256: "0x{SHA[:62]}"'), ok, None),
        ("sha placeholder", _doc("token_sha256: CHANGEME"), ok, None),
        ("sha missing", _doc().replace(f'    token_sha256: "{SHA}"\n', ""), ok, None),
        ("label placeholder", _doc("label: CHANGEME"), ok, None),
        ("label replace-me", _doc("label: replace-me"), ok, None),
        ("label blank", _doc('label: "  "'), ok, None),
        ("label missing", _doc().replace("  - label: homepage\n    ", "  - "), ok, None),
        ("label int", _doc("label: 123"), ok, None),
        (
            "duplicate labels",
            _doc() + _doc().split("tokens:\n", 1)[1],
            ok,
            None,
        ),
        ("tokens empty", SMTP + "tokens: []\n", ok, None),
        ("tokens missing", SMTP, ok, None),
        ("tokens mapping", SMTP + "tokens: {label: x}\n", ok, None),
        ("token entry scalar", SMTP + "tokens: [x]\n", ok, None),
        ("top level list", "- a\n- b\n", ok, None),
        ("empty document", "", ok, None),
        ("comments only", "# nothing\n", ok, None),
        ("smtp missing", _doc(smtp=""), ok, None),
        ("smtp list", _doc(smtp="smtp: [a]\n"), ok, None),
        ("username empty", _doc(smtp="smtp: {username: '', password: x}\n"), ok, None),
        ("username blank", _doc(smtp="smtp: {username: ' \t', password: x}\n"), ok, None),
        ("username placeholder", _doc(smtp="smtp: {username: changeme, password: x}\n"), ok, None),
        ("username bool", _doc(smtp="smtp: {username: no, password: x}\n"), ok, None),
        ("password empty", _doc(smtp="smtp: {username: relay, password: ''}\n"), ok, None),
        ("password missing", _doc(smtp="smtp: {username: relay}\n"), ok, None),
        ("password int", _doc(smtp="smtp: {username: relay, password: 1234}\n"), ok, None),
        ("password null", _doc(smtp="smtp: {username: relay, password: ~}\n"), ok, None),
        ("password quoted digits", _doc(smtp="smtp: {username: r, password: '1234'}\n"), ok, None),
        (
            "domains missing",
            _doc().replace("    mailgun_domains: [mg.wersdoerfer.de]\n", ""),
            ok,
            None,
        ),
        ("domains empty", _doc("mailgun_domains: []"), ok, None),
        ("domains string", _doc("mailgun_domains: mg.wersdoerfer.de"), ok, None),
        ("domain entry empty", _doc("mailgun_domains: ['']"), ok, None),
        ("domain entry null", _doc("allowed_from_domains: [~]"), ok, None),
        ("domain entry int", _doc("allowed_from_domains: [1]"), ok, None),
        ("domain underscore", _doc("allowed_from_domains: [a_b.de]"), ok, None),
        ("domain leading hyphen", _doc("allowed_from_domains: [-x.de]"), ok, None),
        ("domain bad punycode", _doc("allowed_from_domains: [xn--abc.de]"), ok, None),
        ("domain empty label", _doc("allowed_from_domains: [a..b]"), ok, None),
        ("domain idn", _doc("allowed_from_domains: [wersdörfer.de, ß.de, ÄÖÜ.example]"), ok, None),
        ("domain trailing dot", _doc("mailgun_domains: [mg.wersdoerfer.de.]"), ok, None),
        ("domain localhost", _doc("mailgun_domains: [localhost]"), ok, None),
        ("domain compatibility form", _doc("allowed_from_domains: [Ⅻ.de]"), ok, None),
        ("domain fullwidth", _doc(f"allowed_from_domains: [{FULLWIDTH_A}.de]"), ok, None),
        ("domain mixed script", _doc(f"allowed_from_domains: [{PAYPAL}.de]"), ok, None),
        ("domain greek", _doc("allowed_from_domains: [αβ.gr]"), ok, None),
        ("domain emoji", _doc("allowed_from_domains: [\U0001f600.de]"), ok, None),
        ("domain symbol", _doc("allowed_from_domains: [☃.de]"), ok, None),
        ("domain combining mark", _doc("allowed_from_domains: [áb.de]"), ok, None),
        ("domain mapped to middle dot", _doc("allowed_from_domains: [\u0140.de]"), ok, None),
        ("domain a-label of a symbol", _doc("mailgun_domains: [xn--n3h.de]"), ok, None),
        (
            "domain a-label with idn tld",
            _doc("mailgun_domains: [xn--wersdrfer-47a.\u00fc]"),
            ok,
            None,
        ),
        ("address a-label of a symbol", _doc("allowed_from_addresses: [a@xn--n3h.de]"), ok, None),
        ("addresses null", _doc("allowed_from_addresses: null"), ok, None),
        ("addresses empty", _doc("allowed_from_addresses: []"), ok, None),
        ("addresses string", _doc("allowed_from_addresses: a@wersdoerfer.de"), ok, None),
        ("address entry empty", _doc("allowed_from_addresses: ['']"), ok, None),
        ("address without at", _doc("allowed_from_addresses: [wersdoerfer.de]"), ok, None),
        ("address without local", _doc("allowed_from_addresses: ['@wersdoerfer.de']"), ok, None),
        ("address two ats", _doc("allowed_from_addresses: ['a@b@wersdoerfer.de']"), ok, None),
        ("address bad domain", _doc("allowed_from_addresses: [a@a_b.de]"), ok, None),
        ("address eai local", _doc("allowed_from_addresses: [jörg@wersdörfer.de]"), ok, None),
        ("address mixed-script domain", _doc(f"allowed_from_addresses: [a@{PAYPAL}.de]"), ok, None),
    ]
    yaml11 = ["yes", "On", "off", "0777", "1_000", "0x1F", "1:20", "1.5", ".inf", "~"]
    yaml11 += ["2026-10-15", "2026-10-15 10:00:00", "null"]
    cases += [(f"label plain {v}", _doc(f"label: {v}"), ok, None) for v in yaml11]
    cases += [
        ("label quoted yes", _doc('label: "yes"'), ok, None),
        ("label tagged str", _doc("label: !!str 0777"), ok, None),
        ("label plain y", _doc("label: y"), ok, None),
        ("label plain date-like", _doc("label: 2026-1-5"), ok, None),
        ("label block literal", _doc("label: |\n      multi\n      line"), ok, None),
        (
            "flow style",
            SMTP + f"tokens: [{{label: a, token_sha256: '{SHA}', "
            "mailgun_domains: [a.de], allowed_from_domains: [a.de]}]\n",
            ok,
            None,
        ),
        ("unknown keys ignored", _doc("comment: x", extra="other: [1, 2]\n"), ok, None),
        ("duplicate key last wins", _doc() + "smtp: {username: second, password: pw2}\n", ok, None),
        (
            "anchors and aliases",
            _doc("mailgun_domains: &d [a.de]\nallowed_from_domains: *d"),
            ok,
            None,
        ),
        (
            "duplicate anchor",
            _doc("mailgun_domains: &d [a.de]\nallowed_from_domains: &d [b.de]"),
            ok,
            None,
        ),
        ("merge key", _doc(extra="base: &b {k: 1}\nother:\n  <<: *b\n"), ok, "D-6"),
        ("int tag", _doc(extra="other: !!int '5'\n"), ok, "D-6"),
        ("seq tag", _doc("mailgun_domains: !!seq [a.de]"), ok, "D-6"),
        ("python tag", _doc(extra="other: !!python/name:os.system ''\n"), ok, None),
        ("custom tag", _doc(extra="other: !custom 1\n"), ok, None),
        ("recursive alias", _doc(extra="other: &r [*r]\n"), ok, "D-6"),
        ("deep nesting", _doc(extra="other: " + "[" * 70 + "]" * 70 + "\n"), ok, "D-6"),
        ("nel in quoted value", _doc(extra='other: "a\x85b"\n'), ok, "D-6"),
        ("line separator in quoted value", _doc(extra=f'other: "a{LINE_SEPARATOR}b"\n'), ok, "D-6"),
        ("invalid date in unknown key", _doc(extra="other: 2026-02-30\n"), ok, None),
        ("empty binary int in unknown key", _doc(extra="other: 0b_\n"), ok, None),
        ("value scalar", _doc(extra="other: =\n"), ok, None),
        ("merge scalar as value", _doc(extra="other: <<\n"), ok, None),
        ("collection key", _doc(extra="? [a]\n: b\n"), ok, None),
        ("two documents", _doc() + "---\n" + _doc(), ok, None),
        ("syntax error", _doc(extra="other: [a\n"), ok, None),
        ("tab before value", _doc(extra="other:\tb\n"), ok, None),
        ("control character", _doc(extra="other: a\x01\n"), ok, None),
        ("byte order mark", "﻿" + _doc(), ok, None),
        ("crlf line endings", _doc().replace("\n", "\r\n"), ok, None),
        ("explicit document markers", "---\n" + _doc() + "...\n", ok, None),
        ("yaml 1.1 directive", "%YAML 1.1\n---\n" + _doc(), ok, "D-6"),
        ("yaml 2.0 directive", "%YAML 2.0\n---\n" + _doc(), ok, None),
        ("tag directive", "%TAG !e! tag:example.com,2000:\n---\n" + _doc(), ok, "D-6"),
        ("tab in quoted value", _doc(extra='other: "a\tb"\n'), ok, "D-6"),
        (
            "tab before password",
            _doc(smtp="smtp:\n  username: relay\n  password:\thunter2\n"),
            ok,
            None,
        ),
        ("empty flow key", _doc(extra="other: {: x}\n"), ok, None),
        ("long decimal int in unknown key", _doc(extra=f"other: {'1' * 4301}\n"), ok, None),
        ("decimal int at the digit limit", _doc(extra=f"other: {'1' * 4300}\n"), ok, None),
        ("long octal int in unknown key", _doc(extra=f"other: 0{'7' * 5000}\n"), ok, None),
        (
            "aliased password as address",
            _doc(
                "allowed_from_addresses: [*pw]",
                smtp="smtp:\n  username: relay\n  password: &pw hunter2\n",
            ),
            ok,
            None,
        ),
    ]
    return cases


def _python_secrets(text: str, mode: int) -> dict[str, Any] | None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "secrets.yml"
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        try:
            secrets = load_secrets(path)
        except Exception:  # every failure stops the process at startup
            return None
    return {
        "smtp": {"username": secrets.smtp.username, "password": secrets.smtp.password},
        "tokens": [
            {
                "label": token.label,
                "token_sha256": token.token_sha256,
                "mailgun_domains": sorted(token.mailgun_domains),
                "allowed_from_domains": sorted(token.allowed_from_domains),
                "allowed_from_addresses": (
                    None
                    if token.allowed_from_addresses is None
                    else sorted(token.allowed_from_addresses)
                ),
            }
            for token in secrets.tokens
        ],
    }


def _config_domain_entry_ok(domain: str) -> bool:
    return config_domain_ok(domain, normalize_domain(domain))


def _schema_divergence(text: str) -> str | None:
    """D-5, D-10, D-17 for a document Python loaded."""
    for entry in yaml.safe_load(text)["tokens"]:
        if not isinstance(entry["token_sha256"], str):
            return "D-5"
        for key in ("mailgun_domains", "allowed_from_domains"):
            if not all(_config_domain_entry_ok(domain) for domain in entry[key]):
                return "D-10"
        for address in entry.get("allowed_from_addresses") or []:
            local, _, domain = address.strip().rpartition("@")
            if not local.isascii():
                return "D-17"
            if not _config_domain_entry_ok(domain):
                return "D-10"
    return None


def build_config_secrets() -> dict[str, Any]:
    cases = []
    for name, text, mode, parser_divergence in _secrets_cases():
        python = _python_secrets(text, mode)
        case: dict[str, Any] = {"name": name, "yaml": text, "mode": mode}
        divergence = None
        if python is not None:
            divergence = _schema_divergence(text)
            assert divergence is None or parser_divergence is None, name
            divergence = divergence or parser_divergence
        else:
            assert parser_divergence is None, f"{name}: Python rejects it already"
        case["expected"] = None if divergence else python
        if divergence:
            case["divergence"] = divergence
            case["python_loads"] = True
        cases.append(case)
    return {"source": "mailgun_relay.config.load_secrets", "cases": cases}


# -------------------------------------------------------------------- auth

AUTH_TOKENS = [
    ("homepage-production", "homepage-token-secret"),
    ("python-podcast-production", "podcast-token-secret"),
    ("colon", "a:b:c"),
    ("umlaut", "pässwört"),
    ("empty", ""),
    ("spaces", " padded "),
    ("dup-first", "shared"),
    ("dup-second", "shared"),
]


def _basic(user: bytes, password: bytes, *, scheme: bytes = b"Basic ") -> bytes:
    return scheme + base64.b64encode(user + b":" + password)


def _auth_headers() -> list[tuple[str, bytes | None]]:
    good = _basic(b"api", b"homepage-token-secret")
    encoded = good[len(b"Basic ") :]
    cases: list[tuple[str, bytes | None]] = [("absent", None), ("empty", b"")]
    cases += [(f"token {label}", _basic(b"api", t.encode())) for label, t in AUTH_TOKENS]
    users = [b"API", b"Api", b"api ", b" api", b"", b"apix", b"ap", b"api\x00", b"\xc3\xa4pi"]
    cases += [(f"user {u!r}", _basic(u, b"homepage-token-secret")) for u in users]
    schemes = [b"basic ", b"BASIC ", b"Basic", b"Basic\t", b"Basic  ", b"Bearer ", b" Basic "]
    cases += [(f"scheme {scheme!r}", scheme + encoded) for scheme in schemes]
    whitespace = [b"\t", b"\n", b"\x0b", b"\x0c", b"\r", b"\x1c", b"\x1d", b"\x1e", b"\x1f", b" "]
    whitespace += [b"\x85", b"\xa0"]
    cases += [(f"leading {w!r}", b"Basic " + w + encoded) for w in whitespace]
    cases += [(f"trailing {w!r}", good + w) for w in whitespace]
    cases += [
        (f"base64 {b!r}", b"Basic " + b)
        for b in [
            encoded.rstrip(b"="),
            encoded + b"=",
            encoded + b"==",
            b"=" + encoded,
            encoded[:4] + b" " + encoded[4:],
            encoded[:4] + b"\n" + encoded[4:],
            encoded + b"YQ==",
            encoded.replace(b"+", b"-").replace(b"/", b"_"),
            b"!!!notbase64!!!",
            b"YXBpOnQ=",
            b"YXBpOnR=",
            b"YXBpOnQ",
            b"YXBpOnQ==",
            b"Y",
            b"====",
            b"",
        ]
    ]
    cases += [
        (f"decoded {raw!r}", b"Basic " + base64.b64encode(raw))
        for raw in [
            b"justuser",
            b"api",
            b"api:",
            b":homepage-token-secret",
            b"api::homepage-token-secret",
            b"api:homepage-token-secret\x00",
            b"api:\xff",
            b"api:\xed\xa0\x80",
            b"api:\xc0\xaf",
            b"api:p\xc3\xa4ssw\xc3\xb6rt",
            b"api:p\xe4ssw\xf6rt",
        ]
    ]
    cases += [
        ("non-ascii before base64", b"Basic \xe9" + encoded),
        ("non-ascii after base64", good + b"\xe9"),
        ("non-ascii inside base64", b"Basic " + encoded[:4] + b"\x80" + encoded[4:]),
        ("non-ascii scheme", b"B\xe4sic " + encoded),
    ]
    rng = random.Random(20261015)  # noqa: S311 - a fixed seed, reproducible
    for i in range(40):
        header = bytearray(good)
        for _ in range(rng.randint(1, 3)):
            position = rng.randrange(len(header) + 1)
            choice = rng.random()
            if choice < 0.4 and position < len(header):
                del header[position]
            elif choice < 0.7:
                header.insert(position, rng.choice(b"AZaz09+/= \t-_\x85\xa0\xe9:"))
            elif position < len(header):
                header[position] = rng.randrange(256)
        cases.append((f"mutation {i}", bytes(header)))
    return cases


def build_auth() -> dict[str, Any]:
    policies = [
        TokenPolicy(
            label=label,
            token_sha256=hashlib.sha256(token.encode()).hexdigest(),
            mailgun_domains=frozenset({"mg.wersdoerfer.de"}),
            allowed_from_domains=frozenset({"wersdoerfer.de"}),
        )
        for label, token in AUTH_TOKENS
    ]
    cases = []
    for name, header in _auth_headers():
        text = None if header is None else header.decode("latin-1")
        try:
            expected: str | None = authenticate(text, policies).label
        except AuthError:
            expected = None
        cases.append({"name": name, "header": text, "expected": expected})
    return {
        "source": "mailgun_relay.auth.authenticate (header bytes as their latin-1 decoding)",
        "tokens": [{"label": p.label, "token_sha256": p.token_sha256} for p in policies],
        "cases": cases,
    }


# ------------------------------------------------------------------ domain

# Path domains Python refuses (IDNA2008, 400) and the Rust port maps to an
# A-label with UTS46 (403, D-10), with that A-label.
D10_PATH_DOMAINS = {
    "☃.de": "xn--n3h.de",
    "\U0001f600.de": "xn--e28h.de",
    "a\u00b7b.de": "xn--ab-0ea.de",
    "\u0140.de": "xn--l-gda.de",
    "x\u013fy.de": "xn--xly-mga.de",
    "x\u0140y.de": "xn--xly-mga.de",
    "\u30fb.jp": "xn--vek.jp",
    "xn--n3h.de": "xn--n3h.de",
    "xn--e28h.de": "xn--e28h.de",
}

LATIN_SET = [chr(c) for low, high in CONFIG_RANGES for c in range(low, high + 1)]


def _domain_inputs() -> list[str]:
    inputs = [
        "wersdoerfer.de",
        "mg.wersdoerfer.de",
        "MG.WERSDOERFER.DE",
        "mg.python-podcast.de",
        "mg.staging.django-cast.com",
        "email.mg.staging.django-cast.com",
        "mg.konektom.org",
        "wersdörfer.de",
        "WERSDÖRFER.DE",
        "xn--wersdrfer-47a.de",
        "XN--wersdrfer-47a.DE",
        "mg.wersdörfer.de",
        " mg.wersdoerfer.de ",
        "\tmg.wersdoerfer.de\n",
        "\x1cmg.wersdoerfer.de\x85",
        "\u00a0mg.wersdoerfer.de\u3000",
        "\u200bmg.wersdoerfer.de",
        "mg.wersdoerfer.de.",
        "mg.wersdoerfer.de..",
        ".mg.wersdoerfer.de",
        ".",
        "",
        " ",
        "localhost",
        "de",
        "a..b",
        "a_b.de",
        "-x.de",
        "x-.de",
        "ab--c.de",
        "xn--abc.de",
        "xn--.de",
        "xn--4ca-.de",
        "xn--a-ecp.de",
        "ß.de",
        "ς.gr",
        "ⅻ.de",
        f"{FULLWIDTH_A}.de",
        "ﬁ.de",
        "İ.de",
        "ä.de",
        "a\u0308.de",
        "\u0308a.de",
        "αβ.gr",
        "ΑΣ.gr",
        PAYPAL + ".de",
        "пример.рф",
        "例子.中国",
        "한국.kr",
        "עברית.il",
        "مثال.eg",
        "a\u200db.de",
        "a\u200cb.de",
        "l·l.cat",
        "͵\u03b1.gr",
        "א\u05f3.il",
        "・.jp",
        "\u0661\u06f1.eg",
        "1.2.3.4",
        "[::1]",
        "a@b.de",
        "a:25",
        "a/b.de",
        "a%2Fb.de",
        "a b.de",
        "a*b.de",
        "123.456",
        "x.123",
        "\U0001f600.de",
        "☃.de",
        "a·b.de",
        "ŀ.de",
        "xn--n3h.de",
        "xn--e28h.de",
        "a.xn--wersdrfer-47a.ü",
        "a" * 63 + ".de",
        "a" * 64 + ".de",
        ".".join(["a" * 63] * 3) + "." + "a" * 61,
        ".".join(["a" * 63] * 3) + "." + "a" * 62,
        ".".join(["a" * 63] * 3) + "." + "a" * 61 + ".",
        "ä" * 59 + ".de",
        "ä" * 60 + ".de",
    ]
    inputs += [f"x{char}y.de" for char in LATIN_SET]
    rng = random.Random(20261016)  # noqa: S311 - a fixed seed, reproducible
    pool = "abcxyz09-._ÄäöÖüßéÉ ᵃ\u0301\u200dⅻ"
    for _ in range(60):
        inputs.append("".join(rng.choice(pool) for _ in range(rng.randint(1, 12))) + ".de")
    return list(dict.fromkeys(inputs))


def _python_domain(value: str) -> str | None:
    try:
        return normalize_domain(value)
    except InvalidAddressError:
        return None


def build_domain() -> dict[str, Any]:
    cases = []
    for value in _domain_inputs():
        python = _python_domain(value)
        expected = D10_PATH_DOMAINS.get(value, python)
        config = python if python is not None and _config_domain_entry_ok(value) else None
        case: dict[str, Any] = {"input": value, "expected": expected, "config": config}
        if expected != python:
            assert python is None, value
            case["divergence"] = "D-10"
            case["python"] = python
        cases.append(case)
    return {
        "source": "mailgun_relay.policy.normalize_domain (config: the D-10 set)",
        "cases": cases,
    }


# ----------------------------------------------------------------- address

U_LABEL = "wersdörfer.de"
A_LABEL = "xn--wersdrfer-47a.de"


def _address_inputs() -> list[str]:
    inputs = [
        # Python tests (test_headers.py, test_policy.py, test_idn_addresses.py,
        # test_messages_endpoint.py).
        "a@x.test",
        "b@y.test",
        "Alice <alice@x.test>",
        "alice@x.test\nBcc: evil@y.test",
        "not an address",
        "bad@bad domain",
        "a@x..test",
        "foo@",
        "@bar.com",
        "user@-.example.com",
        "no-at-sign",
        '"Doe, Jane" <jane@example.test>',
        "a@x.test, b@y.test, Carol <c@z.test>",
        "a@x.test,\nb@y.test",
        "a@x.test, bad@bad domain",
        f"foo@{U_LABEL}",
        "foo@WERSDÖRFER.de",
        f"foo@{A_LABEL}",
        f"Jörg <foo@{U_LABEL}>",
        "Some.User@Example.TEST",
        "x@wersdoerfer.de",
        "someone@wersdörfer.de",
        "Jochen-Homepage@wersdoerfer.de",
        "Jochen <jochen@wersdörfer.de>",
        "someone-else@wersdoerfer.de",
        "not-an-email",
        "ok@wersdoerfer.de\nBcc: evil@wersdoerfer.de",
        "Jörg <jörg@wersdoerfer.de>",
        "jörg@wersdoerfer.de",
        "jörg@example.org",
        "A <a@WERSDÖRFER.DE>",
        f"Cc Person <cc@{U_LABEL}>",
        "hidden@bü.test",
        f"Jörg <reply@{U_LABEL}>, other@bü.test",
        "support@wersdoerfer.de, jörg@example.org",
        "intruder@example.org",
        "Anyone <anyone@wersdoerfer.de>",
        f"visitor@{U_LABEL}",
        "=?utf-8?B?YQ0KYg==?= <victim@wersdoerfer.de>",
        "gone-user@Example.org",
        "a@wersdoerfer.de, b@wersdoerfer.de",
        # Production shapes (fix-403-diagnosis.md 1.3, 1.4).
        "Homepage <jochen-homepage@wersdoerfer.de>",
        "jochen-django@wersdoerfer.de",
        "Python Podcast <noreply@mg.python-podcast.de>",
        "noreply@email.mg.staging.django-cast.com",
        "noreply@konektom.org",
        "jochen-villakunterbunt@wersdoerfer.de",
        "recorder@wersdoerfer.de",
        "webmaster@localhost",
        "mailgun-relay@xn--wersdrfer-47a.de",
        "Jochen Wersdörfer <jochen@wersdoerfer.de>",
        "=?utf-8?b?Sm9jaGVuIFdlcnNkw7ZyZmVy?= <jochen@wersdoerfer.de>",
        '"Wersdörfer, Jochen" <jochen@wersdoerfer.de>',
        # Mailbox forms.
        " a@x.de ",
        "\ta@x.de\t",
        "Jane<a@x.de>",
        '"Jane" <a@x.de>',
        "Doe, Jane <a@x.de>",
        "Dr. Jane <a@x.de>",
        "Dr.  Jane   Doe <a@x.de>",
        "<a@x.de>",
        "< a@x.de >",
        "<\ta@x.de\t>",
        "<a@x.de> trailing",
        "a@x.de (Kommentar)",
        "(Kommentar) a@x.de",
        "(c1) a@x.de (c2)",
        "a@x.de ()",
        "Jane (c) <a@x.de>",
        "(c) Jane <a@x.de>",
        "(c) <a@x.de>",
        "Jane <a@x.de> (c)",
        "Jane <a@x.de> (c, d)",
        "a@x.de (Doe, Jane)",
        "a@x.de (a (nested) comment)",
        "a@x.de (unclosed",
        "a@x.de )",
        "a@x.de (with \\) escape)",
        'a@x.de (with "quote")',
        "a . b@x.de",
        "a@x . de",
        "a@ x.de",
        "a @x.de",
        "a(c)@x.de",
        "a@x.de(c)",
        '"a b"@x.de',
        '"ab"@x.de',
        "a@[1.2.3.4]",
        "a@[IPv6:::1]",
        "a@x.de>",
        "<a@x.de",
        "Jane <a@x.de",
        "Jane a@x.de>",
        "Jörg <a@x.de>",
        "=?utf-8?b?SsO2cmc=?= <a@x.de>",
        "=?utf-8?q?J=C3=B6rg?= <a@x.de>",
        "a@b@x.de",
        "a,b@x.de",
        "a;b@x.de",
        "grp: a@x.de;",
        "undisclosed-recipients:;",
        "a@x.de, b@x.de",
        "a@x.de,",
        ",a@x.de",
        "a@x.de,,b@x.de",
        "a@x.de, ,b@x.de",
        '"Doe, Jane" <a@x.de>, b@x.de',
        '"a,b" <a@x.de>, "c,d" <c@x.de>',
        "'Jane' <a@x.de>",
        'Jane "Q" Doe <a@x.de>',
        '"Jane \\"Q\\" Doe" <a@x.de>',
        '"Jane\\\\ Doe" <a@x.de>',
        '"Jane\\ Doe" <a@x.de>',
        '"Jane  Doe" <a@x.de>',
        '"" <a@x.de>',
        '"Jane <a@x.de>',
        '"Jane\\" <a@x.de>',
        "Jane\\ Doe <a@x.de>",
        "Jane <<a@x.de>>",
        "Jane <a@x.de><b@x.de>",
        "Jane <a@x.de> <b@x.de>",
        "Jane: <a@x.de>",
        "Jane; <a@x.de>",
        "Ja[ne] <a@x.de>",
        "Jane@home <a@x.de>",
        "Jö rg <a@x.de>",
        "J\u00a0D <a@x.de>",
        "Jane\u3000Doe <a@x.de>",
        ".Jane <a@x.de>",
        "Jane. <a@x.de>",
        "<a@x.de> <b@x.de>",
        "a@x.de b@x.de",
        "a@x.de\tb@x.de",
        "a@x.de\x00",
        "a@x.de\x7f",
        "a@x.de\x85",
        "a@x.de\u2028",
        "Jane\x01 <a@x.de>",
        "a@x.de\r\n",
        "",
        " ",
        "@",
        "<>",
        "Jane <>",
        "<@x.de>",
        # Local parts.
        "@x.de",
        "a@",
        ".a@x.de",
        "a.@x.de",
        "a..b@x.de",
        "a.b.c@x.de",
        "a+tag@x.de",
        "a/b=c?d^e`f{g|h}i~j!k#l$m%n&o'p*q@x.de",
        "o'brien@wersdoerfer.de",
        "O'Brien <o'brien@wersdoerfer.de>",
        "a\\b@x.de",
        'a"b@x.de',
        "a b@x.de",
        "jörg@x.de",
        "ä@x.de",
        "a\u0308@x.de",
        "é@x.de",
        "日本@x.de",
        "INFO@X.DE",
        "Info <Postmaster@x.de>",
        "Support@x.de",
        "WebMaster@x.de",
        "Infos@x.de",
        "Sales.Team@x.de",
        # Domains.
        "a@x",
        "a@test",
        "a@x.test",
        "a@localhost",
        "a@x.localhost",
        "a@x.local",
        "a@x.invalid",
        "a@x.onion",
        "a@x.arpa",
        "a@home.arpa",
        "a@arpa",
        "a@x.example",
        "a@example.com",
        "a@123.45",
        "a@x.123",
        "a@x.1a",
        "a@x.a1",
        "a@1.2.3.4",
        "a@x.de.",
        "a@.x.de",
        "a@x..de",
        "a@x_y.de",
        "a@-x.de",
        "a@x-.de",
        "a@x.-de",
        "a@ab--c.de",
        "a@xn--abc.de",
        "a@xn--4ca.de",
        "a@XN--4CA.DE",
        "a@xn--wersdrfer-47a.DE",
        "a@xn--n3h.de",
        "a@ä.de",
        "a@a\u0308.de",
        "a@\u0308a.de",
        "a@ß.de",
        "a@ẞ.de",
        "a@İ.de",
        "a@ŀ.de",
        "a@ŉ.de",
        "a@ǆ.de",
        "a@☃.de",
        "a@\U0001f600.de",
        "a@ⅻ.de",
        f"a@{FULLWIDTH_A}.de",
        "a@x\uff0ede",
        "a@x。de",
        "a@αβ.gr",
        "a@пример.рф",
        "a@例子.中国",
        f"a@{PAYPAL}.de",
        "a@a\u200db.de",
        "a@l·l.cat",
        "a@x.de\u00ad",
        "a@x\uff20y.de",
        # Lengths: local 63-66, labels 63/64, domain 253/254, address 254/255.
        "a" * 63 + "@x.de",
        "a" * 64 + "@x.de",
        "a" * 65 + "@x.de",
        "a" * 66 + "@x.de",
        "a@" + "b" * 63 + ".de",
        "a@" + "b" * 64 + ".de",
        "a@" + ".".join(["b" * 63] * 3) + "." + "c" * 61,
        "a@" + ".".join(["b" * 63] * 3) + "." + "c" * 62,
        "a" * 64 + "@" + ".".join(["b" * 63, "c" * 63, "d" * 58]) + ".de",
        "a" * 64 + "@" + ".".join(["b" * 63, "c" * 63, "d" * 59]) + ".de",
        "a" * 100 + "@" + "b" * 63 + "." + "c" * 63 + "." + "d" * 20 + ".de",
        "a" * 100 + "@" + "b" * 63 + "." + "c" * 63 + "." + "d" * 21 + ".de",
        "a" * 200 + "@" + "ä" * 20 + ".de",
        "a" * 200 + "@" + "ä" * 23 + ".de",
        "a" * 200 + "@" + "ä" * 25 + ".de",
        "a" * 230 + "@" + "x" * 20 + ".de",
        "a" * 240 + "@" + "x" * 10 + ".de",
        "a" * 240 + "@" + "x" * 11 + ".de",
    ]
    inputs += [f"a@x{char}y.de" for char in LATIN_SET]
    # A combining mark where a domain or a label starts.
    marks = sorted(COMBINING_MARKS)
    inputs += [f"a@{mark}x.de" for mark in marks] + [f"a@x.{mark}y.de" for mark in marks]
    inputs += [f"a@{char}x.de" for char in "äßǅɐḁ"]
    rng = random.Random(20261017)  # noqa: S311 - a fixed seed, reproducible
    seeds = [
        "Homepage <jochen-homepage@wersdoerfer.de>",
        "jochen-django@wersdoerfer.de",
        '"Doe, Jane" <jane@wersdörfer.de>',
        "a.b+c@mg.python-podcast.de (Kommentar)",
    ]
    pool = [*" \t.@<>()\",;:[]\\'äé日☃ⅻ\u0301\u00a0", "..", "@@", "xn--", "-"]
    for i in range(240):
        value = seeds[i % len(seeds)]
        for _ in range(rng.randint(1, 3)):
            position = rng.randrange(len(value) + 1)
            if rng.random() < 0.3 and position < len(value):
                value = value[:position] + value[position + 1 :]
            else:
                value = value[:position] + rng.choice(pool) + value[position:]
        inputs.append(value)
    return list(dict.fromkeys(inputs))


def _python_strict(value: str) -> str | None:
    try:
        return parse_email_strict(value)[0]
    except InvalidAddressError:
        return None


def _python_list(value: str) -> list[list[str]] | None:
    try:
        return [[a.display_name, a.addr_spec] for a in parse_address_list([value])]
    except HeaderInjectionError:
        return None


def _python_header_list(value: str) -> list[list[str]] | None:
    try:
        return [[a.display_name, a.addr_spec] for a in parse_header_address_list(value)]
    except HeaderInjectionError:
        return None


def _python_normalize_address(value: str) -> str | None:
    try:
        return normalize_address(value)
    except InvalidAddressError:
        return None


def _rust_normalize_address(value: str) -> str | None:
    """``normalize_config_address``: Python's result unless the local part
    is not ASCII (D-17) or the domain is outside the D-10 set."""
    python = _python_normalize_address(value)
    if python is None:
        return None
    local, _, domain = value.strip().rpartition("@")
    if not local.isascii() or not _config_domain_entry_ok(domain):
        return None
    return python


def build_address() -> dict[str, Any]:
    cases = []
    for value in _address_inputs():
        strict = _python_strict(value)
        single = _python_list(value)
        header = _python_header_list(value)
        mailbox = rust_mailbox(value)
        mailboxes = rust_mailbox_list(value)
        if mailbox is not None:
            # The fail-closed property: Rust's result is Python's result.
            assert strict == mailbox[2], (value, strict, mailbox)
            assert single == [[mailbox[0], mailbox[1]]], (value, single, mailbox)
        if mailboxes is not None:
            assert header == [[m[0], m[1]] for m in mailboxes], (value, header, mailboxes)
        python_normalized = _python_normalize_address(value)
        normalized = _rust_normalize_address(value)
        case: dict[str, Any] = {
            "input": value,
            "python": {
                "parse_email_strict": strict,
                "parse_address_list": single,
                "parse_header_address_list": header,
                "normalize_address": python_normalized,
            },
            "expected": {
                "mailbox": None if mailbox is None else list(mailbox),
                "mailbox_list": None if mailboxes is None else [list(m) for m in mailboxes],
                "normalize_address": normalized,
            },
        }
        divergences = []
        if (mailbox is None and (strict or single)) or (mailboxes is None and header):
            divergences.append("D-11")
        if normalized != python_normalized:
            local = value.strip().rpartition("@")[0]
            divergences.append("D-10" if local.isascii() else "D-17")
        if divergences:
            case["divergence"] = ",".join(divergences)
        cases.append(case)
    return {
        "source": (
            "mailgun_relay.policy.parse_email_strict, normalize_address; "
            "mailgun_relay.headers.parse_address_list, parse_header_address_list"
        ),
        "cases": cases,
    }


# ------------------------------------------------------------------ policy

POLICIES = [
    # Production shapes after the 403 fix (fix-403-diagnosis.md 1.3).
    (
        "homepage-production",
        ["mg.wersdoerfer.de"],
        ["wersdoerfer.de"],
        ["jochen-homepage@wersdoerfer.de", "jochen-django@wersdoerfer.de"],
    ),
    (
        "python-podcast-production",
        ["mg.python-podcast.de"],
        ["mg.python-podcast.de", "wersdoerfer.de"],
        ["noreply@mg.python-podcast.de", "jochen-django@wersdoerfer.de"],
    ),
    (
        "registry-staging",
        ["mg.staging.django-cast.com"],
        ["email.mg.staging.django-cast.com"],
        ["noreply@email.mg.staging.django-cast.com"],
    ),
    ("domain-only", ["mg.wersdoerfer.de"], ["wersdoerfer.de"], None),
    (
        "idn",
        ["mg.wersdörfer.de"],
        ["wersdörfer.de", "WERSDOERFER.de"],
        ["Jochen@Wersdörfer.de", "o'brien@wersdoerfer.de"],
    ),
]

POLICY_PATHS = [
    "mg.wersdoerfer.de",
    "MG.WERSDOERFER.DE",
    " mg.wersdoerfer.de ",
    "mg.wersdoerfer.de.",
    "wersdoerfer.de",
    "mg.python-podcast.de",
    "mg.staging.django-cast.com",
    "mg.wersdörfer.de",
    "mg.xn--wersdrfer-47a.de",
    "evil.test",
    "a_b.de",
    "",
    "☃.de",
]

POLICY_FROMS = [
    "Homepage <jochen-homepage@wersdoerfer.de>",
    "jochen-homepage@wersdoerfer.de",
    "Jochen-Homepage@WERSDOERFER.DE",
    "jochen-django@wersdoerfer.de",
    "Python Podcast <noreply@mg.python-podcast.de>",
    "noreply@mg.python-podcast.de",
    "noreply@email.mg.staging.django-cast.com",
    "webmaster@localhost",
    "someone-else@wersdoerfer.de",
    "x@evil.test",
    "x@mg.wersdoerfer.de",
    "jochen@wersdörfer.de",
    "Jochen <JOCHEN@xn--wersdrfer-47a.de>",
    "jochen@wersdoerfer.de",
    "O'Brien <o'brien@wersdoerfer.de>",
    "jörg@wersdoerfer.de",
    "not-an-email",
    "ok@wersdoerfer.de\nBcc: evil@wersdoerfer.de",
    "a . b@wersdoerfer.de",
    "Jane <jochen-django@wersdoerfer.de",
    "jochen-django@wersdoerfer.de, x@evil.test",
    "",
]


def _token_policy(entry: tuple[str, list[str], list[str], list[str] | None]) -> TokenPolicy:
    label, mailgun, from_domains, addresses = entry
    return TokenPolicy(
        label=label,
        token_sha256="0" * 64,
        mailgun_domains=frozenset(normalize_domain(d) for d in mailgun),
        allowed_from_domains=frozenset(normalize_domain(d) for d in from_domains),
        allowed_from_addresses=(
            None if addresses is None else frozenset(normalize_address(a) for a in addresses)
        ),
    )


def _python_policy(policy: TokenPolicy, path: str, sender: str) -> dict[str, Any]:
    try:
        enforce_policy(policy, path_domain=path, from_address=sender)
    except InvalidAddressError:
        return {"status": 400, "detail": None}
    except PolicyError as exc:
        return {"status": 403, "detail": str(exc)}
    return {"status": 200, "detail": parse_email_strict(sender)[0]}


def _rust_policy(policy: TokenPolicy, path: str, sender: str) -> dict[str, Any]:
    """``policy::enforce_policy``: Python's order with the D-10 path
    domains and the mailbox decisions of the Rust grammar (D-11)."""
    normalized = D10_PATH_DOMAINS.get(path, _python_domain(path))
    if normalized is None:
        return {"status": 400, "detail": None}
    if normalized not in policy.mailgun_domains:
        return {"status": 403, "detail": f"token not allowed for path domain {normalized!r}"}
    mailbox = rust_mailbox(sender)
    if mailbox is None:
        return {"status": 400, "detail": None}
    address = mailbox[2]
    domain = address.rpartition("@")[2]
    if domain not in policy.allowed_from_domains:
        return {"status": 403, "detail": f"token not allowed for from domain {domain!r}"}
    allowed = policy.allowed_from_addresses
    if allowed is not None and address not in allowed:
        return {"status": 403, "detail": f"token not allowed for from address {address!r}"}
    return {"status": 200, "detail": address}


def build_policy() -> dict[str, Any]:
    policies = [_token_policy(entry) for entry in POLICIES]
    cases = []
    for policy in policies:
        for path in POLICY_PATHS:
            for sender in POLICY_FROMS:
                python = _python_policy(policy, path, sender)
                expected = _rust_policy(policy, path, sender)
                case: dict[str, Any] = {
                    "policy": policy.label,
                    "path": path,
                    "from": sender,
                    "expected": expected,
                }
                if expected != python:
                    case["python"] = python
                    case["divergence"] = "D-10" if path in D10_PATH_DOMAINS else "D-11"
                cases.append(case)
    return {
        "source": "mailgun_relay.policy.enforce_policy (detail: 403 message or policy address)",
        "policies": [
            {
                "label": p.label,
                "mailgun_domains": sorted(p.mailgun_domains),
                "allowed_from_domains": sorted(p.allowed_from_domains),
                "allowed_from_addresses": (
                    None if p.allowed_from_addresses is None else sorted(p.allowed_from_addresses)
                ),
            }
            for p in policies
        ],
        "cases": cases,
    }


# ----------------------------------------------------------------- headers

HEADER_MAX = 20

# Every character the control-character rule distinguishes, and neighbours.
CONTROL_PROBES = [chr(c) for c in range(0xA1)] + [
    "\u2027",
    LINE_SEPARATOR,
    "\u2029",
    "\u202a",
    "\u00ad",
    "\ufeff",
    "\U0001f600",
]

SUBJECTS = [
    "Hello there",
    "  Hello  ",
    "Hello\tthere",
    "\tHello\t",
    "",
    "   ",
    "Hi\nBcc: evil@x.com",
    "Hi\rEvil",
    "Hi\r\n",
    "Hi\n",
    "\nHi",
    "\x1cHi\x1f",
    "Hi\x1cthere",
    "\x85Hi\xa0",
    "Hi\x85there",
    "Hi\xa0there",
    "Hi\u2028",
    "\u2029",
    "Hi\u3000",
    "[Django] ERROR (EXTERNAL IP)",
    "Passwort zurücksetzen",
    "=?utf-8?B?YQ0KYg==?=",
    "a" * HEADER_MAX,
    "a" * (HEADER_MAX + 1),
    "ü" * HEADER_MAX,
    "ü" * (HEADER_MAX + 1),
    "\U0001f600" * HEADER_MAX,
    " " + "a" * HEADER_MAX + " ",
] + [f"Hi{c}World" for c in CONTROL_PROBES]

HEADER_NAMES = [
    "Reply-To",
    "X-Mailer",
    "Auto-Submitted",
    "X1",
    "X",
    "x-y-z",
    "In-Reply-To",
    "References",
    "List-Unsubscribe",
    "X Bad Name",
    "X_Bad",
    "1X",
    "-X",
    "",
    "X-Ä",
    "X-Foo\n",
    "Bcc\n",
    "X-Foo\r",
    "X-Foo\n\n",
    "X-Foo:",
    "X-Foo\t",
    "Resent-From",
    "resent-x",
    "RESENT-",
    "Resent",
    "Resentx",
    "X-Bcc",
    "Bcc-X",
] + [
    variant
    for name in sorted(headers_module._DANGEROUS_HEADER_NAMES)
    for variant in (name, name.upper(), name.title())
]

HEADER_VALUES = [
    "support@example.test",
    "auto-generated",
    "",
    " padded ",
    "a\tb",
    "a\x00b",
    "ok\nBcc: evil@x.com",
    "a\rb",
    "a\x7fb",
    "a\x85b",
    "a\u2028b",
    "x" * HEADER_MAX,
    "x" * (HEADER_MAX + 1),
    "ö" * HEADER_MAX,
    "ö" * (HEADER_MAX + 1),
]


def _python_headers(headers: list[tuple[str, str]]) -> str:
    try:
        validate_custom_headers(dict(headers), max_value_length=HEADER_MAX)
    except DangerousHeaderError:
        return "dangerous"
    except HeaderTooLongError:
        return "too_long"
    except HeaderInjectionError:
        return "injection"
    return "ok"


def _rust_headers(headers: list[tuple[str, str]]) -> str:
    """``headers::validate_custom_headers``: Python's rules, but a name must
    match the pattern in full (D-19: no final newline)."""
    for name, _ in dict(headers).items():
        if name.endswith("\n") and headers_module._HEADER_NAME_RE.match(name):
            return "injection"
        python = _python_headers([(name, dict(headers)[name])])
        if python != "ok":
            return python
    return "ok"


def build_headers() -> dict[str, Any]:
    subjects = []
    for value in SUBJECTS:
        try:
            expected: dict[str, Any] = {"subject": validate_subject(value, max_length=HEADER_MAX)}
        except HeaderInjectionError:
            expected = {"error": "injection"}
        except HeaderTooLongError:
            expected = {"error": "too_long"}
        subjects.append({"value": value, "expected": expected})
    header_sets: list[list[tuple[str, str]]] = [[(name, "ok")] for name in HEADER_NAMES]
    header_sets += [[("X-Custom", value)] for value in HEADER_VALUES]
    header_sets += [
        # Map order decides which error wins.
        [("X-Long", "x" * (HEADER_MAX + 1)), ("Bcc", "a@b.de")],
        [("Bcc", "a@b.de"), ("X-Long", "x" * (HEADER_MAX + 1))],
        [("X-A", "a\nb"), ("X Bad", "ok")],
        [("X-A", "ok"), ("X-B", "ok"), ("X-C", "a\x00b")],
        [("Reply-To", "a@b.de"), ("reply-to", "c@d.de")],
        [("X-Foo\n", "ok"), ("Bcc", "x")],
    ]
    cases = []
    for headers in header_sets:
        python = _python_headers(headers)
        status = _rust_headers(headers)
        case: dict[str, Any] = {"headers": [list(pair) for pair in headers], "expected": status}
        if status != python:
            case["python"] = python
            case["divergence"] = "D-19"
        cases.append(case)
    control = [
        {"value": f"a{c}b", "expected": contains_forbidden_control_chars(f"a{c}b")}
        for c in CONTROL_PROBES
    ]
    return {
        "source": (
            "mailgun_relay.headers validate_subject, validate_custom_headers, "
            "contains_forbidden_control_chars"
        ),
        "max_length": HEADER_MAX,
        "subjects": subjects,
        "headers": cases,
        "control": control,
    }


# ------------------------------------------------------------------ driver

GENERATORS: dict[str, Callable[[], Mapping[str, Any]]] = {
    "address.json": build_address,
    "auth.json": build_auth,
    "config_env.json": build_config_env,
    "config_secrets.json": build_config_secrets,
    "domain.json": build_domain,
    "headers.json": build_headers,
    "policy.json": build_policy,
}


def render(name: str) -> str:
    """Render one fixture file exactly as it is committed."""
    content = GENERATORS[name]()
    return json.dumps(content, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def check_fixtures(directory: Path = FIXTURES_DIR) -> list[str]:
    """Return the fixture files in ``directory`` that differ from a fresh render."""
    stale = []
    for name in sorted(GENERATORS):
        path = directory / name
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current != render(name):
            stale.append(name)
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when a file is stale")
    args = parser.parse_args(argv)
    if args.check:
        stale = check_fixtures()
        for name in stale:
            print(f"stale fixture: {name} (run rust/fixtures/generate.py)", file=sys.stderr)
        return 1 if stale else 0
    for name in sorted(GENERATORS):
        (FIXTURES_DIR / name).write_text(render(name), encoding="utf-8")
        print(f"wrote {FIXTURES_DIR / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
