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
import json
import logging
import os
import sys
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from unittest import mock

import idna
import uvicorn.config
import yaml

from mailgun_relay.config import Settings, load_secrets
from mailgun_relay.policy import normalize_domain

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


def _config_chars_ok(domain: str) -> bool:
    ranges = [
        (0xC0, 0xD6),
        (0xD8, 0xF6),
        (0xF8, 0x24F),
        (0x250, 0x2AF),
        (0x300, 0x36F),
        (0x1E00, 0x1EFF),
    ]
    return all(
        char in "abcdefghijklmnopqrstuvwxyz0123456789-."
        or any(low <= ord(char) <= high for low, high in ranges)
        for char in domain.strip().lower()
    )


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


# ------------------------------------------------------------------ driver

GENERATORS: dict[str, Callable[[], Mapping[str, Any]]] = {
    "config_env.json": build_config_env,
    "config_secrets.json": build_config_secrets,
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
