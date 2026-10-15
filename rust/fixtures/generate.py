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
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from unittest import mock

import idna
import uvicorn.config

from mailgun_relay.config import Settings

FIXTURES_DIR = Path(__file__).resolve().parent

# Look-alike characters, spelled out so the source stays unambiguous.
PAYPAL = f"p{chr(0x430)}ypal"  # Cyrillic small a: a mixed-script domain
NBSP = chr(0xA0)

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


# ------------------------------------------------------------------ driver

GENERATORS: dict[str, Callable[[], Mapping[str, Any]]] = {
    "config_env.json": build_config_env,
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
