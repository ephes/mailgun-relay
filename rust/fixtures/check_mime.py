"""Read the messages the Rust port built with Python's parser (rust/PLAN.md 2.10).

``mime::tests::mime_fixture`` writes every message it builds from
``mime.json`` to ``$MIME_FIXTURE_DUMP/<case index>.eml``. This script
parses each with ``email`` (``policy.default``), the parser the fixture's
expectations come from, and checks that the Rust message is semantically the
one Python sent (``semantic_message``), is 7-bit with CRLF line endings,
lines of at most 998 octets and top-level encoded words of at most 75
characters, and has no parser defects beyond those Python's
own message has for the same input (client content such as an encoded control
character).

Usage::

    MIME_FIXTURE_DUMP=$(mktemp -d) cargo test --locked mime_fixture
    uv run python rust/fixtures/check_mime.py "$MIME_FIXTURE_DUMP"
"""

from __future__ import annotations

import email
import email.policy
import importlib.util
import json
import re
import sys
from email.message import EmailMessage
from pathlib import Path
from types import ModuleType
from typing import Any

FIXTURES_DIR = Path(__file__).resolve().parent


def _generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "rust_fixture_generator", FIXTURES_DIR / "generate.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def check_message(generator: ModuleType, raw: bytes, case: dict[str, Any]) -> list[str]:
    """The problems of one Rust message; empty when it passes."""
    problems = []
    if not raw.isascii():
        problems.append("not 7-bit")
    lines = raw.split(b"\r\n")
    if lines[-1] != b"":
        problems.append("does not end with CRLF")
    for line in lines:
        if b"\r" in line or b"\n" in line:
            problems.append(f"bare CR or LF in {line[:60]!r}")
        if len(line) > 998:
            problems.append(f"line of {len(line)} octets")
    head = raw.split(b"\r\n\r\n", 1)[0].decode("ascii", "replace")
    for word in re.findall(r"=\?[^?\s]*\?[bBqQ]\?[^?\s]*\?=", head):
        if len(word) > 75:
            problems.append(f"encoded word of {len(word)} characters")
    expected = case["expected"]
    actual = generator.semantic_message(raw)
    if actual != expected["message"]:
        problems.append(
            f"semantic view differs:\n  rust   {json.dumps(actual, ensure_ascii=False)}"
            f"\n  python {json.dumps(expected['message'], ensure_ascii=False)}"
        )
    parsed = email.message_from_bytes(raw, policy=email.policy.default)
    assert isinstance(parsed, EmailMessage)
    extra = set(generator._defects(parsed)) - set(expected["defects"])
    if extra:
        problems.append(f"parser defects {sorted(extra)}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    dump = Path(argv[1])
    generator = _generator()
    fixture = json.loads((FIXTURES_DIR / "mime.json").read_text(encoding="utf-8"))
    failures = 0
    checked = 0
    for index, case in enumerate(fixture["cases"]):
        if case["expected"]["status"] != 200:
            continue
        path = dump / f"{index}.eml"
        problems = (
            check_message(generator, path.read_bytes(), case) if path.exists() else ["missing"]
        )
        checked += 1
        for problem in problems:
            failures += 1
            print(f"{case['name']}: {problem}", file=sys.stderr)
    print(f"checked {checked} Rust messages, {failures} problems")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
