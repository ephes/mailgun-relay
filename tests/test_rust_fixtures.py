"""Drift guard for the Rust port's shared fixtures (rust/PLAN.md 7.2).

The fixtures in ``rust/fixtures`` are generated from the Python implementation
and pin the behaviour the Rust port must reproduce. A Python change that
alters any of them must regenerate the files
(``uv run --python 3.14.10 python rust/fixtures/generate.py``), which then shows the Rust side
what to change.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

GENERATOR_PATH = Path(__file__).resolve().parents[1] / "rust" / "fixtures" / "generate.py"


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rust_fixture_generator", GENERATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_committed_fixtures_match_the_python_implementation(generator: ModuleType) -> None:
    stale = generator.check_fixtures()
    assert not stale, (
        f"stale Rust fixtures {stale}: run "
        "`uv run --python 3.14.10 python rust/fixtures/generate.py` "
        "and update the Rust side to match"
    )


def test_drift_check_detects_a_hand_edited_fixture(generator: ModuleType, tmp_path: Path) -> None:
    for name in generator.GENERATORS:
        shutil.copy(generator.FIXTURES_DIR / name, tmp_path / name)
    assert generator.check_fixtures(tmp_path) == []

    edited = tmp_path / "config_env.json"
    text = edited.read_text(encoding="utf-8")
    assert '"smtp_port": 587' in text
    edited.write_text(text.replace('"smtp_port": 587', '"smtp_port": 588', 1), encoding="utf-8")
    assert generator.check_fixtures(tmp_path) == ["config_env.json"]

    (tmp_path / "config_secrets.json").unlink()
    assert generator.check_fixtures(tmp_path) == ["config_env.json", "config_secrets.json"]


def _cases(generator: ModuleType, name: str) -> list[dict[str, object]]:
    content = json.loads((generator.FIXTURES_DIR / name).read_text(encoding="utf-8"))
    cases: list[dict[str, object]] = content["cases"]
    return cases


@pytest.mark.parametrize(
    ("name", "minimum", "labels"),
    [
        # S1 acceptance (PLAN.md 6): >= 60 env sets, >= 40 YAML documents.
        ("config_env.json", 60, {"D-7", "D-10", "D-15", "D-18"}),
        ("config_secrets.json", 40, {"D-5", "D-6", "D-10", "D-17"}),
        ("yaml_parser.json", 40, {"D-6"}),
        # S2 acceptance: >= 400 addresses, >= 100 domains (D-11).
        ("address.json", 400, {"D-10", "D-11", "D-17", "D-11,D-10"}),
        ("domain.json", 100, {"D-10"}),
        ("auth.json", 60, set()),
        ("policy.json", 100, {"D-10", "D-11"}),
        # S4: every row of PLAN.md 2.10 and test_mime_build.py.
        ("mime.json", 100, {"D-11", "D-21"}),
        # S5: every row of PLAN.md 2.4 against the scripted SMTP server.
        ("smtp_outcomes.json", 100, {"D-3", "D-4"}),
    ],
)
def test_corpus_sizes_and_divergence_labels(
    generator: ModuleType, name: str, minimum: int, labels: set[str]
) -> None:
    """Every case where the Rust expectation differs names its D-entry."""
    cases = _cases(generator, name)
    assert len(cases) >= minimum
    for case in cases:
        assert case.get("divergence") in labels | {None}, case


def test_rust_address_decisions_never_widen_python(generator: ModuleType) -> None:
    """The fail-closed property of D-11 on the committed corpus: every
    mailbox the Rust port accepts, Python accepts with the same address."""
    for case in _cases(generator, "address.json"):
        expected = case["expected"]
        python = case["python"]
        assert isinstance(expected, dict) and isinstance(python, dict)
        mailbox = expected["mailbox"]
        if mailbox is not None:
            display, addr_spec, policy_address = mailbox
            assert python["parse_email_strict"] == policy_address
            assert python["parse_address_list"] == [[display, addr_spec]]
        if expected["mailbox_list"] is not None:
            assert python["parse_header_address_list"] == [
                [display, addr_spec] for display, addr_spec, _ in expected["mailbox_list"]
            ]


def test_rust_mime_decisions_never_widen_python(generator: ModuleType) -> None:
    """Fail closed (D-11, D-21): every input Python's ``build_message``
    refuses, the Rust port refuses."""
    for case in _cases(generator, "mime.json"):
        expected = case["expected"]
        python = case.get("python", expected)
        assert isinstance(expected, dict) and isinstance(python, dict)
        if python["status"] == 400:
            assert expected["status"] == 400, case["name"]


def test_check_mime_flags_broken_messages(generator: ModuleType) -> None:
    """``check_mime.py`` accepts Python's own message and catches a bare LF,
    a long line and a changed header."""
    spec = importlib.util.spec_from_file_location(
        "rust_check_mime", GENERATOR_PATH.with_name("check_mime.py")
    )
    assert spec is not None and spec.loader is not None
    check_mime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check_mime)
    [case] = [c for c in _cases(generator, "mime.json") if c["name"] == "text and html"]
    built = generator.python_message(case["input"])
    assert built is not None
    raw: bytes = built[0]
    assert check_mime.check_message(generator, raw, case) == []
    bare_lf = raw.replace(b"hello\r\n", b"hello\n", 1)
    assert "bare CR or LF" in " ".join(check_mime.check_message(generator, bare_lf, case))
    long_line = raw.replace(b"Subject: hi", b"Subject: " + b"x" * 1000, 1)
    problems = check_mime.check_message(generator, long_line, case)
    assert any("line of" in p for p in problems)
    assert any("semantic view differs" in p for p in problems)
    # A transfer-encoding defect shows only when the payload is decoded.
    [case] = [c for c in _cases(generator, "mime.json") if c["name"] == "attachment"]
    built = generator.python_message(case["input"])
    assert built is not None
    raw = built[0]
    assert check_mime.check_message(generator, raw, case) == []
    payload = b"aGVsbG8gYXR0YWNobWVudA=="
    assert payload in raw
    broken = raw.replace(payload, b"!" + payload, 1)
    problems = check_mime.check_message(generator, broken, case)
    assert problems == ["parser defects ['InvalidBase64CharactersDefect']"], problems


def test_yaml_parser_probes_survive_schema_tightening(generator: ModuleType) -> None:
    cases = {case["name"]: case for case in _cases(generator, "yaml_parser.json")}
    for name in ["decimal int at the digit limit", "long octal int in unknown key"]:
        assert cases[name]["python_accepts"] is True
        assert cases[name]["expected"] is True
    for name in [
        "merge key",
        "int tag",
        "recursive alias",
        "deep nesting",
        "nel in quoted value",
        "line separator in quoted value",
        "tab in quoted value",
    ]:
        assert cases[name]["python_accepts"] is True
        assert cases[name]["expected"] is False
        assert cases[name]["divergence"] == "D-6"


def test_encoded_comma_keeps_one_display_name(generator: ModuleType) -> None:
    cases = {case["name"]: case for case in _cases(generator, "mime.json")}
    case = cases["encoded comma in display name"]
    python = case["python"]
    assert isinstance(python, dict)
    assert isinstance(python["message"], dict)
    assert python["status"] == 200
    assert python["defects"] == []
    assert ["to", [["Doe, Jane", "b@x.de"]]] in python["message"]["headers"]
    assert generator._python_mime(case["input"]) == python
    assert case["expected"] == {"status": 400}
    assert case["divergence"] == "D-21"


def test_encoded_local_part_has_explicit_interpreter_outcome(generator: ModuleType) -> None:
    cases = {case["name"]: case for case in _cases(generator, "mime.json")}
    case = cases["encoded local part"]
    assert case["expected"] == {"status": 400}
    assert case["divergence"] == "D-21"
    refusal = {"status": 502, "error": "HeaderWriteError"}
    assert case["python_versions"] == {"3.15": refusal}
    expected = refusal if sys.version_info[:2] == (3, 15) else case["python"]
    assert generator._python_mime(case["input"]) == expected
    # This is a serialization refusal, not a widening of ordinary Unicode names.
    ordinary = cases["encoded display name"]
    assert generator._python_mime(ordinary["input"]) == ordinary["expected"]
    assert isinstance(ordinary["expected"], dict)
    assert ordinary["expected"]["status"] == 200


def test_serialization_refusal_is_not_a_build_rejection(
    generator: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    from email.errors import HeaderWriteError
    from email.message import EmailMessage

    def refuse(*args: object, **kwargs: object) -> bytes:
        raise HeaderWriteError("synthetic refusal")

    monkeypatch.setattr(EmailMessage, "as_bytes", refuse)
    assert generator._python_mime(generator._mime_input({})) == {
        "status": 502,
        "error": "HeaderWriteError",
    }


def test_only_canonical_interpreter_can_rewrite(
    generator: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(generator, "CANONICAL_PYTHON", (0, 0, 0))
    monkeypatch.setattr(generator, "FIXTURES_DIR", tmp_path)
    assert generator.main([]) == 2
    assert list(tmp_path.iterdir()) == []


def test_consumer_drift_check_detects_changed_alternate(
    generator: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(generator, "GENERATORS", {"mime.json": generator.build_mime})
    shutil.copy(generator.FIXTURES_DIR / "mime.json", tmp_path / "mime.json")
    assert generator.check_fixtures(tmp_path) == []
    content = json.loads((tmp_path / "mime.json").read_text())
    case = next(c for c in content["cases"] if c["name"] == "encoded local part")
    case["python_versions"]["3.15"]["status"] = 200
    (tmp_path / "mime.json").write_text(
        json.dumps(content, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    )
    assert "mime.json" in generator.check_fixtures(tmp_path)


@pytest.mark.parametrize("name", ["long header name", "attachment filenames"])
def test_other_parser_observations_are_explicit(generator: ModuleType, name: str) -> None:
    case = next(c for c in _cases(generator, "mime.json") if c["name"] == name)
    versions = case["python_versions"]
    assert isinstance(versions, dict)
    expected = versions["3.15"] if sys.version_info[:2] == (3, 15) else case["python"]
    assert generator._python_mime(case["input"]) == expected


@pytest.mark.parametrize("field", ["expected", "input", "python"])
def test_mime_consumer_checks_rust_decisions_inputs_and_observations(
    generator: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    monkeypatch.setattr(generator, "GENERATORS", {"mime.json": generator.build_mime})
    shutil.copy(generator.FIXTURES_DIR / "mime.json", tmp_path / "mime.json")
    assert generator.check_fixtures(tmp_path) == []
    content = json.loads((tmp_path / "mime.json").read_text())
    case = next(c for c in content["cases"] if c["name"] == "encoded display name")
    if field == "input":
        case[field]["text"] = "changed"
    else:
        case[field] = {"status": 400}
    (tmp_path / "mime.json").write_text(
        json.dumps(content, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    )
    assert generator.check_fixtures(tmp_path) == ["mime.json"]


@pytest.mark.parametrize("change", ["defect", "refusal"])
def test_attachment_rust_budget_tracks_oracle_and_status(
    generator: ModuleType, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    overrides = next(v for n, v in generator._mime_cases() if n == "attachment filenames")
    target = generator._mime_input(overrides)
    if change == "defect":
        original = generator._python_mime

        def observe(case: dict[str, object]) -> dict[str, object]:
            outcome = original(case)
            if case == target:
                outcome["defects"].append("SyntheticDefect")
            assert isinstance(outcome, dict)
            return outcome

        monkeypatch.setattr(generator, "_python_mime", observe)
    else:
        original_status = generator._rust_mime_status

        def status(case: dict[str, object]) -> int:
            return 400 if case == target else int(original_status(case))

        monkeypatch.setattr(generator, "_rust_mime_status", status)
    case = next(c for c in generator.build_mime()["cases"] if c["name"] == "attachment filenames")
    if change == "defect":
        assert "SyntheticDefect" in case["expected"]["defects"]
    else:
        assert case["expected"] == {"status": 400}
