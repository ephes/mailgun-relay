"""Drift guard for the Rust port's shared fixtures (rust/PLAN.md 7.2).

The fixtures in ``rust/fixtures`` are generated from the Python implementation
and pin the behaviour the Rust port must reproduce. A Python change that
alters any of them must regenerate the files
(``uv run python rust/fixtures/generate.py``), which then shows the Rust side
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
        f"stale Rust fixtures {stale}: run `uv run python rust/fixtures/generate.py` "
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
        # S2 acceptance: >= 400 addresses, >= 100 domains (D-11).
        ("address.json", 400, {"D-10", "D-11", "D-17", "D-11,D-10"}),
        ("domain.json", 100, {"D-10"}),
        ("auth.json", 60, set()),
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
