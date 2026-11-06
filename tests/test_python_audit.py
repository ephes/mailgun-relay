"""Offline checks for the frozen Python dependency audit gate."""

import runpy
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_ci_runs_python_audit_with_read_only_permissions() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert workflow["permissions"] == {"contents": "read"}
    steps = workflow["jobs"]["python"]["steps"]
    assert any(step.get("run") == "uv run python scripts/audit_python.py" for step in steps)


def test_audit_exports_frozen_runtime_and_dev_graph_before_auditing() -> None:
    audit = runpy.run_path(str(ROOT / "scripts/audit_python.py"))
    with patch("subprocess.run") as run:
        audit["main"]()
    export, auditor = run.call_args_list
    assert export.kwargs["check"] is True
    assert auditor.kwargs["check"] is True
    assert export.args[0][:2] == ["uv", "export"]
    assert {"--frozen", "--all-groups", "--no-emit-project", "--no-hashes"} <= set(export.args[0])
    assert auditor.args[0][:2] == ["uvx", "pip-audit==2.9.0"]
    assert {"--strict", "--no-deps", "--disable-pip"} <= set(auditor.args[0])
    requirements = Path(export.args[0][-1])
    assert auditor.args[0][-2:] == ["--requirement", str(requirements)]
    assert not requirements.parent.exists()  # temporary export is cleaned up


@pytest.mark.parametrize("failed_command", [1, 2])
def test_export_or_auditor_failure_is_fatal(failed_command: int) -> None:
    audit = runpy.run_path(str(ROOT / "scripts/audit_python.py"))
    error = subprocess.CalledProcessError(1, ["synthetic-failure"])
    outcomes = [None] * (failed_command - 1) + [error]
    with patch("subprocess.run", side_effect=outcomes) as run:
        with pytest.raises(subprocess.CalledProcessError):
            audit["main"]()
    assert run.call_count == failed_command
