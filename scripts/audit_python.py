"""Audit the frozen Python runtime/dev graph without installing project packages."""

# Fixed executable names and arguments; subprocesses never use a shell.
# ruff: noqa: S603, S607

import subprocess
import tempfile
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="mailgun-python-audit-") as temporary:
        requirements = str(Path(temporary) / "requirements.txt")
        subprocess.run(
            [
                "uv",
                "export",
                "--frozen",
                "--all-groups",
                "--no-emit-project",
                "--no-hashes",
                "--format",
                "requirements-txt",
                "--output-file",
                requirements,
            ],
            cwd=root,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "uvx",
                "pip-audit==2.9.0",
                "--strict",
                "--cache-dir",
                str(Path(temporary) / "cache"),
                "--no-deps",
                "--disable-pip",
                "--requirement",
                requirements,
            ],
            cwd=root,
            check=True,
        )


if __name__ == "__main__":
    main()
