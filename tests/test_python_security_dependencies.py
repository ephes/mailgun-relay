"""Security floor for the Python email-validation dependency graph."""

import tomllib
from pathlib import Path

from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]


def test_dnspython_security_floor() -> None:
    packages = tomllib.loads((ROOT / "uv.lock").read_text())["package"]
    dns_packages = [package for package in packages if package["name"] == "dnspython"]
    assert dns_packages
    # CVE-2026-114605: bound DNS compression-pointer traversal (fixed in 2.9.0).
    for package in dns_packages:
        assert Version(package["version"]) >= Version("2.9.0")
