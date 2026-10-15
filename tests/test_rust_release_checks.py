"""Release checks of the Rust port (rust/PLAN.md section 8).

``rust/scripts/release_checks.py`` gates the release workflow: the tag must
match the crate version, the binary must not need glibc newer than the floor
or libraries outside glibc/libgcc, ``--version`` must name the version and
commit, ``--check-config`` must accept a test configuration, and the archive
must be deterministic with exactly two files.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "rust" / "scripts" / "release_checks.py"
COMMIT = "27cf52e7bd2525d6f8ba4b2f9be42a880c2f6e1a"

# Shapes of binutils 2.38 (ubuntu-22.04) output: `objdump -T` then `objdump -p`.
OBJDUMP_OK = """
mailgun-relay:     file format elf64-x86-64

DYNAMIC SYMBOL TABLE:
0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.2.5) free
0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.34) __libc_start_main
0000000000000000      DF *UND*\t0000000000000000  GLIBC_2.18  __cxa_thread_atexit_impl
0000000000000000      DF *UND*\t0000000000000000 (GCC_4.2.0) _Unwind_Backtrace
0000000000000000  w   D  *UND*\t0000000000000000  Base        __gmon_start__

mailgun-relay:     file format elf64-x86-64

Dynamic Section:
  NEEDED               libgcc_s.so.1
  NEEDED               libm.so.6
  NEEDED               libc.so.6
  NEEDED               ld-linux-x86-64.so.2
  FLAGS                0x0000000000000008

Version References:
  required from libgcc_s.so.1:
    0x0b792650 0x00 13 GCC_3.0
    0x0d696914 0x00 12 GCC_4.2.0
  required from libc.so.6:
    0x06969194 0x00 05 GLIBC_2.14
    0x069691b5 0x00 04 GLIBC_2.35
    0x09691a75 0x00 02 GLIBC_2.2.5
"""


@pytest.fixture(scope="module")
def checks() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rust_release_checks", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def metadata(*packages: tuple[str, str]) -> dict[str, Any]:
    return {"packages": [{"name": name, "version": version} for name, version in packages]}


def test_version_comes_from_the_relay_package(checks: ModuleType) -> None:
    data = metadata(("mailgun-relay-parity", "9.9.9"), ("mailgun-relay", "0.2.0"))
    assert checks.package_version(data) == "0.2.0"
    assert checks.package_version(metadata(("mailgun-relay", "1.2.3-rc.1"))) == "1.2.3-rc.1"


@pytest.mark.parametrize("version", ["0.2", "02.0.0", "0.2.0+build.5", "0.2.0-", "v0.2.0"])
def test_version_must_be_semver_without_build_metadata(checks: ModuleType, version: str) -> None:
    with pytest.raises(checks.CheckError, match="not semver"):
        checks.package_version(metadata(("mailgun-relay", version)))


def test_version_requires_exactly_one_relay_package(checks: ModuleType) -> None:
    with pytest.raises(checks.CheckError, match="found 0"):
        checks.package_version(metadata(("mailgun-relay-parity", "0.2.0")))
    with pytest.raises(checks.CheckError, match="found 2"):
        checks.package_version(metadata(("mailgun-relay", "0.2.0"), ("mailgun-relay", "0.2.0")))


def test_tag_must_equal_the_crate_version(checks: ModuleType) -> None:
    checks.check_tag("rs-v0.2.0", "0.2.0")
    for tag in ("rs-v0.2.1", "rs-0.2.0", "v0.2.0", "rs-v0.2.0-rc.1", "agent-rs-v0.2.0"):
        with pytest.raises(checks.CheckError, match=re.escape("expected 'rs-v0.2.0'")):
            checks.check_tag(tag, "0.2.0")


def test_glibc_floor_accepts_the_ubuntu_22_04_build(checks: ModuleType) -> None:
    assert checks.glibc_versions(OBJDUMP_OK) == {"2.2.5", "2.14", "2.18", "2.34", "2.35"}
    assert checks.needed_libraries(OBJDUMP_OK) == [
        "libgcc_s.so.1",
        "libm.so.6",
        "libc.so.6",
        "ld-linux-x86-64.so.2",
    ]
    assert checks.check_glibc(OBJDUMP_OK, "2.35") == "2.35"


def test_glibc_floor_compares_numerically(checks: ModuleType) -> None:
    # 2.4 < 2.14 < 2.35 numerically, not as strings.
    text = OBJDUMP_OK.replace("GLIBC_2.35", "GLIBC_2.4")
    with pytest.raises(
        checks.CheckError, match=re.escape("newer than 2.14: GLIBC_2.18, GLIBC_2.34")
    ):
        checks.check_glibc(text, "2.14")
    assert checks.check_glibc(text, "2.34") == "2.34"


@pytest.mark.parametrize(
    ("symbol", "message"),
    [
        ("GLIBC_2.36", "newer than 2.35: GLIBC_2.36"),
        ("GLIBC_2.39", "newer than 2.35: GLIBC_2.39"),
        ("GLIBC_PRIVATE", "unexpected glibc symbol version GLIBC_PRIVATE"),
    ],
)
def test_glibc_floor_rejects_newer_or_private_versions(
    checks: ModuleType, symbol: str, message: str
) -> None:
    text = OBJDUMP_OK + f"0000000000000000      DF *UND*\t0000000000000000 ({symbol}) foo\n"
    with pytest.raises(checks.CheckError, match=message):
        checks.check_glibc(text, "2.35")


def test_glibc_floor_rejects_foreign_libraries_and_static_binaries(checks: ModuleType) -> None:
    with pytest.raises(checks.CheckError, match=re.escape("outside glibc/libgcc: libssl.so.3")):
        checks.check_glibc(OBJDUMP_OK + "  NEEDED               libssl.so.3\n", "2.35")
    without_needed = "\n".join(line for line in OBJDUMP_OK.splitlines() if "NEEDED" not in line)
    with pytest.raises(checks.CheckError, match="no NEEDED entries"):
        checks.check_glibc(without_needed, "2.35")
    with pytest.raises(checks.CheckError, match="no GLIBC symbol versions"):
        checks.check_glibc("statically linked\n", "2.35")
    with pytest.raises(checks.CheckError, match="not a glibc version"):
        checks.check_glibc(OBJDUMP_OK, "2.35a")


def test_version_output_must_name_version_and_commit(checks: ModuleType) -> None:
    checks.check_version_output(f"mailgun-relay 0.2.0 ({COMMIT})\n", "0.2.0", COMMIT)
    for stdout in (
        "mailgun-relay 0.2.0\n",
        f"mailgun-relay 0.2.0 ({COMMIT})",
        "mailgun-relay 0.2.0 (unknown)\n",
        f"mailgun-relay 0.2.0 ({COMMIT[:12]})\n",
        f"mailgun-relay 0.2.1 ({COMMIT})\n",
    ):
        with pytest.raises(checks.CheckError, match="--version printed"):
            checks.check_version_output(stdout, "0.2.0", COMMIT)


def test_check_config_output_must_be_exit_0_with_the_summary(checks: ModuleType) -> None:
    summary = (
        "mailgun-relay: configuration OK (bind 127.0.0.1:18085, log level WARNING, 2 token(s))\n"
    )
    checks.check_config_output(0, summary, "")
    for returncode, stdout in (
        (1, ""),
        (1, summary),
        (0, ""),
        (0, summary.replace("18085", "8085")),
        (0, summary.replace("WARNING", "INFO")),
        (0, summary.replace("2 token(s)", "1 token(s)")),
    ):
        with pytest.raises(checks.CheckError, match="--check-config exited"):
            checks.check_config_output(returncode, stdout, "mailgun-relay: configuration error")


def test_smoke_configuration_is_the_role_shape(checks: ModuleType) -> None:
    """The variables of the role's env template (`mailgun-relay.env.j2`), nothing else."""
    environment = checks.smoke_environment(Path("/run/smoke/secrets.yml"))
    assert environment["MAILGUN_RELAY_SECRETS_PATH"] == "/run/smoke/secrets.yml"
    assert all(key.startswith("MAILGUN_RELAY_") for key in environment)
    assert len(environment) == 16
    assert checks.SMOKE_TOKEN_SHA256 in checks.SMOKE_SECRETS
    assert checks.SMOKE_SECRETS.count("token_sha256:") == 2


def test_archive_is_deterministic_and_holds_binary_and_license(checks: ModuleType) -> None:
    binary, license_text = b"\x7fELF binary", b"MIT License\n"
    first = checks.build_archive(binary, license_text, 1_700_000_000)
    assert first == checks.build_archive(binary, license_text, 1_700_000_000)
    assert first != checks.build_archive(binary, license_text, 1_700_000_001)
    checks.verify_archive(first, binary, license_text)
    # gzip header: no FNAME flag, the given mtime.
    assert first[3] & 0x08 == 0
    assert int.from_bytes(first[4:8], "little") == 1_700_000_000
    with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
    assert set(members) == {"LICENSE", "mailgun-relay"}
    assert members["mailgun-relay"].mode == 0o755
    assert members["LICENSE"].mode == 0o644
    assert {(m.uid, m.gid, m.uname, m.gname, m.mtime) for m in members.values()} == {
        (0, 0, "root", "root", 1_700_000_000)
    }
    with pytest.raises(checks.CheckError, match="differs from its source"):
        checks.verify_archive(first, b"other", license_text)
    assert checks.archive_name("0.2.0", "x86_64-unknown-linux-gnu") == (
        "mailgun-relay-0.2.0-x86_64-unknown-linux-gnu.tar.gz"
    )


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - the script under test
        [sys.executable, "-I", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_version_and_tag(tmp_path: Path) -> None:
    path = tmp_path / "metadata.json"
    path.write_text(json.dumps(metadata(("mailgun-relay", "0.2.0"))), encoding="utf-8")
    result = run_script("version", "--metadata", str(path), "--tag", "rs-v0.2.0")
    assert (result.returncode, result.stdout) == (0, "0.2.0\n")
    result = run_script("version", "--metadata", str(path))
    assert (result.returncode, result.stdout) == (0, "0.2.0\n")
    result = run_script("version", "--metadata", str(path), "--tag", "rs-v0.3.0")
    assert result.returncode == 1
    assert "release check failed: tag 'rs-v0.3.0'" in result.stderr


def test_cli_pack_writes_archive_and_sha256sum_line(tmp_path: Path) -> None:
    binary = tmp_path / "mailgun-relay"
    binary.write_bytes(b"binary")
    license_path = tmp_path / "LICENSE"
    license_path.write_bytes(b"MIT\n")
    out = tmp_path / "dist"
    result = run_script(
        "pack",
        "--binary",
        str(binary),
        "--license",
        str(license_path),
        "--version",
        "0.2.0",
        "--target",
        "x86_64-unknown-linux-gnu",
        "--mtime",
        "1700000000",
        "--out-dir",
        str(out),
    )
    name = "mailgun-relay-0.2.0-x86_64-unknown-linux-gnu.tar.gz"
    assert (result.returncode, result.stdout) == (0, f"{name}\n")
    data = (out / name).read_bytes()
    assert (out / f"{name}.sha256").read_text(encoding="utf-8") == (
        f"{hashlib.sha256(data).hexdigest()}  {name}\n"
    )


# A stand-in for the binary: `--version` as the release build prints it;
# `--check-config` passes only with a cleared environment and a
# secrets file of mode 0600 that holds the smoke token hash.
FAKE_BINARY = """#!/bin/sh
case "$1" in
--version) echo 'mailgun-relay 0.2.0 ({commit})' ;;
--check-config)
  [ -z "${{HOME+x}}" ] || {{ echo "environment not cleared" >&2; exit 1; }}
  [ "$(stat -c %a "$MAILGUN_RELAY_SECRETS_PATH" 2>/dev/null \
      || stat -f %Lp "$MAILGUN_RELAY_SECRETS_PATH")" = 600 ] || exit 1
  grep -q "{token}" "$MAILGUN_RELAY_SECRETS_PATH" || exit 1
  echo "mailgun-relay: configuration OK (bind $MAILGUN_RELAY_BIND_HOST:$MAILGUN_RELAY_BIND_PORT, \
log level $MAILGUN_RELAY_LOG_LEVEL, {tokens} token(s))"
  ;;
*) exit 2 ;;
esac
"""


def fake_binary(tmp_path: Path, checks: ModuleType, tokens: int = 2) -> Path:
    fake = tmp_path / "mailgun-relay"
    fake.write_text(
        FAKE_BINARY.format(commit=COMMIT, token=checks.SMOKE_TOKEN_SHA256, tokens=tokens),
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell script fake")
def test_cli_smoke_runs_version_and_check_config(tmp_path: Path, checks: ModuleType) -> None:
    base = ["smoke", "--binary", str(fake_binary(tmp_path, checks)), "--version"]
    result = run_script(*base, "0.2.0", "--commit", COMMIT)
    assert (result.returncode, result.stderr) == (0, "")
    assert result.stdout == (
        f"mailgun-relay 0.2.0 ({COMMIT})\n"
        "mailgun-relay: configuration OK (bind 127.0.0.1:18085, log level WARNING, 2 token(s))\n"
    )
    assert run_script(*base, "0.2.1", "--commit", COMMIT).returncode == 1
    result = run_script(*base, "0.2.0", "--commit", COMMIT[:12])
    assert result.returncode == 1
    assert "40 lowercase hex digits" in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell script fake")
def test_cli_smoke_fails_when_check_config_disagrees(tmp_path: Path, checks: ModuleType) -> None:
    fake = fake_binary(tmp_path, checks, tokens=1)
    result = run_script("smoke", "--binary", str(fake), "--version", "0.2.0", "--commit", COMMIT)
    assert result.returncode == 1
    assert "release check failed: --check-config exited 0" in result.stderr


def test_release_workflow_runs_every_check() -> None:
    workflow = (REPO / ".github" / "workflows" / "rust-release.yml").read_text(encoding="utf-8")
    for needle in (
        "runs-on: ubuntu-22.04",
        'GLIBC_FLOOR: "2.35"',
        '- "rs-v*"',
        "MAILGUN_RELAY_GIT_COMMIT: ${{ github.sha }}",
        "release_checks.py version",
        "release_checks.py glibc-floor",
        "release_checks.py smoke",
        "release_checks.py pack",
        "cargo fmt --check",
        "cargo clippy --all-targets --locked -- -D warnings",
        "cargo test --locked",
        'cargo build --release --locked --target "$TARGET"',
        "sha256sum --check",
        "--verify-tag",
        "--prerelease",
    ):
        assert needle in workflow, needle
    assert "actions/cache" not in workflow
