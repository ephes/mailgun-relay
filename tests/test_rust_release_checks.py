"""Release checks of the Rust port (rust/PLAN.md section 8).

``rust/scripts/release_checks.py`` gates the local release (``local_release.py``): the tag must
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
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

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


@pytest.mark.parametrize("floor", ["2.35", "2.35.0"])
@pytest.mark.parametrize("symbol", ["2.35", "2.35.0", "2.35.0.0"])
def test_glibc_floor_ignores_trailing_zero_components(
    checks: ModuleType, floor: str, symbol: str
) -> None:
    assert checks.check_glibc(OBJDUMP_OK.replace("GLIBC_2.35", f"GLIBC_{symbol}"), floor) == symbol
    too_new = OBJDUMP_OK.replace("GLIBC_2.35", "GLIBC_2.35.1")
    with pytest.raises(
        checks.CheckError, match=re.escape(f"glibc newer than {floor}: GLIBC_2.35.1")
    ):
        checks.check_glibc(too_new, floor)


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


@pytest.mark.parametrize(
    ("data", "diagnostic"),
    [
        ([], "cargo metadata root must be an object"),
        ({}, "cargo metadata packages must be an array"),
        ({"packages": {}}, "cargo metadata packages must be an array"),
        (
            {
                "packages": [
                    "synthetic-invalid-entry",
                    {"name": "mailgun-relay", "version": "1.2.3"},
                ]
            },
            "cargo metadata packages[0] must be an object",
        ),
        (
            {"packages": [{"name": "mailgun-relay"}]},
            "cargo metadata packages[0].version must be a string",
        ),
        (
            {"packages": [{"name": 3, "version": "1.2.3"}]},
            "cargo metadata packages[0].name must be a string",
        ),
        (
            metadata(("mailgun-relay", "1.2.3-rc.1\u0662")),
            "mailgun-relay version is not semver (without build metadata)",
        ),
    ],
)
def test_cli_version_reports_invalid_metadata(
    tmp_path: Path, data: object, diagnostic: str
) -> None:
    path = tmp_path / "metadata.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    result = run_script("version", "--metadata", str(path))
    assert (result.returncode, result.stdout, result.stderr) == (
        1,
        "",
        f"release check failed: {diagnostic}\n",
    )


@pytest.mark.parametrize(
    ("data", "diagnostic"),
    [
        (b'{"packages": [', "cargo metadata is not valid JSON"),
        (b'{"packages": ["\xff"]}', "cargo metadata is not valid UTF-8"),
        (None, "No such file or directory"),
    ],
)
def test_cli_version_reports_metadata_input_failures(
    tmp_path: Path, data: bytes | None, diagnostic: str
) -> None:
    path = tmp_path / "metadata.json"
    if data is not None:
        path.write_bytes(data)
    result = run_script("version", "--metadata", str(path))
    assert (result.returncode, result.stdout) == (1, "")
    assert result.stderr.startswith("release check failed: ")
    assert diagnostic in result.stderr
    assert len(result.stderr.splitlines()) == 1


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


def test_local_release_runs_every_check() -> None:
    """rust/local-release.json drives rust/scripts/local_release.py (no CI
    release workflow): the old workflow's checks, floor, tag and commit."""
    config = json.loads((REPO / "rust" / "local-release.json").read_text(encoding="utf-8"))
    assert config["github_repository"] == "ephes/mailgun-relay"
    assert config["tag_prefix"] == "rs-v"
    assert config["target"] == "x86_64-unknown-linux-gnu"
    assert config["mode"] == "linux-container"
    assert config["glibc_floor"] == "2.35"
    assert config["commit_env"] == "MAILGUN_RELAY_GIT_COMMIT"
    assert config["checks"] == [
        "cargo fmt --check",
        "cargo clippy --all-targets --locked -- -D warnings",
        "cargo test --locked",
    ]
    assert not (REPO / ".github" / "workflows" / "rust-release.yml").exists()


def test_smoke_secrets_load_with_distinct_credentials(checks: ModuleType, tmp_path: Path) -> None:
    from mailgun_relay.config import load_secrets

    path = tmp_path / "smoke.yml"
    path.write_text(checks.SMOKE_SECRETS)
    path.chmod(0o600)
    policies = load_secrets(path).tokens
    assert len({policy.token_sha256 for policy in policies}) == 2


@pytest.mark.parametrize("phase", ["config", "version", "objdump"])
def test_release_helpers_have_a_whole_command_deadline(
    checks: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    helper = tmp_path / "objdump"
    helper.write_text("#!/bin/sh\nsleep 0.3\n")
    helper.chmod(0o755)
    monkeypatch.setattr(checks, "COMMAND_TIMEOUT", 0.05, raising=False)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    if phase == "version":
        assert (
            checks.main(
                ["smoke", "--binary", str(helper), "--version", "0.2.0", "--commit", COMMIT]
            )
            == 1
        )
        assert "deadline" in capsys.readouterr().err
        return
    with pytest.raises(checks.CheckError, match="deadline"):
        if phase == "config":
            checks.run_check_config(helper)
        else:
            checks._objdump(helper)


@pytest.mark.parametrize("fd", [1, 2])
def test_release_helpers_refuse_output_overflow_without_echoing_it(
    checks: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fd: int
) -> None:
    helper = tmp_path / "flood"
    helper.write_text(f"#!{sys.executable}\nimport os\nos.write({fd}, b'CANARY' * 10000)\n")
    helper.chmod(0o755)
    monkeypatch.setattr(checks, "OUTPUT_LIMIT", 1024, raising=False)
    with pytest.raises(checks.CheckError, match="output byte ceiling") as error:
        checks.run_check_config(helper)
    assert "CANARY" not in str(error.value)


@pytest.mark.parametrize(
    "version,target",
    [
        ("../1.2.3", "x86_64-unknown-linux-gnu"),
        ("1.2.3\n", "x86_64-unknown-linux-gnu"),
        ("1.2.3", "../../elsewhere"),
        ("1.2.3", "/absolute/out"),
        ("1.2.3", "linux\nchecksum"),
        ("1.2.3", "unsupported"),
    ],
)
def test_pack_refuses_components_before_reading_inputs(
    checks: ModuleType, tmp_path: Path, version: str, target: str
) -> None:
    assert (
        checks.main(
            [
                "pack",
                "--version",
                version,
                "--target",
                target,
                "--binary",
                str(tmp_path / "missing"),
                "--license",
                "missing",
                "--mtime",
                "0",
                "--out-dir",
                str(tmp_path / "out"),
            ]
        )
        == 1
    )
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("failure", ["stage", "first", "second"])
def test_pack_failed_publication_preserves_previous_pair_and_retry_repairs(
    checks: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    binary, license_path = tmp_path / "binary", tmp_path / "LICENSE"
    binary.write_bytes(b"old")
    license_path.write_bytes(b"MIT")
    out = tmp_path / "out"
    args = [
        "pack",
        "--binary",
        str(binary),
        "--license",
        str(license_path),
        "--version",
        "1.2.3-rc.1",
        "--target",
        "x86_64-unknown-linux-gnu",
        "--mtime",
        "0",
        "--out-dir",
        str(out),
    ]
    assert checks.main(args) == 0
    name = checks.archive_name("1.2.3-rc.1", "x86_64-unknown-linux-gnu")
    previous = {p.name: p.read_bytes() for p in out.iterdir() if not p.name.startswith(".")}
    binary.write_bytes(b"new")
    replace, write = os.replace, Path.write_text
    calls = 0

    def fail_replace(src: Any, dst: Any, *a: Any, **kw: Any) -> None:
        nonlocal calls
        if Path(dst).parent == out and Path(dst).name in previous:
            calls += 1
            if calls == (1 if failure == "first" else 2):
                raise OSError("synthetic publication failure")
        replace(src, dst, *a, **kw)

    def fail_write(path: Path, *a: Any, **kw: Any) -> int:
        if path.name.endswith(".sha256"):
            raise OSError("synthetic checksum write failure")
        return write(path, *a, **kw)

    with monkeypatch.context() as patch:
        if failure == "stage":
            patch.setattr(Path, "write_text", fail_write)
        else:
            patch.setattr(os, "replace", fail_replace)
        assert checks.main(args) == 1
    assert {p.name: p.read_bytes() for p in out.iterdir() if not p.name.startswith(".")} == previous
    # A clean rollback restores a usable pair, so no incomplete marker remains.
    assert not (out / f".{name}.incomplete").exists()
    assert checks.main(args) == 0
    data = (out / name).read_bytes()
    checks.verify_archive(data, b"new", b"MIT")
    assert (out / f"{name}.sha256").read_text() == checks.checksum_line(data, name)
    assert not list(out.glob("*.incomplete"))


def test_pack_retains_backups_when_one_restore_fails(
    checks: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    name = "relay.tar.gz"
    checksum = f"{name}.sha256"
    checks.publish_archive(out, name, b"old")
    old_checksum = (out / checksum).read_bytes()
    replace = os.replace
    publication_failure = OSError("synthetic checksum install failure")
    restore_attempts = []

    def fail_replace(src: Any, dst: Any) -> None:
        if Path(src).name == checksum:
            raise publication_failure
        if Path(src).suffix == ".old":
            restore_attempts.append(Path(dst).name)
            if Path(dst).name == name:
                raise OSError("synthetic archive restore failure")
        replace(src, dst)

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", fail_replace)
        with pytest.raises(
            checks.CheckError, match=r"^synthetic checksum install failure"
        ) as error:
            checks.publish_archive(out, name, b"new")

    assert error.value.__cause__ is publication_failure
    assert restore_attempts == [name, checksum]
    assert (out / f".{name}.incomplete").is_file()
    assert (out / checksum).read_bytes() == old_checksum
    (stage,) = out.glob(".pack-*")
    assert str(stage) in str(error.value)
    assert (stage / f"{name}.old").read_bytes() == b"old"

    checks.publish_archive(out, name, b"new")
    assert not (out / f".{name}.incomplete").exists()
    assert (stage / f"{name}.old").read_bytes() == b"old"


def test_failed_publication_keeps_an_earlier_incomplete_marker(
    checks: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    checks.publish_archive(out, "relay.tar.gz", b"old")
    marker = out / ".relay.tar.gz.incomplete"
    marker.write_text("earlier interrupted run\n")
    replace = os.replace

    def fail_replace(src: Any, dst: Any, *a: Any, **kw: Any) -> None:
        if Path(dst).parent == out and Path(src).parent != out and not str(src).endswith(".old"):
            raise OSError("synthetic publication failure")
        replace(src, dst, *a, **kw)

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", fail_replace)
        with pytest.raises(OSError):
            checks.publish_archive(out, "relay.tar.gz", b"new")
    assert (out / "relay.tar.gz").read_bytes() == b"old"
    assert marker.exists()


def test_command_deadline_retires_descendant_holding_pipes(
    checks: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    pidfile = tmp_path / "pid"
    escaped = tmp_path / "survived"
    code = f"""
import os,time,pathlib
pid = os.fork()
if pid == 0:
    pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid()))
    time.sleep(0.4)
    pathlib.Path({str(escaped)!r}).write_text('survived cleanup')
    time.sleep(1)
else:
    while not pathlib.Path({str(pidfile)!r}).exists():
        time.sleep(0.005)
"""
    monkeypatch.setattr(checks, "COMMAND_TIMEOUT", 0.2)
    started = time.monotonic()
    with pytest.raises(checks.CheckError, match="deadline"):
        checks.run_command([sys.executable, "-c", code])
    assert time.monotonic() - started < 2
    assert int(pidfile.read_text()) > 0
    # A live descendant would write this witness even after its parent exits.
    time.sleep(0.5)
    assert not escaped.exists()


def test_command_cancellation_and_launch_errors_become_check_errors(
    checks: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(checks.CheckError, match="launch"):
        checks.run_command(["/nonexistent-release-helper"])

    def interrupt(*args: Any, **kwargs: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(checks.selectors.SelectSelector, "select", interrupt)
    # Use the public selector class explicitly so the seam also works on epoll/kqueue.
    monkeypatch.setattr(checks.selectors, "DefaultSelector", checks.selectors.SelectSelector)
    with pytest.raises(checks.CheckError, match="cancellation"):
        checks.run_command([sys.executable, "-c", "import time; time.sleep(5)"])


@pytest.mark.parametrize("returncode", [0, 1])
def test_command_cleanup_preserves_primary_failure_and_closes_both_pipes(
    checks: ModuleType, monkeypatch: pytest.MonkeyPatch, returncode: int
) -> None:
    command = ["synthetic-helper"]
    process = Mock(pid=42)
    process.wait.side_effect = [returncode, subprocess.TimeoutExpired(command, 1)]
    process.stdout.close.side_effect = OSError("synthetic close failure")
    selector = Mock()
    selector.get_map.return_value = {}
    with monkeypatch.context() as patch:
        patch.setattr(checks.subprocess, "Popen", Mock(return_value=process))
        patch.setattr(checks.selectors, "DefaultSelector", lambda: nullcontext(selector))
        patch.setattr(checks.os, "set_blocking", Mock())
        kill_group = Mock()
        patch.setattr(checks.os, "killpg", kill_group)
        primary = "helper command exited unsuccessfully" if returncode else "helper cleanup failed"
        with pytest.raises(checks.CheckError, match=f"^{primary}") as failure:
            checks.run_command(command)
    assert "reap" in str(failure.value)
    assert "stdout" in str(failure.value)
    kill_group.assert_called_once_with(42, checks.signal.SIGKILL)
    process.stdout.close.assert_called_once_with()
    process.stderr.close.assert_called_once_with()


def test_pack_process_death_leaves_marker_and_rerun_repairs_pair(
    checks: ModuleType, tmp_path: Path
) -> None:
    binary, license_path = tmp_path / "binary", tmp_path / "LICENSE"
    binary.write_bytes(b"old")
    license_path.write_bytes(b"MIT")
    out = tmp_path / "out"
    args = [
        "pack",
        "--binary",
        str(binary),
        "--license",
        str(license_path),
        "--version",
        "1.2.3",
        "--target",
        "x86_64-unknown-linux-gnu",
        "--mtime",
        "0",
        "--out-dir",
        str(out),
    ]
    assert checks.main(args) == 0
    binary.write_bytes(b"new")
    code = f"""
import os, runpy, signal
module = runpy.run_path({str(SCRIPT)!r})
replace = os.replace
def die_after_archive(src, dst):
    replace(src, dst)
    if str(dst).endswith('.tar.gz'):
        os.kill(os.getpid(), signal.SIGKILL)
os.replace = die_after_archive
module['main']({args!r})
"""
    result = subprocess.run([sys.executable, "-c", code], check=False, timeout=5)  # noqa: S603
    assert result.returncode < 0
    assert list(out.glob("*.incomplete"))
    assert checks.main(args) == 0
    name = checks.archive_name("1.2.3", "x86_64-unknown-linux-gnu")
    assert (out / f"{name}.sha256").read_text() == checks.checksum_line(
        (out / name).read_bytes(), name
    )
    assert not list(out.glob("*.incomplete"))
