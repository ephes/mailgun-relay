#!/usr/bin/env python3
"""Release checks for the Rust port (rust/PLAN.md section 8).

Used by `rust/scripts/local_release.py`; stdlib only and Python 3.10
compatible (its release job runs on ubuntu-22.04's system Python). The pure
parts are tested in `tests/test_rust_release_checks.py`. Adapted from
`nyxmon:agent-rs/scripts/release_checks.py`.

Subcommands:

- ``version``: print the version of the ``mailgun-relay`` package from
  ``cargo metadata`` JSON; with ``--tag`` also require the tag to be
  ``rs-v<that version>``.
- ``glibc-floor``: require every glibc symbol version the binary needs to be
  at most ``--max`` and every shared library it links to be part of glibc or
  libgcc (``objdump -T`` and ``objdump -p``).
- ``smoke``: run ``<binary> --version`` and require exactly
  ``mailgun-relay <version> (<commit>)``; then run ``<binary> --check-config``
  with only a test environment (the variables of the role's env file) and a
  test secrets file (the role's template shape, mode 0600) and require exit 0
  with the configuration summary those files give.
- ``pack``: write ``mailgun-relay-<version>-<target>.tar.gz`` (binary and
  LICENSE at the archive root, deterministic) and its ``.sha256`` file.
"""

from __future__ import annotations

import argparse
import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

PACKAGE = "mailgun-relay"
TAG_PREFIX = "rs-v"

# Semantic Versioning 2.0.0 (the regex of semver.org without build metadata:
# a `+` in the tag would end up in the release download URL).
SEMVER = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?",
    re.ASCII,
)
SUPPORTED_TARGETS = frozenset({"x86_64-unknown-linux-gnu"})
COMMIT = re.compile(r"[0-9a-f]{40}")

# Shared libraries a glibc build may link to (PLAN.md 8: only glibc and
# libgcc; TLS is rustls with ring).
ALLOWED_LIBRARIES = frozenset(
    {
        "ld-linux-x86-64.so.2",
        "libc.so.6",
        "libdl.so.2",
        "libgcc_s.so.1",
        "libm.so.6",
        "libpthread.so.0",
        "librt.so.1",
        "libutil.so.1",
    }
)

GLIBC_VERSION = re.compile(r"\bGLIBC_([0-9A-Za-z_.]+)")
NEEDED = re.compile(r"^\s*NEEDED\s+(\S+)\s*$", re.MULTILINE)

# `--check-config` smoke test: the variables of the role's
# `mailgun-relay.env.j2` with values that differ from the defaults, so the
# summary line proves the environment was read, and a secrets file in the
# shape of its `secrets.yml.j2` (not a real token or password).
SMOKE_TOKEN_SHA256 = hashlib.sha256(b"release-smoke-token").hexdigest()
SMOKE_SECRETS = f"""\
# Release smoke test (rust/scripts/release_checks.py); no real credentials.
smtp:
  username: "relay@example.org"
  password: "smoke-test-password"

tokens:
  - label: "smoke-a"
    token_sha256: "{SMOKE_TOKEN_SHA256}"
    mailgun_domains:
      - "mg.example.org"
    allowed_from_domains:
      - "example.org"
  - label: "smoke-b"
    token_sha256: "{hashlib.sha256(b"release-smoke-token-b").hexdigest()}"
    mailgun_domains:
      - "mg.xn--wersdrfer-47a.de"
    allowed_from_domains:
      - "xn--wersdrfer-47a.de"
    allowed_from_addresses:
      - "noreply@example.org"
"""
SMOKE_CHECK_CONFIG_OUTPUT = (
    f"{PACKAGE}: configuration OK (bind 127.0.0.1:18085, log level WARNING, 2 token(s))\n"
)


class CheckError(Exception):
    """A release check failed; the message is the reason."""


COMMAND_TIMEOUT = 10.0
OUTPUT_LIMIT = 1 << 20


def run_command(
    command: list[str], *, env: dict[str, str] | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Bound the whole command, both pipes and its POSIX process group."""
    deadline = time.monotonic() + COMMAND_TIMEOUT
    process: subprocess.Popen[bytes] | None = None
    output = [bytearray(), bytearray()]
    total = 0
    primary: CheckError | None = None
    try:
        process = subprocess.Popen(  # noqa: S603 - explicit executable under validation
            command,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        with selectors.DefaultSelector() as selector:
            for index, pipe in enumerate((process.stdout, process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, index)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CheckError("helper command deadline exceeded")
                for key, _ in selector.select(min(remaining, 0.05)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > OUTPUT_LIMIT:
                        raise CheckError("helper output byte ceiling exceeded")
                    output[key.data].extend(chunk)
        returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if check and returncode != 0:
            raise CheckError("helper command exited unsuccessfully")
        return subprocess.CompletedProcess(
            command, returncode, *(bytes(part).decode("utf-8", "replace") for part in output)
        )
    except CheckError as error:
        primary = error
        raise
    except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        primary = CheckError("helper command launch, deadline or cancellation failure")
        raise primary from error
    finally:
        if process is not None:
            failures = _retire_helper(process)
            if failures:
                evidence = f"helper cleanup failed: {', '.join(failures)}"
                if primary is None:
                    raise CheckError(evidence)
                # Keep the primary diagnostic and cause on Python 3.10 too.
                primary.args = (f"{primary}; {evidence}",)


def _retire_helper(process: subprocess.Popen[bytes]) -> list[str]:
    """Attempt every cleanup step, recording only bounded operation names."""
    failures = []
    try:
        # Also retire descendants of an already exited group leader.
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except (OSError, KeyboardInterrupt):
        failures.append("retire process group")
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
        failures.append("reap process")
    for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
        if pipe is not None:
            try:
                pipe.close()
            except (OSError, KeyboardInterrupt):
                failures.append(f"close {name}")
    return failures


def parse_version(text: str) -> tuple[int, ...]:
    """`2.35` → (2, 35); anything but dot-separated decimals is an error."""
    if not re.fullmatch(r"\d+(?:\.\d+)*", text):
        raise CheckError(f"not a glibc version: {text!r}")
    return tuple(int(part) for part in text.split("."))


def package_version(metadata: object) -> str:
    """The `mailgun-relay` version from `cargo metadata --no-deps` output."""
    if not isinstance(metadata, dict):
        raise CheckError("cargo metadata root must be an object")
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise CheckError("cargo metadata packages must be an array")
    versions = []
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise CheckError(f"cargo metadata packages[{index}] must be an object")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str):
            raise CheckError(f"cargo metadata packages[{index}].name must be a string")
        if not isinstance(version, str):
            raise CheckError(f"cargo metadata packages[{index}].version must be a string")
        if name == PACKAGE:
            versions.append(version)
    if len(versions) != 1:
        raise CheckError(f"expected one {PACKAGE} package in cargo metadata, found {len(versions)}")
    version = versions[0]
    if not SEMVER.fullmatch(version):
        raise CheckError(f"{PACKAGE} version is not semver (without build metadata)")
    return version


def check_tag(tag: str, version: str) -> None:
    expected = f"{TAG_PREFIX}{version}"
    if tag != expected:
        raise CheckError(f"tag {tag!r} does not match the {PACKAGE} version: expected {expected!r}")


def glibc_versions(objdump_text: str) -> set[str]:
    """Every `GLIBC_<x>` symbol or version reference in objdump output."""
    return set(GLIBC_VERSION.findall(objdump_text))


def needed_libraries(objdump_text: str) -> list[str]:
    """The `NEEDED` entries of the dynamic section (`objdump -p`)."""
    return NEEDED.findall(objdump_text)


def check_glibc(objdump_text: str, maximum: str) -> str:
    """Validate objdump output; return the highest glibc version required."""
    limit = parse_version(maximum)
    versions = glibc_versions(objdump_text)
    if not versions:
        raise CheckError("no GLIBC symbol versions found: not a dynamically linked glibc binary?")
    parsed = {}
    for version in versions:
        try:
            parsed[version] = parse_version(version)
        except CheckError:
            raise CheckError(f"unexpected glibc symbol version GLIBC_{version}") from None
    newest = max(parsed, key=lambda version: parsed[version])
    too_new = sorted(
        (version for version, value in parsed.items() if value > limit),
        key=lambda version: parsed[version],
    )
    if too_new:
        listed = ", ".join(f"GLIBC_{version}" for version in too_new)
        raise CheckError(f"binary requires glibc newer than {maximum}: {listed}")
    libraries = needed_libraries(objdump_text)
    if not libraries:
        raise CheckError("no NEEDED entries found in the dynamic section")
    unexpected = sorted(set(libraries) - ALLOWED_LIBRARIES)
    if unexpected:
        raise CheckError(f"binary links to libraries outside glibc/libgcc: {', '.join(unexpected)}")
    return newest


def check_version_output(stdout: str, version: str, commit: str) -> None:
    expected = f"{PACKAGE} {version} ({commit})\n"
    if stdout != expected:
        raise CheckError(f"--version printed {stdout!r}, expected {expected!r}")


def smoke_environment(secrets_path: Path) -> dict[str, str]:
    """The only variables `--check-config` sees (the role's env file keys)."""
    return {
        "MAILGUN_RELAY_BIND_HOST": "127.0.0.1",
        "MAILGUN_RELAY_BIND_PORT": "18085",
        "MAILGUN_RELAY_PUBLIC_HOST": "mailgun.example.org",
        "MAILGUN_RELAY_SECRETS_PATH": str(secrets_path),
        "MAILGUN_RELAY_SMTP_HOST": "smtp.example.org",
        "MAILGUN_RELAY_SMTP_PORT": "587",
        "MAILGUN_RELAY_SMTP_STARTTLS": "true",
        "MAILGUN_RELAY_SMTP_TIMEOUT_S": "30",
        "MAILGUN_RELAY_SMTP_MAX_CONCURRENCY": "4",
        "MAILGUN_RELAY_ENVELOPE_SENDER": "relay@xn--wersdrfer-47a.de",
        "MAILGUN_RELAY_MAX_BODY_BYTES": "26214400",
        "MAILGUN_RELAY_MAX_ATTACHMENTS": "10",
        "MAILGUN_RELAY_MAX_ATTACHMENT_BYTES": "10485760",
        "MAILGUN_RELAY_MAX_RECIPIENTS": "100",
        "MAILGUN_RELAY_MAX_HEADER_VALUE_LENGTH": "998",
        "MAILGUN_RELAY_LOG_LEVEL": "WARNING",
    }


def check_config_output(returncode: int, stdout: str, stderr: str) -> None:
    if returncode != 0 or stdout != SMOKE_CHECK_CONFIG_OUTPUT:
        raise CheckError(
            f"--check-config exited {returncode} with stdout {stdout!r} and stderr "
            f"{stderr!r}, expected exit 0 and {SMOKE_CHECK_CONFIG_OUTPUT!r}"
        )


def run_check_config(binary: Path) -> str:
    """Run `--check-config` against the test files; return its stdout."""
    with tempfile.TemporaryDirectory(prefix="mailgun-relay-smoke-") as directory:
        secrets_path = Path(directory) / "secrets.yml"
        descriptor = os.open(secrets_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(SMOKE_SECRETS)
        result = run_command(
            [str(binary), "--check-config"], env=smoke_environment(secrets_path), check=False
        )
    check_config_output(result.returncode, result.stdout, result.stderr)
    return result.stdout


def archive_name(version: str, target: str) -> str:
    if not SEMVER.fullmatch(version):
        raise CheckError("artifact version must be semver without build metadata")
    if target not in SUPPORTED_TARGETS:
        raise CheckError("unsupported artifact target")
    return f"{PACKAGE}-{version}-{target}.tar.gz"


def _tar_member(
    name: str, data: bytes, mode: int, mtime: int
) -> tuple[tarfile.TarInfo, io.BytesIO]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = mtime
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.type = tarfile.REGTYPE
    return info, io.BytesIO(data)


def build_archive(binary: bytes, license_text: bytes, mtime: int) -> bytes:
    """Deterministic tar.gz with `LICENSE` (0644) and `mailgun-relay` (0755)."""
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, data, mode in (
            ("LICENSE", license_text, 0o644),
            (PACKAGE, binary, 0o755),
        ):
            archive.addfile(*_tar_member(name, data, mode, mtime))
    compressed = io.BytesIO()
    # filename="" and a fixed mtime keep the gzip header reproducible.
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=mtime
    ) as gz:
        gz.write(tar_bytes.getvalue())
    return compressed.getvalue()


def verify_archive(data: bytes, binary: bytes, license_text: bytes) -> None:
    """Read the archive back: exactly the two files, contents and modes."""
    expected = {"LICENSE": (license_text, 0o644), PACKAGE: (binary, 0o755)}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if sorted(names) != sorted(expected):
            raise CheckError(f"archive members {names}, expected {sorted(expected)}")
        for member in members:
            content, mode = expected[member.name]
            if not member.isreg() or member.mode != mode:
                raise CheckError(f"archive member {member.name} has mode {oct(member.mode)}")
            extracted = archive.extractfile(member)
            if extracted is None or extracted.read() != content:
                raise CheckError(f"archive member {member.name} differs from its source")


def checksum_line(data: bytes, name: str) -> str:
    """`sha256sum` output format: `<hex>  <name>\\n`."""
    return f"{hashlib.sha256(data).hexdigest()}  {name}\n"


def sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_archive(directory: Path, name: str, data: bytes) -> None:
    """Stage a verified pair; retain an incomplete marker across process death."""
    directory.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = directory / f".{name}.incomplete"
        names = (name, f"{name}.sha256")
        stage = Path(tempfile.mkdtemp(prefix=".pack-", dir=directory))
        retain_stage = False
        try:
            (stage / name).write_bytes(data)
            (stage / names[1]).write_text(checksum_line(data, name), encoding="utf-8")
            if (stage / name).read_bytes() != data or (
                stage / names[1]
            ).read_text() != checksum_line(data, name):
                raise CheckError("staged artifact verification failed")
            for item in names:
                with (stage / item).open("rb") as handle:
                    os.fsync(handle.fileno())
                if (directory / item).exists():
                    shutil.copyfile(directory / item, stage / f"{item}.old")
            # A marker left by an earlier interrupted run means the current pair is
            # itself unusable, so a rollback to it must keep that marker.
            previously_marked = marker.exists()
            marker.write_text("incomplete artifact pair; rerun pack before use\n")
            with marker.open("rb") as handle:
                os.fsync(handle.fileno())
            sync_directory(directory)
            try:
                for item in names:
                    os.replace(stage / item, directory / item)
                sync_directory(directory)
            except BaseException as primary:
                # Keep remaining backups unless the whole rollback succeeds.
                retain_stage = True
                failures = []
                for item in names:
                    backup = stage / f"{item}.old"
                    try:
                        if backup.exists():
                            os.replace(backup, directory / item)
                        else:
                            (directory / item).unlink(missing_ok=True)
                    except (OSError, KeyboardInterrupt):
                        failures.append(f"restore {item}")
                try:
                    sync_directory(directory)
                except (OSError, KeyboardInterrupt):
                    failures.append("sync output directory")
                if not failures and not previously_marked:
                    try:
                        marker.unlink(missing_ok=True)
                        sync_directory(directory)
                    except (OSError, KeyboardInterrupt):
                        failures.append("clear incomplete marker")
                if failures:
                    raise CheckError(
                        f"{primary}; rollback failed ({', '.join(failures)}); "
                        f"recovery files retained in {stage.absolute()}"
                    ) from primary
                retain_stage = False
                raise
            marker.unlink()
            sync_directory(directory)
        finally:
            if not retain_stage:
                shutil.rmtree(stage)

    finally:
        os.close(descriptor)


def _objdump(binary: Path) -> str:
    texts = []
    for flag in ("-T", "-p"):
        command = ["objdump", flag, str(binary)]  # binutils from PATH
        result = run_command(command)
        texts.append(result.stdout)
    return "\n".join(texts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    version = commands.add_parser("version")
    version.add_argument("--metadata", type=Path, required=True, help="cargo metadata JSON file")
    version.add_argument("--tag", help="release tag that must match the version")

    floor = commands.add_parser("glibc-floor")
    floor.add_argument("--max", required=True, help="highest allowed glibc version, e.g. 2.35")
    floor.add_argument("binary", type=Path)

    smoke = commands.add_parser("smoke")
    smoke.add_argument("--binary", type=Path, required=True)
    smoke.add_argument("--version", required=True)
    smoke.add_argument("--commit", required=True, help="full 40-digit commit")

    pack = commands.add_parser("pack")
    pack.add_argument("--binary", type=Path, required=True)
    pack.add_argument("--license", type=Path, required=True)
    pack.add_argument("--version", required=True)
    pack.add_argument("--target", required=True)
    pack.add_argument("--mtime", type=int, required=True, help="Unix time for all entries")
    pack.add_argument("--out-dir", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "version":
            metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
            found = package_version(metadata)
            if args.tag is not None:
                check_tag(args.tag, found)
            print(found)
        elif args.command == "glibc-floor":
            newest = check_glibc(_objdump(args.binary), args.max)
            print(
                f"{args.binary}: newest glibc symbol version GLIBC_{newest} "
                f"(floor {args.max}); libraries OK"
            )
        elif args.command == "smoke":
            if not COMMIT.fullmatch(args.commit):
                raise CheckError(f"--commit must be 40 lowercase hex digits, got {args.commit!r}")
            result = run_command([str(args.binary), "--version"])
            check_version_output(result.stdout, args.version, args.commit)
            print(result.stdout, end="")
            print(run_check_config(args.binary), end="")
        else:
            name = archive_name(args.version, args.target)
            binary = args.binary.read_bytes()
            license_text = args.license.read_bytes()
            data = build_archive(binary, license_text, args.mtime)
            verify_archive(data, binary, license_text)
            publish_archive(args.out_dir, name, data)
            print(name)
    except (CheckError, OSError) as error:
        print(f"release check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
