#!/usr/bin/env python3
"""Release checks for the Rust port (rust/PLAN.md section 8).

Used by `.github/workflows/rust-release.yml`; stdlib only and Python 3.10
compatible (the release job runs on ubuntu-22.04's system Python). The pure
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
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

PACKAGE = "mailgun-relay"
TAG_PREFIX = "rs-v"

# Semantic Versioning 2.0.0 (the regex of semver.org without build metadata:
# a `+` in the tag would end up in the release download URL).
SEMVER = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
)
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
    token_sha256: "{SMOKE_TOKEN_SHA256}"
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


def parse_version(text: str) -> tuple[int, ...]:
    """`2.35` → (2, 35); anything but dot-separated decimals is an error."""
    if not re.fullmatch(r"\d+(?:\.\d+)*", text):
        raise CheckError(f"not a glibc version: {text!r}")
    return tuple(int(part) for part in text.split("."))


def package_version(metadata: dict[str, Any]) -> str:
    """The `mailgun-relay` version from `cargo metadata --no-deps` output."""
    versions = [
        package["version"]
        for package in metadata.get("packages", [])
        if package.get("name") == PACKAGE
    ]
    if len(versions) != 1:
        raise CheckError(f"expected one {PACKAGE} package in cargo metadata, found {len(versions)}")
    version = versions[0]
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise CheckError(f"{PACKAGE} version {version!r} is not semver (without build metadata)")
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
        result = subprocess.run(  # noqa: S603 - the binary under test
            [str(binary), "--check-config"],
            env=smoke_environment(secrets_path),
            capture_output=True,
            text=True,
            check=False,
        )
    check_config_output(result.returncode, result.stdout, result.stderr)
    return result.stdout


def archive_name(version: str, target: str) -> str:
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


def _objdump(binary: Path) -> str:
    texts = []
    for flag in ("-T", "-p"):
        command = ["objdump", flag, str(binary)]  # binutils from PATH
        result = subprocess.run(command, check=True, capture_output=True, text=True)  # noqa: S603
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
            result = subprocess.run(  # noqa: S603 - the binary under test
                [str(args.binary), "--version"],
                check=True,
                capture_output=True,
                text=True,
            )
            check_version_output(result.stdout, args.version, args.commit)
            print(result.stdout, end="")
            print(run_check_config(args.binary), end="")
        else:
            binary = args.binary.read_bytes()
            license_text = args.license.read_bytes()
            name = archive_name(args.version, args.target)
            data = build_archive(binary, license_text, args.mtime)
            verify_archive(data, binary, license_text)
            args.out_dir.mkdir(parents=True, exist_ok=True)
            (args.out_dir / name).write_bytes(data)
            (args.out_dir / f"{name}.sha256").write_text(
                checksum_line(data, name), encoding="utf-8"
            )
            print(name)
    except CheckError as error:
        print(f"release check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
