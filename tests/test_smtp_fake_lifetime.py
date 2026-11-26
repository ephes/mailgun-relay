"""Synthetic durability and ownership journeys for the local SMTP fixtures."""

from __future__ import annotations

import json
import os
import smtplib
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rust" / "parity"))
import smtp_fake


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    return smtp_fake.make_certificates(tmp_path_factory.mktemp("owned-pki"))


@pytest.fixture
def smtp(pki: dict[str, str]) -> Iterator[smtp_fake.ScriptedSmtp]:
    server = smtp_fake.ScriptedSmtp(smtp_fake.server_contexts(pki))
    yield server
    server.close()


def test_capture_failure_never_exposes_partial_json_and_restart_reports_attempt(
    smtp: smtp_fake.ScriptedSmtp, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = smtp.start(record_dir=tmp_path)
    client = smtplib.SMTP("localhost", sink.port, timeout=2)
    with monkeypatch.context() as patch:

        def fail_sync(fd: int) -> None:
            raise OSError("synthetic sync failure")

        patch.setattr(os, "fsync", fail_sync)
        client.quit()
        sink.settle()
        with pytest.raises(RuntimeError, match="capture publication"):
            smtp.stop(sink)
    assert not list(tmp_path.glob("*.json"))
    assert (tmp_path / "000001.active").exists()
    restarted = smtp.start(record_dir=tmp_path)
    assert restarted.incomplete
    with smtplib.SMTP("localhost", restarted.port, timeout=2):
        pass
    restarted.settle()
    smtp.stop(restarted)
    assert json.loads((tmp_path / "000002.json").read_text())["state"] == "closed"


def test_capture_directory_has_one_owner_and_startup_failure_releases_it(
    smtp: smtp_fake.ScriptedSmtp, tmp_path: Path
) -> None:
    first = smtp.start(record_dir=tmp_path)
    second = None
    try:
        with pytest.raises((OSError, RuntimeError), match=r"owned|lock|unavailable"):
            second = smtp.start(record_dir=tmp_path)
    finally:
        if second is not None:
            smtp.stop(second)
        smtp.stop(first)
    restarted = smtp.start(record_dir=tmp_path)
    smtp.stop(restarted)

    occupying = smtp.start()
    with pytest.raises(OSError):
        smtp.start(port=occupying.port, record_dir=tmp_path)
    smtp.stop(occupying)
    recovered = smtp.start(record_dir=tmp_path)
    smtp.stop(recovered)


@pytest.mark.parametrize("kind", ["commands", "data"])
def test_session_aggregate_limits_refuse_without_truncated_success(
    smtp: smtp_fake.ScriptedSmtp, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    monkeypatch.setattr(smtp_fake, "MAX_COMMANDS", 4, raising=False)
    monkeypatch.setattr(smtp_fake, "MAX_SESSION_BYTES", 128, raising=False)
    sink = smtp.start({"offer_starttls": False})
    with smtplib.SMTP("localhost", sink.port, timeout=2) as client:
        if kind == "commands":
            replies = [client.docmd("NOOP")[0] for _ in range(5)]
            assert replies[-1] == 421
        else:
            client.putcmd("DATA")
            assert client.getreply()[0] == 354
            client.send(b"small line\r\n" * 20 + b".\r\n")
            assert client.getreply()[0] == 421
    sink.settle()
    [session] = sink.take()
    smtp.stop(sink)
    assert session["state"] == "limited"
    assert len(session["commands"]) <= 4
    assert session["message"] is None


def test_concurrent_and_retained_session_admission_is_bounded(
    smtp: smtp_fake.ScriptedSmtp, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(smtp_fake, "MAX_SESSIONS", 1, raising=False)
    monkeypatch.setattr(smtp_fake, "MAX_RETAINED_SESSIONS", 1, raising=False)
    sink = smtp.start()
    first = smtplib.SMTP("localhost", sink.port, timeout=2)
    try:
        with pytest.raises(smtplib.SMTPConnectError) as error:
            smtplib.SMTP("localhost", sink.port, timeout=2)
        assert error.value.smtp_code == 421
    finally:
        first.quit()
    sink.settle()
    with pytest.raises(smtplib.SMTPConnectError):
        smtplib.SMTP("localhost", sink.port, timeout=2)
    assert len(sink.sessions) == 1
    sink.take()
    with smtplib.SMTP("localhost", sink.port, timeout=2):
        pass
    smtp.stop(sink)


def test_close_drains_live_sessions_listeners_and_thread(
    pki: dict[str, str], tmp_path: Path
) -> None:
    import socket

    server = smtp_fake.ScriptedSmtp(smtp_fake.server_contexts(pki))
    sink = server.start(record_dir=tmp_path)
    client = smtplib.SMTP("localhost", sink.port, timeout=2)
    try:
        server.close()
        server.close()  # idempotent
        assert not server.thread.is_alive()
        assert not sink.tasks
        assert sink.server is not None and not sink.server.is_serving()
        assert json.loads((tmp_path / "000001.json").read_text())["state"] == "closed"
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", sink.port))
    finally:
        client.close()


@pytest.mark.parametrize("damage", ["missing", "mismatch"])
def test_pki_refuses_partial_or_mismatched_keys_and_recovers(tmp_path: Path, damage: str) -> None:
    paths = smtp_fake.make_certificates(tmp_path / "pki")
    good_key = Path(f"{paths['good']}.key")
    if damage == "missing":
        good_key.unlink()
    else:
        good_key.write_bytes(Path(f"{paths['wrongname']}.key").read_bytes())
    recovered = smtp_fake.make_certificates(tmp_path / "pki")
    smtp_fake.server_contexts(recovered)


def test_failed_pki_generation_preserves_previous_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    directory = tmp_path / "pki"
    paths = smtp_fake.make_certificates(directory)
    previous = {p.name: p.read_bytes() for p in directory.iterdir()}
    run = subprocess.run
    calls = 0

    def fail_generation(command: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        if command[1] == "x509" and "-checkend" in command:
            return subprocess.CompletedProcess(command, 1, b"", b"")
        if command[1] == "req":
            calls += 1
            if calls == 2:
                raise subprocess.CalledProcessError(1, command)
        return run(command, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", fail_generation)
        with pytest.raises(subprocess.CalledProcessError):
            smtp_fake.make_certificates(directory)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == previous
    smtp_fake.server_contexts(paths)
    smtp_fake.server_contexts(smtp_fake.make_certificates(directory))


def test_first_pki_publication_failure_retires_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "pki"
    sync_directory = smtp_fake.sync_directory
    parent_syncs: list[bytes] = []

    def fail_first_publication(path: Path) -> None:
        if path == tmp_path and directory.exists():
            parent_syncs.append((directory / "ca.pem").read_bytes())
            if len(parent_syncs) == 1:
                raise OSError("first publication sync failed")
        sync_directory(path)

    monkeypatch.setattr(smtp_fake, "sync_directory", fail_first_publication)
    with pytest.raises(OSError, match="first publication sync failed"):
        smtp_fake.make_certificates(directory)
    assert not directory.exists()

    smtp_fake.server_contexts(smtp_fake.make_certificates(directory))
    assert smtp_fake.usable_certificates(directory)
    assert len(parent_syncs) == 2
    assert parent_syncs[0] != parent_syncs[1] == (directory / "ca.pem").read_bytes()


@pytest.mark.parametrize("expired", ["ca", "good"])
def test_pki_checks_each_expiry_and_reuses_only_fresh_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, expired: str
) -> None:
    import subprocess

    directory = tmp_path / "pki"
    paths = smtp_fake.make_certificates(directory)
    old_ca = Path(f"{paths['ca']}.pem").read_bytes()
    assert smtp_fake.make_certificates(directory) == paths
    assert Path(f"{paths['ca']}.pem").read_bytes() == old_ca
    run = subprocess.run

    def expired_once(command: Any, *args: Any, **kwargs: Any) -> Any:
        if (
            "-checkend" in command
            and Path(command[command.index("-in") + 1]).name == f"{expired}.pem"
            and Path(kwargs["cwd"]) == directory
        ):
            return subprocess.CompletedProcess(command, 1, b"", b"")
        return run(command, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", expired_once)
        renewed = smtp_fake.make_certificates(directory)
    assert Path(f"{renewed['ca']}.pem").read_bytes() != old_ca
    smtp_fake.server_contexts(renewed)


def test_standalone_ownership_and_interrupt_drain(pki: dict[str, str], tmp_path: Path) -> None:
    import selectors
    import signal
    import subprocess

    script = Path(smtp_fake.__file__)
    args = [
        sys.executable,
        str(script),
        "--listen",
        "127.0.0.1:0",
        "--certs",
        str(Path(pki["ca"]).parent),
        "--record-dir",
        str(tmp_path),
    ]
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  # noqa: S603
    client = None
    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(5), "standalone listener failed to announce readiness"
            ready = process.stdout.readline()
        port = int(ready.split("127.0.0.1:")[1].split(",")[0])
        other = subprocess.run(args, capture_output=True, text=True, check=False, timeout=5)  # noqa: S603
        assert other.returncode != 0 and "already owned" in other.stderr
        client = smtplib.SMTP("localhost", port, timeout=2)
        process.send_signal(signal.SIGINT)
        _, stderr = process.communicate(timeout=5)
        assert process.returncode == 0
        assert "Task was destroyed" not in stderr and "Exception ignored" not in stderr
        assert json.loads((tmp_path / "000001.json").read_text())["state"] == "closed"
        server = smtp_fake.ScriptedSmtp(smtp_fake.server_contexts(pki))
        try:
            sink = server.start(record_dir=tmp_path, port=port)
            server.stop(sink)
        finally:
            server.close()
    finally:
        if client is not None:
            client.close()
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


def test_capture_final_directory_sync_failure_retains_active_marker(
    smtp: smtp_fake.ScriptedSmtp, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = smtp.start(record_dir=tmp_path)
    client = smtplib.SMTP("localhost", sink.port, timeout=2)
    sync = smtp_fake.sync_directory

    def fail_after_marker_removal(directory: Path) -> None:
        if not list(directory.glob("*.active")):
            raise OSError("synthetic final directory sync failure")
        sync(directory)

    monkeypatch.setattr(smtp_fake, "sync_directory", fail_after_marker_removal)
    client.quit()
    sink.settle()
    with pytest.raises(RuntimeError, match="capture publication"):
        smtp.stop(sink)
    assert (tmp_path / "000001.active").exists()
    assert json.loads((tmp_path / "000001.json").read_text())["state"] == "closed"


def test_take_keeps_sessions_accepted_while_older_session_is_draining(
    smtp: smtp_fake.ScriptedSmtp, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio
    import threading

    sink = smtp.start()
    first = smtplib.SMTP("localhost", sink.port, timeout=2)
    assert first.sock is not None
    first_port = first.sock.getsockname()[1]
    entered, release = threading.Event(), threading.Event()
    original = asyncio.StreamWriter.wait_closed
    result: list[list[dict[str, Any]]] = []

    async def delayed_close(writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        if peer and peer[1] == first_port:
            entered.set()
            while not release.is_set():
                await asyncio.sleep(0.005)
        await original(writer)

    monkeypatch.setattr(asyncio.StreamWriter, "wait_closed", delayed_close)
    worker = threading.Thread(target=lambda: result.append(sink.take()))
    worker.start()
    second = None
    try:
        assert entered.wait(2)
        second = smtplib.SMTP("localhost", sink.port, timeout=2)
        release.set()
        worker.join(2)
        assert not worker.is_alive()
        assert len(result[0]) == 1
        assert len(sink.tasks) == 1
        assert len(sink.sessions) == 1 and sink.sessions[0]["state"] == "open"
    finally:
        release.set()
        worker.join(2)
        first.close()
        if second is not None:
            second.quit()
        sink.settle()
        smtp.stop(sink)


def test_cli_interrupt_reports_capture_publication_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    closed: list[smtp_fake.ScriptedSmtp] = []
    real_close = smtp_fake.ScriptedSmtp.close

    def failing_close(self: smtp_fake.ScriptedSmtp) -> None:
        closed.append(self)
        raise RuntimeError("capture publication failed; incomplete attempts retained")

    def interrupt() -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(smtp_fake, "wait_for_shutdown", interrupt)
    monkeypatch.setattr(smtp_fake.ScriptedSmtp, "close", failing_close)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "smtp_fake.py",
            "--listen",
            "localhost:0",
            "--certs",
            str(tmp_path / "pki"),
            "--record-dir",
            str(tmp_path / "records"),
        ],
    )
    with pytest.raises(SystemExit) as exit_info:
        smtp_fake.main()
    assert exit_info.value.code == 1
    assert len(closed) == 1
    real_close(closed[0])  # retire the real listener the patched close left running
    captured = capsys.readouterr()
    assert "smtp sink on localhost:" in captured.out
    assert "capture publication failed" in captured.err
