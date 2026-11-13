"""The parity harness itself (rust/parity, rust/PLAN.md 7.4): the fake SMTP
server records what a client sends, the comparison catches every kind of
difference the contract cares about, and the corpus has the cases S6
requires. The harness run against both implementations is the CI job
``parity``."""

from __future__ import annotations

import copy
import json
import re
import smtplib
import ssl
import sys
from collections.abc import Iterator
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rust" / "parity"))
import cases as corpus
import run_parity
from smtp_fake import ScriptedSmtp, make_certificates, server_contexts, session_from_json

PLAN = Path(__file__).resolve().parents[1] / "rust" / "PLAN.md"


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    return make_certificates(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def smtp(pki: dict[str, str]) -> Iterator[ScriptedSmtp]:
    server = ScriptedSmtp(server_contexts(pki))
    yield server
    server.close()


def _message(text: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = "a@example.org"
    message["To"] = "b@example.org"
    message["Subject"] = "s"
    message["Message-ID"] = "<1@x.test>"
    message["Date"] = "Thu, 15 Oct 2026 12:00:00 +0000"
    message.set_content(text)
    return message


def test_fake_records_the_session(smtp: ScriptedSmtp, pki: dict[str, str]) -> None:
    sink = smtp.start({"rcpt": {"gone": 550}})
    context = ssl.create_default_context(cafile=f"{pki['ca']}.pem")
    with smtplib.SMTP("localhost", sink.port, timeout=5) as client:
        client.starttls(context=context)
        client.login("relay", "secret")
        refused = client.send_message(
            _message(".leading dot\n"),
            from_addr="relay@example.org",
            to_addrs=["b@example.org", "gone@example.org"],
        )
    assert refused == {"gone@example.org": (550, b"rcpt result")}
    sink.settle()
    [session] = sink.take()
    smtp.stop(sink)
    assert session["tls"] and session["auth_user"] == "relay"
    assert session["mail_from"] == "relay@example.org"
    assert session["rcpt"] == [["b@example.org", 250], ["gone@example.org", 550]]
    assert session["data_for"] == ["b@example.org"]
    # Dot-stuffing undone; the final CRLF is the client's, no extra line.
    assert session["message"].endswith(b"\r\n\r\n.leading dot\r\n")


def test_recording_sink_keeps_nothing_and_numbers_on(
    smtp: ScriptedSmtp, pki: dict[str, str], tmp_path: Path
) -> None:
    context = ssl.create_default_context(cafile=f"{pki['ca']}.pem")
    for run in range(2):  # the second sink is a restarted one
        sink = smtp.start(record_dir=tmp_path)
        with smtplib.SMTP("localhost", sink.port, timeout=5) as client:
            client.starttls(context=context)
            client.login("relay", "secret")
            client.send_message(_message(f"run {run}\n"))
        sink.settle()
        smtp.stop(sink)
        assert sink.sessions == [] and sink.tasks == set()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["000001.json", "000002.json"]
    first = session_from_json(json.loads((tmp_path / "000001.json").read_text()))
    assert first["message"].endswith(b"run 0\r\n") and first["data_for"] == ["b@example.org"]


def _response(status: int, body: str, **headers: str) -> run_parity.Response:
    headers.setdefault("content-type", "application/json")
    return run_parity.Response(status, headers, body.encode())


def _outcome() -> run_parity.Outcome:
    raw = _message("Hallo Welt\n").as_bytes(policy=_message("").policy.clone(linesep="\r\n"))
    session = {
        "state": "closed",
        "tls": True,
        "commands": [],
        "auth_user": "relay",
        "mail_from": "relay@example.org",
        "rcpt": [["b@example.org", 250]],
        "data_for": ["b@example.org"],
        "message": raw,
    }
    record = {
        "event": "request",
        "token_label": "homepage-production",
        "result": "ok",
        "status_code": 200,
        "recipient_count": 1,
        "refused_count": 0,
        "message_id": "<1@x.test>",
    }
    response = _response(200, '{"id":"<1@x.test>","message":"Queued. Thank you."}')
    return run_parity.Outcome(response, [session], [record])


def _differences(change: Any, case: corpus.Case | None = None) -> list[str]:
    case = case or corpus.Case("c", corpus.Request(), 200)
    rust = copy.deepcopy(_outcome())
    change(rust)
    diffs, _ = run_parity.compare(case, _outcome(), rust)
    return diffs


def _set_message(outcome: run_parity.Outcome, old: bytes, new: bytes) -> None:
    outcome.sessions[0]["message"] = outcome.sessions[0]["message"].replace(old, new)


def test_identical_outcomes_pass() -> None:
    assert _differences(lambda rust: None) == []


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda o: setattr(o.response, "status", 503), "status"),
        (lambda o: o.response.headers.update({"www-authenticate": "x"}), "www-authenticate"),
        (lambda o: setattr(o.response, "body", b'{"id":"<1@x.test>","message":"Ok"}'), "message"),
        (lambda o: o.sessions.clear(), "SMTP sessions"),
        (lambda o: o.sessions[0].update(mail_from="other@x.test"), "mail_from"),
        (lambda o: o.sessions[0].update(rcpt=[]), "rcpt"),
        (lambda o: o.sessions[0].update(auth_user=None), "login"),
        (lambda o: _set_message(o, b"Subject: s", b"Subject: t"), "message differs"),
        (lambda o: _set_message(o, b"Hallo Welt\r\n", b"Hallo Welt\r\n\r\n"), "message differs"),
        (lambda o: _set_message(o, b"Subject: s", b"Bcc: x@y.z\r\nSubject: s"), "Bcc"),
        (lambda o: _set_message(o, b"<1@x.test>", b"<2@x.test>"), "not the response id"),
        (lambda o: _set_message(o, b"Hallo Welt\r\n", b"Hallo\nWelt\r\n"), "bare CR or LF"),
        (lambda o: o.records.clear(), "request records"),
        (lambda o: o.records[0].update(token_label="-"), "token_label"),
        (lambda o: o.records[0].update(result="smtp_temporary"), "result"),
    ],
)
def test_every_contract_difference_is_caught(change: Any, expected: str) -> None:
    diffs = _differences(change)
    assert any(expected in diff for diff in diffs), diffs


def test_health_body_and_queued_messages_are_checked() -> None:
    case = corpus.Case("health", corpus.Request(method="GET", path="/health"), 200)
    health = run_parity.Outcome(_response(200, '{"status":"ok"}'), [], None)
    for body in ('{"status":"failed"}', '{"status":null}', "[]", '{"status":"ok","version":"1"}'):
        rust = run_parity.Outcome(_response(200, body), [], None)
        diffs, _ = run_parity.compare(case, health, rust)
        assert diffs, body
    missing = _outcome()
    missing.sessions.clear()
    diffs, _ = run_parity.compare(corpus.Case("c", corpus.Request(), 200), missing, missing)
    assert any("queued, but 0 SMTP sessions" in d for d in diffs), diffs
    divergent = corpus.Case("c", corpus.Request(), 200, divergence="D-21", rust_status=400)
    rust = run_parity.Outcome(_response(400, '{"message":"x"}'), [], None)
    diffs, _ = run_parity.compare(divergent, missing, rust)
    assert any("python: queued, but 0" in d for d in diffs), diffs


def test_free_details_are_not_differences() -> None:
    def change(rust: run_parity.Outcome) -> None:
        rust.response.headers["server"] = "hyper"
        rust.response.body = b'{"id":"<1@x.test>","message":"Queued. Thank you."}'
        assert rust.records is not None
        rust.records[0].update(ts="2026-10-15T12:00:00Z", error_class="Rust")
        _set_message(rust, b"Subject: s", b"Subject:  s")
        _set_message(rust, b"Message-ID: <1@x.test>", b"Message-ID:\r\n <1@x.test>")

    assert _differences(change) == []
    error = _response(400, '{"message":"free text"}')
    case = corpus.Case("c", corpus.Request(), 400)
    py = run_parity.Outcome(error, [], [])
    rs = run_parity.Outcome(_response(400, '{"message":"other text"}'), [], [])
    assert run_parity.compare(case, py, rs) == ([], None)


def test_divergences_pin_the_rust_status_and_must_show() -> None:
    case = corpus.Case("c", corpus.Request(), 200, divergence="D-21", rust_status=400)
    py = _outcome()
    rs = run_parity.Outcome(_response(400, '{"message":"x"}'), [], None)
    assert run_parity.compare(case, py, rs) == ([], "D-21")
    stale, _ = run_parity.compare(case, py, _outcome())
    assert any("no longer shows" in d for d in stale), stale
    oracle, _ = run_parity.compare(corpus.Case("c", corpus.Request(), 400), _outcome(), _outcome())
    assert any("the case expects 400" in d for d in oracle), oracle


def test_request_framing() -> None:
    request = corpus.Request(headers=[("X-A", "1")], body=b"abc")
    [raw] = run_parity.request_pieces(request)
    assert raw.endswith(b"\r\nX-A: 1\r\nConnection: close\r\nContent-Length: 3\r\n\r\nabc")
    chunked = corpus.Request(length=None, chunks=[b"ab", b"c"], split=7)
    head, rest = run_parity.request_pieces(chunked)
    assert (head + rest).endswith(
        b"Transfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n"
    )
    assert rest == b"1\r\nc\r\n0\r\n\r\n"
    assert run_parity._dechunk(b"2\r\nab\r\n1\r\nc\r\n0\r\n\r\n") == b"abc"


def test_log_tail_splits_records_at_markers() -> None:
    tail = run_parity.LogTail()
    for line in ['{"event":"request","n":1}', "not json", '{"path_domain":"marker-1.parity"}']:
        tail.feed(line)
    tail.feed('{"path_domain":"marker-2.parity"}')
    assert tail.until_marker(1) == [{"event": "request", "n": 1}]
    assert tail.until_marker(2) == []
    assert tail.until_marker(3, timeout=0.05) is None


def test_corpus_covers_the_s6_requirements() -> None:
    cases = corpus.request_cases()
    names = [c.name for c in cases]
    assert len(cases) >= 150 and len(set(names)) == len(names)
    assert set(corpus.PROFILES) >= {c.profile for c in cases}
    decided = set(re.findall(r"^\| (D-\d+) \|", PLAN.read_text(encoding="utf-8"), re.MULTILINE))
    for case in cases:
        if case.divergence is not None:
            assert case.divergence in decided and case.rust_status is not None, case.name
    shown = {c.divergence for c in cases} | {c.divergence for c in corpus.STARTUP_CASES}
    assert shown >= {"D-3", "D-4", "D-9", "D-10", "D-11", "D-20", "D-21", "D-22"}
    for required in ("D-1", "D-12", "D-16", "D-19", "D-2"):
        assert any(f"({required})" in name for name in names), required
    for label in corpus.PRODUCTION_LABELS:
        assert f"policy {label} allowed" in names and f"policy {label} foreign path" in names
    assert len(corpus.PRODUCTION_LABELS) == 12
    assert sum(name.startswith("recorder multipart") for name in names) >= 8
    assert sum(name.startswith("anymail") for name in names) >= 40
    assert any(name.startswith("smtp strict partial") for name in names)


@pytest.mark.parametrize("limit", ["deadline", "header", "body"])
def test_exchange_bounds_real_loopback_response(
    monkeypatch: pytest.MonkeyPatch, limit: str
) -> None:
    import socket
    import threading
    import time

    monkeypatch.setattr(run_parity, "MAX_RESPONSE_HEADER_BYTES", 128, raising=False)
    monkeypatch.setattr(run_parity, "MAX_RESPONSE_BODY_BYTES", 128, raising=False)
    closed = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        address = listener.getsockname()

        def respond() -> None:
            with listener.accept()[0] as peer:
                peer.settimeout(2)
                peer.recv(4096)
                try:
                    if limit == "deadline":
                        peer.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                        for _ in range(20):
                            peer.sendall(b"x")
                            time.sleep(0.02)
                    elif limit == "header":
                        peer.sendall(b"HTTP/1.1 200 OK\r\nX-Pad: " + b"x" * 256 + b"\r\n\r\n")
                    else:
                        peer.sendall(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 256)
                    peer.shutdown(socket.SHUT_WR)
                    assert peer.recv(1) == b""
                except BrokenPipeError, ConnectionResetError:
                    pass
                finally:
                    closed.set()

        worker = threading.Thread(target=respond)
        worker.start()
        try:
            expected = TimeoutError if limit == "deadline" else RuntimeError
            with pytest.raises(expected, match=r"deadline|header|body"):
                run_parity.exchange(address, [b"GET / HTTP/1.1\r\n\r\n"], timeout=0.12)
        finally:
            worker.join(3)
        assert closed.is_set()


@pytest.mark.parametrize("failure", [RuntimeError("probe failed"), KeyboardInterrupt()])
def test_start_unwinds_probe_failure(
    monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    import socket
    import subprocess

    processes: list[subprocess.Popen[bytes]] = []
    original_spawn = run_parity.spawn

    def spawn(command: list[str], env: dict[str, str]) -> subprocess.Popen[bytes]:
        process = original_spawn(command, env)
        processes.append(process)
        return process

    def probe(*args: Any, **kwargs: Any) -> None:
        raise failure

    monkeypatch.setattr(run_parity, "spawn", spawn)
    monkeypatch.setattr(socket, "create_connection", probe)
    try:
        with pytest.raises(type(failure)) as caught:
            run_parity.start(
                "python",
                [sys.executable, "-c", "import time; time.sleep(60)"],
                {},
                None,  # type: ignore[arg-type]
            )
        assert caught.value is failure
        assert processes and all(p.poll() is not None for p in processes)
    finally:
        for process in processes:
            run_parity.stop(process)
            assert process.stdout is not None
            process.stdout.close()


@pytest.mark.parametrize("failure", [RuntimeError("second start failed"), KeyboardInterrupt()])
def test_local_unwinds_partial_startup(
    monkeypatch: pytest.MonkeyPatch, pki: dict[str, str], failure: BaseException
) -> None:
    import argparse
    import subprocess

    smtp = ScriptedSmtp(server_contexts(pki))

    processes: list[subprocess.Popen[bytes]] = []
    sinks: list[Any] = []
    stopped: list[Any] = []
    original_start = smtp.start
    original_stop = smtp.stop

    def sink_start() -> Any:
        sink = original_start()
        sinks.append(sink)
        return sink

    def sink_stop(sink: Any) -> None:
        stopped.append(sink)
        original_stop(sink)

    def start(name: str, command: list[str], env: dict[str, str], sink: Any) -> Any:
        if processes:
            raise failure
        process = run_parity.spawn([sys.executable, "-c", "import time; time.sleep(60)"], {})
        processes.append(process)
        return run_parity.Target(name, ("127.0.0.1", 1), sink=sink, process=process)

    monkeypatch.setattr(smtp, "start", sink_start)
    monkeypatch.setattr(smtp, "stop", sink_stop)
    monkeypatch.setattr(run_parity, "ScriptedSmtp", lambda _: smtp)
    monkeypatch.setattr(run_parity, "start", start)
    args = argparse.Namespace(python=[], binary="unused", verbose=False, filter=None)
    try:
        with pytest.raises(type(failure)) as caught:
            run_parity.run_local(
                args, [corpus.Case("test", corpus.Request(), 200)], run_parity.Report()
            )
        assert caught.value is failure
        assert processes[0].poll() is not None
        assert stopped == list(reversed(sinks))
        assert all(run_parity._port_free(sink.port) for sink in sinks)
    finally:
        for process in processes:
            run_parity.stop(process)
            assert process.stdout is not None
            process.stdout.close()


@pytest.mark.parametrize("failure", [RuntimeError("probe failed"), KeyboardInterrupt()])
def test_startup_cases_unwind_probe_failure(
    monkeypatch: pytest.MonkeyPatch, smtp: ScriptedSmtp, failure: BaseException
) -> None:
    import argparse

    target = run_parity.Target("python", ("127.0.0.1", 1))
    process = run_parity.spawn([sys.executable, "-c", "import time; time.sleep(60)"], {})
    target.process = process
    stopped: list[Any] = []
    original_stop = smtp.stop

    def stop(sink: Any) -> None:
        stopped.append(sink)
        original_stop(sink)

    def probe(*args: Any) -> None:
        raise failure

    monkeypatch.setattr(run_parity, "start", lambda *args: target)
    monkeypatch.setattr(run_parity, "exchange", probe)
    monkeypatch.setattr(smtp, "stop", stop)
    monkeypatch.setattr(corpus, "STARTUP_CASES", corpus.STARTUP_CASES[:1])
    args = argparse.Namespace(python=[], binary="unused", verbose=False, filter=None)
    try:
        with pytest.raises(type(failure)) as caught:
            run_parity.run_startup_cases(args, {}, run_parity.Report(), smtp)
        assert caught.value is failure
        assert process.poll() is not None
        assert len(stopped) == 1
    finally:
        run_parity.stop(process)
        assert process.stdout is not None
        process.stdout.close()


@pytest.mark.parametrize("mode", ["local", "targets"])
def test_empty_selection_fails_before_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    def unexpected(*args: Any) -> None:
        pytest.fail("empty selection reached target startup")

    monkeypatch.setattr(run_parity, "run_local", unexpected)
    monkeypatch.setattr(run_parity, "run_targets", unexpected)
    argv = ["--filter", "no-such-parity-case"]
    if mode == "targets":
        argv += ["--targets", "http://127.0.0.1:1,http://127.0.0.1:2", "--sinks", "a,b"]
    with pytest.raises(SystemExit, match="no runnable request cases"):
        run_parity.main(argv)
    assert run_parity.main([*argv, "--write-secrets", str(tmp_path / "secrets.yml")]) == 0


def test_all_skipped_targets_fail_before_capture_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = corpus.Case("unsupported", corpus.Request(), 200, profile="strict")
    monkeypatch.setattr(corpus, "request_cases", lambda: [case])
    with pytest.raises(SystemExit, match="no runnable request cases"):
        run_parity.main(
            ["--targets", "http://127.0.0.1:1,http://127.0.0.1:2", "--sinks", "missing,missing"]
        )


def test_target_subset_counts_exercised_cases(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    selected = [
        corpus.Case("health", corpus.Request(method="GET", path="/health"), 200),
        corpus.Case("unsupported", corpus.Request(), 200, profile="strict"),
    ]
    calls: list[str] = []
    monkeypatch.setattr(corpus, "request_cases", lambda: selected)

    def run_case(target: run_parity.Target, case: corpus.Case, n: int) -> run_parity.Outcome:
        calls.append(target.name)
        return run_parity.Outcome(_response(200, '{"status":"ok"}'), [], None)

    monkeypatch.setattr(run_parity, "run_case", run_case)
    report = tmp_path / "report.json"
    assert (
        run_parity.main(
            [
                "--targets",
                "http://127.0.0.1:1,http://127.0.0.1:2",
                "--sinks",
                f"{tmp_path},{tmp_path}",
                "--report",
                str(report),
            ]
        )
        == 0
    )
    receipt = json.loads(report.read_text())
    assert receipt["request_cases"] == 1
    assert receipt["selected_request_cases"] == 2
    assert receipt["skipped"] == 1
    assert [c["name"] for c in receipt["cases"]] == ["health"]
    assert calls == ["python", "rust"]


def _record_one_case(args: Any, cases: list[corpus.Case], report: run_parity.Report) -> None:
    report.observe(cases[0], _outcome(), _outcome())
    report.record(cases[0].name, [], None, False)


@pytest.mark.parametrize(
    "fault", ["short-write", "write", "interrupt", "flush", "fsync", "replace"]
)
def test_report_publication_failure_preserves_previous_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], fault: str
) -> None:
    import io
    import os

    report = tmp_path / "report.json"
    previous = '{"previous":"complete"}\n'
    report.write_text(previous)
    monkeypatch.setattr(run_parity, "run_local", _record_one_case)
    original_open = io.open

    class FaultyFile:
        def __init__(self, stream: Any) -> None:
            self.stream = stream

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *args: Any) -> Any:
            return self.stream.__exit__(*args)

        def __getattr__(self, name: str) -> Any:
            return getattr(self.stream, name)

        def write(self, data: str) -> int:
            if fault in ("short-write", "write", "interrupt"):
                written: int = self.stream.write(data[: len(data) // 2])
                if fault == "interrupt":
                    raise KeyboardInterrupt
                if fault == "write":
                    raise OSError("injected write failure")
                return written
            result: int = self.stream.write(data)
            return result

        def flush(self) -> None:
            if fault == "flush":
                raise OSError("injected flush failure")
            self.stream.flush()

    def open_file(*args: Any, **kwargs: Any) -> Any:
        return FaultyFile(original_open(*args, **kwargs))

    def fail(*args: Any, **kwargs: Any) -> None:
        raise OSError(f"injected {fault} failure")

    with monkeypatch.context() as patch:
        patch.setattr(io, "open", open_file)
        if fault in ("fsync", "replace"):
            patch.setattr(os, fault, fail)
        if fault == "interrupt":
            with pytest.raises(KeyboardInterrupt):
                run_parity.main(["--report", str(report)])
        else:
            assert run_parity.main(["--report", str(report)]) == 1
    assert report.read_text() == previous
    assert list(tmp_path.iterdir()) == [report]
    if fault != "interrupt":
        assert "report publication failed" in capsys.readouterr().err


@pytest.mark.parametrize("failed", [False, True])
def test_complete_report_is_published_after_sync(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failed: bool
) -> None:
    import os

    report = tmp_path / "report.json"
    report.write_text('{"previous":true}\n')
    events: list[str] = []
    original_fsync, original_replace = os.fsync, os.replace

    def record(args: Any, cases: list[corpus.Case], receipt: run_parity.Report) -> None:
        _record_one_case(args, cases, receipt)
        if failed:
            receipt.record("synthetic failure", ["mismatch"], None, False)

    def fsync(fd: int) -> None:
        events.append("sync")
        original_fsync(fd)

    def replace(source: Any, destination: Any) -> None:
        assert Path(source).parent == report.parent
        assert json.loads(Path(source).read_text())["failed"] == int(failed)
        assert json.loads(report.read_text()) == {"previous": True}
        events.append("replace")
        original_replace(source, destination)

    monkeypatch.setattr(run_parity, "run_local", record)
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    assert run_parity.main(["--report", str(report)]) == int(failed)
    assert events == ["sync", "replace"]
    assert json.loads(report.read_text())["failed"] == int(failed)
    assert list(tmp_path.iterdir()) == [report]


@pytest.mark.parametrize("existing_mode", [None, 0o644, 0o640])
def test_published_report_keeps_previous_or_umask_mode(
    tmp_path: Path, existing_mode: int | None
) -> None:
    import os
    import stat

    report = tmp_path / "report.json"
    if existing_mode is not None:
        report.write_text('{"previous":true}\n')
        report.chmod(existing_mode)
    previous_umask = os.umask(0o022)
    try:
        run_parity.publish_report(report, {"failed": 0})
    finally:
        os.umask(previous_umask)
    expected = 0o644 if existing_mode is None else existing_mode
    assert stat.S_IMODE(report.stat().st_mode) == expected
    assert json.loads(report.read_text()) == {"failed": 0}
    assert list(tmp_path.iterdir()) == [report]
