"""Differential parity harness: Python and Rust relay as real processes
(rust/PLAN.md 7.4).

Starts the Python relay (``python -m mailgun_relay``, real uvicorn) and the
Rust release binary on loopback ports with identical environment and secrets
(the production policy shapes with fake tokens, ``cases.POLICIES``), each
with its own fake SMTP server (``smtp_fake.py``: STARTTLS with a throwaway
CA, AUTH, scripted replies). Every case of ``cases.py`` is sent
byte-identically to both, and the outcomes are compared as the parity
contract says (``handoff/parity-contract.md``, PLAN.md 2):

- status; the contract headers ``www-authenticate``, ``allow``,
  ``location`` and the JSON content type; the JSON keys, the ``Queued``
  message and the texts PLAN.md 2.2 keeps verbatim;
- whether an SMTP session happened, TLS, login, ``MAIL FROM``, every
  ``RCPT TO`` with its reply and the recipients the message was sent for;
- the message as a receiver's parser reads it (``semantic.py``): decoded
  headers, no Bcc, the MIME tree with decoded bodies and parts; the
  Message-Id equals the response ``id``, a Date is present; the Rust message
  is 7-bit, CRLF only, lines of at most 998 octets, with no parser defects
  beyond Python's own;
- the log minimum: one ``event=request`` record with the same
  ``token_label``, ``result``, ``status_code``, counts and refusals, and the
  ``event=startup`` record of both.

Cases can also pin the diagnostic ``error_class`` for both relays. Other
non-contract error texts, headers, MIME bytes and log fields are omitted.
Python's status must also match the case (the oracle). A case that differs
on purpose names its divergence (``divergence="D-n"``, PLAN.md section 3)
and the Rust status. A case whose status matches but whose JSON
message or record ``result`` differs on purpose names it as
``value_divergence`` with both expected values and is otherwise compared in
full; every other difference fails the run.

Usage (from the repository root, after ``cargo build --release``)::

    uv run python rust/parity/run_parity.py [--filter TEXT] [--report FILE]

Against two running instances (the shadow of PLAN.md 10.1), whose SMTP
goes to two capture sinks (``smtp_fake.py --record-dir``) and whose secrets
come from ``--write-secrets``::

    python3 rust/parity/run_parity.py --targets http://127.0.0.1:8087,http://127.0.0.1:8089 \\
        --sinks /var/lib/shadow/py,/var/lib/shadow/rs [--logs PY.log,RS.log]

That mode runs the cases of the default profile whose SMTP scenario is the
accepting default; the others need a scripted server and are skipped.
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, deque
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from email.errors import MessageError
from pathlib import Path
from typing import IO, Any
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cases as corpus
import semantic
from smtp_fake import ScriptedSmtp, Sink, make_certificates, server_contexts, session_from_json

REPO = Path(__file__).resolve().parents[2]
HOST_HEADER = "relay.parity.test"
MAX_RESPONSE_HEADER_BYTES = 64 * 1024
# Includes wire framing for chunked responses. Relay replies are small JSON.
MAX_RESPONSE_BODY_BYTES = 1024 * 1024
# Texts PLAN.md 2.2 keeps verbatim; other error texts are free.
KEPT_TEXTS = {
    "Unauthorized",
    "Payload Too Large",
    "Queued. Thank you.",
    "Upstream SMTP temporarily unavailable",
    "Upstream SMTP rejected the message",
    "Internal Server Error",
}
# Strings Anymail special-cases in a response (PLAN.md 2.2).
ANYMAIL_SPECIAL = ("Domain not found", "Mailgun Magnificent API")
# Startup fields both implementations log with the same value.
STARTUP_FIELDS = (
    "event",
    "public_host",
    "smtp_host",
    "smtp_starttls",
    "smtp_custom_ca",
    "smtp_max_concurrency",
    "fail_on_partial_refusal",
    "log_level",
    "token_labels",
    "max_body_bytes",
    "max_recipients",
)
RECORD_FIELDS = ("token_label", "result", "status_code", "recipient_count", "refused_count")


# ------------------------------------------------------------------ HTTP


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        if not self.headers.get("content-type", "").startswith("application/json"):
            return None
        try:
            return json.loads(self.body)
        except ValueError:
            return None


def _dechunk(body: bytes) -> bytes:
    out = bytearray()
    cursor = 0
    while True:
        line_end = body.find(b"\r\n", cursor)
        if line_end < 0:
            break
        extension = body.find(b";", cursor, line_end)
        size_field = body[cursor : extension if extension >= 0 else line_end]
        if not re.fullmatch(rb"[0-9a-fA-F]+", size_field):
            raise RuntimeError("invalid HTTP response chunk size")
        size = int(size_field, 16)
        start = line_end + 2
        if size == 0:
            if body.startswith(b"\r\n", start):
                trailer_end = start + 2
            else:
                separator = body.find(b"\r\n\r\n", start)
                trailer_end = separator + 4 if separator >= 0 else -1
            if trailer_end == len(body):
                return bytes(out)
            break
        end = start + size
        if end > len(body) or not body.startswith(b"\r\n", end):
            break
        out.extend(body[start:end])
        cursor = end + 2
    raise RuntimeError("incomplete or invalid HTTP response chunk framing")


def exchange(address: tuple[str, int], pieces: list[bytes], timeout: float = 60) -> Response:
    """Send and receive within one deadline, with bounded response storage."""
    deadline = time.monotonic() + timeout

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("HTTP exchange deadline exceeded")
        return left

    with socket.create_connection(address, timeout=remaining()) as sock:
        for i, piece in enumerate(pieces):
            if i:
                time.sleep(min(0.05, remaining()))
            sock.settimeout(remaining())
            try:
                sock.sendall(piece)
            except (BrokenPipeError, ConnectionResetError):
                break  # the server answered early (413) and closed
        data = bytearray()
        head_start = 0
        search_from = 0
        body_start = None
        status = 0
        reset = False
        while True:
            sock.settimeout(remaining())
            try:
                chunk = sock.recv(65536)
            except TimeoutError as exc:
                raise TimeoutError("HTTP exchange deadline exceeded") from exc
            except ConnectionResetError:
                reset = True
                break
            if not chunk:
                break
            data.extend(chunk)
            while body_start is None:
                header_end = data.find(b"\r\n\r\n", search_from)
                if (header_end if header_end >= 0 else len(data)) > MAX_RESPONSE_HEADER_BYTES:
                    raise RuntimeError("HTTP response header limit exceeded")
                if header_end < 0:
                    search_from = max(head_start, len(data) - 3)
                    break
                status_line = data[head_start:header_end].split(b"\r\n", 1)[0]
                fields = status_line.split()
                if (
                    len(fields) < 2
                    or not fields[0].startswith(b"HTTP/")
                    or not re.fullmatch(rb"[1-5][0-9]{2}", fields[1])
                ):
                    raise RuntimeError("invalid HTTP response status line")
                status = int(fields[1])
                if status >= 200:
                    body_start = header_end + 4
                elif status == 101:
                    raise RuntimeError("unexpected HTTP protocol upgrade")
                else:
                    head_start = search_from = header_end + 4
            if body_start is not None and len(data) - body_start > MAX_RESPONSE_BODY_BYTES:
                raise RuntimeError("HTTP response body limit exceeded")

    if body_start is None:
        raise RuntimeError("incomplete HTTP response headers")
    lines = data[head_start : body_start - 4].decode("latin-1").split("\r\n")
    headers: dict[str, str] = {}
    lengths: list[str] = []
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if not separator or not name.strip():
            raise RuntimeError("invalid HTTP response header")
        name, value = name.strip().lower(), value.strip()
        headers.setdefault(name, value)
        if name == "content-length":
            lengths.extend(item.strip() for item in value.split(","))

    body = bytes(data[body_start:])
    if status in (204, 304) or (pieces and pieces[0].startswith(b"HEAD ")):
        if body:
            raise RuntimeError("unexpected HTTP response body")
    elif headers.get("transfer-encoding", "").split(",")[-1].strip().lower() == "chunked":
        body = _dechunk(body)
    elif lengths and "transfer-encoding" not in headers:
        if any(
            not re.fullmatch(r"[0-9]+", length) or (length.lstrip("0") or "0") != str(len(body))
            for length in lengths
        ):
            raise RuntimeError("invalid or incomplete HTTP response Content-Length framing")
    elif reset:
        raise RuntimeError("HTTP response reset before a clean EOF")
    return Response(status, headers, body)


def request_pieces(request: corpus.Request) -> list[bytes]:
    lines = [f"{request.method} {request.path} HTTP/1.1".encode(), f"Host: {HOST_HEADER}".encode()]
    for name, value in request.headers:
        lines.append(name.encode() + b": " + (value.encode() if isinstance(value, str) else value))
    lines.append(b"Connection: close")
    body = request.body
    if request.chunks is not None:
        lines.append(b"Transfer-Encoding: chunked")
        body = b"".join(b"%x\r\n%s\r\n" % (len(c), c) for c in request.chunks if c) + b"0\r\n\r\n"
    elif request.length == "auto":
        lines.append(f"Content-Length: {len(body)}".encode())
    elif request.length is not None:
        lines.append(b"Content-Length: " + request.length.encode())
    head = b"\r\n".join(lines) + b"\r\n\r\n"
    if request.split is None:
        return [head + body]
    # The split offset counts in the body as sent (chunk framing included).
    return [head + body[: request.split], body[request.split :]]


def marker_request(n: int) -> bytes:
    """A request whose record ends a case: 401, path domain ``marker-n.parity``."""
    return (
        f"POST /v3/{marker_domain(n)}/messages HTTP/1.1\r\nHost: {HOST_HEADER}\r\n"
        "Connection: close\r\nContent-Length: 0\r\n\r\n"
    ).encode()


def marker_domain(n: int) -> str:
    return f"marker-{n}.parity"


# ------------------------------------------------------------------ logs


class LogTail:
    """JSON records from a process's stdout or a growing log file."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.lines: deque[str] = deque(maxlen=3)
        self.cond = threading.Condition()

    def recent_lines(self) -> list[str]:
        with self.cond:
            return list(self.lines)

    def feed(self, line: str) -> None:
        with self.cond:
            self.lines.append(line)
            try:
                record = json.loads(line)
            except ValueError:
                record = None
            if isinstance(record, dict):
                self.records.append(record)
            self.cond.notify_all()

    def follow_pipe(self, stream: Any) -> None:
        def pump() -> None:
            for raw in stream:
                self.feed(raw.decode("utf-8", "replace").rstrip("\n"))

        threading.Thread(target=pump, daemon=True).start()

    @contextmanager
    def follow_file(self, path: Path) -> Iterator[None]:
        stopped = threading.Event()
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)

            def pump() -> None:
                buffer = b""
                while not stopped.is_set():
                    chunk = stream.readline()
                    if not chunk:
                        stopped.wait(0.05)
                        continue
                    buffer += chunk
                    if buffer.endswith(b"\n"):
                        self.feed(buffer.decode("utf-8", "replace").rstrip("\n"))
                        buffer = b""

            worker = threading.Thread(target=pump, daemon=True)
            worker.start()
            try:
                yield
            finally:
                stopped.set()
                worker.join()

    def wait(self, predicate: Any, timeout: float) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        with self.cond:
            while True:
                for record in self.records:
                    if predicate(record):
                        return record
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self.cond.wait(remaining)

    def until_marker(self, n: int, timeout: float = 10) -> list[dict[str, Any]] | None:
        """The records since the last marker, up to marker ``n``."""
        domain = marker_domain(n)
        with self.cond:
            found = self.wait(lambda r: r.get("path_domain") == domain, timeout)
            if found is None:
                return None
            index = self.records.index(found)
            records = self.records[:index]
            del self.records[: index + 1]
            return records


# ------------------------------------------------------------------ targets


class CaptureTimeoutError(TimeoutError):
    """The external sink still owns a capture from the current case."""


@dataclass
class Target:
    """One implementation under test: its HTTP address, its SMTP sink and
    its log."""

    name: str
    address: tuple[str, int]
    sink: Sink | None = None
    sink_dir: Path | None = None
    log: LogTail | None = None
    process: subprocess.Popen[bytes] | None = None
    seen_sessions: set[str] = field(default_factory=set)
    # Incomplete attempts a restarted sink retained from earlier runs: only
    # markers that appear during this run can be captures in progress.
    stale_active: set[str] = field(default_factory=set)
    startup_settle: float = 5.0

    def __post_init__(self) -> None:
        if self.sink_dir is None:
            return
        # Let a capture really in progress at startup finish first; markers that
        # outlive this settle period are retained attempts from earlier runs.
        deadline = time.monotonic() + self.startup_settle
        while any(self.sink_dir.glob("*.active")) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.stale_active = {p.name for p in self.sink_dir.glob("*.active")}
        self.seen_sessions.update(p.name for p in self.sink_dir.glob("*.json"))

    def in_flight(self) -> bool:
        assert self.sink_dir is not None
        return any(p.name not in self.stale_active for p in self.sink_dir.glob("*.active"))

    def sessions(self) -> list[dict[str, Any]]:
        if self.sink is not None:
            self.sink.settle()
            return self.sink.take()
        if self.sink_dir is None:
            return []
        deadline = time.monotonic() + 5
        while self.in_flight():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CaptureTimeoutError(
                    f"{self.name}: SMTP captures did not settle within 5 seconds"
                )
            time.sleep(min(0.02, remaining))
        found = []
        for path in sorted(self.sink_dir.glob("*.json")):
            if path.name not in self.seen_sessions:
                self.seen_sessions.add(path.name)
                found.append(session_from_json(json.loads(path.read_text(encoding="utf-8"))))
        return found


@dataclass
class Outcome:
    response: Response
    sessions: list[dict[str, Any]]
    records: list[dict[str, Any]] | None


def run_case(target: Target, case: corpus.Case, n: int) -> Outcome:
    if target.sink is not None:
        target.sink.configure(case.smtp, case.cert)
    response = exchange(target.address, request_pieces(case.request))
    sessions = target.sessions()
    records = None
    if target.log is not None:
        exchange(target.address, [marker_request(n)])
        records = target.log.until_marker(n)
        if records is None:
            raise RuntimeError(f"{target.name}: no record for marker {n}")
    return Outcome(response, sessions, records)


# ------------------------------------------------------------------ compare


def _status_ok(status: int, expected: int | frozenset[int]) -> bool:
    return status in expected if isinstance(expected, frozenset) else status == expected


def _compare_http(
    py: Response, rs: Response, rust_values: dict[str, tuple[str, str]] | None = None
) -> list[str]:
    diffs = []
    rust_values = rust_values or {}
    if py.status != rs.status:
        return [f"status: python {py.status}, rust {rs.status}"]
    for name in ("www-authenticate", "allow", "location"):
        if py.headers.get(name) != rs.headers.get(name):
            diffs.append(f"header {name}: {py.headers.get(name)!r} vs {rs.headers.get(name)!r}")
    py_json, rs_json = py.json(), rs.json()
    if (py_json is None) != (rs_json is None) or type(py_json) is not type(rs_json):
        diffs.append(f"JSON body: python {py.body[:80]!r}, rust {rs.body[:80]!r}")
        return diffs
    if not isinstance(py_json, dict):
        if py_json != rs_json:
            diffs.append(f"JSON body: {py_json!r} vs {rs_json!r}")
    elif isinstance(rs_json, dict):
        if sorted(py_json) != sorted(rs_json):
            diffs.append(f"JSON keys: {sorted(py_json)} vs {sorted(rs_json)}")
        for key in ("message", "detail", "status"):
            text = py_json.get(key)
            if key in rust_values:
                # A decided value difference: both sides must show it.
                if (text, rs_json.get(key)) != rust_values[key]:
                    diffs.append(
                        f"JSON {key}: {text!r} vs {rs_json.get(key)!r}, expected"
                        f" {rust_values[key][0]!r} vs {rust_values[key][1]!r}"
                    )
                continue
            kept = text in KEPT_TEXTS or str(text).startswith("token not allowed for ")
            # 404/405 details and /health's status are kept as they are.
            if key != "message" or kept:
                if text != rs_json.get(key):
                    diffs.append(f"JSON {key}: {text!r} vs {rs_json.get(key)!r}")
        if "id" in py_json and not all(isinstance(j.get("id"), str) for j in (py_json, rs_json)):
            diffs.append("id is not a string")
    for special in ANYMAIL_SPECIAL:
        if special.encode() in rs.body:
            diffs.append(f"rust body contains {special!r}")
    return diffs


def _message_problems(name: str, raw: bytes, response: Response) -> list[str]:
    message = semantic.parse(raw)
    problems = []
    # Python folds the Message-ID with the production PUBLIC_HOST; the parser
    # of Python 3.12.3 (the shadow host's python3) keeps the folding space.
    if response.status == 200 and str(message["Message-ID"]).strip() != response.json()["id"]:
        problems.append(f"{name}: Message-Id {message['Message-ID']} is not the response id")
    if message["Date"] is None:
        problems.append(f"{name}: no Date")
    if message["Bcc"] is not None:
        problems.append(f"{name}: Bcc header")
    return problems


def _uncaptured(py: Outcome, rs: Outcome) -> list[str]:
    """A queued message must have reached the sink (no silent gaps)."""
    diffs = []
    for name, outcome in (("python", py), ("rust", rs)):
        body = outcome.response.json()
        queued = outcome.response.status == 200 and isinstance(body, dict) and "id" in body
        if queued and sum(s["message"] is not None for s in outcome.sessions) != 1:
            diffs.append(f"{name}: queued, but {len(outcome.sessions)} SMTP sessions captured")
    return diffs


def _compare_smtp(py: Outcome, rs: Outcome) -> list[str]:
    if len(py.sessions) != len(rs.sessions):
        return [f"SMTP sessions: python {len(py.sessions)}, rust {len(rs.sessions)}"]
    diffs = []
    for p, r in zip(py.sessions, rs.sessions, strict=True):
        for key in ("tls", "mail_from", "rcpt", "data_for"):
            if p[key] != r[key]:
                diffs.append(f"SMTP {key}: {p[key]!r} vs {r[key]!r}")
        if (p["auth_user"] is None) != (r["auth_user"] is None):
            diffs.append(f"SMTP login: {p['auth_user']!r} vs {r['auth_user']!r}")
        if (p["message"] is None) != (r["message"] is None):
            diffs.append("SMTP message sent by one side only")
        elif p["message"] is not None:
            try:
                py_view = semantic.semantic_message(p["message"])
                rs_view = semantic.semantic_message(r["message"])
            except (LookupError, UnicodeError, MessageError) as exc:
                # Unknown codecs raise LookupError itself. Let indexing and
                # mapping errors in the harness surface normally.
                if isinstance(exc, (IndexError, KeyError)):
                    raise
                diffs.append(f"SMTP MIME comparison failed: {type(exc).__name__}")
                continue
            if py_view != rs_view:
                diffs.append(
                    "message differs:\n      python "
                    + json.dumps(py_view, ensure_ascii=False)
                    + "\n      rust   "
                    + json.dumps(rs_view, ensure_ascii=False)
                )
            diffs += _message_problems("python", p["message"], py.response)
            diffs += _message_problems("rust", r["message"], rs.response)
            diffs += [f"rust message: {p}" for p in semantic.conformance(r["message"])]
            extra = set(semantic.defects(semantic.parse(r["message"]))) - set(
                semantic.defects(semantic.parse(p["message"]))
            )
            if extra:
                diffs.append(f"rust message parser defects {sorted(extra)}")
    return diffs


def _by_event(records: list[dict[str, Any]], event: str) -> list[dict[str, Any]]:
    return [r for r in records if r.get("event") == event]


def _compare_records(
    py: Outcome,
    rs: Outcome,
    rust_values: dict[str, tuple[str, str]] | None = None,
    *,
    error_class: str | None = None,
) -> list[str]:
    if py.records is None or rs.records is None:
        return []
    diffs = []
    rust_values = rust_values or {}
    for event in ("request", "recipients_refused"):
        p, r = _by_event(py.records, event), _by_event(rs.records, event)
        if len(p) != len(r):
            diffs.append(f"{event} records: python {len(p)}, rust {len(r)}")
            continue
        for pr, rr in zip(p, r, strict=True):
            for key in (*RECORD_FIELDS, "refused"):
                if event == "request" and key in rust_values:
                    # A decided value difference: both sides must show it.
                    if (pr.get(key), rr.get(key)) != rust_values[key]:
                        diffs.append(
                            f"{event} record {key}: {pr.get(key)!r} vs {rr.get(key)!r},"
                            f" expected {rust_values[key][0]!r} vs {rust_values[key][1]!r}"
                        )
                    continue
                if pr.get(key) != rr.get(key):
                    diffs.append(f"{event} record {key}: {pr.get(key)!r} vs {rr.get(key)!r}")
            py_id, rs_id = pr.get("message_id"), rr.get("message_id")
            if (py_id == "-") != (rs_id == "-"):
                diffs.append(f"{event} record message_id: {py_id!r} vs {rs_id!r}")
    for name, outcome in (("python", py), ("rust", rs)):
        assert outcome.records is not None
        requests = _by_event(outcome.records, "request")
        if error_class is not None:
            actual = [record.get("error_class") for record in requests]
            if actual != [error_class]:
                diffs.append(f"{name}: request error_class {actual!r}, expected {[error_class]!r}")
        if requests and requests[0].get("status_code") != outcome.response.status:
            diffs.append(f"{name}: record status_code {requests[0].get('status_code')}")
        body = outcome.response.json()
        if requests and outcome.response.status == 200 and isinstance(body, dict):
            if requests[0].get("message_id") != body.get("id"):
                diffs.append(f"{name}: record message_id is not the response id")
    return diffs


def compare(case: corpus.Case, py: Outcome, rs: Outcome) -> tuple[list[str], str | None]:
    """The unexplained differences of a case and the divergence it shows."""
    diffs = _uncaptured(py, rs)
    if not _status_ok(py.response.status, case.status):
        diffs.append(f"python status {py.response.status}, the case expects {case.status}")
    if case.divergence is not None:
        # Only the decided Rust status is pinned; a divergence that no longer
        # shows (Python fixed, Rust changed) is stale and fails too.
        if rs.response.status != case.rust_status:
            diffs.append(
                f"rust status {rs.response.status}, {case.divergence} expects {case.rust_status}"
            )
        # A divergence that depends on how Python reads the body (D-20) may
        # not show in every run; the others must.
        if isinstance(case.status, int) and rs.response.status == py.response.status:
            diffs.append(f"{case.divergence} no longer shows")
        # A refusal sends nothing (fail closed).
        if rs.response.status < 500 and any(x["message"] is not None for x in rs.sessions):
            diffs.append(f"rust sent a message although it answered {rs.response.status}")
        if rs.records is not None:
            requests = _by_event(rs.records, "request")
            if requests and requests[0].get("status_code") != rs.response.status:
                diffs.append(f"rust record status_code {requests[0].get('status_code')}")
        return diffs, case.divergence
    diffs += _compare_http(py.response, rs.response, case.rust_values)
    diffs += _compare_smtp(py, rs)
    diffs += _compare_records(py, rs, case.rust_values, error_class=case.error_class)
    return diffs, case.value_divergence


# ------------------------------------------------------------------ processes


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def base_env(secrets: Path, ca_file: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "MAILGUN_RELAY_SECRETS_PATH": str(secrets),
        "MAILGUN_RELAY_BIND_HOST": "127.0.0.1",
        "MAILGUN_RELAY_PUBLIC_HOST": "mailgun.parity.test",
        "MAILGUN_RELAY_SMTP_HOST": "localhost",
        "MAILGUN_RELAY_SMTP_STARTTLS": "true",
        "MAILGUN_RELAY_SMTP_TIMEOUT_S": "3",
        "MAILGUN_RELAY_SMTP_CA_FILE": str(ca_file),
        "MAILGUN_RELAY_ENVELOPE_SENDER": "mailgun-relay@xn--wersdrfer-47a.de",
        "MAILGUN_RELAY_LOG_LEVEL": "INFO",
    }


def spawn(command: list[str], env: dict[str, str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 - the commands of this harness
        command,
        env=env,
        cwd=REPO,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class StartError(RuntimeError):
    def __init__(self, name: str, code: int | None, lines: list[str]) -> None:
        super().__init__(f"{name} did not start (exit {code}): {lines[-3:]}")
        self.code = code


def _port_free(port: int) -> bool:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def _watch_uvicorn_bind(stream: IO[bytes], bind: str) -> threading.Event:
    ready = threading.Event()
    message = f"Uvicorn running on http://{bind} (Press CTRL+C to quit)".encode()

    def pump() -> None:
        # Drain stderr without retaining unstructured errors or tracebacks.
        with stream:
            for line in stream:
                if line.startswith(b"INFO:") and line[5:].strip() == message:
                    ready.set()

    threading.Thread(target=pump, daemon=True).start()
    return ready


def start(name: str, command: list[str], env: dict[str, str], sink: Sink) -> Target:
    """Start one implementation on a free port and wait until it serves.
    Another process can take the port before the bind; then another port
    is tried."""
    for _ in range(5):
        port = free_port()
        process = spawn(command, {**env, "MAILGUN_RELAY_BIND_PORT": str(port)})
        with ExitStack() as owner:
            owner.callback(stop, process)
            log = LogTail()
            assert process.stdout is not None and process.stderr is not None
            log.follow_pipe(process.stdout)
            bind = f"127.0.0.1:{port}"
            address = ("127.0.0.1", port)
            uvicorn_ready = _watch_uvicorn_bind(process.stderr, bind)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and process.poll() is None:
                # Uvicorn's app factory logs startup before the socket is bound.
                # Rust emits its structured startup record after acquiring listeners.
                if name == "python":
                    ready = uvicorn_ready.is_set()
                else:
                    ready = (
                        log.wait(
                            lambda r, bind=bind: (
                                r.get("event") == "startup"
                                and r.get("impl") == "rust"
                                and r.get("bind") == bind
                            ),
                            0,
                        )
                        is not None
                    )
                remaining = deadline - time.monotonic()
                if ready and remaining > 0:
                    try:
                        socket.create_connection(address, timeout=min(1, remaining)).close()
                    except OSError:
                        pass
                    else:
                        if process.poll() is not None:
                            break
                        target = Target(name, address, sink=sink, log=log, process=process)
                        owner.pop_all()
                        return target
                time.sleep(0.05)
        code = process.returncode
        if _port_free(port):
            raise StartError(name, code, log.recent_lines())
    raise StartError(name, None, log.recent_lines())


def stop(process: subprocess.Popen[bytes]) -> int:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    return process.returncode


def startup_diffs(py: Target, rs: Target) -> list[str]:
    assert py.log is not None and rs.log is not None
    p = py.log.wait(lambda r: r.get("event") == "startup", 10)
    r = rs.log.wait(lambda r: r.get("event") == "startup", 10)
    if p is None or r is None:
        return [f"startup record: python {p is not None}, rust {r is not None}"]
    diffs = [
        f"startup {key}: {p.get(key)!r} vs {r.get(key)!r}"
        for key in STARTUP_FIELDS
        if p.get(key) != r.get(key)
    ]
    missing = set(p) - set(r)
    if missing:
        diffs.append(f"startup fields missing in rust: {sorted(missing)}")
    if r.get("impl") != "rust":
        diffs.append("rust startup record without impl=rust")
    return diffs


def write_secrets(path: Path) -> None:
    path.write_text(corpus.secrets_yaml(), encoding="utf-8")
    path.chmod(0o640)


# ------------------------------------------------------------------ runs


@dataclass
class Report:
    passed: int = 0
    failures: list[tuple[str, list[str]]] = field(default_factory=list)
    divergences: Counter[str] = field(default_factory=Counter)
    skipped: list[str] = field(default_factory=list)
    started: float = field(default_factory=time.monotonic)
    # Per request case: the statuses and what was compared.
    cases: list[dict[str, Any]] = field(default_factory=list)

    def record(
        self, name: str, diffs: list[str], divergence: str | None, verbose: bool, note: str = ""
    ) -> None:
        if diffs:
            self.failures.append((name, diffs))
            print(f"FAIL {name} {note}")
            for diff in diffs:
                print(f"    {diff}")
            return
        self.passed += 1
        if divergence is not None:
            self.divergences[divergence] += 1
        if verbose:
            print(f"ok   {name} {note}" + (f" ({divergence})" if divergence else ""))

    def observe(self, case: corpus.Case, py: Outcome, rs: Outcome) -> str:
        entry = {
            "name": case.name,
            "python": py.response.status,
            "rust": rs.response.status,
            "divergence": case.divergence,
            "smtp_sessions": len(py.sessions),
            "messages": sum(s["message"] is not None for s in py.sessions),
            "request_records": None
            if py.records is None
            else len(_by_event(py.records, "request")),
        }
        self.cases.append(entry)
        return f"[{entry['python']}/{entry['rust']}]"

    def totals(self) -> dict[str, Any]:
        compared = [c for c in self.cases if c["divergence"] is None]
        return {
            "statuses": dict(sorted(Counter(str(c["python"]) for c in self.cases).items())),
            "smtp_sessions_compared": sum(c["smtp_sessions"] for c in compared),
            "messages_compared": sum(c["messages"] for c in compared),
            "request_records_compared": sum(c["request_records"] or 0 for c in compared),
        }


def run_cases(
    py: Target,
    rs: Target,
    cases: list[corpus.Case],
    report: Report,
    counter: list[int],
    verbose: bool,
) -> None:
    for index, case in enumerate(cases):
        counter[0] += 1
        n = counter[0]
        try:
            py_outcome = run_case(py, case, n)
            rs_outcome = run_case(rs, case, n)
        except CaptureTimeoutError as exc:
            report.record(case.name, [f"harness error: {exc}"], None, verbose)
            report.skipped.extend(c.name for c in cases[index + 1 :])
            break
        except (OSError, RuntimeError) as exc:
            report.record(case.name, [f"harness error: {exc}"], None, verbose)
            continue
        note = report.observe(case, py_outcome, rs_outcome)
        diffs, divergence = compare(case, py_outcome, rs_outcome)
        report.record(case.name, diffs, divergence, verbose, note)


def run_local(args: argparse.Namespace, cases: list[corpus.Case], report: Report) -> None:
    with tempfile.TemporaryDirectory(prefix="parity-") as tmp:
        directory = Path(tmp)
        certs = make_certificates(directory / "pki")
        secrets = directory / "secrets.yml"
        write_secrets(secrets)
        env = base_env(secrets, Path(f"{certs['ca']}.pem"))
        smtp = ScriptedSmtp(server_contexts(certs))
        counter = [0]
        try:
            for profile, overrides in corpus.PROFILES.items():
                selected = [c for c in cases if c.profile == profile]
                if not selected:
                    continue
                print(f"profile {profile}: {len(selected)} cases")
                codes: dict[str, int] = {}
                with ExitStack() as owners:
                    targets = []
                    for name, command in (("python", args.python), ("rust", [args.binary])):
                        sink = smtp.start()
                        owners.callback(smtp.stop, sink)
                        profile_env = {
                            **env,
                            **overrides,
                            "MAILGUN_RELAY_SMTP_PORT": str(sink.port),
                        }
                        target = start(name, command, profile_env, sink)
                        assert target.process is not None

                        def stop_target(
                            target: Target = target, codes: dict[str, int] = codes
                        ) -> None:
                            assert target.process is not None
                            codes[target.name] = stop(target.process)

                        owners.callback(stop_target)
                        targets.append(target)
                    py, rs = targets
                    diffs = startup_diffs(py, rs)
                    report.record(f"[{profile}] startup records", diffs, None, args.verbose)
                    run_cases(py, rs, selected, report, counter, args.verbose)
                # uvicorn re-raises SIGTERM after its graceful shutdown (a
                # clean stop for systemd); the Rust binary exits 0.
                bad = {
                    name: code
                    for name, code in codes.items()
                    if code not in ((0, -signal.SIGTERM) if name == "python" else (0,))
                }
                report.record(
                    f"[{profile}] SIGTERM exits 0",
                    [f"exit codes {bad}"] if bad else [],
                    None,
                    args.verbose,
                )
            run_startup_cases(args, env, report, smtp)
        finally:
            smtp.close()


def run_startup_cases(
    args: argparse.Namespace, env: dict[str, str], report: Report, smtp: ScriptedSmtp
) -> None:
    """Configurations: both start and serve, or both refuse to start (exit
    1, no bind); D-22 pins where Rust refuses what Python serves."""
    for case in corpus.STARTUP_CASES:
        if args.filter and args.filter not in case.name:
            continue
        with ExitStack() as owners:
            sink = smtp.start()
            owners.callback(smtp.stop, sink)
            outcomes = {}
            for name, command in (("python", args.python), ("rust", [args.binary])):
                case_env = {**env, "MAILGUN_RELAY_SMTP_PORT": str(sink.port), **case.env}
                if case.secrets_mode is not None:
                    path = Path(case_env["MAILGUN_RELAY_SECRETS_PATH"]).with_name(
                        f"mode-{name}.yml"
                    )
                    write_secrets(path)
                    path.chmod(case.secrets_mode)
                    case_env["MAILGUN_RELAY_SECRETS_PATH"] = str(path)
                try:
                    target = start(name, command, case_env, sink)
                except StartError as exc:
                    outcomes[name] = f"exits {exc.code}"
                    continue
                assert target.process is not None
                with ExitStack() as process_owner:
                    process_owner.callback(stop, target.process)
                    response = exchange(target.address, request_pieces(case.probe))
                    target.sessions()
                    outcomes[name] = f"serves {response.status}"
        expected_rust = case.rust or case.python
        diffs = []
        if outcomes["python"] != case.python:
            diffs.append(f"python {outcomes['python']}, the case expects {case.python}")
        if outcomes["rust"] != expected_rust:
            diffs.append(f"rust {outcomes['rust']}, expected {expected_rust}")
        report.record(f"[startup] {case.name}", diffs, case.divergence, args.verbose)


def run_targets(args: argparse.Namespace, cases: list[corpus.Case], report: Report) -> None:
    urls = args.targets.split(",")
    sinks = args.sinks.split(",")
    logs = args.logs.split(",") if args.logs else [None, None]
    if not len(urls) == len(sinks) == len(logs) == 2:
        raise SystemExit("--targets, --sinks and --logs take two values each (python,rust)")
    with ExitStack() as captures:
        targets = []
        for name, url, sink, log_path in zip(("python", "rust"), urls, sinks, logs, strict=True):
            if not Path(sink).is_dir() or (log_path is not None and not Path(log_path).is_file()):
                raise SystemExit(f"{name}: no capture directory {sink} or log file {log_path}")
            parts = urlsplit(url)
            assert parts.hostname is not None and parts.port is not None, url
            log = None
            if log_path is not None:
                log = LogTail()
                try:
                    captures.enter_context(log.follow_file(Path(log_path)))
                except OSError as exc:
                    raise SystemExit(
                        f"{name}: cannot initialize log capture {log_path}: {exc}"
                    ) from exc
            target = Target(name, (parts.hostname, parts.port), sink_dir=Path(sink), log=log)
            targets.append(target)
        # Distinct markers per run: the log files may hold earlier runs.
        counter = [int(time.time()) * 1000]
        run_cases(targets[0], targets[1], cases, report, counter, args.verbose)


class ReportDurabilityError(OSError):
    """The new receipt is visible, but its directory entry may not survive a crash."""


def publish_report(path: Path, detail: dict[str, Any]) -> None:
    """Sync the complete receipt before replacement, then sync its directory."""
    serialized = json.dumps(detail, indent=2, ensure_ascii=False) + "\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            if stream.write(serialized) != len(serialized):
                raise OSError("short parity report write")
            stream.flush()
            # mkstemp creates 0600; keep the previous receipt's mode, or the
            # umask-derived mode a plain write would have used.
            try:
                mode = stat.S_IMODE(path.stat().st_mode)
            except FileNotFoundError:
                umask = os.umask(0)
                os.umask(umask)
                mode = 0o666 & ~umask
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise ReportDurabilityError(f"could not sync {path.parent}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--binary", default=str(REPO / "rust/target/release/mailgun-relay"))
    parser.add_argument(
        "--python",
        nargs="+",
        default=[sys.executable, "-m", "mailgun_relay"],
        help="command of the Python relay",
    )
    parser.add_argument("--filter", help="only cases whose name contains this text")
    parser.add_argument("--report", type=Path, help="write a JSON report here")
    parser.add_argument("--targets", help="PY_URL,RS_URL of running instances")
    parser.add_argument("--sinks", help="PY_DIR,RS_DIR: record dirs of their SMTP sinks")
    parser.add_argument("--logs", help="PY_LOG,RS_LOG: files their JSON records go to")
    parser.add_argument("--write-secrets", type=Path, help="write the test secrets file and exit")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.write_secrets is not None:
        write_secrets(args.write_secrets)
        print(f"wrote {args.write_secrets} ({len(corpus.POLICIES)} policies, mode 0640)")
        return 0
    cases = corpus.request_cases()
    names = Counter(c.name for c in cases)
    duplicates = [name for name, count in names.items() if count > 1]
    if duplicates:
        raise SystemExit(f"duplicate case names: {duplicates}")
    if args.filter:
        cases = [c for c in cases if args.filter in c.name]
    report = Report()
    selected_count = len(cases)
    if args.targets:
        runnable = []
        for case in cases:
            if case.profile != "default" or case.smtp or case.cert != "good":
                report.skipped.append(case.name)
            else:
                runnable.append(case)
        cases = runnable
    if not cases:
        raise SystemExit("no runnable request cases selected; check --filter and --targets support")
    if args.targets:
        if not args.sinks:
            raise SystemExit("--targets needs --sinks")
        run_targets(args, cases, report)
    else:
        run_local(args, cases, report)

    elapsed = time.monotonic() - report.started
    summary = {
        "selected_request_cases": selected_count,
        "request_cases": selected_count - len(report.skipped),
        "passed_checks": report.passed,
        "failed": len(report.failures),
        "skipped": len(report.skipped),
        "divergences": dict(sorted(report.divergences.items())),
        **report.totals(),
        "seconds": round(elapsed, 1),
    }
    print(json.dumps(summary))
    if args.report is not None:
        detail = {
            **summary,
            "failures": report.failures,
            "skipped_cases": report.skipped,
            "cases": report.cases,
        }
        try:
            publish_report(args.report, detail)
        except ReportDurabilityError as exc:
            print(f"report published with durability uncertain: {exc}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"report publication failed: {exc}", file=sys.stderr)
            return 1
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main())
