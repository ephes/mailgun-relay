"""A scripted fake SMTP server and capture sink (rust/PLAN.md 7.4, 10.1).

Standard library only, so it runs from the repository (``uv run``) and with a
host's bare ``python3``. It is the server of the S1b spike
(``scripted_smtp.py``), also used by ``rust/fixtures/generate.py`` for
``smtp_outcomes.json``, and speaks the scenario format of that fixture and of
the Rust fake (``rust/tests/support/fake_smtp.rs``): a reply code per phase
(``banner``, ``ehlo``, ``ehlo_tls``, ``starttls``, ``auth``, ``mail``,
``data``, ``data_end``, ``quit``; ``auth_plain``/``auth_login`` for one
mechanism), a code per recipient local part (``rcpt``), the offered
extensions (``offer_starttls``, ``auth_offer``) and faults per phase
(``garbage``: a reply without a code, ``close``: the server closes,
``hang``: no reply). STARTTLS uses certificates from a throwaway ``openssl``
CA with key identifiers (Python's ``VERIFY_X509_STRICT`` needs them).

Every session is recorded: TLS, the AUTH user, ``MAIL FROM``, each ``RCPT``
with its reply code, the recipients the message was sent for and the
un-stuffed message bytes. With a record directory a finished session is
also written there as ``<n>.json`` (the message base64-encoded) and dropped
from memory; a session still open has a ``<n>.active`` file. A restarted
sink numbers on and never replaces a capture.

As a standalone capture sink (shadow runs, PLAN.md 10.1)::

    python3 rust/parity/smtp_fake.py --listen 127.0.0.1:2526 \\
        --certs /var/lib/mailgun-relay-shadow/pki --record-dir /var/lib/.../py

accepts every message (STARTTLS and AUTH required as in production) and only
records it; ``--certs`` is created on first use, the relay gets its
``ca.pem`` as ``SMTP_CA_FILE``.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import fcntl
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

SMTP_DEFAULTS: dict[str, Any] = {
    "banner": 220,
    "ehlo": 250,
    "ehlo_tls": 250,
    "offer_starttls": True,
    "starttls": 220,
    "auth_offer": "PLAIN LOGIN",
    "auth": 235,
    "mail": 250,
    "rcpt": {},
    "data": 354,
    "data_end": 250,
    "quit": 221,
    "fault": {},
}

MAX_SESSION_BYTES = 64 << 20
MAX_COMMANDS = 4096
MAX_SESSIONS = 16
MAX_RETAINED_SESSIONS = 256


class SessionLimitError(Exception):
    """The synthetic peer's per-session retention budget was exhausted."""


CERT_NAMES = ("good", "wrongname", "selfsigned")


PKI_REUSE_SECONDS = 3600


def certificate_paths(directory: Path) -> dict[str, str]:
    return {name: str(directory / name) for name in (*CERT_NAMES, "ca")}


def usable_certificates(directory: Path) -> bool:
    """Admit the whole fixture generation, including keys, chain and validity."""
    try:
        for name in (*CERT_NAMES, "ca"):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(directory / f"{name}.pem", directory / f"{name}.key")
            result = subprocess.run(  # noqa: S603 - fixed local OpenSSL fixture operations
                [  # noqa: S607 - fixed executable from the fixture toolchain
                    "openssl",
                    "x509",
                    "-checkend",
                    str(PKI_REUSE_SECONDS),
                    "-noout",
                    "-in",
                    f"{name}.pem",
                ],
                cwd=directory,
                check=False,
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                return False
        for name, hostname, authority in (
            ("good", "localhost", "ca"),
            ("wrongname", "other.test", "ca"),
            ("selfsigned", "localhost", "selfsigned"),
        ):
            result = subprocess.run(  # noqa: S603 - fixed local OpenSSL fixture operations
                [  # noqa: S607 - fixed executable from the fixture toolchain
                    "openssl",
                    "verify",
                    "-CAfile",
                    f"{authority}.pem",
                    "-purpose",
                    "sslserver",
                    "-verify_hostname",
                    hostname,
                    f"{name}.pem",
                ],
                cwd=directory,
                check=False,
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                return False
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return True


def make_certificates(directory: Path) -> dict[str, str]:
    """Reuse a complete fresh set or stage and publish a replacement generation."""
    directory.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(directory.parent, os.O_RDONLY)
    previous = directory.with_name(f".{directory.name}.previous")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        if not directory.exists() and previous.exists():
            os.replace(previous, directory)
        if usable_certificates(directory):
            return certificate_paths(directory)
        with tempfile.TemporaryDirectory(
            prefix=f".{directory.name}-pki-", dir=directory.parent
        ) as tmp:
            stage = Path(tmp)
            generate_certificates(stage)
            if not usable_certificates(stage):
                raise RuntimeError("generated fixture PKI is not usable")
            for path in stage.iterdir():
                with path.open("rb") as handle:
                    os.fsync(handle.fileno())
            sync_directory(stage)
            if previous.exists():
                shutil.rmtree(previous)
            had_previous = directory.exists()
            if had_previous:
                os.replace(directory, previous)
            try:
                os.replace(stage, directory)
                sync_directory(directory.parent)
            except BaseException:
                if had_previous:
                    if directory.exists():
                        shutil.rmtree(directory)
                    os.replace(previous, directory)
                raise
            if previous.exists():
                shutil.rmtree(previous)
        return certificate_paths(directory)
    finally:
        os.close(descriptor)


def generate_certificates(directory: Path) -> None:
    """Write only inside an unpublished, owned staging directory."""

    def openssl(*args: str) -> None:
        subprocess.run(  # noqa: S603 - fixed fixture arguments
            ["openssl", *args],  # noqa: S607
            check=True,
            capture_output=True,
            cwd=directory,
            timeout=10,
        )

    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2"]
    ca = [
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign",
    ]
    openssl("req", "-x509", *ec, "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=CA", *ca)
    for name, san in (("good", "DNS:localhost,IP:127.0.0.1"), ("wrongname", "DNS:other.test")):
        subject = f"/CN={san.split(',')[0][4:]}"
        openssl("req", *ec[:-2], "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", subject)
        (directory / f"{name}.ext").write_text(
            f"subjectAltName={san}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
        )
        signing = ["-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "2"]
        extensions = ["-extfile", f"{name}.ext"]
        openssl("x509", "-req", "-in", f"{name}.csr", *signing, *extensions, "-out", f"{name}.pem")
    selfsigned = ["-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"]
    openssl("req", "-x509", *ec, "-keyout", "selfsigned.key", "-out", "selfsigned.pem", *selfsigned)


def server_contexts(paths: dict[str, str]) -> dict[str, ssl.SSLContext]:
    contexts = {}
    for name in CERT_NAMES:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(f"{paths[name]}.pem", f"{paths[name]}.key")
        contexts[name] = context
    return contexts


def session_json(session: dict[str, Any]) -> dict[str, Any]:
    """A session as JSON (the message base64-encoded)."""
    out = dict(session)
    if out["message"] is not None:
        out["message"] = base64.b64encode(out["message"]).decode()
    return out


def session_from_json(data: dict[str, Any]) -> dict[str, Any]:
    if data["message"] is not None:
        data["message"] = base64.b64decode(data["message"])
    return data


class Sink:
    """One listening server whose scenario can change between sessions."""

    def __init__(self, owner: ScriptedSmtp, scenario: dict[str, Any], cert: str) -> None:
        self.owner = owner
        self.server: asyncio.Server | None = None
        self.port = 0
        self.sessions: list[dict[str, Any]] = []
        self.record_dir: Path | None = None
        self.tasks: set[asyncio.Task[None]] = set()
        self.finishing: set[asyncio.Task[None]] = set()
        self.counter = 0
        self.lock: int | None = None
        self.incomplete: list[Path] = []
        self.errors: list[str] = []
        self.stopped = False
        self.configure(scenario, cert)

    def configure(self, scenario: dict[str, Any], cert: str = "good") -> None:
        """The script of the next sessions."""
        if cert not in self.owner.contexts:
            raise ValueError("unknown fixture certificate")
        self.script = {**SMTP_DEFAULTS, **scenario}
        self.cert = cert

    def settle(self, timeout: float = 5.0) -> None:
        """Wait until every session has ended or hangs on purpose."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.finishing and all(s["state"] != "open" for s in self.sessions):
                return
            time.sleep(0.01)

    def take(self) -> list[dict[str, Any]]:
        """The sessions so far; hanging ones are cut off."""

        async def take() -> list[dict[str, Any]]:
            sessions = list(self.sessions)
            await self._cancel()
            if self.record_dir is not None:
                return []
            identities = {id(session) for session in sessions}
            self.sessions = [s for s in self.sessions if id(s) not in identities]
            return sessions

        result: list[dict[str, Any]] = self.owner.run(take())
        return result

    async def _cancel(self) -> None:
        for task in list(self.tasks):
            if task not in self.finishing:
                task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        excess = (
            len(self.tasks) >= MAX_SESSIONS
            or len(self.sessions) >= MAX_RETAINED_SESSIONS
            or bool(self.errors)
        )
        self.tasks.add(task)
        if excess:
            self.finishing.add(task)
            try:
                writer.write(b"421 fixture session capacity exceeded\r\n")
                writer.close()
                with contextlib.suppress(ConnectionError, OSError, TimeoutError):
                    await asyncio.wait_for(writer.wait_closed(), 1)
            finally:
                self.tasks.discard(task)
                self.finishing.discard(task)
            return
        script = self.script
        context = self.owner.contexts[self.cert]
        self.counter += 1
        number = self.counter
        session: dict[str, Any] = {
            "state": "open",
            "tls": False,
            "commands": [],
            "auth_user": None,
            "mail_from": None,
            "rcpt": [],
            "data_for": None,
            "message": None,
        }
        self.sessions.append(session)
        active = None
        if self.record_dir is not None:
            active = self.record_dir / f"{number:06d}.active"
            try:
                with active.open("x") as marker:
                    marker.flush()
                    os.fsync(marker.fileno())
                sync_directory(self.record_dir)
            except OSError as error:
                if not self.errors:
                    self.errors.append(type(error).__name__)
                self.sessions.remove(session)
                self.finishing.add(task)
                writer.close()
                with contextlib.suppress(ConnectionError, OSError, TimeoutError):
                    await asyncio.wait_for(writer.wait_closed(), 1)
                self.finishing.discard(task)
                self.tasks.discard(task)
                return
        received = 0

        async def read_line() -> bytes:
            nonlocal received
            line = await reader.readline()
            received += len(line)
            if received > MAX_SESSION_BYTES:
                raise SessionLimitError
            return line

        accepted: list[str] = []
        tls = False

        async def reply(phase: str, code: int, lines: list[str]) -> bool:
            fault = script["fault"].get(phase)
            if fault == "close":
                return False
            if fault == "hang":
                session["state"] = "hanging"
                await asyncio.sleep(3600)
            if fault == "garbage":
                writer.write(b"garbage reply\r\n")
                await writer.drain()
                return True
            for i, line in enumerate(lines):
                sep = " " if i == len(lines) - 1 else "-"
                writer.write(f"{code}{sep}{line}\r\n".encode())
            await writer.drain()
            return code != 421

        def ehlo_lines() -> list[str]:
            lines = ["fake.test", "PIPELINING", "SIZE 52428800", "8BITMIME"]
            if not tls and script["offer_starttls"]:
                lines.append("STARTTLS")
            if (tls or not script["offer_starttls"]) and script["auth_offer"]:
                lines.append("AUTH " + script["auth_offer"])
            return lines

        async def auth(parts: list[str]) -> bool:
            mechanism = parts[1].upper() if len(parts) > 1 else ""
            answers = parts[2:3]
            prompts: list[str] = []
            if mechanism == "LOGIN":
                prompts = ["UGFzc3dvcmQ6"] if answers else ["VXNlcm5hbWU6", "UGFzc3dvcmQ6"]
            elif not answers:
                prompts = [""]
            for prompt in prompts:
                writer.write(f"334 {prompt}\r\n".encode())
                await writer.drain()
                answers.append((await read_line()).decode("ascii", "replace").strip())
            with contextlib.suppress(ValueError, IndexError):
                if mechanism == "PLAIN":
                    session["auth_user"] = base64.b64decode(answers[0]).split(b"\0")[1].decode()
                elif mechanism == "LOGIN":
                    session["auth_user"] = base64.b64decode(answers[0]).decode()
            code = script.get(f"auth_{mechanism.lower()}", script["auth"])
            if code != 235:
                session["auth_user"] = None
            return await reply("auth", code, ["auth result"])

        async def message() -> bytes | None:
            data = bytearray()
            while True:
                line = await read_line()
                if not line:
                    return None
                if line == b".\r\n":
                    return bytes(data)
                data.extend(line[1:] if line.startswith(b".") else line)

        try:
            if not await reply("banner", script["banner"], ["fake.test ESMTP"]):
                return
            while True:
                raw = await read_line()
                if not raw:
                    return
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                parts = line.split()
                verb = parts[0].upper() if parts else ""
                if len(session["commands"]) >= MAX_COMMANDS:
                    raise SessionLimitError
                session["commands"].append(verb)
                if verb in ("EHLO", "HELO"):
                    phase = "ehlo_tls" if tls else "ehlo"
                    code = script[phase]
                    ok = await reply(phase, code, ehlo_lines() if code == 250 else ["no"])
                elif verb == "STARTTLS":
                    ok = await reply("starttls", script["starttls"], ["go ahead"])
                    if ok and script["starttls"] == 220:
                        await writer.start_tls(context)
                        tls = session["tls"] = True
                elif verb == "AUTH":
                    ok = await auth(parts)
                elif verb == "MAIL":
                    sender = line.split(":", 1)[1].strip() if ":" in line else ""
                    session["mail_from"] = sender.split(">", 1)[0].lstrip("<")
                    ok = await reply("mail", script["mail"], ["sender result"])
                elif verb == "RCPT":
                    addr = line.split(":", 1)[1].strip().strip("<>") if ":" in line else ""
                    code = script["rcpt"].get(addr.split("@", 1)[0], 250)
                    session["rcpt"].append([addr, code])
                    if code in (250, 251):
                        accepted.append(addr)
                    ok = await reply("rcpt", code, ["rcpt result"])
                elif verb == "DATA":
                    ok = await reply("data", script["data"], ["send data"])
                    if ok and script["data"] == 354 and "data" not in script["fault"]:
                        data = await message()
                        if data is None:
                            return
                        session["data_for"] = list(accepted)
                        session["message"] = data
                        ok = await reply("data_end", script["data_end"], ["queued"])
                elif verb == "RSET":
                    accepted.clear()
                    ok = await reply("rset", 250, ["reset"])
                elif verb == "QUIT":
                    await reply("quit", script["quit"], ["bye"])
                    return
                else:
                    ok = await reply("other", 502, ["not implemented"])
                if not ok:
                    return
        except (SessionLimitError, ValueError):
            session["state"] = "limited"
            session["message"] = None
            writer.write(b"421 fixture session budget exceeded\r\n")
            with contextlib.suppress(ConnectionError, OSError):
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            self.finishing.add(task)
            writer.close()
            if session["state"] != "limited":
                session["state"] = "closed"
            with contextlib.suppress(ConnectionError, OSError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 1)
            if self.record_dir is not None and active is not None:
                # A recording sink keeps nothing in memory (shadow runs last
                # a day) and never replaces an earlier capture.
                try:
                    publish_capture(self.record_dir, number, session)
                    active.unlink()
                    sync_directory(self.record_dir)
                except Exception as error:
                    # Failure after marker removal must remain visibly incomplete.
                    with contextlib.suppress(OSError):
                        with active.open("x") as marker:
                            marker.flush()
                            os.fsync(marker.fileno())
                        sync_directory(self.record_dir)
                    if not self.errors:
                        self.errors.append(type(error).__name__)
                finally:
                    self.sessions.remove(session)
            self.tasks.discard(task)
            self.finishing.discard(task)


def sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_capture(directory: Path, number: int, session: dict[str, Any]) -> None:
    """Only complete, synced JSON gets an exclusive final name."""
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix=f".{number:06d}-",
        suffix=".pending",
        dir=directory,
        delete=False,
    ) as stage:
        json.dump(session_json(session), stage)
        stage.flush()
        os.fsync(stage.fileno())
    temporary = Path(stage.name)
    os.link(temporary, directory / f"{number:06d}.json")
    sync_directory(directory)
    temporary.unlink()


class ScriptedSmtp:
    """Fake SMTP servers on an event loop in a thread."""

    def __init__(self, contexts: dict[str, ssl.SSLContext]) -> None:
        self.contexts = contexts
        self.sinks: list[Sink] = []
        self.closed = False
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def run(self, coro: Any) -> Any:
        if self.closed:
            coro.close()
            raise RuntimeError("SMTP fixture is closed")
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        try:
            return future.result(timeout=10)
        except BaseException:
            future.cancel()
            raise

    def start(
        self,
        scenario: dict[str, Any] | None = None,
        cert: str = "good",
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        record_dir: Path | None = None,
    ) -> Sink:
        sink = Sink(self, scenario or {}, cert)
        sink.record_dir = record_dir
        try:
            if record_dir is not None:
                sink.lock = os.open(record_dir, os.O_RDONLY)
                try:
                    fcntl.flock(sink.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise RuntimeError("capture directory already owned") from None
                sink.incomplete = sorted(
                    [*record_dir.glob("*.active"), *record_dir.glob("*.pending")]
                )
                numbers = [int(p.stem) for p in record_dir.iterdir() if p.stem.isdigit()]
                sink.counter = max(numbers, default=0)
            server = self.run(asyncio.start_server(sink.handle, host, port, limit=64 << 20))
        except BaseException:
            if sink.lock is not None:
                os.close(sink.lock)
                sink.lock = None
            raise
        sink.server = server
        sink.port = server.sockets[0].getsockname()[1]
        self.sinks.append(sink)
        return sink

    def stop(self, sink: Sink) -> None:
        if sink.stopped:
            return

        async def close() -> None:
            assert sink.server is not None
            sink.server.close()
            await asyncio.wait_for(sink._cancel(), 3)
            await sink.server.wait_closed()

        try:
            self.run(close())
        finally:
            sink.stopped = True
            self.sinks.remove(sink)
            if sink.lock is not None:
                os.close(sink.lock)
                sink.lock = None
        if sink.errors:
            raise RuntimeError("capture publication failed; incomplete attempts retained")

    def close(self) -> None:
        if self.closed:
            return
        error: BaseException | None = None
        try:
            for sink in list(self.sinks):
                try:
                    self.stop(sink)
                except BaseException as failure:
                    if error is None:
                        error = failure
        finally:
            self.closed = True
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                raise RuntimeError("SMTP fixture thread did not stop")
            self.loop.close()
        if error is not None:
            raise error


def main() -> None:
    parser = argparse.ArgumentParser(description="SMTP capture sink (accepts and records)")
    parser.add_argument("--listen", required=True, help="HOST:PORT")
    parser.add_argument("--certs", required=True, type=Path, help="CA directory (created)")
    parser.add_argument("--record-dir", required=True, type=Path)
    args = parser.parse_args()
    host, _, port = args.listen.rpartition(":")
    args.record_dir.mkdir(parents=True, exist_ok=True)
    smtp = ScriptedSmtp(server_contexts(make_certificates(args.certs)))
    try:
        sink = smtp.start(host=host, port=int(port), record_dir=args.record_dir)
        print(f"smtp sink on {host}:{sink.port}, CA {args.certs / 'ca.pem'}", flush=True)
        if sink.incomplete:
            print(f"incomplete capture attempts: {len(sink.incomplete)}", flush=True)
        threading.Event().wait()
    except BaseException:
        # Cleanup must not replace the failure that triggered shutdown.
        with contextlib.suppress(Exception):
            smtp.close()
        raise
    else:
        smtp.close()


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        main()
