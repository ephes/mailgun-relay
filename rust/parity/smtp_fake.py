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
import json
import ssl
import subprocess
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

CERT_NAMES = ("good", "wrongname", "selfsigned")


def make_certificates(directory: Path) -> dict[str, str]:
    """A throwaway CA with key identifiers, a ``localhost`` leaf, a leaf for
    another name and a self-signed one; paths without the ``.pem``/``.key``
    suffix. Existing files are kept."""
    directory.mkdir(parents=True, exist_ok=True)
    paths = {name: str(directory / name) for name in (*CERT_NAMES, "ca")}
    if all((directory / f"{name}.pem").exists() for name in paths):
        return paths

    def openssl(*args: str) -> None:
        subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=directory)  # noqa: S603, S607

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
    return paths


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
        self.counter = 0
        self.configure(scenario, cert)

    def configure(self, scenario: dict[str, Any], cert: str = "good") -> None:
        """The script of the next sessions."""
        self.script = {**SMTP_DEFAULTS, **scenario}
        self.cert = cert

    def settle(self, timeout: float = 5.0) -> None:
        """Wait until every session has ended or hangs on purpose."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if all(s["state"] != "open" for s in self.sessions):
                return
            time.sleep(0.01)

    def take(self) -> list[dict[str, Any]]:
        """The sessions so far; hanging ones are cut off."""
        self.owner.run(self._cancel())
        sessions, self.sessions = self.sessions, []
        return sessions

    async def _cancel(self) -> None:
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks.clear()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self.tasks.add(task)
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
            active.touch()
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
                answers.append((await reader.readline()).decode("ascii", "replace").strip())
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
            lines: list[bytes] = []
            while True:
                line = await reader.readline()
                if not line:
                    return None
                if line == b".\r\n":
                    return b"".join(lines)
                lines.append(line[1:] if line.startswith(b".") else line)

        try:
            if not await reply("banner", script["banner"], ["fake.test ESMTP"]):
                return
            while True:
                raw = await reader.readline()
                if not raw:
                    return
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                parts = line.split()
                verb = parts[0].upper() if parts else ""
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
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            session["state"] = "closed"
            self.tasks.discard(task)
            if self.record_dir is not None and active is not None:
                # A recording sink keeps nothing in memory (shadow runs last
                # a day) and never replaces an earlier capture.
                path = self.record_dir / f"{number:06d}.json"
                with path.open("x", encoding="utf-8") as out:
                    out.write(json.dumps(session_json(session)))
                active.unlink()
                self.sessions.remove(session)


class ScriptedSmtp:
    """Fake SMTP servers on an event loop in a thread."""

    def __init__(self, contexts: dict[str, ssl.SSLContext]) -> None:
        self.contexts = contexts
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def run(self, coro: Any) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result()

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
        if record_dir is not None:
            # Number on from the captures already there (a restarted sink).
            numbers = [int(p.stem) for p in record_dir.iterdir() if p.stem.isdigit()]
            sink.counter = max(numbers, default=0)
        # Messages of up to 64 MiB in one line still parse (a broken client).
        server = self.run(asyncio.start_server(sink.handle, host, port, limit=64 << 20))
        sink.server = server
        sink.port = server.sockets[0].getsockname()[1]
        return sink

    def stop(self, sink: Sink) -> None:
        async def close() -> None:
            assert sink.server is not None
            sink.server.close()
            await sink._cancel()
            await sink.server.wait_closed()

        self.run(close())

    def close(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join()
        self.loop.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="SMTP capture sink (accepts and records)")
    parser.add_argument("--listen", required=True, help="HOST:PORT")
    parser.add_argument("--certs", required=True, type=Path, help="CA directory (created)")
    parser.add_argument("--record-dir", required=True, type=Path)
    args = parser.parse_args()
    host, _, port = args.listen.rpartition(":")
    args.record_dir.mkdir(parents=True, exist_ok=True)
    smtp = ScriptedSmtp(server_contexts(make_certificates(args.certs)))
    sink = smtp.start(host=host, port=int(port), record_dir=args.record_dir)
    print(f"smtp sink on {host}:{sink.port}, CA {args.certs / 'ca.pem'}", flush=True)
    with contextlib.suppress(KeyboardInterrupt):
        threading.Event().wait()


if __name__ == "__main__":
    main()
