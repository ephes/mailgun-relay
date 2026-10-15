"""Scripted fake SMTP server for the S1b spike (test tooling, not production code).

One scenario per process, given as JSON on the command line. Every phase can
answer with a chosen reply code, a garbage line, or a silent close, so both
the Rust prototype and the Python relay (oracle) can be driven through the
same faults. STARTTLS uses a throwaway certificate; AUTH PLAIN/LOGIN accept
any credentials unless the scenario says otherwise. Credentials are never
logged.

Usage: python scripted_smtp.py PORT CERT KEY 'SCENARIO_JSON' TRANSCRIPT_FILE
"""

from __future__ import annotations

import asyncio
import json
import ssl
import sys

DEFAULTS = {
    "banner": 220,
    "ehlo": 250,
    "ehlo_tls": 250,
    "offer_starttls": True,
    "starttls": 220,
    "auth_offer": "PLAIN LOGIN",
    "auth": 235,
    "smtputf8": False,
    "mail": 250,
    # recipient local part -> reply code; others get 250
    "rcpt": {},
    "data": 354,
    "data_end": 250,
    "quit": 221,
    # phase -> "garbage" | "close" | "hang"
    "fault": {},
}


def main() -> None:
    port = int(sys.argv[1])
    cert, key = sys.argv[2], sys.argv[3]
    scenario = {**DEFAULTS, **json.loads(sys.argv[4])}
    transcript_path = sys.argv[5]
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        log: list[str] = []
        state = {"tls": False, "rcpts": [], "data_for": None}

        async def reply(phase: str, code: int, text: str = "ok", lines: list[str] | None = None) -> bool:
            """Send the reply for a phase; False means the session ends here."""
            fault = scenario["fault"].get(phase)
            if fault == "close":
                log.append(f"S: <close at {phase}>")
                writer.close()
                return False
            if fault == "hang":
                log.append(f"S: <hang at {phase}>")
                await asyncio.sleep(3600)
                return False
            if fault == "garbage":
                writer.write(b"garbage reply\r\n")
                log.append("S: garbage reply")
                await writer.drain()
                return True
            lines = lines or [text]
            for i, line in enumerate(lines):
                sep = " " if i == len(lines) - 1 else "-"
                writer.write(f"{code}{sep}{line}\r\n".encode())
                log.append(f"S: {code}{sep}{line}")
            await writer.drain()
            if code == 421:
                # 421 means the server closes the transmission channel
                writer.close()
                return False
            return True

        def ehlo_lines() -> list[str]:
            lines = ["fake.test", "PIPELINING", "SIZE 52428800", "8BITMIME"]
            if not state["tls"] and scenario["offer_starttls"]:
                lines.append("STARTTLS")
            if (state["tls"] or not scenario["offer_starttls"]) and scenario["auth_offer"]:
                lines.append("AUTH " + scenario["auth_offer"])
            if scenario["smtputf8"]:
                lines.append("SMTPUTF8")
            return lines

        try:
            if not await reply("banner", scenario["banner"], "fake.test ESMTP"):
                return
            while True:
                raw = await reader.readline()
                if not raw:
                    log.append("C: <eof>")
                    return
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                verb = line.split(" ", 1)[0].upper()
                log.append("C: " + (line if verb != "AUTH" else "AUTH <redacted>"))
                if verb in ("EHLO", "HELO"):
                    phase = "ehlo_tls" if state["tls"] else "ehlo"
                    code = scenario[phase]
                    ok = await reply(phase, code, lines=ehlo_lines() if code == 250 else ["no"])
                elif verb == "STARTTLS":
                    ok = await reply("starttls", scenario["starttls"], "go ahead")
                    if ok and scenario["starttls"] == 220:
                        await writer.start_tls(ctx)
                        state["tls"] = True
                        log.append("S: <tls established>")
                elif verb == "AUTH":
                    parts = line.split()
                    if parts[1].upper() == "LOGIN":
                        for prompt in ("VXNlcm5hbWU6", "UGFzc3dvcmQ6"):
                            if len(parts) == 3 and prompt == "VXNlcm5hbWU6":
                                continue
                            writer.write(f"334 {prompt}\r\n".encode())
                            await writer.drain()
                            await reader.readline()
                    elif len(parts) == 2:
                        writer.write(b"334 \r\n")
                        await writer.drain()
                        await reader.readline()
                    ok = await reply("auth", scenario["auth"], "auth result")
                elif verb == "MAIL":
                    ok = await reply("mail", scenario["mail"], "sender result")
                elif verb == "RCPT":
                    addr = line.split(":", 1)[1].strip().strip("<>")
                    code = scenario["rcpt"].get(addr.split("@", 1)[0], 250)
                    if code == 250:
                        state["rcpts"].append(addr)
                    ok = await reply("rcpt", code, "rcpt result")
                elif verb == "DATA":
                    ok = await reply("data", scenario["data"], "send data")
                    if ok and scenario["data"] == 354:
                        body = []
                        while True:
                            chunk = await reader.readline()
                            if chunk in (b".\r\n", b""):
                                break
                            body.append(chunk)
                        state["data_for"] = list(state["rcpts"])
                        log.append(f"C: <message {sum(map(len, body))} bytes for {state['data_for']}>")
                        ok = await reply("data_end", scenario["data_end"], "queued")
                elif verb == "RSET":
                    state["rcpts"] = []
                    ok = await reply("rset", 250, "reset")
                elif verb == "QUIT":
                    await reply("quit", scenario["quit"], "bye")
                    writer.close()
                    return
                else:
                    ok = await reply("other", 502, "not implemented")
                if not ok:
                    return
        except (ConnectionError, ssl.SSLError) as exc:
            log.append(f"S: <connection error {type(exc).__name__}>")
        finally:
            with open(transcript_path, "a") as fh:
                fh.write(json.dumps({"log": log, "data_for": state["data_for"]}) + "\n")
            try:
                writer.close()
            except Exception:
                pass

    async def serve() -> None:
        server = await asyncio.start_server(handle, "127.0.0.1", port)
        print("ready", flush=True)
        async with server:
            await server.serve_forever()

    asyncio.run(serve())


if __name__ == "__main__":
    main()
