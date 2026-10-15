"""aiosmtpd server with STARTTLS (required) and AUTH PLAIN/LOGIN (TLS only)
that refuses RCPT for local part "bad" with 550 and prints each accepted
envelope. Third-party server cross-check for the partial-refusal case.

Usage: uv run --with aiosmtpd python aiosmtpd_server.py PORT CERT KEY
"""

from __future__ import annotations

import asyncio
import ssl
import sys

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult


class Handler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if address.split("@", 1)[0] == "bad":
            return "550 5.1.1 no such user"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        print(
            f"DATA from={envelope.mail_from} rcpts={envelope.rcpt_tos} bytes={len(envelope.content)} "
            f"tls={session.ssl is not None} auth={session.authenticated}",
            flush=True,
        )
        return "250 2.0.0 queued"


def authenticator(server, session, envelope, mechanism, auth_data):
    print(f"AUTH mechanism={mechanism}", flush=True)
    return AuthResult(success=auth_data.login == b"relay" and auth_data.password == b"test-password")


def main() -> None:
    port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)
    controller = Controller(
        Handler(),
        hostname="127.0.0.1",
        port=port,
        tls_context=ctx,
        require_starttls=True,
        authenticator=authenticator,
        auth_require_tls=True,
    )
    controller.start()
    print("ready", flush=True)
    try:
        asyncio.run(asyncio.sleep(3600))
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
