"""Finite loopback peers for the retained Python outcome/cleanup budgets."""

from __future__ import annotations

import dataclasses
import socketserver
import threading
import time
from collections.abc import Iterator
from typing import cast

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from mailgun_relay.app import create_app
from mailgun_relay.routes import AppState
from mailgun_relay.smtp_client import submit
from tests.test_messages_endpoint import _minimum_form, basic
from tests.test_smtp_submission import _plain_transport


class Peer(socketserver.ThreadingTCPServer):
    daemon_threads = False
    delay = 0.0
    trickle_banner = False
    stall_tls = False
    stall_quit = False
    lose_data_reply = False
    partial_data_reply = False
    partial_reject = False
    messages = 0

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.stop = threading.Event()


class Handler(socketserver.StreamRequestHandler):
    server: Peer

    def handle(self) -> None:
        self.request.settimeout(2)
        try:
            banner = b"220 synthetic SMTP\r\n"
            if self.server.trickle_banner:
                for byte in banner:
                    self.wfile.write(bytes([byte]))
                    if self.server.stop.wait(0.05):
                        return
            else:
                self.wfile.write(banner)
            while line := self.rfile.readline():
                verb = line.split()[0].upper()
                if self.server.stop.wait(self.server.delay):
                    return
                if verb == b"EHLO":
                    self.wfile.write(b"250-synthetic\r\n250 STARTTLS\r\n")
                elif verb == b"STARTTLS":
                    self.wfile.write(b"220 go ahead\r\n")
                    if self.server.stall_tls:
                        self.server.stop.wait(2)
                        return
                elif verb == b"DATA":
                    self.wfile.write(b"354 send data\r\n")
                    while self.rfile.readline() not in (b".\r\n", b""):
                        pass
                    self.server.messages += 1
                    if self.server.lose_data_reply:
                        self.server.stop.wait(2)
                        return
                    if self.server.partial_data_reply:
                        code = b"550 rejected" if self.server.partial_reject else b"250 queued"
                        self.wfile.write(code)  # no complete final reply
                        self.server.stop.wait(2)
                        return
                    self.wfile.write(b"250 queued\r\n")
                elif verb == b"QUIT":
                    if self.server.stall_quit:
                        for byte in b"221 synthetic cleanup completed\r\n":
                            self.wfile.write(bytes([byte]))
                            if self.server.stop.wait(0.05):
                                return
                        return
                    self.wfile.write(b"221 bye\r\n")
                    return
                else:
                    self.wfile.write(b"250 ok\r\n")
        except OSError:
            pass  # deadline closes only this session


@pytest.fixture
def peer() -> Iterator[Peer]:
    with Peer() as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            yield server
        finally:
            server.stop.set()
            server.shutdown()
            thread.join(3)
            assert not thread.is_alive()


@pytest.mark.parametrize(
    "phase", ["successive", "banner", "tls", "data", "partial_data", "partial_reject", "quit"]
)
def test_http_session_budget_and_next_send(
    peer: Peer,
    app_state: AppState,
    homepage_token: str,
    phase: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport = dataclasses.replace(
        _plain_transport(peer.server_address[1]),
        timeout_s=0.9,
        session_timeout_s=0.3,
    )
    if phase == "successive":
        peer.delay = 0.12  # every legal reply is inside the inactivity timeout
    elif phase == "banner":
        peer.trickle_banner = True
    elif phase == "tls":
        peer.stall_tls = True
        transport = dataclasses.replace(transport, use_starttls=True)
    elif phase == "data":
        peer.lose_data_reply = True
    elif phase in {"partial_data", "partial_reject"}:
        peer.partial_data_reply = True
        peer.partial_reject = phase == "partial_reject"
    else:
        peer.stall_quit = True
        transport = dataclasses.replace(transport, timeout_s=0.2)
    state = dataclasses.replace(
        app_state,
        transport=transport,
        smtp_submit=submit,
        settings=app_state.settings.model_copy(update={"smtp_max_concurrency": 1}),
    )
    app = create_app(app_state=state)
    with TestClient(app) as client:

        def post() -> Response:
            return cast(
                Response,
                client.post(
                    "/v3/mg.wersdoerfer.de/messages",
                    data=_minimum_form(),
                    headers={"Authorization": basic("api", homepage_token)},
                ),
            )

        start = time.monotonic()
        response = post()
        elapsed = time.monotonic() - start
        assert response.status_code == (200 if phase == "quit" else 503), response.text
        assert elapsed < 0.65, f"session exceeded its total budget: {elapsed}"
        assert peer.messages == (
            1 if phase in {"data", "partial_data", "partial_reject", "quit"} else 0
        )
        peer.delay = 0
        peer.trickle_banner = peer.stall_tls = peer.lose_data_reply = peer.stall_quit = False
        peer.partial_data_reply = False
        # TLS startup is tested above; a later cleartext synthetic request is
        # independent and can reuse the sole admission slot.
        app.state.app_state = dataclasses.replace(
            state, transport=dataclasses.replace(transport, use_starttls=False)
        )
        assert post().status_code == 200
        assert peer.messages == (
            2 if phase in {"data", "partial_data", "partial_reject", "quit"} else 1
        )
    if phase == "quit":
        assert any(getattr(r, "event", None) == "smtp_cleanup_failed" for r in caplog.records)


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), float("-inf"), 1e10])
def test_direct_transport_refuses_invalid_session_budget(value: float) -> None:
    with pytest.raises(ValueError, match="session_timeout_s"):
        dataclasses.replace(_plain_transport(25), session_timeout_s=value)


def test_app_passes_session_budget_to_transport(
    app_state: AppState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mailgun_relay.app import _app_state_from_settings

    monkeypatch.setattr("mailgun_relay.app.load_secrets", lambda _: app_state.secrets)
    settings = app_state.settings.model_copy(update={"smtp_session_timeout_s": 0.25})
    assert _app_state_from_settings(settings).transport.session_timeout_s == 0.25


def test_late_resolver_result_does_not_open_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    from mailgun_relay.smtp_client import FailureCategory, SmtpSubmitError
    from tests.test_smtp_submission import _msg

    addresses = socket.getaddrinfo("127.0.0.1", 25, type=socket.SOCK_STREAM)

    def resolve(*args: object, **kwargs: object) -> object:
        threading.Event().wait(0.1)  # libc resolution itself cannot be cancelled
        return addresses

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", lambda *_: pytest.fail("late DNS opened a connection"))
    transport = dataclasses.replace(_plain_transport(25), session_timeout_s=0.03)
    with pytest.raises(SmtpSubmitError) as caught:
        submit(_msg(), envelope_sender="x@x", recipients=["y@y"], transport=transport)
    assert caught.value.category == FailureCategory.TEMPORARY
    assert caught.value.reason == "TimeoutError"
