"""Finite loopback peers for the retained Python outcome/cleanup budgets."""

from __future__ import annotations

import asyncio
import dataclasses
import io
import smtplib
import socket
import socketserver
import threading
import time
from collections.abc import Buffer, Iterator
from email.message import EmailMessage
from typing import cast
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from mailgun_relay import smtp_client
from mailgun_relay.app import create_app
from mailgun_relay.routes import AppState
from mailgun_relay.smtp_client import (
    FailureCategory,
    SmtpSubmitError,
    _SessionSMTP,
    _SocketDeadline,
    submit,
)
from tests.test_messages_endpoint import _minimum_form, basic
from tests.test_smtp_submission import _msg, _plain_transport


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


@pytest.mark.parametrize("outcome", ["fallback", "exhausted", "cancelled"])
def test_failed_candidate_close_preserves_connect_result(
    monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    first_error = ConnectionRefusedError("synthetic connect failure")
    final_error = TimeoutError("synthetic final connect failure")
    cancellation = asyncio.CancelledError("synthetic cancellation")
    first = Mock()
    first.connect.side_effect = cancellation if outcome == "cancelled" else first_error
    first.close.side_effect = OSError("synthetic close failure")
    second = Mock()
    if outcome == "exhausted":
        second.connect.side_effect = final_error
        second.close.side_effect = OSError("synthetic final close failure")
    candidates = Mock(side_effect=[first, second])
    addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (host, 25))
        for host in ("192.0.2.1", "192.0.2.2")
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: addresses)
    monkeypatch.setattr(socket, "socket", candidates)
    budget = _SocketDeadline(30)
    monkeypatch.setattr(budget, "watch", Mock())
    smtp = _SessionSMTP("", 0, timeout=5, budget=budget)
    banner = Mock(return_value=(220, b"synthetic SMTP"))
    monkeypatch.setattr(smtp, "getreply", banner)

    if outcome == "cancelled":
        with pytest.raises(asyncio.CancelledError) as cancelled:
            smtp.connect("smtp.example")
        assert cancelled.value is cancellation
        assert candidates.call_count == 1
        banner.assert_not_called()
    elif outcome == "exhausted":
        with pytest.raises(TimeoutError) as failed:
            smtp.connect("smtp.example")
        assert failed.value is final_error
        second.connect.assert_called_once_with(addresses[1][4])
        second.close.assert_called_once_with()
        banner.assert_not_called()
    else:
        assert smtp.connect("smtp.example") == (220, b"synthetic SMTP")
        assert smtp.sock is second
        second.connect.assert_called_once_with(addresses[1][4])
        second.close.assert_not_called()
        banner.assert_called_once_with()
    first.connect.assert_called_once_with(addresses[0][4])
    first.close.assert_called_once_with()


@pytest.mark.parametrize(
    "final_reply", [b"250 queued\r\n", b"", b"250 queued", b"550 rejected", b"250-queued\r\n"]
)
def test_data_outcome_at_deadline(monkeypatch: pytest.MonkeyPatch, final_reply: bytes) -> None:
    now = 0.0
    transport = _plain_transport(25)
    accepted = final_reply == b"250 queued\r\n"
    # The 550 RCPT refusal must still be returned when DATA succeeds.
    replies = io.BytesIO(
        b"220 synthetic SMTP\r\n250 synthetic\r\n250 sender ok\r\n"
        b"250 recipient ok\r\n550 recipient refused\r\n354 send data\r\n"
        + final_reply
        + (b"221 bye\r\n" if accepted else b"")
    )

    class ReplyStream(io.RawIOBase):
        def readable(self) -> bool:
            return True

        def readinto(self, buffer: Buffer, /) -> int:
            data = replies.readinto(buffer)
            if data == 0 and not final_reply:
                raise TimeoutError("synthetic DATA read timeout")
            return data

    sock = Mock()
    sock.makefile.side_effect = lambda *_, **kw: (
        ReplyStream() if kw.get("buffering") == 0 else io.BufferedReader(ReplyStream())
    )

    def connect(smtp: _SessionSMTP, *_args: object, **_kwargs: object) -> tuple[int, bytes]:
        smtp.sock = sock
        return smtp.getreply()

    def send_message(
        smtp: _SessionSMTP, message: EmailMessage, *, from_addr: str, to_addrs: list[str]
    ) -> smtp_client.RefusedRecipients:
        nonlocal now
        refused = smtplib.SMTP.send_message(smtp, message, from_addr=from_addr, to_addrs=to_addrs)
        now = transport.session_timeout_s + 1
        return refused

    monkeypatch.setattr(smtp_client, "time", Mock(monotonic=lambda: now))
    monkeypatch.setattr(_SessionSMTP, "connect", connect)
    monkeypatch.setattr(_SessionSMTP, "send_message", send_message)

    def send() -> smtp_client.RefusedRecipients:
        return submit(
            _msg(),
            envelope_sender="sender@example.test",
            recipients=["accepted@example.test", "refused@example.test"],
            transport=transport,
        )

    if accepted:
        assert send() == {"refused@example.test": (550, b"recipient refused")}
    else:
        with pytest.raises(SmtpSubmitError) as caught:
            send()
        assert caught.value.category is FailureCategory.OUTCOME_UNKNOWN


@pytest.mark.parametrize("stop_in_body", [False, True])
def test_interrupted_timer_join_retires_watched_socket(
    monkeypatch: pytest.MonkeyPatch, stop_in_body: bool
) -> None:
    timer = Mock()
    interrupted = asyncio.CancelledError("synthetic timer join interruption")
    timer.join.side_effect = [interrupted, asyncio.CancelledError("unexpected second join")]
    monkeypatch.setattr(threading, "Timer", Mock(return_value=timer))
    sock = Mock()
    duplicate = sock.dup.return_value
    budget = _SocketDeadline(30)

    def close() -> None:
        # A callback dispatched before cancellation can still run after an
        # interrupted join. It must leave the retiring descriptor alone.
        budget._expire()
        raise OSError("synthetic duplicate close failure")

    duplicate.close.side_effect = close
    with pytest.raises(asyncio.CancelledError) as caught:
        with budget:
            budget.watch(sock)
            if stop_in_body:
                budget.stop()

    assert caught.value is interrupted
    timer.cancel.assert_called_once_with()
    timer.join.assert_called_once_with()
    duplicate.close.assert_called_once_with()
    duplicate.shutdown.assert_not_called()
    sock.close.assert_not_called()
    assert budget.socket is None
    assert not budget.expired
