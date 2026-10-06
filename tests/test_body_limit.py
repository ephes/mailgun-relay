from __future__ import annotations

import asyncio

import pytest
from starlette.types import Message, Receive, Scope, Send

from mailgun_relay.app import BodySizeLimitMiddleware
from mailgun_relay.errors import PayloadTooLargeError


async def _drain_app(scope: Scope, receive: Receive, send: Send) -> None:
    """Minimal ASGI app that reads the whole body, then returns 200."""
    while True:
        message = await receive()
        if message["type"] == "http.request" and not message.get("more_body"):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _http_scope(headers: list[tuple[bytes, bytes]]) -> Scope:
    return {"type": "http", "method": "POST", "path": "/", "headers": headers}


class _Collector:
    def __init__(self) -> None:
        self.messages: list[Message] = []
        self.app_called = False

    async def send(self, message: Message) -> None:
        self.messages.append(message)

    @property
    def status(self) -> int | None:
        for m in self.messages:
            if m["type"] == "http.response.start":
                return int(m["status"])
        return None


def test_declared_content_length_over_limit_rejected_before_app() -> None:
    collector = _Collector()

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        collector.app_called = True
        await _drain_app(scope, receive, send)

    mw = BodySizeLimitMiddleware(inner, max_bytes=10)
    scope = _http_scope([(b"content-length", b"100")])

    async def receive() -> Message:
        return {"type": "http.request", "body": b"x" * 100, "more_body": False}

    asyncio.run(mw(scope, receive, collector.send))

    assert collector.status == 413
    # The body is never buffered by the app.
    assert collector.app_called is False


@pytest.mark.parametrize("value", [b"not-a-number", b"-5"])
def test_invalid_or_negative_content_length_rejected(value: bytes) -> None:
    collector = _Collector()
    mw = BodySizeLimitMiddleware(_drain_app, max_bytes=10)
    scope = _http_scope([(b"content-length", value)])

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    asyncio.run(mw(scope, receive, collector.send))
    assert collector.status == 413


def test_streamed_body_over_limit_raises_without_content_length() -> None:
    """A chunked body with no Content-Length is still bounded by byte counting."""
    collector = _Collector()
    mw = BodySizeLimitMiddleware(_drain_app, max_bytes=10)
    scope = _http_scope([])  # no content-length header

    chunks = [
        {"type": "http.request", "body": b"x" * 6, "more_body": True},
        {"type": "http.request", "body": b"x" * 6, "more_body": False},
    ]

    async def receive() -> Message:
        return chunks.pop(0)

    with pytest.raises(PayloadTooLargeError):
        asyncio.run(mw(scope, receive, collector.send))


def test_body_within_limit_passes_through() -> None:
    collector = _Collector()
    mw = BodySizeLimitMiddleware(_drain_app, max_bytes=100)
    scope = _http_scope([(b"content-length", b"5")])

    async def receive() -> Message:
        return {"type": "http.request", "body": b"hello", "more_body": False}

    asyncio.run(mw(scope, receive, collector.send))
    assert collector.status == 200


def test_non_http_scope_passes_through() -> None:
    seen = {"called": False}

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        seen["called"] = True

    async def receive() -> Message:
        raise AssertionError("receive must not be called")

    async def send(message: Message) -> None:
        raise AssertionError("send must not be called")

    mw = BodySizeLimitMiddleware(inner, max_bytes=10)
    asyncio.run(mw({"type": "lifespan"}, receive, send))
    assert seen["called"] is True
