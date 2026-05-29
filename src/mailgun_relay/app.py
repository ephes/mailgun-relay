from __future__ import annotations

from fastapi import FastAPI
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mailgun_relay.config import Settings, load_secrets
from mailgun_relay.errors import PayloadTooLargeError
from mailgun_relay.logging_setup import configure_logging
from mailgun_relay.routes import AppState, register_routes
from mailgun_relay.smtp_client import SmtpTransport
from mailgun_relay.version import __version__


class BodySizeLimitMiddleware:
    """Reject over-large request bodies at the ASGI layer (HTTP 413).

    This enforces the body-size cap *before* the route buffers the request via
    ``request.form()``. Two layers:

    * a declared ``Content-Length`` over the limit is rejected immediately,
      before any body is read;
    * for chunked/streamed bodies (or an understated ``Content-Length``) the
      streamed bytes are counted and ``PayloadTooLargeError`` is raised once the
      limit is crossed, which the route maps to a clean 413.

    Without this, ``request.form()`` on a ``application/x-www-form-urlencoded``
    body buffers the whole request into memory before any app-level limit runs.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = Headers(scope=scope).get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                await self._reject(send)
                return
            if declared < 0 or declared > self.max_bytes:
                await self._reject(send)
                return

        seen = 0

        async def limited_receive() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    raise PayloadTooLargeError(f"request body exceeds {self.max_bytes} bytes")
            return message

        await self.app(scope, limited_receive, send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"message":"Payload Too Large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _app_state_from_settings(settings: Settings) -> AppState:
    secrets = load_secrets(settings.secrets_path)
    transport = SmtpTransport(
        host=settings.smtp_host,
        port=settings.smtp_port,
        username=secrets.smtp.username,
        password=secrets.smtp.password,
        use_starttls=settings.smtp_starttls,
        timeout_s=settings.smtp_timeout_s,
        ca_file=settings.smtp_ca_file or None,
    )
    return AppState(settings=settings, secrets=secrets, transport=transport)


def create_app(app_state: AppState | None = None) -> FastAPI:
    app = FastAPI(
        title="mailgun-relay",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    register_routes(app)
    if app_state is None:
        settings = Settings()
        configure_logging(settings.log_level)
        app_state = _app_state_from_settings(settings)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=app_state.settings.max_body_bytes)
    app.state.app_state = app_state
    return app
