"""A slow SMTP backend must not block /health or other requests.

The submitter is blocking smtplib I/O; the route runs it in a worker thread
behind a dedicated concurrency limiter. These tests drive the ASGI app with
httpx's AsyncClient so several requests are genuinely in flight at once.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import functools
import logging
import threading
from collections.abc import AsyncIterator
from email.message import EmailMessage
from typing import Any

import anyio
import httpx
import pytest
from starlette.datastructures import FormData, UploadFile

from mailgun_relay import routes
from mailgun_relay.app import create_app
from mailgun_relay.config import Settings
from mailgun_relay.routes import AppState
from mailgun_relay.smtp_client import FailureCategory, SmtpSubmitError, SmtpTransport

# Upper bound for anything that should be quick; the blocked submitter waits
# at most this long, so a regression fails the test instead of hanging it.
_TIMEOUT_S = 5.0
_SLOW_RECIPIENT = "slow@wersdoerfer.de"


class GatedSubmitter:
    """Blocks sends to `_SLOW_RECIPIENT` until `release` is set."""

    def __init__(self, raise_with: Exception | None = None) -> None:
        self.release = threading.Event()
        self.slow_entered = threading.Event()
        self.raise_with = raise_with
        self.recipients: list[list[str]] = []
        self._lock = threading.Lock()

    def __call__(
        self,
        message: EmailMessage,
        *,
        envelope_sender: str,
        recipients: list[str],
        transport: SmtpTransport,
    ) -> None:
        with self._lock:
            self.recipients.append(list(recipients))
        if _SLOW_RECIPIENT in recipients:
            self.slow_entered.set()
            if not self.release.wait(_TIMEOUT_S):
                raise RuntimeError("gated submitter was never released")
            if self.raise_with is not None:
                raise self.raise_with


def _auth(token: str) -> dict[str, str]:
    raw = base64.b64encode(f"api:{token}".encode()).decode("ascii")
    return {"Authorization": f"Basic {raw}"}


def _form(to: str) -> dict[str, str]:
    return {
        "from": "Jochen <jochen-homepage@wersdoerfer.de>",
        "to": to,
        "subject": "hi",
        "text": "hello",
    }


def _client(
    app_state: AppState, submitter: GatedSubmitter, **overrides: object
) -> httpx.AsyncClient:
    settings: Settings = app_state.settings.model_copy(update=overrides)
    state = dataclasses.replace(app_state, settings=settings, smtp_submit=submitter)
    transport = httpx.ASGITransport(app=create_app(app_state=state))
    return httpx.AsyncClient(transport=transport, base_url="http://relay.test")


async def _wait_entered(submitter: GatedSubmitter) -> None:
    entered = await asyncio.to_thread(submitter.slow_entered.wait, _TIMEOUT_S)
    assert entered, "slow send never reached the submitter"


def test_health_and_other_sends_stay_responsive_while_a_send_hangs(
    app_state: AppState, homepage_token: str
) -> None:
    submitter = GatedSubmitter()

    async def scenario() -> None:
        async with _client(app_state, submitter) as client:
            path = "/v3/mg.wersdoerfer.de/messages"
            slow = asyncio.create_task(
                client.post(path, headers=_auth(homepage_token), data=_form(_SLOW_RECIPIENT))
            )
            try:
                await _wait_entered(submitter)

                health = await asyncio.wait_for(client.get("/health"), _TIMEOUT_S)
                assert health.status_code == 200
                assert health.json() == {"status": "ok"}

                other = await asyncio.wait_for(
                    client.post(
                        path, headers=_auth(homepage_token), data=_form("admin@wersdoerfer.de")
                    ),
                    _TIMEOUT_S,
                )
                assert other.status_code == 200, other.text
                assert not slow.done(), "slow send finished before it was released"
            finally:
                submitter.release.set()

            response = await asyncio.wait_for(slow, _TIMEOUT_S)
            assert response.status_code == 200, response.text
            assert response.json()["message"] == "Queued. Thank you."

    asyncio.run(scenario())
    assert submitter.recipients == [[_SLOW_RECIPIENT], ["admin@wersdoerfer.de"]]


def test_admission_rejects_before_body_or_mime_but_not_health(
    app_state: AppState,
    homepage_token: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="mailgun_relay.access")
    submitter = GatedSubmitter()

    async def scenario() -> None:
        async with _client(app_state, submitter, smtp_max_concurrency=1) as client:
            path = "/v3/mg.wersdoerfer.de/messages"
            slow = asyncio.create_task(
                client.post(path, headers=_auth(homepage_token), data=_form(_SLOW_RECIPIENT))
            )
            try:
                await _wait_entered(submitter)

                async def unread_body() -> AsyncIterator[bytes]:
                    raise AssertionError("overloaded request body was read")
                    yield b"x" * 524_288

                with monkeypatch.context() as patch:
                    patch.setattr(
                        "mailgun_relay.routes.build_message",
                        lambda *_: pytest.fail("overloaded request built MIME"),
                    )
                    for _ in range(3):
                        response = await asyncio.wait_for(
                            client.post(
                                path,
                                headers={
                                    **_auth(homepage_token),
                                    "Content-Type": "application/x-www-form-urlencoded",
                                },
                                content=unread_body(),
                            ),
                            _TIMEOUT_S,
                        )
                        assert response.status_code == 503
                        assert response.json() == {"message": "Relay busy; retry later"}
                health = await asyncio.wait_for(client.get("/health"), _TIMEOUT_S)
                assert health.status_code == 200
                assert submitter.recipients == [[_SLOW_RECIPIENT]]
            finally:
                submitter.release.set()
            assert (await asyncio.wait_for(slow, _TIMEOUT_S)).status_code == 200
            # The permit is returned after submission, allowing a retry.
            assert (
                await client.post(
                    path, headers=_auth(homepage_token), data=_form("admin@wersdoerfer.de")
                )
            ).status_code == 200

    asyncio.run(scenario())
    assert submitter.recipients == [[_SLOW_RECIPIENT], ["admin@wersdoerfer.de"]]
    overloaded = [
        record for record in caplog.records if getattr(record, "result", None) == "overloaded"
    ]
    assert len(overloaded) == 3
    assert all(
        getattr(record, "status_code", None) == 503
        and getattr(record, "error_class", None) == "AdmissionLimitError"
        for record in overloaded
    )


@pytest.mark.parametrize(
    ("category", "status", "message"),
    [
        (FailureCategory.TEMPORARY, 503, "Upstream SMTP temporarily unavailable"),
        (FailureCategory.PERMANENT, 502, "Upstream SMTP rejected the message"),
    ],
)
def test_smtp_errors_from_the_worker_thread_keep_their_mapping(
    app_state: AppState,
    homepage_token: str,
    category: FailureCategory,
    status: int,
    message: str,
) -> None:
    submitter = GatedSubmitter(raise_with=SmtpSubmitError(category, reason="test"))
    submitter.release.set()

    async def scenario() -> httpx.Response:
        async with _client(app_state, submitter) as client:
            return await client.post(
                "/v3/mg.wersdoerfer.de/messages",
                headers=_auth(homepage_token),
                data=_form(_SLOW_RECIPIENT),
            )

    response = asyncio.run(scenario())
    assert response.status_code == status
    assert response.json() == {"message": message}


def test_smtp_max_concurrency_must_be_positive(test_settings: Settings) -> None:
    with pytest.raises(ValueError, match="smtp_max_concurrency"):
        Settings(**{**test_settings.model_dump(), "smtp_max_concurrency": 0})


@pytest.mark.parametrize("failure", ["validation", "mime", "smtp"])
def test_admission_is_returned_after_failures(
    app_state: AppState, homepage_token: str, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    submitter = GatedSubmitter()
    submitter.release.set()

    async def scenario() -> None:
        async with _client(app_state, submitter, smtp_max_concurrency=1) as client:
            path = "/v3/mg.wersdoerfer.de/messages"
            form = _form("recipient@example.test")
            with monkeypatch.context() as patch:
                if failure == "validation":
                    form.pop("subject")
                elif failure == "mime":

                    def fail(*args: object) -> None:
                        raise RuntimeError("synthetic MIME failure")

                    patch.setattr("mailgun_relay.routes.build_message", fail)
                else:
                    submitter.raise_with = RuntimeError("synthetic SMTP failure")
                    form = _form(_SLOW_RECIPIENT)
                for _ in range(3):
                    response = await client.post(path, headers=_auth(homepage_token), data=form)
                    assert response.status_code == (400 if failure == "validation" else 500)
            submitter.raise_with = None
            response = await client.post(
                path, headers=_auth(homepage_token), data=_form("recipient@example.test")
            )
            assert response.status_code == 200

    asyncio.run(scenario())


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_cancelled_send_keeps_admission_until_worker_and_form_cleanup_finish(
    app_state: AppState,
    homepage_token: str,
    monkeypatch: pytest.MonkeyPatch,
    cleanup_fails: bool,
) -> None:
    submitter = GatedSubmitter()
    parsed_forms: list[FormData] = []
    closed_forms: list[FormData] = []
    parse = routes._parse_form
    close = routes._close_form
    run_sync = anyio.to_thread.run_sync
    finished_workers: list[bool] = []

    async def checkpoint_after_worker(*args: Any, **kwargs: Any) -> Any:
        result = await run_sync(*args, **kwargs)
        if isinstance(args[0], functools.partial) and args[0].func is submitter:
            finished_workers.append(True)
            # Deliver pending cancellation after AnyIO's worker shield exits,
            # forcing the route to unwind through its cleanup finally blocks.
            await anyio.lowlevel.checkpoint()
        return result

    def capture(form: FormData, settings: Settings) -> routes._ParsedForm:
        parsed_forms.append(form)
        return parse(form, settings)

    async def close_form(form: FormData) -> None:
        # Make cleanup genuinely asynchronous so cancellation must be shielded.
        await anyio.lowlevel.checkpoint()
        closed_forms.append(form)
        await close(form)

    monkeypatch.setattr(routes, "_parse_form", capture)
    monkeypatch.setattr(routes, "_close_form", close_form)
    monkeypatch.setattr(anyio.to_thread, "run_sync", checkpoint_after_worker)
    if cleanup_fails:
        close_upload = UploadFile.close

        async def failing_close(upload: UploadFile) -> None:
            await anyio.lowlevel.checkpoint()
            await close_upload(upload)
            raise OSError("synthetic cleanup failure")

        monkeypatch.setattr(UploadFile, "close", failing_close)

    async def scenario() -> None:
        scopes: list[anyio.CancelScope] = []
        done = anyio.Event()
        responses: list[httpx.Response] = []
        async with _client(app_state, submitter, smtp_max_concurrency=1) as client:
            path = "/v3/mg.wersdoerfer.de/messages"

            async def send() -> None:
                with anyio.CancelScope() as scope:
                    scopes.append(scope)
                    responses.append(
                        await client.post(
                            path,
                            headers=_auth(homepage_token),
                            data=_form(_SLOW_RECIPIENT),
                            files={"attachment": ("synthetic.txt", b"invented attachment")},
                        )
                    )
                done.set()

            with anyio.fail_after(_TIMEOUT_S):
                async with anyio.create_task_group() as group:
                    group.start_soon(send)
                    try:
                        await _wait_entered(submitter)
                        [form] = parsed_forms
                        [upload] = [v for _, v in form.multi_items() if isinstance(v, UploadFile)]
                        # Parsing already read the bytes into an Attachment and closed
                        # the spool. Request-level form cleanup still waits for SMTP.
                        assert upload.file.closed
                        scopes[0].cancel()
                        busy = await client.post(
                            path,
                            headers=_auth(homepage_token),
                            data=_form("retry@example.test"),
                        )
                        assert busy.status_code == 503
                        assert (await client.get("/health")).status_code == 200
                        assert not done.is_set()
                        assert closed_forms == []
                        assert submitter.recipients == [[_SLOW_RECIPIENT]]
                    finally:
                        submitter.release.set()
                    await done.wait()
                assert scopes[0].cancelled_caught
                assert responses == []
                assert finished_workers == [True]
                assert len(closed_forms) == 1 and closed_forms[0] is form
                assert upload.file.closed
                retry = await client.post(
                    path,
                    headers=_auth(homepage_token),
                    data=_form("retry@example.test"),
                )
                assert retry.status_code == 200
                assert len(closed_forms) == 2
                assert closed_forms[1] is parsed_forms[1]
                assert submitter.recipients == [[_SLOW_RECIPIENT], ["retry@example.test"]]

    anyio.run(scenario)
