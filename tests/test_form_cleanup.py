"""Parsed multipart uploads are owned by the request on every exit path."""

from __future__ import annotations

import asyncio
import base64
import io
import tempfile
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import FormData, UploadFile

from mailgun_relay import routes
from mailgun_relay.config import Settings
from tests.conftest import RecordingSubmitter


def test_form_cleanup_drains_uploads_before_propagating_task_cancellation() -> None:
    async def scenario() -> None:
        entered = asyncio.Event()
        release = asyncio.Event()
        attempts: list[UploadFile] = []

        class TrackedUpload(UploadFile):
            async def close(self) -> None:
                attempts.append(self)
                if self.filename == "first.txt":
                    entered.set()
                    await release.wait()
                await super().close()
                if self.filename == "second.txt":
                    raise OSError("synthetic upload close failure")

        with io.BytesIO() as first, io.BytesIO() as second, io.BytesIO() as third:
            uploads = [
                TrackedUpload(first, filename="first.txt"),
                TrackedUpload(second, filename="second.txt"),
                TrackedUpload(third, filename="third.txt"),
            ]
            form = FormData([("attachment", upload) for upload in uploads])
            async with asyncio.timeout(5):
                cleanup = asyncio.create_task(routes._close_form(form))
                try:
                    await entered.wait()
                    cleanup.cancel("primary cancellation")
                    await asyncio.sleep(0)
                    cleanup.cancel("second cancellation")
                    await asyncio.sleep(0)
                    finished_before_release = cleanup.done()
                finally:
                    release.set()
                with pytest.raises(asyncio.CancelledError, match=r"^primary cancellation$"):
                    await cleanup

            assert not finished_before_release
            assert attempts == uploads
            assert first.closed and second.closed and third.closed

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "outcome", ["bad_field", "oversized", "parse_error", "mime_error", "smtp_error", "success"]
)
def test_all_spooled_uploads_close(
    client: TestClient,
    homepage_token: str,
    test_settings: Settings,
    recording_smtp: RecordingSubmitter,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    uploads: list[UploadFile] = []
    close_attempts: list[UploadFile] = []

    def track_close(upload: UploadFile, spool: tempfile.SpooledTemporaryFile[bytes]) -> None:
        close = spool.close

        def recorded_close() -> None:
            close_attempts.append(upload)
            close()

        monkeypatch.setattr(spool, "close", recorded_close)

    parse = routes._parse_form

    def capture(form: FormData, settings: Settings) -> routes._ParsedForm:
        uploads.extend(value for _, value in form.multi_items() if isinstance(value, UploadFile))
        # Exercise disk-backed spools without platform-specific paths or sizes.
        for upload in uploads:
            assert isinstance(upload.file, tempfile.SpooledTemporaryFile)
            upload.file.rollover()
            track_close(upload, upload.file)
        if outcome == "parse_error":
            raise RuntimeError("synthetic parse failure")
        return parse(form, settings)

    def fail(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(routes, "_parse_form", capture)
    if outcome == "mime_error":
        monkeypatch.setattr(routes, "build_message", fail)
    elif outcome == "smtp_error":
        recording_smtp.raise_with = RuntimeError("synthetic SMTP failure")
    fields = [
        ("from", (None, "jochen-homepage@wersdoerfer.de")),
        ("to", (None, "recipient@example.test")),
        ("subject", (None, "fixture")),
        ("text", (None, "body")),
    ]
    if outcome == "bad_field":
        fields.insert(0, ("unsupported", (None, "value")))
    second = (
        b"x" * (test_settings.max_attachment_bytes + 1) if outcome == "oversized" else b"second"
    )
    files = [
        ("attachment", ("a.txt", b"first")),
        ("attachment", ("b.txt", second)),
        ("inline", ("c.txt", b"third")),
    ]
    response = client.post(
        "/v3/mg.wersdoerfer.de/messages",
        headers={
            "Authorization": "Basic " + base64.b64encode(f"api:{homepage_token}".encode()).decode()
        },
        files=[*fields, *files],
    )
    expected = {
        "bad_field": 400,
        "oversized": 413,
        "parse_error": 500,
        "mime_error": 500,
        "smtp_error": 500,
        "success": 200,
    }
    assert response.status_code == expected[outcome], response.text
    assert len(uploads) == 3
    try:
        assert close_attempts == uploads
        assert all(upload.file.closed for upload in uploads)
    finally:
        for upload in uploads:
            if not upload.file.closed:
                upload.file.close()
    if outcome == "success":
        parts = list(recording_smtp.calls[0].message.iter_attachments())
        assert {part.get_filename(): part.get_payload(decode=True) for part in parts} == {
            "a.txt": b"first",
            "b.txt": b"second",
            "c.txt": b"third",
        }
