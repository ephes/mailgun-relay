"""Parsed multipart uploads are owned by the request on every exit path."""

from __future__ import annotations

import base64
import tempfile
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import FormData, UploadFile

from mailgun_relay import routes
from mailgun_relay.config import Settings
from tests.conftest import RecordingSubmitter


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
    parse = routes._parse_form

    def capture(form: FormData, settings: Settings) -> routes._ParsedForm:
        uploads.extend(value for _, value in form.multi_items() if isinstance(value, UploadFile))
        # Exercise disk-backed spools without platform-specific paths or sizes.
        for upload in uploads:
            assert isinstance(upload.file, tempfile.SpooledTemporaryFile)
            upload.file.rollover()
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
    first = b"x" * (test_settings.max_attachment_bytes + 1) if outcome == "oversized" else b"first"
    files = [
        ("attachment", ("a.txt", first)),
        ("attachment", ("b.txt", b"second")),
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
        assert all(upload.file.closed for upload in uploads)
    finally:
        for upload in uploads:
            upload.file.close()
    if outcome == "success":
        parts = list(recording_smtp.calls[0].message.iter_attachments())
        assert {part.get_filename(): part.get_payload(decode=True) for part in parts} == {
            "a.txt": b"first",
            "b.txt": b"second",
            "c.txt": b"third",
        }
