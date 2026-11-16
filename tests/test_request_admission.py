"""Only complete, unambiguous HTTP forms may reach SMTP."""

from __future__ import annotations

import base64
import tempfile
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette import formparsers

from tests.conftest import RecordingSubmitter


def multipart() -> bytes:
    parts = [
        ("from", None, "jochen-homepage@wersdoerfer.de"),
        ("to", None, "recipient@example.test"),
        ("subject", None, "synthetic subject"),
        ("text", None, "synthetic body"),
        ("attachment", "complete.txt", "first upload"),
        ("attachment", "truncated.txt", "second upload"),
    ]
    body = b""
    for name, filename, value in parts:
        disposition = f'Content-Disposition: form-data; name="{name}"'
        if filename:
            disposition += f'; filename="{filename}"'
        body += f"--admission\r\n{disposition}\r\n\r\n{value}\r\n".encode()
    return body + b"--admission--\r\n"


@pytest.mark.parametrize("ending", ["upload", "boundary", "dash", "complete", "epilogue"])
def test_multipart_completion_before_smtp(
    client: TestClient,
    homepage_token: str,
    recording_smtp: RecordingSubmitter,
    monkeypatch: pytest.MonkeyPatch,
    ending: str,
) -> None:
    spools: list[Any] = []

    def spool(*args: Any, **kwargs: Any) -> Any:
        file = tempfile.SpooledTemporaryFile(*args, **kwargs)
        file.rollover()
        spools.append(file)
        return file

    monkeypatch.setattr(formparsers, "SpooledTemporaryFile", spool)
    body = multipart()
    if ending == "upload":
        body = body[: body.index(b"second upload") + 6]
    elif ending == "boundary":
        body = body[:-6]
    elif ending == "dash":
        body = body[:-3]
    elif ending == "epilogue":
        body += b"valid epilogue"
    response = client.post(
        "/v3/mg.wersdoerfer.de/messages",
        headers={
            "Authorization": "Basic " + base64.b64encode(f"api:{homepage_token}".encode()).decode(),
            "Content-Type": "multipart/form-data; boundary=admission",
        },
        content=body,
    )
    try:
        complete = ending in {"complete", "epilogue"}
        assert response.status_code == (200 if complete else 400), response.text
        if not complete:
            assert response.json() == {"message": "malformed form"}
        assert len(recording_smtp.calls) == int(complete)
        assert len(spools) == 2
        assert all(file.closed for file in spools)
    finally:
        for file in spools:
            file.close()
