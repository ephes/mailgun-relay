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


@pytest.mark.parametrize("header", ["Authorization", "Content-Type"])
@pytest.mark.parametrize("identical", [True, False])
@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("mixed_case", [True, False])
def test_duplicate_http_singletons_before_body_and_admission(
    client: TestClient,
    homepage_token: str,
    recording_smtp: RecordingSubmitter,
    monkeypatch: pytest.MonkeyPatch,
    header: str,
    identical: bool,
    reverse: bool,
    mixed_case: bool,
) -> None:
    from mailgun_relay import routes

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("ambiguous request reached body parsing or admission")

    monkeypatch.setattr(routes, "_read_form", forbidden)
    monkeypatch.setattr(routes, "CapacityLimiter", forbidden)
    auth = "Basic " + base64.b64encode(f"api:{homepage_token}".encode()).decode()
    first = auth if header == "Authorization" else "application/x-www-form-urlencoded"
    second = (
        first if identical else ("Basic invalid" if header == "Authorization" else "text/plain")
    )
    values = [first, second]
    if reverse:
        values.reverse()
    headers = [(header, values[0]), (header.lower() if mixed_case else header, values[1])]
    if header == "Content-Type":
        headers.append(("Authorization", auth))
    else:
        headers.append(("Content-Type", "application/x-www-form-urlencoded"))
    response = client.post(
        "/v3/mg.wersdoerfer.de/messages", headers=headers, content=b"synthetic body"
    )
    assert response.status_code == 400, response.text
    assert response.json() == {"message": "duplicate singleton HTTP header"}
    assert not recording_smtp.calls


@pytest.mark.parametrize("over_limit", [True, False])
def test_multipart_limit_before_later_framing_error(
    client: TestClient,
    homepage_token: str,
    recording_smtp: RecordingSubmitter,
    monkeypatch: pytest.MonkeyPatch,
    over_limit: bool,
) -> None:
    spools: list[Any] = []

    def spool(*args: Any, **kwargs: Any) -> Any:
        file = tempfile.SpooledTemporaryFile(*args, **kwargs)
        spools.append(file)
        return file

    monkeypatch.setattr(formparsers, "SpooledTemporaryFile", spool)
    files = 6 if over_limit else 2
    body = b"".join(
        f'--admission\r\nContent-Disposition: form-data; name="attachment"; '
        f'filename="f{index}.txt"\r\n\r\nupload {index}\r\n'.encode()
        for index in range(files)
    )
    # A later part whose header name holds an invalid token character.
    body += b"--admission\r\nBad Header: x\r\n\r\nvalue\r\n--admission--\r\n"
    response = client.post(
        "/v3/mg.wersdoerfer.de/messages",
        headers={
            "Authorization": "Basic " + base64.b64encode(f"api:{homepage_token}".encode()).decode(),
            "Content-Type": "multipart/form-data; boundary=admission",
        },
        content=body,
    )
    try:
        if over_limit:
            assert response.status_code == 413, response.text
            assert response.json() == {"message": "request exceeds multipart limits"}
        else:
            assert response.status_code == 400, response.text
            assert response.json() == {"message": "malformed form"}
        assert not recording_smtp.calls
        assert spools and all(file.closed for file in spools)
    finally:
        for file in spools:
            file.close()
