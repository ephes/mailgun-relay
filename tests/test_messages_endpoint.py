from __future__ import annotations

import base64
import io
import json
import logging

import pytest
from fastapi.testclient import TestClient

from mailgun_relay.logging_setup import _JsonFormatter, access_logger
from mailgun_relay.smtp_client import FailureCategory, SmtpSubmitError
from tests.conftest import RecordingSubmitter


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode("ascii")


@pytest.fixture
def auth(homepage_token: str) -> dict[str, str]:
    return {"Authorization": basic("api", homepage_token)}


@pytest.fixture
def podcast_auth(podcast_token: str) -> dict[str, str]:
    return {"Authorization": basic("api", podcast_token)}


def _minimum_form() -> dict[str, list[str]]:
    return {
        "from": ["Jochen <jochen-homepage@wersdoerfer.de>"],
        "to": ["admin@wersdoerfer.de"],
        "subject": ["hi"],
        "text": ["hello"],
    }


def _with(extra: dict[str, list[str]]) -> dict[str, list[str]]:
    f = _minimum_form()
    for k, vs in extra.items():
        f.setdefault(k, []).extend(vs)
    return f


def test_happy_path_returns_queued(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["message"] == "Queued. Thank you."
    assert body["id"].startswith("<") and body["id"].endswith("@mailgun.home.xn--wersdrfer-47a.de>")
    assert len(recording_smtp.calls) == 1
    sent = recording_smtp.calls[0]
    assert sent.envelope_sender == "mailgun-relay@xn--wersdrfer-47a.de"
    assert sent.recipients == ["admin@wersdoerfer.de"]
    assert sent.message["Message-Id"] == body["id"]


def test_auth_missing_returns_401_with_realm(client: TestClient) -> None:
    r = client.post("/v3/wersdoerfer.de/messages", data=_minimum_form())
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate") == 'Basic realm="MG API"'


def test_auth_wrong_password_returns_401(client: TestClient) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers={"Authorization": basic("api", "nope")},
        data=_minimum_form(),
    )
    assert r.status_code == 401


def test_auth_wrong_username_returns_401(client: TestClient, homepage_token: str) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers={"Authorization": basic("notapi", homepage_token)},
        data=_minimum_form(),
    )
    assert r.status_code == 401


def test_path_domain_not_allowed_returns_403(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post("/v3/evil.test/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 403


def test_from_address_outside_allowlist_returns_403(
    client: TestClient, auth: dict[str, str]
) -> None:
    form = {
        "from": ["Someone Else <someone-else@wersdoerfer.de>"],
        "to": ["admin@wersdoerfer.de"],
        "subject": ["hi"],
        "text": ["hello"],
    }
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 403


def test_from_domain_outside_allowlist_returns_403(
    client: TestClient, auth: dict[str, str]
) -> None:
    form = {
        "from": ["Someone <someone@other.test>"],
        "to": ["admin@wersdoerfer.de"],
        "subject": ["hi"],
        "text": ["hello"],
    }
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 403


def test_unsupported_o_field_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers=auth,
        data=_with({"o:tag": ["foo"]}),
    )
    assert r.status_code == 400


def test_unsupported_v_field_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers=auth,
        data=_with({"v:userid": ["xyz"]}),
    )
    assert r.status_code == 400


def test_template_field_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers=auth,
        data=_with({"template": ["welcome"]}),
    )
    assert r.status_code == 400


def test_recipient_variables_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers=auth,
        data=_with({"recipient-variables": ["{}"]}),
    )
    assert r.status_code == 400


def test_subject_crlf_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    form = {
        "from": ["Jochen <jochen-homepage@wersdoerfer.de>"],
        "to": ["admin@wersdoerfer.de"],
        "subject": ["hi\nBcc: evil@x.com"],
        "text": ["hello"],
    }
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 400


def test_dangerous_h_bcc_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers=auth,
        data=_with({"h:Bcc": ["evil@x.com"]}),
    )
    assert r.status_code == 400


def test_reply_to_header_propagates(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers=auth,
        data=_with({"h:Reply-To": ["support@wersdoerfer.de"]}),
    )
    assert r.status_code == 200, r.text
    assert recording_smtp.calls[0].message["Reply-To"] == "support@wersdoerfer.de"


def test_reply_to_with_quoted_comma_in_display_name(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers=auth,
        data=_with({"h:Reply-To": ['"Doe, Jane" <support@wersdoerfer.de>']}),
    )
    assert r.status_code == 200, r.text
    assert "support@wersdoerfer.de" in str(recording_smtp.calls[0].message["Reply-To"])


def test_reply_to_with_multiple_addresses(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers=auth,
        data=_with({"h:Reply-To": ["a@wersdoerfer.de, b@wersdoerfer.de"]}),
    )
    assert r.status_code == 200, r.text
    rt = str(recording_smtp.calls[0].message["Reply-To"])
    assert "a@wersdoerfer.de" in rt
    assert "b@wersdoerfer.de" in rt


def test_bcc_only_envelope_not_in_headers(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers=auth,
        data=_with({"bcc": ["secret@wersdoerfer.de"]}),
    )
    assert r.status_code == 200, r.text
    sent = recording_smtp.calls[0]
    assert set(sent.recipients) == {"admin@wersdoerfer.de", "secret@wersdoerfer.de"}
    assert sent.message.get("Bcc") is None
    serialized = bytes(sent.message)
    assert b"secret@wersdoerfer.de" not in serialized


def test_cc_in_headers_and_envelope(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    r = client.post(
        "/v3/wersdoerfer.de/messages",
        headers=auth,
        data=_with({"cc": ["copied@wersdoerfer.de"]}),
    )
    assert r.status_code == 200, r.text
    sent = recording_smtp.calls[0]
    assert "copied@wersdoerfer.de" in str(sent.message["Cc"])
    assert "copied@wersdoerfer.de" in sent.recipients


def test_smtp_temporary_returns_503(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    recording_smtp.raise_with = SmtpSubmitError(FailureCategory.TEMPORARY, reason="busy")
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 503


def test_smtp_permanent_returns_502(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    recording_smtp.raise_with = SmtpSubmitError(FailureCategory.PERMANENT, reason="rejected")
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 502


def test_smtp_auth_returns_502(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    recording_smtp.raise_with = SmtpSubmitError(FailureCategory.AUTH, reason="bad creds")
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 502


def test_attachment_accepted(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    files = [("attachment", ("hello.txt", b"hello attachment", "text/plain"))]
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=_minimum_form(), files=files)
    assert r.status_code == 200, r.text
    sent = recording_smtp.calls[0]
    serialized = bytes(sent.message)
    assert b"hello.txt" in serialized


def test_attachment_too_big_returns_413(client: TestClient, auth: dict[str, str]) -> None:
    too_big = b"x" * 600_000
    files = [("attachment", ("big.bin", too_big, "application/octet-stream"))]
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=_minimum_form(), files=files)
    assert r.status_code == 413


def test_too_many_attachments_returns_413(client: TestClient, auth: dict[str, str]) -> None:
    files = [("attachment", (f"f{i}.txt", b"x", "text/plain")) for i in range(4)]
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=_minimum_form(), files=files)
    assert r.status_code == 413


def test_python_podcast_token_uses_its_own_path(
    client: TestClient, podcast_auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    form = {
        "from": ["Python Podcast <noreply@mg.python-podcast.de>"],
        "to": ["jochen-pythonpodcast@wersdoerfer.de"],
        "subject": ["ack"],
        "text": ["body"],
    }
    r = client.post("/v3/mg.python-podcast.de/messages", headers=podcast_auth, data=form)
    assert r.status_code == 200, r.text
    sent = recording_smtp.calls[0]
    assert sent.envelope_sender == "mailgun-relay@xn--wersdrfer-47a.de"
    assert sent.message["From"] == "Python Podcast <noreply@mg.python-podcast.de>"


def test_homepage_token_cannot_use_podcast_domain(client: TestClient, auth: dict[str, str]) -> None:
    form = {
        "from": ["Python Podcast <noreply@mg.python-podcast.de>"],
        "to": ["anyone@wersdoerfer.de"],
        "subject": ["hi"],
        "text": ["hi"],
    }
    r = client.post("/v3/mg.python-podcast.de/messages", headers=auth, data=form)
    assert r.status_code == 403


def test_no_recipients_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    form = {
        "from": ["Jochen <jochen-homepage@wersdoerfer.de>"],
        "subject": ["hi"],
        "text": ["hello"],
    }
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 400


def test_no_body_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    form = {
        "from": ["Jochen <jochen-homepage@wersdoerfer.de>"],
        "to": ["admin@wersdoerfer.de"],
        "subject": ["hi"],
    }
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 400


def test_huge_text_returns_413(client: TestClient, auth: dict[str, str], app_state: object) -> None:
    # tests/conftest.py sets max_body_bytes=1_048_576; exceed it with text.
    form = {
        "from": ["Jochen <jochen-homepage@wersdoerfer.de>"],
        "to": ["admin@wersdoerfer.de"],
        "subject": ["x"],
        "text": ["A" * 2_000_000],
    }
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 413


def test_inline_counts_toward_max_attachments_returns_413(
    client: TestClient, auth: dict[str, str]
) -> None:
    # max_attachments=3 in the test settings.
    files = [("inline", (f"f{i}.txt", b"x", "text/plain")) for i in range(4)]
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=_minimum_form(), files=files)
    assert r.status_code == 413


def test_mixed_attachment_inline_counts_toward_max_attachments(
    client: TestClient, auth: dict[str, str]
) -> None:
    # 2 attachments + 2 inlines = 4 > max_attachments(3)
    files = [("attachment", (f"a{i}.txt", b"x", "text/plain")) for i in range(2)] + [
        ("inline", (f"i{i}.txt", b"x", "text/plain")) for i in range(2)
    ]
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=_minimum_form(), files=files)
    assert r.status_code == 413


def test_malformed_to_address_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    form = {
        "from": ["Jochen <jochen-homepage@wersdoerfer.de>"],
        "to": ["bad@bad domain"],
        "subject": ["x"],
        "text": ["body"],
    }
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 400


def test_malformed_reply_to_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    form = _with({"h:Reply-To": ["bad@bad domain"]})
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 400


def test_path_domain_logged_as_punycode(
    client: TestClient,
    auth: dict[str, str],
    homepage_token: str,
) -> None:
    """A request whose path uses a U-label should still log the A-label."""
    import io as _io
    import logging as _logging

    buf = _io.StringIO()
    handler = _logging.StreamHandler(buf)
    handler.setFormatter(_JsonFormatter())
    log = access_logger()
    saved = list(log.handlers)
    saved_prop = log.propagate
    log.handlers = [handler]
    log.setLevel(_logging.INFO)
    log.propagate = False
    try:
        # Path uses U-label for an unrelated domain; we only assert on the log,
        # not on the response status (policy will reject 403).
        r = client.post(
            "/v3/wersdörfer.de/messages",
            headers=auth,
            data=_minimum_form(),
        )
        assert r.status_code in (200, 403)
    finally:
        handler.flush()
        log.handlers = saved
        log.propagate = saved_prop
    rec = next(json.loads(line) for line in buf.getvalue().splitlines() if line.strip())
    assert rec["path_domain"] == "xn--wersdrfer-47a.de"


def test_log_redacts_token_and_smtp_password(
    client: TestClient,
    auth: dict[str, str],
    homepage_token: str,
) -> None:
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(_JsonFormatter())
    log = access_logger()
    saved_handlers = list(log.handlers)
    saved_propagate = log.propagate
    log.handlers = [handler]
    log.setLevel(logging.INFO)
    log.propagate = False
    try:
        r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=_minimum_form())
        assert r.status_code == 200, r.text
    finally:
        handler.flush()
        log.handlers = saved_handlers
        log.propagate = saved_propagate
    out = buf.getvalue()
    assert homepage_token not in out
    assert "not-a-real-password" not in out
    parsed = [json.loads(line) for line in out.splitlines() if line.strip()]
    rec = next(r for r in parsed if r.get("event") == "request")
    assert rec["token_label"] == "homepage-staging"
    assert rec["recipient_count"] == 1
    assert rec["status_code"] == 200
    assert rec["message_id"].startswith("<")
    assert rec["from"] == "Jochen <jochen-homepage@wersdoerfer.de>"
