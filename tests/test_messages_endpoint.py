from __future__ import annotations

import base64
import io
import json
import logging
import tomllib
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mailgun_relay.app import create_app
from mailgun_relay.logging_setup import _JsonFormatter, access_logger
from mailgun_relay.routes import AppState
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
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form())
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
    r = client.post("/v3/mg.wersdoerfer.de/messages", data=_minimum_form())
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate") == 'Basic realm="MG API"'


def test_auth_wrong_password_returns_401(client: TestClient) -> None:
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages",
        headers={"Authorization": basic("api", "nope")},
        data=_minimum_form(),
    )
    assert r.status_code == 401


def test_auth_wrong_username_returns_401(client: TestClient, homepage_token: str) -> None:
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages",
        headers={"Authorization": basic("notapi", homepage_token)},
        data=_minimum_form(),
    )
    assert r.status_code == 401


def test_path_domain_not_allowed_returns_403(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post("/v3/evil.test/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 403


def test_homepage_uses_cross_domain_path_and_from(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    """Production homepage uses cross-domain policy: path subdomain != from domain.

    This pins the shipped shape so a future refactor that conflates the two
    domains (or that copy-pastes a same-domain example into SOPS) fails fast.
    """
    # Path subdomain: mg.wersdoerfer.de (Mailgun sender domain).
    # From-domain: wersdoerfer.de (the parent — Mailgun lets you send from
    # the parent through a sender subdomain).
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 200, r.text
    sent = recording_smtp.calls[0]
    assert str(sent.message["From"]).endswith("@wersdoerfer.de>")


def test_homepage_parent_domain_as_path_returns_403(
    client: TestClient, auth: dict[str, str]
) -> None:
    """Regression guard: POST to /v3/wersdoerfer.de/messages must 403.

    The pre-deploy plan-doc value used `wersdoerfer.de` as path subdomain.
    The shipped token policy is strict: only `mg.wersdoerfer.de` is in
    `mailgun_domains`. Any operator who copies the old example into SOPS
    will see this 403 — the test exists so the production policy shape
    cannot quietly regress to that wrong value.
    """
    r = client.post("/v3/wersdoerfer.de/messages", headers=auth, data=_minimum_form())
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
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
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
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 403


def test_unsupported_o_field_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages",
        headers=auth,
        data=_with({"o:tag": ["foo"]}),
    )
    assert r.status_code == 400


def test_unsupported_v_field_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages",
        headers=auth,
        data=_with({"v:userid": ["xyz"]}),
    )
    assert r.status_code == 400


def test_template_field_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages",
        headers=auth,
        data=_with({"template": ["welcome"]}),
    )
    assert r.status_code == 400


def test_recipient_variables_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages",
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
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 400


def test_dangerous_h_bcc_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages",
        headers=auth,
        data=_with({"h:Bcc": ["evil@x.com"]}),
    )
    assert r.status_code == 400


def test_reply_to_header_propagates(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages",
        headers=auth,
        data=_with({"h:Reply-To": ["support@wersdoerfer.de"]}),
    )
    assert r.status_code == 200, r.text
    assert recording_smtp.calls[0].message["Reply-To"] == "support@wersdoerfer.de"


def test_reply_to_with_quoted_comma_in_display_name(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages",
        headers=auth,
        data=_with({"h:Reply-To": ['"Doe, Jane" <support@wersdoerfer.de>']}),
    )
    assert r.status_code == 200, r.text
    assert "support@wersdoerfer.de" in str(recording_smtp.calls[0].message["Reply-To"])


def test_reply_to_with_multiple_addresses(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages",
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
        "/v3/mg.wersdoerfer.de/messages",
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
        "/v3/mg.wersdoerfer.de/messages",
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
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 503


def test_smtp_permanent_returns_502(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    recording_smtp.raise_with = SmtpSubmitError(FailureCategory.PERMANENT, reason="rejected")
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 502


def test_smtp_auth_returns_502(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    recording_smtp.raise_with = SmtpSubmitError(FailureCategory.AUTH, reason="bad creds")
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 502


def test_attachment_accepted(
    client: TestClient, auth: dict[str, str], recording_smtp: RecordingSubmitter
) -> None:
    files = [("attachment", ("hello.txt", b"hello attachment", "text/plain"))]
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form(), files=files
    )
    assert r.status_code == 200, r.text
    sent = recording_smtp.calls[0]
    serialized = bytes(sent.message)
    assert b"hello.txt" in serialized


def test_attachment_too_big_returns_413(client: TestClient, auth: dict[str, str]) -> None:
    too_big = b"x" * 600_000
    files = [("attachment", ("big.bin", too_big, "application/octet-stream"))]
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form(), files=files
    )
    assert r.status_code == 413


def test_too_many_attachments_returns_413(client: TestClient, auth: dict[str, str]) -> None:
    files = [("attachment", (f"f{i}.txt", b"x", "text/plain")) for i in range(4)]
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form(), files=files
    )
    assert r.status_code == 413


def test_far_too_many_attachments_still_returns_413(
    client: TestClient, auth: dict[str, str]
) -> None:
    """A flood well past max_files hits starlette's cap; must still be 413, not 400."""
    files = [("attachment", (f"f{i}.txt", b"x", "text/plain")) for i in range(20)]
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form(), files=files
    )
    assert r.status_code == 413, r.text


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
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 400


def test_no_body_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    form = {
        "from": ["Jochen <jochen-homepage@wersdoerfer.de>"],
        "to": ["admin@wersdoerfer.de"],
        "subject": ["hi"],
    }
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 400


def test_huge_text_returns_413(client: TestClient, auth: dict[str, str], app_state: object) -> None:
    # tests/conftest.py sets max_body_bytes=1_048_576; exceed it with text.
    form = {
        "from": ["Jochen <jochen-homepage@wersdoerfer.de>"],
        "to": ["admin@wersdoerfer.de"],
        "subject": ["x"],
        "text": ["A" * 2_000_000],
    }
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 413


def test_inline_counts_toward_max_attachments_returns_413(
    client: TestClient, auth: dict[str, str]
) -> None:
    # max_attachments=3 in the test settings.
    files = [("inline", (f"f{i}.txt", b"x", "text/plain")) for i in range(4)]
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form(), files=files
    )
    assert r.status_code == 413


def test_mixed_attachment_inline_counts_toward_max_attachments(
    client: TestClient, auth: dict[str, str]
) -> None:
    # 2 attachments + 2 inlines = 4 > max_attachments(3)
    files = [("attachment", (f"a{i}.txt", b"x", "text/plain")) for i in range(2)] + [
        ("inline", (f"i{i}.txt", b"x", "text/plain")) for i in range(2)
    ]
    r = client.post(
        "/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form(), files=files
    )
    assert r.status_code == 413


@pytest.mark.parametrize("bad_from", ["not-an-email", "bad@bad domain"])
def test_malformed_from_address_returns_400(
    client: TestClient, auth: dict[str, str], bad_from: str
) -> None:
    """A malformed sender is a bad request (400), not an authorization failure (403)."""
    form = {"from": [bad_from], "to": ["admin@wersdoerfer.de"], "subject": ["x"], "text": ["y"]}
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 400, r.text


def test_injected_from_crlf_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    """CRLF in `from` is header injection → 400, not silently reinterpreted to 403."""
    form = {
        "from": ["jochen-homepage@wersdoerfer.de\nBcc: evil@wersdoerfer.de"],
        "to": ["admin@wersdoerfer.de"],
        "subject": ["x"],
        "text": ["y"],
    }
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 400, r.text


def test_malformed_to_address_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    form = {
        "from": ["Jochen <jochen-homepage@wersdoerfer.de>"],
        "to": ["bad@bad domain"],
        "subject": ["x"],
        "text": ["body"],
    }
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
    assert r.status_code == 400


def test_malformed_reply_to_returns_400(client: TestClient, auth: dict[str, str]) -> None:
    form = _with({"h:Reply-To": ["bad@bad domain"]})
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=form)
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
        r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form())
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


# --- Partial recipient refusal ------------------------------------------------


def _partial_form() -> dict[str, list[str]]:
    form = _minimum_form()
    form["to"] = ["admin@wersdoerfer.de", "gone-user@Example.org"]
    form["bcc"] = ["hidden-user@example.net"]
    return form


@pytest.fixture
def access_log_lines() -> Iterator[io.StringIO]:
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(_JsonFormatter())
    log = access_logger()
    saved_handlers = list(log.handlers)
    saved_propagate = log.propagate
    saved_level = log.level
    log.handlers = [handler]
    log.setLevel(logging.INFO)
    log.propagate = False
    try:
        yield buf
    finally:
        handler.flush()
        log.handlers = saved_handlers
        log.propagate = saved_propagate
        log.setLevel(saved_level)


def _records(buf: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line.strip()]


def test_partial_refusal_answers_200_and_reports_refusals_in_logs(
    client: TestClient,
    auth: dict[str, str],
    recording_smtp: RecordingSubmitter,
    access_log_lines: io.StringIO,
) -> None:
    recording_smtp.refused = {
        "gone-user@Example.org": (550, b"5.1.1 <gone-user@Example.org>: no such user"),
        "hidden-user@example.net": (450, b"4.2.0 <hidden-user@example.net>: greylisted"),
    }
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=_partial_form())

    # Mailgun-compatible: the message was accepted for the other recipient, so
    # the body keeps the exact shape Anymail parses, and a retry would only
    # duplicate it.
    assert r.status_code == 200, r.text
    assert r.json()["message"] == "Queued. Thank you."

    out = access_log_lines.getvalue()
    # Local parts of refused recipients are personal data and never logged,
    # neither directly nor through the SMTP reply text that echoes them.
    assert "gone-user" not in out
    assert "hidden-user" not in out
    assert "no such user" not in out

    records = _records(access_log_lines)
    warning = next(rec for rec in records if rec.get("event") == "recipients_refused")
    request = next(rec for rec in records if rec.get("event") == "request")
    assert warning["level"] == "WARNING"
    assert warning["refused_count"] == 2
    assert warning["recipient_count"] == 3
    assert warning["refused"] == [
        {"domain": "example.net", "code": 450},
        {"domain": "example.org", "code": 550},
    ]
    assert warning["request_id"] == request["request_id"]
    assert warning["message_id"] == request["message_id"] == r.json()["id"]
    assert request["refused_count"] == 2
    assert request["recipient_count"] == 3
    assert request["result"] == "partial_refusal"
    assert request["status_code"] == 200


def test_full_acceptance_logs_zero_refusals(
    client: TestClient,
    auth: dict[str, str],
    access_log_lines: io.StringIO,
) -> None:
    r = client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 200, r.text
    records = _records(access_log_lines)
    assert not any(rec.get("event") == "recipients_refused" for rec in records)
    request = next(rec for rec in records if rec.get("event") == "request")
    assert request["refused_count"] == 0
    assert request["result"] == "ok"


@pytest.fixture
def strict_client(app_state: AppState) -> Iterator[TestClient]:
    settings = app_state.settings.model_copy(update={"fail_on_partial_refusal": True})
    app = create_app(app_state=replace(app_state, settings=settings))
    with TestClient(app) as tc:
        yield tc


def test_partial_refusal_answers_502_when_configured(
    strict_client: TestClient,
    auth: dict[str, str],
    recording_smtp: RecordingSubmitter,
    access_log_lines: io.StringIO,
) -> None:
    recording_smtp.refused = {"gone-user@example.org": (550, b"no")}
    r = strict_client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=_partial_form())
    assert r.status_code == 502
    body = r.json()
    assert set(body) == {"message"}
    assert "1 of 3" in body["message"]
    assert "gone-user" not in body["message"]
    # The message was still handed to SMTP once; the relay does not retry.
    assert len(recording_smtp.calls) == 1

    records = _records(access_log_lines)
    assert any(rec.get("event") == "recipients_refused" for rec in records)
    request = next(rec for rec in records if rec.get("event") == "request")
    assert request["status_code"] == 502
    assert request["result"] == "partial_refusal"
    assert request["refused_count"] == 1


def test_strict_mode_full_acceptance_still_200(
    strict_client: TestClient,
    auth: dict[str, str],
) -> None:
    r = strict_client.post("/v3/mg.wersdoerfer.de/messages", headers=auth, data=_minimum_form())
    assert r.status_code == 200, r.text


def test_mypy_without_arguments_checks_the_tests() -> None:
    """`uv run mypy` (README, CI) relies on pyproject's `files` list."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    config = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    files = config["tool"]["mypy"]["files"]
    assert "tests" in files
    assert "src/mailgun_relay" in files
