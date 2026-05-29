from __future__ import annotations

import contextlib
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.datastructures import UploadFile

from mailgun_relay.auth import AuthError, authenticate
from mailgun_relay.config import Secrets, Settings
from mailgun_relay.errors import (
    BadRequestError,
    MailgunRelayError,
    PayloadTooLargeError,
)
from mailgun_relay.headers import (
    DangerousHeaderError,
    HeaderInjectionError,
    HeaderTooLongError,
    validate_custom_headers,
    validate_subject,
)
from mailgun_relay.logging_setup import access_logger
from mailgun_relay.mime_build import Attachment, MessageInput, build_message
from mailgun_relay.policy import (
    InvalidAddressError,
    PolicyError,
    enforce_policy,
    normalize_domain,
)
from mailgun_relay.smtp_client import FailureCategory, SmtpSubmitError, SmtpTransport, submit


@dataclass(frozen=True)
class AppState:
    settings: Settings
    secrets: Secrets
    transport: SmtpTransport
    smtp_submit: Any = None  # injected for tests; defaults to `submit`


_KNOWN_FORM_FIELDS = frozenset(
    {"from", "to", "cc", "bcc", "subject", "text", "html", "amp-html", "attachment", "inline"}
)

# Headroom above max_recipients for the non-recipient fields a request may
# legitimately carry (from/subject/text/html/amp-html plus custom h:* headers),
# so the multipart field cap never rejects a well-formed message.
_FORM_FIELD_HEADROOM = 100

# Cap on the attacker-controlled `from` value written to the access log.
_FROM_LOG_MAX_LEN = 320

# Substrings in starlette's MultiPartException messages that mean "too big"
# rather than "malformed", so they map to 413 instead of 400. Matched on the
# stable phrasing; an unexpected wording degrades safely to 400.
_MULTIPART_LIMIT_MARKERS = ("Too many files", "Too many fields", "exceeded maximum size")


def register_routes(app: FastAPI) -> None:
    @app.get("/health")
    def health() -> dict[str, str]:
        # Intentionally does not disclose the service version to unauthenticated
        # callers (avoids handing a CVE-matching hint to anyone who can reach it).
        return {"status": "ok"}

    @app.post("/v3/{domain}/messages")
    async def post_messages(domain: str, request: Request) -> JSONResponse:
        state: AppState = app.state.app_state
        log = access_logger()
        request_id = uuid.uuid4().hex
        start = time.monotonic()

        token_label = "-"  # noqa: S105 - this is a log placeholder, not a password
        from_for_log = "-"
        recipient_count = 0
        message_id: str | None = None
        result = "ok"
        error_class = None
        status_code = 200
        # Normalize for logging up front; falls back to the raw value if
        # normalization fails so the log line still has *something* useful.
        try:
            path_domain_log = normalize_domain(domain)
        except InvalidAddressError:
            path_domain_log = domain

        try:
            policy = authenticate(
                request.headers.get("Authorization"),
                state.secrets.tokens,
            )
            token_label = policy.label

            try:
                # Bound the multipart parser to the relay's own policy so it
                # cannot spool far more parts/bytes than we will ever accept.
                # `max_files` leaves room for the relay's own 413 on the
                # (max_attachments + 1)th file; starlette's cap is a backstop.
                form = await request.form(
                    max_files=state.settings.max_attachments + 1,
                    max_fields=state.settings.max_recipients + _FORM_FIELD_HEADROOM,
                    max_part_size=state.settings.max_body_bytes,
                )
            except PayloadTooLargeError:
                # Raised by the ASGI body-size limit while streaming; preserve 413.
                raise
            except Exception as exc:
                # Starlette converts a MultiPartException into HTTPException(400);
                # its resource-limit variants are really "payload too large", so
                # map those to 413 to match the relay's own count/size limits and
                # the documented contract. Genuinely malformed bodies stay 400.
                detail = getattr(exc, "detail", "") or str(exc)
                if any(marker in detail for marker in _MULTIPART_LIMIT_MARKERS):
                    raise PayloadTooLargeError("request exceeds multipart limits") from exc
                raise BadRequestError(f"malformed multipart form: {type(exc).__name__}") from exc

            parsed = _parse_form(form, state.settings)
            # Cap the logged (attacker-controlled, pre-validation) value so a
            # huge `from` cannot bloat each log line. JSON encoding already
            # neutralizes control chars, so truncation is the only gap left.
            from_for_log = parsed.from_address[:_FROM_LOG_MAX_LEN]

            enforce_policy(
                policy,
                path_domain=domain,
                from_address=parsed.from_address,
            )

            payload = MessageInput(
                from_address=parsed.from_address,
                to=parsed.to,
                cc=parsed.cc,
                bcc=parsed.bcc,
                subject=validate_subject(
                    parsed.subject,
                    max_length=state.settings.max_header_value_length,
                ),
                text=parsed.text,
                html=parsed.html,
                amp_html=parsed.amp_html,
                custom_headers=validate_custom_headers(
                    parsed.custom_headers,
                    max_value_length=state.settings.max_header_value_length,
                ),
                attachments=parsed.attachments,
                inline=parsed.inline,
                public_host=state.settings.public_host,
            )

            envelope_count = len(parsed.to) + len(parsed.cc) + len(parsed.bcc)
            if envelope_count == 0:
                raise BadRequestError("at least one of to/cc/bcc is required")
            if envelope_count > state.settings.max_recipients:
                raise PayloadTooLargeError(
                    f"too many recipients (max {state.settings.max_recipients})"
                )

            msg, message_id, envelope_recipients = build_message(payload)
            recipient_count = len(envelope_recipients)

            submitter = state.smtp_submit or submit
            submitter(
                msg,
                envelope_sender=state.settings.envelope_sender,
                recipients=envelope_recipients,
                transport=state.transport,
            )

            return JSONResponse(
                {"id": message_id, "message": "Queued. Thank you."},
                status_code=200,
            )

        except AuthError as exc:
            error_class = type(exc).__name__
            result = "auth_error"
            status_code = 401
            return _err_response(status_code, "Unauthorized", realm=True)
        except InvalidAddressError as exc:
            # A malformed or injected address is a bad request, not an
            # authorization failure — must precede the PolicyError handler
            # because InvalidAddressError is a PolicyError subclass.
            error_class = type(exc).__name__
            result = "bad_request"
            status_code = 400
            return _err_response(status_code, str(exc))
        except PolicyError as exc:
            error_class = type(exc).__name__
            result = "policy_error"
            status_code = 403
            return _err_response(status_code, str(exc))
        except (
            BadRequestError,
            HeaderInjectionError,
            HeaderTooLongError,
            DangerousHeaderError,
        ) as exc:
            error_class = type(exc).__name__
            result = "bad_request"
            status_code = 400
            return _err_response(status_code, str(exc))
        except PayloadTooLargeError as exc:
            error_class = type(exc).__name__
            result = "too_large"
            status_code = 413
            return _err_response(status_code, str(exc))
        except SmtpSubmitError as exc:
            error_class = type(exc).__name__
            if exc.category is FailureCategory.TEMPORARY:
                result = "smtp_temporary"
                status_code = 503
                msg_out = "Upstream SMTP temporarily unavailable"
            else:
                result = "smtp_permanent"
                status_code = 502
                msg_out = "Upstream SMTP rejected the message"
            return _err_response(status_code, msg_out)
        except MailgunRelayError as exc:
            error_class = type(exc).__name__
            result = "error"
            status_code = exc.info.status_code
            return _err_response(status_code, exc.info.public_message)
        except Exception as exc:
            error_class = type(exc).__name__
            result = "internal_error"
            status_code = 500
            return _err_response(status_code, "Internal Server Error")
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            log.info(
                "request",
                extra={
                    "event": "request",
                    "request_id": request_id,
                    "token_label": token_label,
                    "path_domain": path_domain_log,
                    "from": from_for_log,
                    "recipient_count": recipient_count,
                    "message_id": message_id or "-",
                    "result": result,
                    "status_code": status_code,
                    "error_class": error_class,
                    "duration_ms": duration_ms,
                },
            )


def _err_response(status_code: int, message: str, *, realm: bool = False) -> JSONResponse:
    headers = {"WWW-Authenticate": 'Basic realm="MG API"'} if realm else None
    return JSONResponse({"message": message}, status_code=status_code, headers=headers)


@dataclass
class _ParsedForm:
    from_address: str
    to: list[str]
    cc: list[str]
    bcc: list[str]
    subject: str
    text: str | None
    html: str | None
    amp_html: str | None
    custom_headers: dict[str, str]
    attachments: list[Attachment]
    inline: list[Attachment]


def _parse_form(form: Any, settings: Settings) -> _ParsedForm:
    from_addresses: list[str] = []
    to: list[str] = []
    cc: list[str] = []
    bcc: list[str] = []
    subject: str | None = None
    text: str | None = None
    html: str | None = None
    amp_html: str | None = None
    custom_headers: dict[str, str] = {}
    attachments: list[Attachment] = []
    inline: list[Attachment] = []

    total_body_bytes = 0

    def _track_text(field_name: str, content: str) -> str:
        nonlocal total_body_bytes
        total_body_bytes += len(content.encode("utf-8"))
        if total_body_bytes > settings.max_body_bytes:
            raise PayloadTooLargeError(
                f"aggregate body size exceeds {settings.max_body_bytes} bytes ({field_name})"
            )
        return content

    for key, value in form.multi_items():
        # Reject metadata/variable namespaces wholesale.
        if key.startswith(("v:", "o:", "t:")) or key == "recipient-variables" or key == "template":
            raise BadRequestError(f"unsupported field: {key}")
        if key.startswith("h:"):
            if not isinstance(value, str):
                raise BadRequestError(f"header {key} must be a string")
            custom_headers[key[2:]] = value
            continue

        if key not in _KNOWN_FORM_FIELDS:
            raise BadRequestError(f"unknown field: {key}")

        if key == "from":
            from_addresses.append(_require_str(key, value))
        elif key == "to":
            to.append(_require_str(key, value))
        elif key == "cc":
            cc.append(_require_str(key, value))
        elif key == "bcc":
            bcc.append(_require_str(key, value))
        elif key == "subject":
            subject = _require_str(key, value)
        elif key == "text":
            text = _track_text("text", _require_str(key, value))
        elif key == "html":
            html = _track_text("html", _require_str(key, value))
        elif key == "amp-html":
            amp_html = _track_text("amp-html", _require_str(key, value))
        elif key in {"attachment", "inline"}:
            att = _read_upload(value, settings)
            total_body_bytes += len(att.data)
            if total_body_bytes > settings.max_body_bytes:
                raise PayloadTooLargeError(
                    f"aggregate body size exceeds {settings.max_body_bytes} bytes"
                )
            if key == "attachment":
                attachments.append(att)
            else:
                inline.append(att)
            # max_attachments caps the combined attachment + inline file count;
            # both occupy MIME parts in the outgoing message.
            if len(attachments) + len(inline) > settings.max_attachments:
                raise PayloadTooLargeError(
                    f"too many attachments+inline (max {settings.max_attachments})"
                )

    if len(from_addresses) != 1:
        raise BadRequestError("exactly one 'from' is required")
    if subject is None:
        raise BadRequestError("subject is required")
    if text is None and html is None:
        raise BadRequestError("at least one of 'text' or 'html' is required")

    return _ParsedForm(
        from_address=from_addresses[0],
        to=to,
        cc=cc,
        bcc=bcc,
        subject=subject,
        text=text,
        html=html,
        amp_html=amp_html,
        custom_headers=custom_headers,
        attachments=attachments,
        inline=inline,
    )


def _require_str(key: str, value: object) -> str:
    if not isinstance(value, str):
        raise BadRequestError(f"field {key!r} must be a string")
    return value


def _read_upload(value: object, settings: Settings) -> Attachment:
    if not isinstance(value, UploadFile):
        raise BadRequestError("attachment/inline must be an uploaded file")
    try:
        # Determine the spooled size before pulling the whole file into memory,
        # so an oversized attachment is rejected without a large allocation.
        fileobj = value.file
        fileobj.seek(0, os.SEEK_END)
        size = fileobj.tell()
        fileobj.seek(0)
        if size > settings.max_attachment_bytes:
            raise PayloadTooLargeError(f"attachment {value.filename!r} exceeds max size")
        data = fileobj.read()
        content_type = value.content_type or "application/octet-stream"
        return Attachment(
            filename=value.filename or "attachment",
            content_type=content_type,
            data=data,
        )
    finally:
        with contextlib.suppress(Exception):
            value.file.close()
