from __future__ import annotations

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from enum import StrEnum


class FailureCategory(StrEnum):
    PERMANENT = "permanent"
    TEMPORARY = "temporary"
    AUTH = "auth"


class SmtpSubmitError(Exception):
    """Raised by submit() when SMTP delivery fails.

    The category attribute drives the HTTP status the route returns:
    PERMANENT -> 502, TEMPORARY -> 503, AUTH -> 502.
    Never carries SMTP credentials; only the SMTP server response code/text.
    """

    def __init__(self, category: FailureCategory, *, reason: str) -> None:
        super().__init__(f"smtp submission failed ({category.value}): {reason}")
        self.category = category
        self.reason = reason


@dataclass(frozen=True)
class SmtpTransport:
    host: str
    port: int
    username: str | None
    password: str | None
    use_starttls: bool
    timeout_s: float


_PERMANENT_TYPES: tuple[type[BaseException], ...] = (
    smtplib.SMTPRecipientsRefused,
    smtplib.SMTPSenderRefused,
    smtplib.SMTPHeloError,
)


def _category_for(exc: BaseException) -> FailureCategory:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return FailureCategory.AUTH
    if isinstance(exc, _PERMANENT_TYPES):
        return FailureCategory.PERMANENT
    if isinstance(exc, smtplib.SMTPResponseException):
        code = exc.smtp_code
        if isinstance(code, int) and 400 <= code <= 499:
            return FailureCategory.TEMPORARY
        return FailureCategory.PERMANENT
    if isinstance(exc, smtplib.SMTPServerDisconnected | smtplib.SMTPConnectError):
        return FailureCategory.TEMPORARY
    if isinstance(exc, ConnectionError | TimeoutError | OSError):
        return FailureCategory.TEMPORARY
    return FailureCategory.PERMANENT


def _safe_reason(exc: BaseException) -> str:
    """Stringify exc without leaking credentials.

    smtplib exceptions carry the server's response, not our credentials,
    so this is generally safe — but we keep it defensive.
    """
    cls = type(exc).__name__
    if isinstance(exc, smtplib.SMTPResponseException):
        code = exc.smtp_code
        # exc.smtp_error is bytes
        text = exc.smtp_error
        if isinstance(text, bytes):
            text_str = text.decode("ascii", errors="replace")
        else:
            text_str = str(text)
        return f"{cls}({code}, {text_str})"
    return cls


def submit(
    message: EmailMessage,
    *,
    envelope_sender: str,
    recipients: list[str],
    transport: SmtpTransport,
) -> None:
    """Submit an EmailMessage via authenticated SMTP.

    Uses STARTTLS when transport.use_starttls is True. Raises SmtpSubmitError on any
    SMTP/connection failure; the exception's category drives the HTTP response mapping.
    """
    try:
        with smtplib.SMTP(transport.host, transport.port, timeout=transport.timeout_s) as smtp:
            smtp.ehlo()
            if transport.use_starttls:
                smtp.starttls()
                smtp.ehlo()
            if transport.username is not None and transport.password is not None:
                smtp.login(transport.username, transport.password)
            smtp.send_message(
                message,
                from_addr=envelope_sender,
                to_addrs=recipients,
            )
    except SmtpSubmitError:
        raise
    except BaseException as exc:
        category = _category_for(exc)
        raise SmtpSubmitError(category, reason=_safe_reason(exc)) from exc
