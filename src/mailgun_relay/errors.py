from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RelayErrorInfo:
    status_code: int
    public_message: str


class MailgunRelayError(Exception):
    """Base for errors that map to a deterministic Mailgun-shaped HTTP response."""

    info: RelayErrorInfo = RelayErrorInfo(500, "Internal Server Error")


class BadRequestError(MailgunRelayError):
    info = RelayErrorInfo(400, "bad request")

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.info = RelayErrorInfo(400, message)


class UnauthorizedError(MailgunRelayError):
    info = RelayErrorInfo(401, "Unauthorized")


class ForbiddenError(MailgunRelayError):
    info = RelayErrorInfo(403, "Forbidden")

    def __init__(self, message: str = "Forbidden") -> None:
        super().__init__(message)
        self.info = RelayErrorInfo(403, message)


class PayloadTooLargeError(MailgunRelayError):
    info = RelayErrorInfo(413, "Payload Too Large")


class SmtpPermanentError(MailgunRelayError):
    info = RelayErrorInfo(502, "Upstream SMTP rejected the message")


class SmtpTemporaryError(MailgunRelayError):
    info = RelayErrorInfo(503, "Upstream SMTP temporarily unavailable")
