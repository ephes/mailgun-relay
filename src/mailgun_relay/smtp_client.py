from __future__ import annotations

import contextlib
import io
import logging
import math
import smtplib
import socket
import ssl
import sys
import threading
import time
from collections.abc import Buffer
from dataclasses import dataclass
from email.message import EmailMessage
from enum import StrEnum
from typing import Any

from mailgun_relay.logging_setup import log_safely, service_logger


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


# Recipients the SMTP server refused while still accepting the message for the
# others: address -> (SMTP reply code, reply text). This is exactly what
# ``smtplib.SMTP.send_message`` returns; it only *raises* when every recipient
# is refused.
RefusedRecipients = dict[str, tuple[int, bytes]]


@dataclass(frozen=True)
class SmtpTransport:
    host: str
    port: int
    username: str | None
    password: str | None
    use_starttls: bool
    timeout_s: float
    # Optional path to a CA bundle used to verify the SMTP server certificate.
    # Empty/None means "use the system trust store". Verification is always on;
    # there is deliberately no switch to disable certificate validation.
    ca_file: str | None = None
    session_timeout_s: float = 120.0

    def __post_init__(self) -> None:
        if not math.isfinite(self.session_timeout_s) or not 0 < self.session_timeout_s <= 1e9:
            raise ValueError("session_timeout_s must be finite and in (0, 1e9]")


class _SocketDeadline:
    """Interrupt only this session's socket, including a STARTTLS handshake.

    A duplicate descriptor keeps ownership stable while SSL detaches/replaces
    smtplib's socket. shutdown(), unlike close(), wakes a blocked file read.
    Fence the timer before joining it or relinquishing the duplicate.
    """

    def __init__(self, seconds: float) -> None:
        self.ends_at = time.monotonic() + seconds
        self.expired = False
        self.stopped = False
        self.socket: socket.socket | None = None
        self.lock = threading.Lock()
        self.timer = threading.Timer(seconds, self._expire)
        self.timer.daemon = True

    def __enter__(self) -> _SocketDeadline:
        self.timer.start()
        return self

    def _expire(self) -> None:
        with self.lock:
            if self.stopped:
                return
            self.expired = True
            if self.socket is not None:
                with contextlib.suppress(OSError):
                    self.socket.shutdown(socket.SHUT_RDWR)

    def remaining(self, inactivity: float) -> float:
        left = self.ends_at - time.monotonic()
        if left <= 0 or self.expired:
            raise TimeoutError("SMTP session deadline")
        return min(left, inactivity)

    def watch(self, sock: socket.socket) -> None:
        with self.lock:
            previous, self.socket = self.socket, None
            if previous is not None:
                previous.close()
            self.socket = sock.dup()
            self.remaining(1e9)

    def stop(self) -> None:
        # Once fenced, the callback cannot touch the socket even if cancel
        # or join is interrupted. Context exit does not retry either call.
        with self.lock:
            if self.stopped:
                return
            self.stopped = True
        self.timer.cancel()
        self.timer.join()

    def __exit__(self, *args: object) -> None:
        try:
            self.stop()
        finally:
            with self.lock:
                watched, self.socket = self.socket, None
            if watched is not None:
                with contextlib.suppress(OSError):
                    watched.close()


class _ReplyReader(io.BufferedReader):
    def readline(self, size: int | None = -1, /) -> bytes:
        line = super().readline(size)
        # shutdown can yield a reply prefix followed by EOF. Leave lines at
        # the size limit to smtplib's existing overlong-line handling.
        if line and not line.endswith(b"\n") and (size is None or size < 0 or len(line) < size):
            raise ConnectionError("incomplete SMTP reply line")
        return line


class _SessionSMTP(smtplib.SMTP):
    """Use smtplib's public connect/reply boundary with one owned TCP budget."""

    def __init__(self, host: str, port: int, *, timeout: float, budget: _SocketDeadline) -> None:
        self.budget = budget
        self.inactivity_timeout = timeout
        try:
            super().__init__(host, port, timeout=budget.remaining(timeout))
        except BaseException:
            with contextlib.suppress(smtplib.SMTPException, OSError):
                self.close()
            raise

    def connect(
        self,
        host: str = "localhost",
        port: int = 0,
        source_address: tuple[Any, ...] | str | Buffer | None = None,
    ) -> tuple[int, bytes]:
        # libc resolution cannot be interrupted by socket shutdown. Charge its
        # elapsed time and refuse a late result before creating any connection.
        self.budget.remaining(self.inactivity_timeout)
        # SMTP.starttls uses the hostname stored by connect for SNI and
        # verification, independently of the resolved TCP address.
        self._host = host
        sys.audit("smtplib.connect", self, host, port)
        addresses = socket.getaddrinfo(host, port or smtplib.SMTP_PORT, type=socket.SOCK_STREAM)
        error: OSError | None = None
        for family, kind, proto, _, address in addresses:
            timeout = self.budget.remaining(self.inactivity_timeout)
            sock = socket.socket(family, kind, proto)
            try:
                self.budget.watch(sock)
                sock.settimeout(timeout)
                if source_address is not None:
                    sock.bind(source_address)
                sock.connect(address)
                # shutdown can race a not-yet-connected TCP socket. Never
                # start reading a greeting from a connection returned late.
                self.budget.remaining(self.inactivity_timeout)
            except OSError as exc:
                with contextlib.suppress(OSError):
                    sock.close()
                error = exc
                continue
            except BaseException:
                with contextlib.suppress(OSError):
                    sock.close()
                raise
            self.sock = sock
            self.file = None
            return self.getreply()
        if error is not None:
            raise error
        raise OSError("no SMTP addresses")

    def getreply(self) -> tuple[int, bytes]:
        if self.file is None and self.sock is not None:
            self.file = _ReplyReader(self.sock.makefile("rb", buffering=0))
        return super().getreply()


def _tls_context(transport: SmtpTransport) -> ssl.SSLContext:
    """Build a verifying TLS context (CERT_REQUIRED + hostname check).

    ``smtplib`` passes ``server_hostname=transport.host`` into the TLS
    handshake, so ``create_default_context`` gives both chain verification and
    hostname matching for free. A private-CA deployment can point ``ca_file`` at
    its bundle; we never disable verification.
    """
    context = ssl.create_default_context()
    if transport.ca_file:
        context.load_verify_locations(cafile=transport.ca_file)
    return context


def _category_for(exc: BaseException) -> FailureCategory:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return FailureCategory.AUTH
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        # No DATA was accepted. A temporary refusal anywhere makes retry useful,
        # including a mixture of temporary and permanent recipient refusals.
        if any(400 <= code <= 499 for code, _reply in exc.recipients.values()):
            return FailureCategory.TEMPORARY
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
) -> RefusedRecipients:
    """Submit an EmailMessage via authenticated SMTP.

    Uses STARTTLS when transport.use_starttls is True. Raises SmtpSubmitError on any
    SMTP/connection failure before acceptance; the category drives the HTTP response.
    Operational teardown failures do not change an accepted submission outcome.
    Supervisor/control-flow exceptions propagate after owned socket cleanup.

    Returns the recipients the server refused while accepting the message for
    the rest (empty when every recipient was accepted). A refusal of *all*
    recipients is not returned: smtplib raises SMTPRecipientsRefused, which
    becomes a temporary error if any reply is 4xx, otherwise permanent.
    """
    smtp: smtplib.SMTP | None = None
    budget: _SocketDeadline | None = None
    try:
        with _SocketDeadline(transport.session_timeout_s) as budget:
            smtp = _SessionSMTP(
                transport.host, transport.port, timeout=transport.timeout_s, budget=budget
            )
            try:
                budget.remaining(transport.timeout_s)
                smtp.ehlo()
                tls_active = False
                if transport.use_starttls:
                    # Verify the server certificate and hostname; raises on a
                    # server that does not advertise STARTTLS (downgrade attempt).
                    budget.remaining(transport.timeout_s)
                    smtp.starttls(context=_tls_context(transport))
                    budget.remaining(transport.timeout_s)
                    smtp.ehlo()
                    tls_active = True
                if transport.username is not None and transport.password is not None:
                    if not tls_active:
                        # Never transmit SMTP credentials over an unencrypted
                        # channel — fail closed instead of leaking them in cleartext.
                        raise SmtpSubmitError(
                            FailureCategory.PERMANENT,
                            reason="refusing to send SMTP credentials over a non-TLS connection",
                        )
                    budget.remaining(transport.timeout_s)
                    smtp.login(transport.username, transport.password)
                budget.remaining(transport.timeout_s)
                refused = smtp.send_message(
                    message,
                    from_addr=envelope_sender,
                    to_addrs=recipients,
                )
            finally:
                # QUIT and its timer are optional once the send has an outcome.
                try:
                    budget.stop()
                    # smtplib already closes on 421 and connection loss.
                    if smtp.sock is not None and not budget.expired:
                        with _SocketDeadline(min(transport.timeout_s, 5.0)) as cleanup:
                            if budget.socket is not None:
                                cleanup.watch(budget.socket)
                            smtp.sock.settimeout(min(transport.timeout_s, 5.0))
                            code, reply = smtp.quit()
                            cleanup.remaining(transport.timeout_s)
                            if code != 221:
                                raise smtplib.SMTPResponseException(code, reply)
                except (smtplib.SMTPException, OSError, RuntimeError) as exc:
                    log_safely(
                        service_logger(),
                        logging.WARNING,
                        "smtp_cleanup_failed",
                        extra={
                            "event": "smtp_cleanup_failed",
                            "error_class": type(exc).__name__,
                        },
                    )
                finally:
                    try:
                        smtp.close()
                    except (smtplib.SMTPException, OSError) as exc:
                        log_safely(
                            service_logger(),
                            logging.WARNING,
                            "smtp_cleanup_failed",
                            extra={
                                "event": "smtp_cleanup_failed",
                                "error_class": type(exc).__name__,
                            },
                        )
    except SmtpSubmitError:
        raise
    except Exception as exc:
        if budget is not None and budget.expired:
            # Preserve the temporary classification for failed operations
            # interrupted by the session timer.
            raise SmtpSubmitError(FailureCategory.TEMPORARY, reason="TimeoutError") from exc
        category = _category_for(exc)
        raise SmtpSubmitError(category, reason=_safe_reason(exc)) from exc
    return dict(refused)
