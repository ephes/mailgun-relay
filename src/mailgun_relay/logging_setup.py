from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

_ACCESS_LOGGER_NAME = "mailgun_relay.access"
_SERVICE_LOGGER_NAME = "mailgun_relay.service"


class _JsonFormatter(logging.Formatter):
    """Minimal JSON log formatter that emits exactly the structured `extra` dict.

    We intentionally do not include the raw `msg` template or args — only the
    explicit structured fields callers attach via `extra=`.
    """

    def format(self, record: logging.LogRecord) -> str:
        event = record.event if hasattr(record, "event") else record.getMessage()
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "event": event,
        }
        for key, value in record.__dict__.items():
            if key in _LOG_RECORD_RESERVED or key == "event":
                continue
            payload[key] = value
        return json.dumps(payload, default=str, separators=(",", ":"))


_LOG_RECORD_RESERVED = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "taskName",
}


_FALLBACK_LINE = b'{"event":"diagnostic_logging_failed"}\n'


def _write_fallback() -> None:
    # Never recurse through the broken handler, format the exception or copy
    # record fields into the fallback. Even stderr may be unavailable.
    try:
        os.write(2, _FALLBACK_LINE)
    except OSError:
        pass


class _IsolatedStreamHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """StreamHandler whose formatter/stream failures stay payload-free.

    The stdlib `Handler.handleError` prints the exception and traceback (which
    may echo record fields) to stderr. Formatter, filter-on-handler and stream
    write errors land here, so replace that with the fixed fallback line.
    """

    def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802 - stdlib API
        _write_fallback()


def configure_logging(level: str = "INFO") -> None:
    """Send structured JSON records to stdout, one flushed line per record.

    `logging.StreamHandler.emit` flushes the stream after every record, so each
    line reaches the reader (journald, a pipe, a container log collector) as
    soon as it is logged. Block buffering of stdout therefore cannot delay or
    swallow these lines, and no `PYTHONUNBUFFERED` is required for them —
    `tests/test_logging.py` pins that property so it is not "fixed" again by
    guesswork.
    """
    handler = _IsolatedStreamHandler(stream=sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())


def access_logger() -> logging.Logger:
    return logging.getLogger(_ACCESS_LOGGER_NAME)


def service_logger() -> logging.Logger:
    """Logger for lifecycle and transport diagnostics without request context."""
    return logging.getLogger(_SERVICE_LOGGER_NAME)


def log_safely(logger: logging.Logger, level: int, event: str, *, extra: dict[str, Any]) -> None:
    """Keep diagnostic sink failures outside the delivery decision path."""
    try:
        logger.log(level, event, extra=extra)
    except Exception:
        _write_fallback()
