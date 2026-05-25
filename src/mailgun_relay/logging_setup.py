from __future__ import annotations

import json
import logging
import sys
from typing import Any

_ACCESS_LOGGER_NAME = "mailgun_relay.access"


class _JsonFormatter(logging.Formatter):
    """Minimal JSON log formatter that emits exactly the structured `extra` dict.

    We intentionally do not include the raw `msg` template or args — only the
    explicit structured fields callers attach via `extra=`.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "event": getattr(record, "event", record.getMessage()),
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


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())


def access_logger() -> logging.Logger:
    return logging.getLogger(_ACCESS_LOGGER_NAME)
