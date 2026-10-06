from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterator
from io import StringIO

import pytest

from mailgun_relay.app import log_startup
from mailgun_relay.config import Secrets, Settings
from mailgun_relay.logging_setup import access_logger, configure_logging
from mailgun_relay.version import __version__


class _FlushCountingStream(StringIO):
    """A stdout stand-in that counts how often it is flushed."""

    def __init__(self) -> None:
        super().__init__()
        self.flush_count = 0

    def flush(self) -> None:
        self.flush_count += 1
        super().flush()


@pytest.fixture(autouse=True)
def restore_root_logger() -> Iterator[None]:
    """Keep `configure_logging`'s global mutation from leaking into other tests."""
    root = logging.getLogger()
    previous_handlers = list(root.handlers)
    previous_level = root.level
    try:
        yield
    finally:
        root.handlers = previous_handlers
        root.setLevel(previous_level)


def _configure_logging_to_stream(
    monkeypatch: pytest.MonkeyPatch, level: str
) -> _FlushCountingStream:
    """Run the real `configure_logging` against a capturable stdout.

    It binds the handler to whatever `sys.stdout` is at call time, so patching
    stdout first exercises the production handler and formatter rather than a
    test double. This must happen inside the test body: pytest's own capture
    reassigns `sys.stdout` between the fixture-setup and call phases, so a
    patch applied during setup would be overwritten.
    """
    stream = _FlushCountingStream()
    monkeypatch.setattr(sys, "stdout", stream)
    configure_logging(level)
    return stream


def test_each_record_is_flushed_to_stdout_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    """Records must not sit in a userspace buffer waiting for the process to exit.

    Under systemd, stdout is a pipe to journald and therefore block-buffered.
    `logging.StreamHandler.emit` flushes after every record, which is what makes
    the relay's log lines show up in the journal in real time. This test pins
    that guarantee: if it ever regresses, the relay silently goes dark instead
    of only looking that way.
    """
    stream = _configure_logging_to_stream(monkeypatch, "INFO")
    access_logger().info("request", extra={"event": "request", "result": "ok"})

    assert stream.flush_count >= 1
    assert json.loads(stream.getvalue().strip())["event"] == "request"


def test_startup_line_records_effective_configuration(
    monkeypatch: pytest.MonkeyPatch,
    test_settings: Settings,
    test_secrets: Secrets,
) -> None:
    stream = _configure_logging_to_stream(monkeypatch, test_settings.log_level)
    log_startup(test_settings, test_secrets)

    payload = json.loads(stream.getvalue().strip())
    assert payload["event"] == "startup"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "mailgun_relay.service"
    assert payload["version"] == __version__
    assert payload["bind"] == f"{test_settings.bind_host}:{test_settings.bind_port}"
    assert payload["smtp_host"] == test_settings.smtp_host
    assert payload["smtp_port"] == test_settings.smtp_port
    assert payload["smtp_starttls"] is test_settings.smtp_starttls
    assert payload["smtp_custom_ca"] is False
    assert payload["smtp_max_concurrency"] == test_settings.smtp_max_concurrency
    assert payload["fail_on_partial_refusal"] is False
    assert payload["token_labels"] == ["homepage-staging", "python-podcast-staging"]


def test_startup_line_survives_a_raised_log_level(
    monkeypatch: pytest.MonkeyPatch,
    test_settings: Settings,
    test_secrets: Secrets,
) -> None:
    """Quietening the access log must not remove the "is logging alive" anchor."""
    stream = _configure_logging_to_stream(monkeypatch, "WARNING")
    access_logger().info("request", extra={"event": "request", "result": "ok"})
    log_startup(test_settings, test_secrets)

    lines = stream.getvalue().splitlines()
    assert len(lines) == 1, "the INFO access record should have been filtered out"
    payload = json.loads(lines[0])
    assert payload["event"] == "startup"
    assert payload["level"] == "WARNING"


def test_startup_line_never_leaks_credentials(
    monkeypatch: pytest.MonkeyPatch,
    test_settings: Settings,
    test_secrets: Secrets,
) -> None:
    stream = _configure_logging_to_stream(monkeypatch, test_settings.log_level)
    log_startup(test_settings, test_secrets)

    line = stream.getvalue()
    assert test_secrets.smtp.password not in line
    assert test_secrets.smtp.username not in line
    for policy in test_secrets.tokens:
        assert policy.token_sha256 not in line
