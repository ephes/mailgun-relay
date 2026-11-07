from __future__ import annotations

import os
from unittest.mock import Mock

import pytest

from mailgun_relay.__main__ import main


@pytest.fixture(autouse=True)
def startup_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("MAILGUN_RELAY_"):
            monkeypatch.delenv(name)
    # Inherited, unrelated credentials must not be dumped by main().
    monkeypatch.setenv("MAILGUN_RELAY_SMTP_PASSWORD", "synthetic-private-password")
    monkeypatch.setenv("MAILGUN_RELAY_API_KEY", "synthetic-private-credential")


@pytest.mark.parametrize(
    ("environment", "host", "port", "level"),
    [
        ({}, "127.0.0.1", 8085, "info"),
        (
            {
                "MAILGUN_RELAY_BIND_HOST": "localhost",
                "MAILGUN_RELAY_BIND_PORT": "9091",
                "MAILGUN_RELAY_LOG_LEVEL": "WARNING",
            },
            "localhost",
            9091,
            "warning",
        ),
    ],
)
def test_startup_arguments(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    environment: dict[str, str],
    host: str,
    port: int,
    level: str,
) -> None:
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    run = Mock()
    monkeypatch.setattr("mailgun_relay.__main__.uvicorn.run", run)
    main()
    run.assert_called_once_with(
        "mailgun_relay.app:create_app",
        factory=True,
        host=host,
        port=port,
        log_level=level,
        access_log=False,
    )
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_invalid_port_never_starts_server(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MAILGUN_RELAY_BIND_PORT", "not-an-integer")
    run = Mock()
    monkeypatch.setattr("mailgun_relay.__main__.uvicorn.run", run)
    with pytest.raises(ValueError):
        main()
    run.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
