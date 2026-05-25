from __future__ import annotations

from fastapi import FastAPI

from mailgun_relay.config import Settings, load_secrets
from mailgun_relay.logging_setup import configure_logging
from mailgun_relay.routes import AppState, register_routes
from mailgun_relay.smtp_client import SmtpTransport
from mailgun_relay.version import __version__


def _app_state_from_settings(settings: Settings) -> AppState:
    secrets = load_secrets(settings.secrets_path)
    transport = SmtpTransport(
        host=settings.smtp_host,
        port=settings.smtp_port,
        username=secrets.smtp.username,
        password=secrets.smtp.password,
        use_starttls=settings.smtp_starttls,
        timeout_s=settings.smtp_timeout_s,
    )
    return AppState(settings=settings, secrets=secrets, transport=transport)


def create_app(app_state: AppState | None = None) -> FastAPI:
    app = FastAPI(
        title="mailgun-relay",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    register_routes(app)
    if app_state is None:
        configure_logging()
        app_state = _app_state_from_settings(Settings())
    app.state.app_state = app_state
    return app
