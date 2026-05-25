from __future__ import annotations

from fastapi import FastAPI

from mailgun_relay.routes import register_routes
from mailgun_relay.version import __version__


def create_app() -> FastAPI:
    app = FastAPI(
        title="mailgun-relay",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    register_routes(app)
    return app


app = create_app()
