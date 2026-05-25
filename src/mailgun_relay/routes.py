from __future__ import annotations

from fastapi import FastAPI

from mailgun_relay.version import __version__


def register_routes(app: FastAPI) -> None:
    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}
