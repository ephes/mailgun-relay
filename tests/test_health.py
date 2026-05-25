from __future__ import annotations

from fastapi.testclient import TestClient

from mailgun_relay.version import __version__


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}
