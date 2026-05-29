from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_does_not_disclose_version(client: TestClient) -> None:
    # The version must not be exposed to unauthenticated callers.
    response = client.get("/health")
    assert "version" not in response.json()
