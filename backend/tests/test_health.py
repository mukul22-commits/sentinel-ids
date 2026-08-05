"""Smoke tests for system endpoints (/health, /health/ready, /health/live)."""

from __future__ import annotations

from app.main import app
from fastapi.testclient import TestClient


def test_health_returns_ok() -> None:
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["version"] == "3.0.0"


def test_health_reports_service_connectivity() -> None:
    with TestClient(app) as client:
        response = client.get("/health")
    payload = response.json()
    assert payload["database"] in {"connected", "disconnected"}
    assert payload["redis"] in {"connected", "disconnected"}


def test_health_ready_reports_state() -> None:
    with TestClient(app) as client:
        response = client.get("/health/ready")
    assert response.status_code in {200, 503}
    payload = response.json()
    assert payload["status"] in {"ready", "not_ready"}
    assert "database" in payload
    assert "redis" in payload


def test_health_live_returns_alive() -> None:
    with TestClient(app) as client:
        response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "alive", "version": "3.0.0"}
