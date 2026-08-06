"""Tests for the v1 response envelope and middleware headers."""

from __future__ import annotations

from app.main import app
from fastapi.testclient import TestClient


def test_ping_returns_envelope() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/ping")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["data"] == "pong"
    assert payload["error"] is None
    assert len(payload["request_id"]) == 32


def test_request_id_is_echoed() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/ping", headers={"X-Request-ID": "test-123"})
    assert response.headers["X-Request-ID"] == "test-123"


def test_process_time_header_present() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/ping")
    assert response.headers["X-Process-Time"]


def test_security_headers_set() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/ping")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_phase5_endpoints_require_auth() -> None:
    with TestClient(app) as client:
        packets_response = client.get("/api/v1/packets")
        alerts_response = client.get("/api/v1/alerts")
        rules_response = client.get("/api/v1/rules")
        iocs_response = client.get("/api/v1/iocs")
    assert packets_response.status_code == 401
    assert alerts_response.status_code == 401
    assert rules_response.status_code == 401
    assert iocs_response.status_code == 401
