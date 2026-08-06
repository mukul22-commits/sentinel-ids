"""Tests for the Prometheus /metrics endpoint."""

from __future__ import annotations

from app.main import app
from fastapi.testclient import TestClient


def test_metrics_endpoint_exposes_sentinel_metrics() -> None:
    with TestClient(app) as client:
        response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    body = response.text
    assert "sentinel_app_info" in body
    assert 'app="sentinel-ids"' in body
    assert "sentinel_alerts_created_total" in body
