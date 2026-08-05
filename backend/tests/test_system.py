"""Tests for /api/v1/system endpoints."""

from __future__ import annotations

from app.main import app
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient


def test_system_info() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/system/info")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["data"]["app"] == "Sentinel IDS Platform"
    assert payload["data"]["version"] == "3.0.0"
    assert payload["data"]["environment"] == "test"
    assert isinstance(payload["data"]["uptime_seconds"], int)


def test_system_stats_envelope() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/system/stats")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["data"]["version"] == "3.0.0"
    assert payload["data"]["uptime_seconds"] >= 0
    assert response.headers["X-Cache"] in {"HIT", "MISS"}


async def test_system_stats_cache_hit(monkeypatch) -> None:
    store: dict[str, object] = {}

    async def fake_get(key: str) -> object | None:
        return store.get(key)

    async def fake_set(key: str, value: object, ttl: int | None = None) -> bool:
        store[key] = value
        return True

    monkeypatch.setattr("app.services.cache.get_json", fake_get)
    monkeypatch.setattr("app.services.cache.set_json", fake_set)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.get("/api/v1/system/stats")
        second = await client.get("/api/v1/system/stats")
    assert first.headers["X-Cache"] == "MISS"
    assert second.headers["X-Cache"] == "HIT"
    assert first.json()["data"] == second.json()["data"]
