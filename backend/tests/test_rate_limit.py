"""Integration test for the slowapi rate-limit decorator and 429 envelope."""

from __future__ import annotations

from app.core.config import settings
from app.core.limiter import limiter, rate_limit_exceeded_handler
from fastapi import FastAPI, Request
from slowapi.errors import RateLimitExceeded
from starlette.testclient import TestClient


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/limited")
    @limiter.limit(settings.RATE_LIMIT_AUTH)
    async def limited(request: Request) -> dict[str, bool]:
        return {"ok": True}

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    return app


# Built once so the limit is registered a single time against the shared
# ``limiter`` singleton (re-decorating would double-count each request).
APP = _build_app()


class TestAuthRateLimit:
    def test_sixth_request_returns_429(self) -> None:
        headers = {"X-Forwarded-For": "10.0.0.1"}
        with TestClient(APP, raise_server_exceptions=False) as c:
            for _ in range(5):
                assert c.get("/limited", headers=headers).status_code == 200
            response = c.get("/limited", headers=headers)
        assert response.status_code == 429
        body = response.json()
        assert body["success"] is False
        assert "Rate limit" in body["error"]

    def test_limit_is_per_client_ip(self) -> None:
        with TestClient(APP, raise_server_exceptions=False) as c:
            for _ in range(5):
                assert c.get("/limited", headers={"X-Forwarded-For": "10.0.0.2"}).status_code == 200
            assert c.get("/limited", headers={"X-Forwarded-For": "10.0.0.2"}).status_code == 429
            assert c.get("/limited", headers={"X-Forwarded-For": "10.0.0.3"}).status_code == 200
