"""Direct tests for the auth/RBAC/sensor dependencies in ``deps.py``."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from app.api.v1 import deps
from app.api.v1.deps import (
    get_current_sensor,
    get_ws_current_user,
    require_permission,
    require_roles,
)
from fastapi import HTTPException, WebSocketException
from starlette.requests import Request


def _http_request(headers: dict[str, str] | None = None) -> Request:
    encoded = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": encoded,
        "client": ("127.0.0.1", 54321),
        "server": ("testserver", 80),
        "scheme": "http",
        "http_version": "1.1",
    }
    return Request(scope)


class _FakeWebSocket:
    def __init__(self, token: str | None = None) -> None:
        self.query_params: dict[str, str] = {"token": token} if token else {}


class TestRoleGuard:
    async def test_analyst_denied_admin(self) -> None:
        guard = require_roles("admin")
        with pytest.raises(HTTPException) as exc:
            await guard(user=SimpleNamespace(role="analyst"))
        assert exc.value.status_code == 403

    async def test_admin_allowed(self) -> None:
        guard = require_roles("admin")
        user = SimpleNamespace(role="admin")
        assert await guard(user=user) is user


class TestPermissionGuard:
    async def test_viewer_denied_manage_users(self) -> None:
        guard = require_permission("manage_users")
        with pytest.raises(HTTPException) as exc:
            await guard(user=SimpleNamespace(role="viewer"))
        assert exc.value.status_code == 403

    async def test_admin_allowed_manage_users(self) -> None:
        guard = require_permission("manage_users")
        user = SimpleNamespace(role="admin")
        assert await guard(user=user) is user


class TestGetCurrentSensor:
    async def test_missing_token(self) -> None:
        with pytest.raises(HTTPException) as exc:
            await get_current_sensor(_http_request(), None)
        assert exc.value.status_code == 401

    async def test_unknown_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(deps, "find_sensor_by_token", _async_stub(None))
        request = _http_request({"X-Sensor-Token": "tok-1"})
        with pytest.raises(HTTPException) as exc:
            await get_current_sensor(request, None)
        assert exc.value.status_code == 401

    async def test_disabled_sensor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            deps,
            "find_sensor_by_token",
            _async_stub(SimpleNamespace(enabled=False)),
        )
        request = _http_request({"X-Sensor-Token": "tok-1"})
        with pytest.raises(HTTPException) as exc:
            await get_current_sensor(request, None)
        assert exc.value.status_code == 403

    async def test_enabled_sensor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sensor = SimpleNamespace(enabled=True)
        monkeypatch.setattr(deps, "find_sensor_by_token", _async_stub(sensor))
        request = _http_request({"X-Sensor-Token": "tok-1"})
        result = await get_current_sensor(request, None)
        assert result is sensor
        assert request.state.current_sensor is sensor


class TestGetWsCurrentUser:
    async def test_missing_token(self) -> None:
        with pytest.raises(WebSocketException) as exc:
            await get_ws_current_user(_FakeWebSocket(), None)
        assert exc.value.code == 1008

    async def test_invalid_token_maps_to_ws_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fail(token: str, db: Any) -> Any:
            raise HTTPException(status_code=401, detail="nope")

        monkeypatch.setattr(deps, "validate_access_token", fail)
        with pytest.raises(WebSocketException) as exc:
            await get_ws_current_user(_FakeWebSocket("bad-token"), None)
        assert exc.value.code == 1008

    async def test_valid_token_returns_user(self, monkeypatch: pytest.MonkeyPatch) -> None:
        user = SimpleNamespace(id=1)
        monkeypatch.setattr(deps, "validate_access_token", _async_stub(user))
        assert await get_ws_current_user(_FakeWebSocket("good-token"), None) is user


def _async_stub(result: Any) -> Any:
    async def stub(*args: Any, **kwargs: Any) -> Any:
        return result

    return stub
