"""HTTP-level tests for the advanced system route groups.

Covers the endpoints that previously had no route coverage: ``/system/detection/*``,
``/system/ml/*``, ``/system/connectors`` (authenticated positive paths) and the
realtime ``/ws/incidents`` WebSocket handshake.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi import WebSocketDisconnect

PASSWORD = "Str0ng!Passw0rd"
API = "/api/v1"

_ip_counter = 0


def _ip() -> str:
    global _ip_counter
    _ip_counter += 1
    return f"10.9.{_ip_counter // 250}.{_ip_counter % 250}"


def _headers() -> dict[str, str]:
    return {"X-Forwarded-For": _ip()}


def _uuid() -> str:
    return uuid.uuid4().hex


def _register(client: Any, email: str, username: str) -> Any:
    return client.post(
        f"{API}/auth/register",
        json={"email": email, "username": username, "password": PASSWORD},
        headers=_headers(),
    )


def _tokens(client: Any, identifier: str) -> dict[str, Any]:
    resp = client.post(
        f"{API}/auth/login",
        json={"identifier": identifier, "password": PASSWORD},
        headers=_headers(),
    )
    return resp.json()["data"]


def _register_admin(client: Any, db_factory: Any, email: str, username: str) -> dict[str, Any]:
    _register(client, email, username)
    _set_role(client, db_factory, email, "admin")
    return _tokens(client, email)


def _set_role(client: Any, db_factory: Any, email: str, role: str) -> None:
    import asyncio

    from app.models.user import User
    from sqlalchemy import select

    async def _apply() -> None:
        async with db_factory() as session:
            user = await session.scalar(select(User).where(User.email == email))
            assert user is not None
            user.role = role
            await session.commit()

    asyncio.run(_apply())


def _auth(tokens: dict[str, Any]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


class TestDetectionRoutes:
    def test_yara_status(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"det.{_uuid()}@x.io", "detadm"
        )
        resp = sqlite_app_client.get(f"{API}/system/detection/yara", headers=_auth(admin))
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert set(body["data"]).issuperset(
            {"enabled", "rules_dir", "max_payload_bytes", "rule_count", "rules", "load_errors"}
        )

    def test_yara_reload(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"det.{_uuid()}@x.io", "detadm"
        )
        resp = sqlite_app_client.post(f"{API}/system/detection/yara/reload", headers=_auth(admin))
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        assert "rule_count" in resp.json()["data"]

    def test_yara_reload_forbidden_for_analyst(
        self, sqlite_app_client: Any, sqlite_db_factory: Any
    ) -> None:
        email = f"det.{_uuid()}@x.io"
        _register(sqlite_app_client, email, "analyst1")
        analyst = _tokens(sqlite_app_client, email)
        resp = sqlite_app_client.post(f"{API}/system/detection/yara/reload", headers=_auth(analyst))
        assert resp.status_code == 403

    def test_payload_extraction(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"det.{_uuid()}@x.io", "detadm"
        )
        resp = sqlite_app_client.post(
            f"{API}/system/detection/payload",
            json={"payload_text": "MZthis-is-sample-payload-data"},
            headers=_auth(admin),
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["extracted"] is True
        assert data["bytes"] > 0

    def test_ueba_status(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"det.{_uuid()}@x.io", "detadm"
        )
        resp = sqlite_app_client.get(f"{API}/system/detection/ueba", headers=_auth(admin))
        assert resp.status_code == 200
        assert set(resp.json()["data"]).issuperset(
            {"enabled", "exists", "path", "threshold", "window_hours"}
        )

    def test_ueba_retrain(
        self,
        sqlite_app_client: Any,
        sqlite_db_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import app.api.v1.routes.detection as detection_routes

        async def _fake_retrain(db: Any) -> dict[str, Any]:
            return {"profile_count": 1, "window_hours": 24}

        monkeypatch.setattr(detection_routes, "retrain_ueba_profiles", _fake_retrain)
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"det.{_uuid()}@x.io", "detadm"
        )
        resp = sqlite_app_client.post(f"{API}/system/detection/ueba/retrain", headers=_auth(admin))
        assert resp.status_code == 200
        assert resp.json()["data"] == {"profile_count": 1, "window_hours": 24}


class TestMlRoutes:
    def test_ml_status(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(sqlite_app_client, sqlite_db_factory, f"ml.{_uuid()}@x.io", "mladm")
        resp = sqlite_app_client.get(f"{API}/system/ml", headers=_auth(admin))
        assert resp.status_code == 200
        assert set(resp.json()["data"]).issuperset({"enabled", "exists", "min_samples"})

    def test_ml_retrain(
        self,
        sqlite_app_client: Any,
        sqlite_db_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import app.api.v1.routes.ml as ml_routes

        async def _fake_retrain(db: Any) -> dict[str, Any]:
            return {"retrained": True, "samples": 42}

        monkeypatch.setattr(ml_routes, "retrain_ml_model", _fake_retrain)
        admin = _register_admin(sqlite_app_client, sqlite_db_factory, f"ml.{_uuid()}@x.io", "mladm")
        resp = sqlite_app_client.post(f"{API}/system/ml/retrain", headers=_auth(admin))
        assert resp.status_code == 200
        assert resp.json()["data"] == {"retrained": True, "samples": 42}

    def test_autoencoder_status(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(sqlite_app_client, sqlite_db_factory, f"ml.{_uuid()}@x.io", "mladm")
        resp = sqlite_app_client.get(f"{API}/system/ml/autoencoder", headers=_auth(admin))
        assert resp.status_code == 200
        assert "exists" in resp.json()["data"]

    def test_autoencoder_retrain(
        self,
        sqlite_app_client: Any,
        sqlite_db_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import app.api.v1.routes.ml as ml_routes

        async def _fake_retrain(db: Any) -> dict[str, Any]:
            return {"retrained": True, "latent_dim": 8}

        monkeypatch.setattr(ml_routes, "retrain_autoencoder_model", _fake_retrain)
        admin = _register_admin(sqlite_app_client, sqlite_db_factory, f"ml.{_uuid()}@x.io", "mladm")
        resp = sqlite_app_client.post(f"{API}/system/ml/autoencoder/retrain", headers=_auth(admin))
        assert resp.status_code == 200
        assert resp.json()["data"] == {"retrained": True, "latent_dim": 8}


class TestConnectorRoutes:
    def test_list_connectors(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(sqlite_app_client, sqlite_db_factory, f"cx.{_uuid()}@x.io", "cxadm")
        resp = sqlite_app_client.get(f"{API}/system/connectors", headers=_auth(admin))
        assert resp.status_code == 200
        names = {connector["name"] for connector in resp.json()["data"]}
        assert "http_webhook" in names
        assert "smtp_email" in names
        for connector in resp.json()["data"]:
            assert set(connector).issuperset({"name", "kind", "enabled", "description"})

    def test_list_connectors_forbidden_for_analyst(
        self, sqlite_app_client: Any, sqlite_db_factory: Any
    ) -> None:
        email = f"cx.{_uuid()}@x.io"
        _register(sqlite_app_client, email, "cxanalyst")
        analyst = _tokens(sqlite_app_client, email)
        resp = sqlite_app_client.get(f"{API}/system/connectors", headers=_auth(analyst))
        assert resp.status_code == 403

    def test_test_connector(
        self,
        sqlite_app_client: Any,
        sqlite_db_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from app.services.connectors import connector_registry

        class _StubConnector:
            name = "http_webhook"
            kind = "http"
            description = "stub"

            def enabled(self) -> bool:
                return True

            async def test(self) -> dict[str, Any]:
                return {"ok": True, "latency_ms": 12}

        monkeypatch.setattr(connector_registry, "get", lambda name: _StubConnector())
        admin = _register_admin(sqlite_app_client, sqlite_db_factory, f"cx.{_uuid()}@x.io", "cxadm")
        resp = sqlite_app_client.post(
            f"{API}/system/connectors/http_webhook/test", headers=_auth(admin)
        )
        assert resp.status_code == 200
        assert resp.json()["data"] == {"ok": True, "latency_ms": 12}

    def test_test_connector_not_found(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(sqlite_app_client, sqlite_db_factory, f"cx.{_uuid()}@x.io", "cxadm")
        resp = sqlite_app_client.post(
            f"{API}/system/connectors/does_not_exist/test", headers=_auth(admin)
        )
        assert resp.status_code == 404


class TestWebsocketRoutes:
    def test_ws_incidents_ping_pong(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(sqlite_app_client, sqlite_db_factory, f"ws.{_uuid()}@x.io", "wsadm")
        with sqlite_app_client.websocket_connect(
            f"/ws/incidents?token={admin['access_token']}"
        ) as ws:
            ws.send_text("ping")
            message = ws.receive_json()
            assert message["type"] == "pong"
            assert "ts" in message["payload"]

    def test_ws_incidents_requires_token(self, sqlite_app_client: Any) -> None:
        with (
            pytest.raises(WebSocketDisconnect),
            sqlite_app_client.websocket_connect("/ws/incidents") as ws,
        ):
            ws.receive_json()
