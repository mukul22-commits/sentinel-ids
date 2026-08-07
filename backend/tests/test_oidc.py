"""Tests for the OIDC single sign-on flow (Phase 9)."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import httpx
import pytest
from app.core.config import settings
from app.core.rbac import ROLE_ANALYST
from app.core.token_store import token_store
from app.db.session import get_db
from app.main import app
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services import oidc as oidc_service
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool


def _enable_oidc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "OIDC_ENABLED", True)
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", "client-1")
    monkeypatch.setattr(settings, "OIDC_CLIENT_SECRET", "client-secret")
    monkeypatch.setattr(settings, "OIDC_DOMAIN", "example.com")
    monkeypatch.setattr(settings, "OIDC_REDIRECT_PATH", "/api/v1/auth/oidc/callback")


def _tokens() -> oidc_service.OidcTokens:
    return oidc_service.OidcTokens(
        access_token="access-1",
        refresh_token="refresh-1",
        id_token="id.token",
        expires_in=3600,
    )


def _stub(result: Any) -> Any:
    async def stub(*args: Any, **kwargs: Any) -> Any:
        return result

    return stub


async def _stored_state(state: str = "state-ok", nonce: str = "nonce-1") -> None:
    await token_store.store_oidc_state(state, f"nonce:{nonce}", 600)


class TestOidcServiceUnit:
    def test_discovery_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _enable_oidc(monkeypatch)
        assert oidc_service.discovery_url() == (
            "https://issuer.example/.well-known/openid-configuration"
        )

    def test_discovery_url_disabled_raises(self) -> None:
        with pytest.raises(oidc_service.OidcUnavailable):
            oidc_service.discovery_url()

    def test_oidc_enabled_reflects_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _enable_oidc(monkeypatch)
        assert oidc_service.oidc_enabled() is True
        monkeypatch.setattr(settings, "OIDC_CLIENT_ID", None)
        assert oidc_service.oidc_enabled() is False

    def test_subject_from_claims_email_normalized(self) -> None:
        assert (
            oidc_service.subject_from_claims({"email": "  User@Example.COM ", "sub": "s1"})
            == "user@example.com"
        )

    def test_subject_from_claims_falls_back_to_sub(self) -> None:
        assert oidc_service.subject_from_claims({"sub": "s1"}) == "s1"

    def test_subject_from_claims_missing_raises(self) -> None:
        with pytest.raises(oidc_service.OidcError):
            oidc_service.subject_from_claims({"preferred_username": "x"})

    def test_generate_nonce_is_unique(self) -> None:
        assert oidc_service.generate_nonce() != oidc_service.generate_nonce()

    async def test_fetch_discovery_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _enable_oidc(monkeypatch)
        document = {
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/authorize",
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=document)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            meta = await oidc_service.fetch_discovery(http)
        assert meta == document

    async def test_fetch_discovery_http_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _enable_oidc(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(oidc_service.OidcError):
                await oidc_service.fetch_discovery(http)

    async def test_exchange_code_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _enable_oidc(monkeypatch)
        document = {"token_endpoint": "https://issuer.example/token"}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/.well-known/openid-configuration":
                return httpx.Response(200, json=document)
            assert request.url.path == "/token"
            assert request.headers.get("authorization", "").startswith("Basic ")
            body = httpx.QueryParams(request.content.decode())
            assert body.get("grant_type") == "authorization_code"
            assert body.get("code") == "code-1"
            return httpx.Response(
                200,
                json={
                    "access_token": "access-1",
                    "refresh_token": "refresh-1",
                    "id_token": "id.token",
                    "expires_in": 3600,
                },
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            tokens = await oidc_service.exchange_code("code-1", "http://test/cb", http)
        assert tokens.id_token == "id.token"
        assert tokens.access_token == "access-1"
        assert tokens.expires_in == 3600

    async def test_exchange_code_missing_id_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _enable_oidc(monkeypatch)
        document = {"token_endpoint": "https://issuer.example/token"}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/.well-known/openid-configuration":
                return httpx.Response(200, json=document)
            return httpx.Response(200, json={"access_token": "access-1"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(oidc_service.OidcError):
                await oidc_service.exchange_code("code-1", "http://test/cb", http)

    async def test_authorization_url_builds_params(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _enable_oidc(monkeypatch)
        document = {"authorization_endpoint": "https://issuer.example/authorize"}

        async def fake_discovery(http: httpx.AsyncClient) -> dict[str, str]:
            return document

        monkeypatch.setattr(oidc_service, "fetch_discovery", fake_discovery)
        url = await oidc_service.authorization_url(
            httpx.AsyncClient(),  # type: ignore[arg-type]
            state="state-1",
            nonce="nonce-1",
            redirect_uri="http://test/api/v1/auth/oidc/callback",
        )
        assert url.startswith("https://issuer.example/authorize?")
        assert "response_type=code" in url
        assert "client_id=client-1" in url
        assert "state=state-1" in url
        assert "nonce=nonce-1" in url
        assert "scope=openid" in url

    def test_require_enabled_raises_when_disabled(self) -> None:
        with pytest.raises(oidc_service.OidcUnavailable):
            oidc_service._require_enabled()


@pytest.fixture
async def db_factory() -> AsyncGenerator[Any, None]:
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    async with engine.begin() as conn:
        await conn.run_sync(User.__table__.create)
        await conn.run_sync(AuditLog.__table__.create)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.fixture
def app_client(db_factory: Any) -> TestClient:
    async def _override_db() -> AsyncGenerator[AsyncSession, None]:
        async with db_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture(autouse=True)
async def _clean_token_store() -> None:
    await token_store.reset()


class TestOidcEndpoints:
    def test_config_reflects_disabled(self) -> None:
        with TestClient(app) as client:
            response = client.get("/api/v1/auth/oidc/config")
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["enabled"] is False
        assert data["issuer"] is None
        assert data["redirect_path"] == "/api/v1/auth/oidc/callback"

    def test_authorize_disabled_returns_404(self) -> None:
        with TestClient(app) as client:
            response = client.get(
                "/api/v1/auth/oidc/authorize",
                headers={"X-Forwarded-For": "10.0.0.1"},
            )
        assert response.status_code == 404

    def test_authorize_returns_provider_url_and_state(
        self, app_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_oidc(monkeypatch)

        async def fake_authorization_url(
            http: httpx.AsyncClient,
            state: str,
            nonce: str,
            redirect_uri: str,
            scope: str | None = None,
        ) -> str:
            return f"https://issuer.example/authorize?state={state}&nonce={nonce}"

        monkeypatch.setattr(oidc_service, "authorization_url", fake_authorization_url)
        response = app_client.get(
            "/api/v1/auth/oidc/authorize",
            headers={"X-Forwarded-For": "10.0.0.2"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        state = body["data"]["state"]
        assert state
        assert state in body["data"]["url"]
        assert "nonce=" in body["data"]["url"]

    def test_authorize_provider_error_maps_to_502(
        self, app_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_oidc(monkeypatch)

        async def fake_authorization_url(*args: Any, **kwargs: Any) -> str:
            raise oidc_service.OidcError("boom")

        monkeypatch.setattr(oidc_service, "authorization_url", fake_authorization_url)
        response = app_client.get(
            "/api/v1/auth/oidc/authorize",
            headers={"X-Forwarded-For": "10.0.0.3"},
        )
        assert response.status_code == 502
        assert "boom" in response.json()["error"]

    async def test_callback_provisions_new_user(
        self,
        app_client: TestClient,
        db_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_oidc(monkeypatch)
        monkeypatch.setattr(oidc_service, "exchange_code", _stub(_tokens()))
        monkeypatch.setattr(
            oidc_service,
            "verify_id_token",
            _stub({"email": "new.user@example.com", "name": "New User", "sub": "sub-1"}),
        )
        await _stored_state()
        response = app_client.get(
            "/api/v1/auth/oidc/callback?code=code-1&state=state-ok",
            headers={"X-Forwarded-For": "10.0.0.4"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        location = response.headers["location"]
        assert location.startswith("http://localhost:5173/#/auth/oidc/callback?")
        assert "access_token=" in location
        assert "refresh_token=" in location

        async with db_factory() as session:
            user = await session.scalar(select(User).where(User.email == "new.user@example.com"))
        assert user is not None
        assert user.role == ROLE_ANALYST
        assert user.username == "new.user"
        assert user.full_name == "New User"

    async def test_callback_login_existing_user(
        self,
        app_client: TestClient,
        db_factory: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_oidc(monkeypatch)
        monkeypatch.setattr(oidc_service, "exchange_code", _stub(_tokens()))
        monkeypatch.setattr(
            oidc_service,
            "verify_id_token",
            _stub({"email": "existing@example.com", "sub": "sub-2"}),
        )
        async with db_factory() as session:
            session.add(
                User(
                    email="existing@example.com",
                    username="existing",
                    role=ROLE_ANALYST,
                    hashed_password="x",
                )
            )
            await session.commit()
        await _stored_state()
        response = app_client.get(
            "/api/v1/auth/oidc/callback?code=code-1&state=state-ok",
            headers={"X-Forwarded-For": "10.0.0.5"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "access_token=" in response.headers["location"]

        async with db_factory() as session:
            user = await session.scalar(select(User).where(User.email == "existing@example.com"))
        assert user is not None
        assert user.last_login_at is not None

    async def test_callback_rejects_unknown_state(
        self, app_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_oidc(monkeypatch)
        response = app_client.get(
            "/api/v1/auth/oidc/callback?code=code-1&state=not-stored",
            headers={"X-Forwarded-For": "10.0.0.6"},
        )
        assert response.status_code == 400

    async def test_callback_enforces_domain(
        self, app_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_oidc(monkeypatch)
        monkeypatch.setattr(oidc_service, "exchange_code", _stub(_tokens()))
        monkeypatch.setattr(
            oidc_service,
            "verify_id_token",
            _stub({"email": "attacker@evil.io", "sub": "sub-3"}),
        )
        await _stored_state()
        response = app_client.get(
            "/api/v1/auth/oidc/callback?code=code-1&state=state-ok",
            headers={"X-Forwarded-For": "10.0.0.7"},
        )
        assert response.status_code == 403

    async def test_callback_provider_error_returns_502(
        self, app_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_oidc(monkeypatch)

        async def fail_exchange(*args: Any, **kwargs: Any) -> Any:
            raise oidc_service.OidcError("token exchange failed")

        monkeypatch.setattr(oidc_service, "exchange_code", fail_exchange)
        await _stored_state()
        response = app_client.get(
            "/api/v1/auth/oidc/callback?code=code-1&state=state-ok",
            headers={"X-Forwarded-For": "10.0.0.8"},
        )
        assert response.status_code == 502
        assert "token exchange failed" in response.json()["error"]
