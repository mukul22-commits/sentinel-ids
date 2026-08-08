"""End-to-end tests for the authentication routes (register/login/refresh/
logout/password flows) plus the auth dependency paths in ``deps.py``.

These run against an in-memory SQLite database so the full request -> route ->
DB -> response pipeline is exercised.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from app.core.config import settings
from app.core.security import (
    ALGORITHM,
    AUDIENCE,
    ISSUER,
    create_access_token,
    decode_access_token,
    decode_refresh_token,
)
from app.core.token_store import token_store
from app.models.user import User
from sqlalchemy import select

PASSWORD = "Str0ng!Passw0rd"
API = "/api/v1/auth"

_ip_counter = 0


def _ip() -> str:
    global _ip_counter
    _ip_counter += 1
    return f"10.9.{_ip_counter // 250}.{_ip_counter % 250}"


def _headers() -> dict[str, str]:
    return {"X-Forwarded-For": _ip()}


def _register(
    client: Any,
    email: str,
    username: str,
    *,
    password: str = PASSWORD,
    full_name: str | None = None,
) -> Any:
    payload: dict[str, Any] = {"email": email, "username": username, "password": password}
    if full_name is not None:
        payload["full_name"] = full_name
    return client.post(f"{API}/register", json=payload, headers=_headers())


def _login(client: Any, identifier: str, password: str = PASSWORD) -> Any:
    return client.post(
        f"{API}/login",
        json={"identifier": identifier, "password": password},
        headers=_headers(),
    )


@pytest.fixture(autouse=True)
async def _clean_token_store() -> None:
    await token_store.reset()


class TestRegister:
    def test_register_success(self, sqlite_app_client: Any) -> None:
        response = _register(
            sqlite_app_client, "New.User@Example.com", "newuser", full_name="New User"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["data"]["email"] == "new.user@example.com"
        assert body["data"]["role"] == "analyst"
        assert body["data"]["full_name"] == "New User"

    def test_register_duplicate_email(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, "dup@example.com", "dupuser")
        response = _register(sqlite_app_client, "DUP@example.com", "othername")
        assert response.status_code == 409
        assert "Email already registered" in response.json()["error"]

    def test_register_duplicate_username(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, "one@example.com", "sameuser")
        response = _register(sqlite_app_client, "two@example.com", "sameuser")
        assert response.status_code == 409
        assert "Username already taken" in response.json()["error"]

    def test_register_weak_password_rejected(
        self, sqlite_app_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "MIN_PASSWORD_LENGTH", 4)
        response = _register(
            sqlite_app_client, "weak@example.com", "weakuser", password="password1"
        )
        assert response.status_code == 400
        assert "too common" in response.json()["error"]

    def test_register_password_matching_username_rejected(self, sqlite_app_client: Any) -> None:
        response = _register(
            sqlite_app_client,
            "nomatch@example.com",
            "SuperSecretPass1",
            password="SuperSecretPass1",
        )
        assert response.status_code == 400


class TestLogin:
    def test_login_success(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, "login@example.com", "loginuser")
        response = _login(sqlite_app_client, "login@example.com", PASSWORD)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["access_token"]
        assert data["refresh_token"]
        assert data["expires_in"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        assert decode_access_token(data["access_token"])["sub"] is not None

    def test_login_by_username(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, "byuser@example.com", "byusername")
        response = _login(sqlite_app_client, "byusername", PASSWORD)
        assert response.status_code == 200

    def test_login_unknown_user(self, sqlite_app_client: Any) -> None:
        response = _login(sqlite_app_client, "ghost@example.com", PASSWORD)
        assert response.status_code == 401

    def test_login_wrong_password(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, "wrongpw@example.com", "wrongpw")
        response = _login(sqlite_app_client, "wrongpw@example.com", "NotTheRight1!")
        assert response.status_code == 401

    async def test_login_locks_account_after_max_attempts(
        self, sqlite_app_client: Any, sqlite_db_factory: Any
    ) -> None:
        _register(sqlite_app_client, "lock@example.com", "lockuser")
        for _ in range(settings.LOGIN_MAX_FAILED_ATTEMPTS):
            response = _login(sqlite_app_client, "lock@example.com", "WrongPass1!")
            assert response.status_code == 401
        locked = _login(sqlite_app_client, "lock@example.com", PASSWORD)
        assert locked.status_code == 403
        assert "locked" in locked.json()["error"]

    async def test_login_inactive_account(
        self, sqlite_app_client: Any, sqlite_db_factory: Any
    ) -> None:
        _register(sqlite_app_client, "inactive@example.com", "inactiveuser")
        async with sqlite_db_factory() as session:
            user = await session.scalar(select(User).where(User.email == "inactive@example.com"))
            assert user is not None
            user.is_active = False
            await session.commit()
        response = _login(sqlite_app_client, "inactive@example.com", PASSWORD)
        assert response.status_code == 403

    async def test_login_temporarily_locked(
        self, sqlite_app_client: Any, sqlite_db_factory: Any
    ) -> None:
        _register(sqlite_app_client, "temp@example.com", "tempuser")
        async with sqlite_db_factory() as session:
            user = await session.scalar(select(User).where(User.email == "temp@example.com"))
            assert user is not None
            user.locked_until = datetime.now(UTC) + timedelta(minutes=5)
            await session.commit()
        response = _login(sqlite_app_client, "temp@example.com", PASSWORD)
        assert response.status_code == 403
        assert "temporarily locked" in response.json()["error"]


class TestRefresh:
    def test_refresh_success(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, "refresh@example.com", "refreshuser")
        tokens = _login(sqlite_app_client, "refresh@example.com", PASSWORD).json()["data"]
        response = sqlite_app_client.post(
            f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}, headers=_headers()
        )
        assert response.status_code == 200
        assert response.json()["data"]["access_token"]
        assert response.json()["data"]["refresh_token"] != tokens["refresh_token"]

    def test_refresh_invalid_token(self, sqlite_app_client: Any) -> None:
        response = sqlite_app_client.post(
            f"{API}/refresh", json={"refresh_token": "not-a-token"}, headers=_headers()
        )
        assert response.status_code == 401

    def test_refresh_access_token_rejected(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, "mixed@example.com", "mixeduser")
        tokens = _login(sqlite_app_client, "mixed@example.com", PASSWORD).json()["data"]
        response = sqlite_app_client.post(
            f"{API}/refresh", json={"refresh_token": tokens["access_token"]}, headers=_headers()
        )
        assert response.status_code == 401

    def test_refresh_reuse_detected_and_revokes_family(
        self, sqlite_app_client: Any, sqlite_db_factory: Any
    ) -> None:
        _register(sqlite_app_client, "reuse@example.com", "reuseuser")
        tokens = _login(sqlite_app_client, "reuse@example.com", PASSWORD).json()["data"]
        first = sqlite_app_client.post(
            f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}, headers=_headers()
        )
        assert first.status_code == 200
        second = sqlite_app_client.post(
            f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}, headers=_headers()
        )
        assert second.status_code == 401
        assert "already used" in second.json()["error"]

    def test_refresh_after_logout_everywhere(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, "revoked@example.com", "revokeduser")
        tokens = _login(sqlite_app_client, "revoked@example.com", PASSWORD).json()["data"]
        user_id = int(decode_refresh_token(tokens["refresh_token"])["sub"])
        asyncio.run(token_store.revoke_user_tokens(user_id))
        response = sqlite_app_client.post(
            f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}, headers=_headers()
        )
        assert response.status_code == 401
        assert "revoked" in response.json()["error"]

    async def test_refresh_inactive_user(
        self, sqlite_app_client: Any, sqlite_db_factory: Any
    ) -> None:
        _register(sqlite_app_client, "refinactive@example.com", "refinactive")
        tokens = _login(sqlite_app_client, "refinactive@example.com", PASSWORD).json()["data"]
        async with sqlite_db_factory() as session:
            user = await session.scalar(select(User).where(User.email == "refinactive@example.com"))
            assert user is not None
            user.is_active = False
            await session.commit()
        response = sqlite_app_client.post(
            f"{API}/refresh", json={"refresh_token": tokens["refresh_token"]}, headers=_headers()
        )
        assert response.status_code == 401


class TestMeAndTokens:
    def _register_and_get_tokens(self, client: Any, email: str, username: str) -> dict[str, Any]:
        _register(client, email, username)
        return _login(client, email, PASSWORD).json()["data"]

    def test_me_success(self, sqlite_app_client: Any) -> None:
        tokens = self._register_and_get_tokens(sqlite_app_client, "me@example.com", "meuser")
        response = sqlite_app_client.get(
            f"{API}/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert response.status_code == 200
        assert response.json()["data"]["email"] == "me@example.com"

    def test_me_missing_token(self, sqlite_app_client: Any) -> None:
        response = sqlite_app_client.get(f"{API}/me")
        assert response.status_code == 401

    def test_me_malformed_auth_header(self, sqlite_app_client: Any) -> None:
        response = sqlite_app_client.get(f"{API}/me", headers={"Authorization": "Basic abc"})
        assert response.status_code == 401

    def test_me_invalid_token(self, sqlite_app_client: Any) -> None:
        response = sqlite_app_client.get(f"{API}/me", headers={"Authorization": "Bearer garbage"})
        assert response.status_code == 401

    def test_me_expired_token(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, "expired@example.com", "expireduser")
        token = jwt.encode(
            {
                "sub": "1",
                "role": "analyst",
                "jti": uuid.uuid4().hex,
                "iat": datetime.now(UTC) - timedelta(hours=1),
                "exp": datetime.now(UTC) - timedelta(minutes=1),
                "aud": AUDIENCE,
                "iss": ISSUER,
                "typ": "access",
            },
            token_store_shared_key(),
            algorithm=ALGORITHM,
        )
        response = sqlite_app_client.get(f"{API}/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401
        assert "expired" in response.json()["error"]

    def test_me_unknown_user(self, sqlite_app_client: Any) -> None:
        token = create_access_token(999_999, "analyst")
        response = sqlite_app_client.get(f"{API}/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401
        assert "not found or inactive" in response.json()["error"]

    async def test_me_inactive_user(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        tokens = self._register_and_get_tokens(
            sqlite_app_client, "meinactive@example.com", "meinactive"
        )
        async with sqlite_db_factory() as session:
            user = await session.scalar(select(User).where(User.email == "meinactive@example.com"))
            assert user is not None
            user.is_active = False
            await session.commit()
        response = sqlite_app_client.get(
            f"{API}/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert response.status_code == 401

    def test_me_blocked_jti(self, sqlite_app_client: Any) -> None:
        tokens = self._register_and_get_tokens(sqlite_app_client, "blocked@example.com", "blocked")
        jti = decode_access_token(tokens["access_token"])["jti"]
        asyncio.run(token_store.block_jti(jti, 600))
        response = sqlite_app_client.get(
            f"{API}/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert response.status_code == 401
        assert "revoked" in response.json()["error"]

    def test_me_revoked_watermark(self, sqlite_app_client: Any) -> None:
        tokens = self._register_and_get_tokens(sqlite_app_client, "water@example.com", "watermark")
        user_id = int(decode_access_token(tokens["access_token"])["sub"])
        asyncio.run(token_store.revoke_user_tokens(user_id))
        response = sqlite_app_client.get(
            f"{API}/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert response.status_code == 401


class TestLogout:
    def test_logout_blocks_tokens(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, "logout@example.com", "logoutuser")
        tokens = _login(sqlite_app_client, "logout@example.com", PASSWORD).json()["data"]
        logout = sqlite_app_client.post(
            f"{API}/logout", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert logout.status_code == 200
        assert logout.json()["data"] is True
        me = sqlite_app_client.get(
            f"{API}/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert me.status_code == 401


class TestChangePassword:
    def test_change_password_wrong_current(self, sqlite_app_client: Any) -> None:
        tokens = _login_after_register(sqlite_app_client, "changepw@example.com", "changepw")
        response = sqlite_app_client.post(
            f"{API}/change-password",
            json={"current_password": "Wrong1!", "new_password": "BrandNew!Pass1"},
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert response.status_code == 400
        assert "incorrect" in response.json()["error"]

    def test_change_password_weak_new_password(self, sqlite_app_client: Any) -> None:
        tokens = _login_after_register(sqlite_app_client, "weakpw@example.com", "weakpw")
        response = sqlite_app_client.post(
            f"{API}/change-password",
            json={"current_password": PASSWORD, "new_password": "password123"},
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert response.status_code == 400

    def test_change_password_success_revokes_old_tokens(self, sqlite_app_client: Any) -> None:
        tokens = _login_after_register(sqlite_app_client, "okpw@example.com", "okpw")
        response = sqlite_app_client.post(
            f"{API}/change-password",
            json={"current_password": PASSWORD, "new_password": "Changed!Pass1"},
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert response.status_code == 200
        me = sqlite_app_client.get(
            f"{API}/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert me.status_code == 401
        assert _login(sqlite_app_client, "okpw@example.com", "Changed!Pass1").status_code == 200
        assert _login(sqlite_app_client, "okpw@example.com", PASSWORD).status_code == 401


class TestForgotResetPassword:
    def test_forgot_password_existing_user(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, "forgot@example.com", "forgotuser")
        response = sqlite_app_client.post(
            f"{API}/forgot-password",
            json={"email": "forgot@example.com"},
            headers=_headers(),
        )
        assert response.status_code == 200

    def test_forgot_password_unknown_email_no_enumeration(self, sqlite_app_client: Any) -> None:
        response = sqlite_app_client.post(
            f"{API}/forgot-password",
            json={"email": "nobody@nowhere.invalid"},
            headers=_headers(),
        )
        assert response.status_code == 200

    def test_reset_password_invalid_token(self, sqlite_app_client: Any) -> None:
        response = sqlite_app_client.post(
            f"{API}/reset-password",
            json={"token": "bogus-token-00000000000000", "new_password": "Fresh!Pass123"},
            headers=_headers(),
        )
        assert response.status_code == 400

    async def test_reset_password_success_single_use(
        self, sqlite_app_client: Any, sqlite_db_factory: Any
    ) -> None:
        _register(sqlite_app_client, "reset@example.com", "resetuser")
        async with sqlite_db_factory() as session:
            user = await session.scalar(select(User).where(User.email == "reset@example.com"))
            assert user is not None
            await token_store.store_reset_token(
                "reset-token-111111111111111", user.id, settings.PASSWORD_RESET_TTL_MINUTES * 60
            )
        response = sqlite_app_client.post(
            f"{API}/reset-password",
            json={"token": "reset-token-111111111111111", "new_password": "Fresh!Pass123"},
            headers=_headers(),
        )
        assert response.status_code == 200
        assert _login(sqlite_app_client, "reset@example.com", "Fresh!Pass123").status_code == 200
        second = sqlite_app_client.post(
            f"{API}/reset-password",
            json={"token": "reset-token-111111111111111", "new_password": "Another!Pass123"},
            headers=_headers(),
        )
        assert second.status_code == 400

    async def test_reset_password_weak_password(
        self, sqlite_app_client: Any, sqlite_db_factory: Any
    ) -> None:
        _register(sqlite_app_client, "resetweak@example.com", "resetweak")
        async with sqlite_db_factory() as session:
            user = await session.scalar(select(User).where(User.email == "resetweak@example.com"))
            assert user is not None
            await token_store.store_reset_token("weak-token-00000000000000", user.id, 600)
        response = sqlite_app_client.post(
            f"{API}/reset-password",
            json={"token": "weak-token-00000000000000", "new_password": "12345678"},
            headers=_headers(),
        )
        assert response.status_code == 400


def _login_after_register(client: Any, email: str, username: str) -> dict[str, Any]:
    _register(client, email, username)
    return _login(client, email, PASSWORD).json()["data"]


def token_store_shared_key() -> str:
    from app.services.secrets import secret_key

    return secret_key()
