"""Unit tests for JWT and password primitives (Phase 3)."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest
from app.core.config import settings
from app.core.security import (
    AuthError,
    WeakPasswordError,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    hash_password,
    validate_password_strength,
    verify_password,
)


class TestPasswordHashing:
    def test_roundtrip(self) -> None:
        hashed = hash_password("A-strong-passphrase-123")
        assert hashed != "A-strong-passphrase-123"
        assert verify_password("A-strong-passphrase-123", hashed)

    def test_wrong_password_rejected(self) -> None:
        hashed = hash_password("A-strong-passphrase-123")
        assert not verify_password("wrong-passphrase-xyz", hashed)

    def test_malformed_hash_rejected(self) -> None:
        assert not verify_password("whatever", "not-a-bcrypt-hash")


class TestPasswordStrength:
    def test_short_password_rejected(self) -> None:
        with pytest.raises(WeakPasswordError):
            validate_password_strength("short")

    def test_common_password_rejected(self) -> None:
        with pytest.raises(WeakPasswordError):
            validate_password_strength("password123")

    def test_username_collision_rejected(self) -> None:
        with pytest.raises(WeakPasswordError):
            validate_password_strength("analyst1-!x", username="analyst1")

    def test_strong_password_accepted(self) -> None:
        validate_password_strength("Correct-Horse-Battery-Staple")


class TestAccessTokens:
    def test_roundtrip(self) -> None:
        token = create_access_token(42, "admin")
        payload = decode_access_token(token)
        assert payload["sub"] == "42"
        assert payload["role"] == "admin"
        assert payload["typ"] == "access"
        assert payload["jti"]
        assert payload["aud"] == settings.JWT_AUDIENCE
        assert payload["iss"] == settings.JWT_ISSUER

    def test_refresh_token_rejected_as_access(self) -> None:
        token = create_refresh_token(42, "admin", "family-1")
        with pytest.raises(AuthError) as excinfo:
            decode_access_token(token)
        assert excinfo.value.code == "type"

    def test_access_token_rejected_as_refresh(self) -> None:
        token = create_access_token(42, "admin")
        with pytest.raises(AuthError) as excinfo:
            decode_refresh_token(token)
        assert excinfo.value.code == "type"

    def test_tampered_signature_rejected(self) -> None:
        token = create_access_token(42, "admin")
        tampered = token[:-4] + ("abcd" if not token.endswith("abcd") else "efgh")
        with pytest.raises(AuthError) as excinfo:
            decode_access_token(tampered)
        assert excinfo.value.code == "invalid"

    def test_wrong_audience_rejected(self) -> None:
        now = datetime.now(UTC)
        payload = {
            "sub": "1",
            "role": "admin",
            "jti": "jti",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "aud": "someone-else",
            "iss": settings.JWT_ISSUER,
            "typ": "access",
        }
        token = pyjwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        with pytest.raises(AuthError) as excinfo:
            decode_access_token(token)
        assert excinfo.value.code == "audience"

    def test_expired_token_rejected(self) -> None:
        past = datetime.now(UTC) - timedelta(minutes=5)
        payload = {
            "sub": "1",
            "role": "admin",
            "jti": "jti",
            "iat": past - timedelta(minutes=10),
            "exp": past,
            "aud": settings.JWT_AUDIENCE,
            "iss": settings.JWT_ISSUER,
            "typ": "access",
        }
        token = pyjwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        with pytest.raises(AuthError) as excinfo:
            decode_access_token(token)
        assert excinfo.value.code == "expired"

    def test_iat_is_numeric(self) -> None:
        token = create_access_token(1, "viewer")
        payload = decode_access_token(token)
        assert isinstance(payload["iat"], int)
        assert payload["exp"] - payload["iat"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        assert isinstance(time.time(), float)
