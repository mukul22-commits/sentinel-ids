"""Password hashing and JWT creation/validation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

from app.core.config import settings
from app.services.secrets import secret_key

ALGORITHM = settings.JWT_ALGORITHM
ISSUER = settings.JWT_ISSUER
AUDIENCE = settings.JWT_AUDIENCE

AUTH_ERROR_MESSAGES = {
    "invalid": "Invalid or malformed token",
    "expired": "Token has expired",
    "audience": "Token audience is invalid",
    "issuer": "Token issuer is invalid",
    "type": "Token type is invalid for this operation",
    "revoked": "Token has been revoked",
}


class AuthError(Exception):
    """Raised when authentication fails; mapped to a 401 envelope."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(AUTH_ERROR_MESSAGES.get(code, code))


class WeakPasswordError(ValueError):
    """Raised when a password does not meet strength requirements."""

    COMMON_PASSWORDS: frozenset[str] = frozenset(
        {
            "password",
            "password1",
            "password123",
            "12345678",
            "123456789",
            "qwerty123",
            "qwertyuiop",
            "letmein",
            "admin123",
            "welcome1",
            "iloveyou",
            "monkey123",
            "dragon123",
            "abc12345",
            "passw0rd",
            "sentinel",
            "sentinel123",
        }
    )


def hash_password(password: str) -> str:
    """Hash a password with bcrypt at the configured cost (>= 12 rounds)."""
    if settings.BCRYPT_ROUNDS < 12:
        raise ValueError("BCRYPT_ROUNDS must be at least 12")
    rounds = settings.BCRYPT_ROUNDS
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def validate_password_strength(password: str, *, email: str = "", username: str = "") -> None:
    """Reject weak/common passwords before they are stored."""
    if len(password) < settings.MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters long"
        )
    lowered = password.lower()
    if lowered in WeakPasswordError.COMMON_PASSWORDS:
        raise WeakPasswordError("Password is too common; choose a stronger one")
    if email and (lowered == email.lower().split("@")[0]):
        raise WeakPasswordError("Password must not match the email local part")
    if username and lowered == username.lower():
        raise WeakPasswordError("Password must not match the username")


def create_access_token(user_id: int, role: str) -> str:
    """Create a short-lived HS256 access token."""
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "role": role,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "aud": AUDIENCE,
        "iss": ISSUER,
        "typ": "access",
    }
    return jwt.encode(payload, secret_key(), algorithm=ALGORITHM)


def create_refresh_token(user_id: int, role: str, family_id: str) -> str:
    """Create a long-lived refresh token bound to a token family."""
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "role": role,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        "aud": AUDIENCE,
        "iss": ISSUER,
        "typ": "refresh",
        "fid": family_id,
    }
    return jwt.encode(payload, secret_key(), algorithm=ALGORITHM)


def _decode_raw(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            secret_key(),
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise AuthError("audience") from exc
    except jwt.InvalidIssuerError as exc:
        raise AuthError("issuer") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("invalid") from exc


def decode_access_token(token: str) -> dict[str, Any]:
    """Validate and return an access token's claims."""
    payload = _decode_raw(token)
    if payload.get("typ") != "access":
        raise AuthError("type")
    return payload


def decode_refresh_token(token: str) -> dict[str, Any]:
    """Validate and return a refresh token's claims."""
    payload = _decode_raw(token)
    if payload.get("typ") != "refresh":
        raise AuthError("type")
    return payload
