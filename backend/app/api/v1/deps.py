"""Shared FastAPI dependencies: request id, auth, and RBAC."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, WebSocket, WebSocketException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import has_permission
from app.core.security import AuthError, decode_access_token
from app.core.token_store import token_store
from app.db.session import get_db
from app.models.user import User

UNAUTHORIZED = HTTPException(status_code=401, detail="Not authenticated")
FORBIDDEN = HTTPException(status_code=403, detail="Insufficient permissions")

DbSession = Annotated[AsyncSession, Depends(get_db)]


def get_request_id(request: Request) -> str:
    """Return the request id assigned by RequestIdMiddleware (if any)."""
    return request.headers.get("x-request-id", "")


def get_bearer_token(request: Request) -> str:
    """Extract the bearer token from the Authorization header."""
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise UNAUTHORIZED
    return header.split(" ", 1)[1].strip()


async def validate_access_token(token: str, db: AsyncSession) -> User:
    """Validate an access token and resolve the active user.

    Checks, in order: signature/claims/expiry, user existence + activity,
    per-``jti`` blocklist, and the "logout everywhere" revocation watermark.
    Shared by HTTP and WebSocket auth paths.
    """
    try:
        payload = decode_access_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=exc.code) from exc

    user = await db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    if await token_store.is_blocked(payload["jti"]):
        raise HTTPException(status_code=401, detail="Token has been revoked")

    revoked_since = await token_store.user_revoked_since(user.id)
    if revoked_since is not None and isinstance(payload["iat"], int | float):
        issued_at = datetime.fromtimestamp(payload["iat"], tz=UTC)
        if issued_at < revoked_since:
            raise HTTPException(status_code=401, detail="Token has been revoked")

    return user


async def get_current_user(
    request: Request,
    token: Annotated[str, Depends(get_bearer_token)],
    db: DbSession,
) -> User:
    """Resolve the authenticated user and tag the request for rate limiting."""
    user = await validate_access_token(token, db)
    request.state.current_user = user
    return user


async def get_ws_current_user(websocket: WebSocket, db: DbSession) -> User:
    """Resolve the user for a WebSocket from the ``token`` query parameter.

    Browsers cannot set Authorization headers on WebSocket handshakes, so the
    access token is passed as ``?token=...`` instead.
    """
    token = websocket.query_params.get("token", "")
    if not token:
        raise WebSocketException(code=1008, reason="Missing token")
    try:
        return await validate_access_token(token, db)
    except HTTPException as exc:
        raise WebSocketException(code=1008, reason=exc.detail) from exc


def require_roles(*roles: str) -> Callable[..., object]:
    """Return a dependency that allows only the given roles (enforces 403)."""

    async def _role_guard(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in roles:
            raise FORBIDDEN
        return user

    return _role_guard


def require_permission(permission: str) -> Callable[..., object]:
    """Return a dependency that enforces a single permission from the matrix."""

    async def _permission_guard(user: Annotated[User, Depends(get_current_user)]) -> User:
        if not has_permission(user.role, permission):
            raise FORBIDDEN
        return user

    return _permission_guard
