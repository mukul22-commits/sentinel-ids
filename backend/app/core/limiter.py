"""Rate limiting configuration (slowapi).

Key strategy:
  - Auth endpoints: the limiter's default key resolves to the client IP
    (no user is authenticated yet on register/login).
  - Protected API routes: ``get_current_user`` sets ``request.state.current_user``
    before the per-user limit is checked, so the key resolves to the user id.

``headers_enabled`` is disabled because slowapi's header injection raises on
endpoints that return an Envelope (non-``Response``) without a ``response``
parameter; the 429 handler still returns the standard envelope.

Storage uses Redis in dev/prod and in-memory storage for tests.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from starlette.responses import JSONResponse

from app.core.config import settings
from app.schemas.common import Envelope

logger = logging.getLogger("sentinel.ratelimit")


def _user_or_ip(request: Request) -> str:
    """Rate-limit key: authenticated user id when present, else client IP."""
    user = getattr(request.state, "current_user", None)
    if user is not None and getattr(user, "id", None) is not None:
        return f"user:{user.id}"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


limiter = Limiter(
    key_func=_user_or_ip,
    headers_enabled=False,
    storage_uri=settings.rate_limit_storage_uri,
)


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Return a 429 envelope when a rate limit is exceeded."""
    request_id = request.headers.get("x-request-id", "")
    body: Envelope[Any] = Envelope(
        success=False,
        data=None,
        error="Rate limit exceeded. Please retry later.",
        request_id=request_id,
    )
    return JSONResponse(status_code=429, content=body.model_dump())
