"""Token revocation store backed by Redis, with an in-memory fallback.

Used for:
  - JWT blocklist (revoked access/refresh tokens by ``jti``)
  - Refresh-token reuse detection (rotated ``jti``s)
  - "Logout everywhere" revocation watermark per user
  - Single-use password-reset tokens (TTL 15 minutes)

When Redis is unreachable (e.g. local test runs) the store transparently falls
back to an in-process memory map so the auth flow stays testable.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import settings
from app.services.cache import _client

logger = logging.getLogger("sentinel.tokenstore")

BLOCK_PREFIX = "jwt:blocked:"
USED_PREFIX = "jwt:used:"
USER_REVOKED_PREFIX = "jwt:user:revoked:"
RESET_PREFIX = "reset:"


class TokenStore:
    """Redis-backed token state with an in-memory fallback."""

    def __init__(self) -> None:
        self._memory: dict[str, tuple[str, float]] = {}
        self._redis_down: bool | None = None

    # --- plumbing -----------------------------------------------------------

    def _mem_set(self, key: str, value: str, ttl: int) -> None:
        self._memory[key] = (value, datetime.now(UTC).timestamp() + ttl)

    def _mem_get(self, key: str) -> str | None:
        entry = self._memory.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if datetime.now(UTC).timestamp() > expires_at:
            self._memory.pop(key, None)
            return None
        return value

    def _mem_delete(self, key: str) -> None:
        self._memory.pop(key, None)

    async def _client(self) -> Redis | None:
        client = _client()
        if self._redis_down is True:
            await client.aclose()
            return None
        try:
            await client.ping()
            return client
        except RedisError:
            await client.aclose()
            self._redis_down = True
            logger.warning("token store falling back to in-memory storage")
            return None

    # --- blocklist ----------------------------------------------------------

    async def block_jti(self, jti: str, ttl: int) -> None:
        client = await self._client()
        if client is None:
            self._mem_set(f"{BLOCK_PREFIX}{jti}", "1", ttl)
            return
        try:
            await client.set(f"{BLOCK_PREFIX}{jti}", "1", ex=ttl)
        except RedisError:
            self._mem_set(f"{BLOCK_PREFIX}{jti}", "1", ttl)
        finally:
            await client.aclose()

    async def is_blocked(self, jti: str) -> bool:
        client = await self._client()
        if client is None:
            return self._mem_get(f"{BLOCK_PREFIX}{jti}") is not None
        try:
            return bool(await client.get(f"{BLOCK_PREFIX}{jti}"))
        except RedisError:
            return self._mem_get(f"{BLOCK_PREFIX}{jti}") is not None
        finally:
            await client.aclose()

    # --- reuse detection ----------------------------------------------------

    async def mark_used(self, jti: str, ttl: int) -> None:
        client = await self._client()
        if client is None:
            self._mem_set(f"{USED_PREFIX}{jti}", "1", ttl)
            return
        try:
            await client.set(f"{USED_PREFIX}{jti}", "1", ex=ttl)
        except RedisError:
            self._mem_set(f"{USED_PREFIX}{jti}", "1", ttl)
        finally:
            await client.aclose()

    async def is_used(self, jti: str) -> bool:
        client = await self._client()
        if client is None:
            return self._mem_get(f"{USED_PREFIX}{jti}") is not None
        try:
            return bool(await client.get(f"{USED_PREFIX}{jti}"))
        except RedisError:
            return self._mem_get(f"{USED_PREFIX}{jti}") is not None
        finally:
            await client.aclose()

    # --- logout everywhere --------------------------------------------------

    async def revoke_user_tokens(self, user_id: int, ttl_days: int | None = None) -> None:
        ttl = (ttl_days or settings.REFRESH_TOKEN_EXPIRE_DAYS) * 86400
        value = datetime.now(UTC).isoformat()
        client = await self._client()
        if client is None:
            self._mem_set(f"{USER_REVOKED_PREFIX}{user_id}", value, ttl)
            return
        try:
            await client.set(f"{USER_REVOKED_PREFIX}{user_id}", value, ex=ttl)
        except RedisError:
            self._mem_set(f"{USER_REVOKED_PREFIX}{user_id}", value, ttl)
        finally:
            await client.aclose()

    async def user_revoked_since(self, user_id: int) -> datetime | None:
        client = await self._client()
        if client is None:
            raw: bytes | str | None = self._mem_get(f"{USER_REVOKED_PREFIX}{user_id}")
        else:
            try:
                raw = await client.get(f"{USER_REVOKED_PREFIX}{user_id}")
            except RedisError:
                raw = self._mem_get(f"{USER_REVOKED_PREFIX}{user_id}")
            finally:
                await client.aclose()
        if raw is None:
            return None
        try:
            return datetime.fromisoformat(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
        except ValueError:
            return None

    # --- password reset tokens ----------------------------------------------

    async def store_reset_token(self, token: str, user_id: int, ttl: int) -> None:
        client = await self._client()
        if client is None:
            self._mem_set(f"{RESET_PREFIX}{token}", str(user_id), ttl)
            return
        try:
            await client.set(f"{RESET_PREFIX}{token}", str(user_id), ex=ttl)
        except RedisError:
            self._mem_set(f"{RESET_PREFIX}{token}", str(user_id), ttl)
        finally:
            await client.aclose()

    async def consume_reset_token(self, token: str) -> int | None:
        """Return the user id and invalidate the token (single-use)."""
        client = await self._client()
        if client is None:
            raw: bytes | str | None = self._mem_get(f"{RESET_PREFIX}{token}")
            self._mem_delete(f"{RESET_PREFIX}{token}")
            return int(raw) if raw is not None else None
        try:
            raw = await client.get(f"{RESET_PREFIX}{token}")
            if raw is None:
                return None
            await client.delete(f"{RESET_PREFIX}{token}")
            return int(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
        except RedisError:
            raw = self._mem_get(f"{RESET_PREFIX}{token}")
            self._mem_delete(f"{RESET_PREFIX}{token}")
            return int(raw) if raw is not None else None
        finally:
            await client.aclose()

    # --- test support -------------------------------------------------------

    async def reset(self) -> None:
        """Clear in-memory state (used by tests between cases)."""
        self._memory.clear()
        self._redis_down = None


token_store = TokenStore()
