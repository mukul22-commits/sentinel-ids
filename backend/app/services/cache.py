"""Async Redis cache helpers."""

from __future__ import annotations

import json
import logging
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import settings

logger = logging.getLogger("sentinel.cache")


def _client() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)


async def check_redis() -> str:
    """Check Redis connectivity using a fresh client."""
    client = _client()
    try:
        await client.ping()
        return "connected"
    except Exception as exc:
        logger.warning("redis connectivity check failed: %s", exc)
        return "disconnected"
    finally:
        await client.aclose()


async def get_json(key: str) -> Any | None:
    """Fetch a JSON-encoded value from the cache, or None on miss/error."""
    client = _client()
    try:
        raw = await client.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except RedisError as exc:
        logger.warning("redis get failed for key %r: %s", key, exc)
        return None
    finally:
        await client.aclose()


async def set_json(key: str, value: Any, ttl: int | None = None) -> bool:
    """Store a JSON-encoded value with an optional TTL in seconds."""
    client = _client()
    try:
        await client.set(key, json.dumps(value), ex=ttl)
        return True
    except RedisError as exc:
        logger.warning("redis set failed for key %r: %s", key, exc)
        return False
    finally:
        await client.aclose()


async def delete(key: str) -> bool:
    """Delete a key from the cache. Returns True when the key existed."""
    client = _client()
    try:
        return bool(await client.delete(key))
    except RedisError as exc:
        logger.warning("redis delete failed for key %r: %s", key, exc)
        return False
    finally:
        await client.aclose()


async def acquire(key: str, *, ttl: int) -> bool:
    """Atomically set ``key`` only when absent (SET NX EX).

    Used for automation cooldowns. Fails open (returns True) when Redis is
    unreachable so response automation is never silently suppressed.
    """
    client = _client()
    try:
        return bool(await client.set(key, "1", nx=True, ex=ttl))
    except RedisError as exc:
        logger.warning("redis acquire failed for key %r: %s", key, exc)
        return True
    finally:
        await client.aclose()
