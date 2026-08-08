"""Tests exercising the Redis-backed branches of the token store and cache.

A fake in-memory Redis client is swapped in for the real one so the ``client is
not None`` paths (and their ``RedisError`` fallbacks) are covered without a live
Redis server.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.core.token_store import token_store
from app.services import cache
from redis.exceptions import RedisError


class _FakeRedis:
    def __init__(self, *, ping_error: bool = False, op_error: bool = False) -> None:
        self.store: dict[str, str] = {}
        self.closed = False
        self.ping_error = ping_error
        self.op_error = op_error
        self.aclose_calls = 0

    async def ping(self) -> None:
        if self.ping_error:
            raise RedisError("unreachable")

    async def aclose(self) -> None:
        self.aclose_calls += 1

    async def get(self, key: str) -> str | None:
        if self.op_error:
            raise RedisError("get failed")
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None, nx: bool = False) -> Any:
        if self.op_error:
            raise RedisError("set failed")
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def delete(self, key: str) -> int:
        if self.op_error:
            raise RedisError("delete failed")
        return 1 if self.store.pop(key, None) is not None else 0


@pytest.fixture(autouse=True)
async def _reset_store() -> None:
    await token_store.reset()


def _patch_redis(monkeypatch: pytest.MonkeyPatch, fake: _FakeRedis) -> None:
    monkeypatch.setattr(cache, "_client", lambda: fake)
    from app.core import token_store as ts

    monkeypatch.setattr(ts, "_client", lambda: fake)


class TestBlocklistRedis:
    async def test_block_and_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeRedis()
        _patch_redis(monkeypatch, fake)
        await token_store.block_jti("jti-1", 600)
        assert await token_store.is_blocked("jti-1") is True
        assert await token_store.is_blocked("jti-2") is False
        assert fake.aclose_calls >= 2

    async def test_set_error_falls_back_to_memory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis(op_error=True))
        await token_store.block_jti("jti-1", 600)
        assert await token_store.is_blocked("jti-1") is True

    async def test_ping_error_falls_back_to_memory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis(ping_error=True))
        await token_store.block_jti("jti-1", 600)
        assert await token_store.is_blocked("jti-1") is True

    async def test_get_error_falls_back_to_memory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis(op_error=True))
        await token_store.block_jti("jti-1", 600)
        assert await token_store.is_blocked("jti-1") is True


class TestUsedAndRevocation:
    async def test_mark_used_and_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis())
        await token_store.mark_used("rt-1", 600)
        assert await token_store.is_used("rt-1") is True
        assert await token_store.is_used("rt-2") is False

    async def test_revocation_watermark(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis())
        await token_store.revoke_user_tokens(42, ttl_days=1)
        revoked = await token_store.user_revoked_since(42)
        assert revoked is not None
        assert await token_store.user_revoked_since(43) is None

    async def test_revocation_watermark_corrupt_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _FakeRedis()
        fake.store["jwt:user:revoked:9"] = "not-a-datetime"
        _patch_redis(monkeypatch, fake)
        assert await token_store.user_revoked_since(9) is None

    async def test_revocation_default_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis())
        await token_store.revoke_user_tokens(7)
        assert await token_store.user_revoked_since(7) is not None


class TestResetTokensRedis:
    async def test_store_and_consume(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis())
        await token_store.store_reset_token("reset-abc", 5, 600)
        assert await token_store.consume_reset_token("reset-abc") == 5

    async def test_consume_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis())
        assert await token_store.consume_reset_token("missing") is None

    async def test_consume_error_falls_back_to_memory(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_redis(monkeypatch, _FakeRedis(op_error=True))
        await token_store.store_reset_token("reset-xyz", 6, 600)
        assert await token_store.consume_reset_token("reset-xyz") == 6


class TestOidcStateRedis:
    async def test_store_and_consume(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis())
        await token_store.store_oidc_state("state-1", "nonce:abc", 600)
        assert await token_store.consume_oidc_state("state-1") == "nonce:abc"

    async def test_consume_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis())
        assert await token_store.consume_oidc_state("state-missing") is None

    async def test_consume_error_falls_back_to_memory(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_redis(monkeypatch, _FakeRedis(op_error=True))
        await token_store.store_oidc_state("state-2", "nonce:xyz", 600)
        assert await token_store.consume_oidc_state("state-2") == "nonce:xyz"


class TestCacheRedis:
    async def test_check_redis_connected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis())
        assert await cache.check_redis() == "connected"

    async def test_check_redis_disconnected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis(ping_error=True))
        assert await cache.check_redis() == "disconnected"

    async def test_get_json_hit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeRedis()
        fake.store["k"] = '{"a": 1}'
        _patch_redis(monkeypatch, fake)
        assert await cache.get_json("k") == {"a": 1}

    async def test_get_json_miss_and_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis())
        assert await cache.get_json("missing") is None
        _patch_redis(monkeypatch, _FakeRedis(op_error=True))
        assert await cache.get_json("k") is None

    async def test_set_json_success_and_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis())
        assert await cache.set_json("k", {"b": 2}, ttl=30) is True
        _patch_redis(monkeypatch, _FakeRedis(op_error=True))
        assert await cache.set_json("k", {"b": 2}) is False

    async def test_delete_success_miss_and_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeRedis()
        fake.store["del"] = "1"
        _patch_redis(monkeypatch, fake)
        assert await cache.delete("del") is True
        assert await cache.delete("del") is False
        _patch_redis(monkeypatch, _FakeRedis(op_error=True))
        assert await cache.delete("del") is False

    async def test_acquire_success_and_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_redis(monkeypatch, _FakeRedis())
        assert await cache.acquire("lock-1", ttl=30) is True
        _patch_redis(monkeypatch, _FakeRedis(op_error=True))
        assert await cache.acquire("lock-2", ttl=30) is True
