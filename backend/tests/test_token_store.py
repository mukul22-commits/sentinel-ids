"""Unit tests for the token revocation store (in-memory fallback path)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.core.token_store import token_store


@pytest.fixture(autouse=True)
async def _reset_store() -> None:
    await token_store.reset()


class TestBlocklist:
    async def test_block_and_unblock(self) -> None:
        assert not await token_store.is_blocked("jti-1")
        await token_store.block_jti("jti-1", ttl=60)
        assert await token_store.is_blocked("jti-1")
        assert not await token_store.is_blocked("jti-2")

    async def test_blocklist_expires(self) -> None:
        token_store._memory["jwt:blocked:jti-1"] = (
            "1",
            (datetime.now(UTC) - timedelta(seconds=1)).timestamp(),
        )
        assert not await token_store.is_blocked("jti-1")


class TestReuseDetection:
    async def test_mark_used(self) -> None:
        assert not await token_store.is_used("jti-x")
        await token_store.mark_used("jti-x", ttl=60)
        assert await token_store.is_used("jti-x")


class TestLogoutEverywhere:
    async def test_revocation_watermark(self) -> None:
        assert await token_store.user_revoked_since(7) is None
        await token_store.revoke_user_tokens(7)
        watermark = await token_store.user_revoked_since(7)
        assert watermark is not None
        assert watermark > datetime.now(UTC) - timedelta(seconds=5)

    async def test_watermark_is_per_user(self) -> None:
        await token_store.revoke_user_tokens(1)
        assert await token_store.user_revoked_since(2) is None


class TestResetTokens:
    async def test_store_and_consume(self) -> None:
        await token_store.store_reset_token("reset-abc", user_id=3, ttl=900)
        assert await token_store.consume_reset_token("reset-abc") == 3

    async def test_single_use(self) -> None:
        await token_store.store_reset_token("reset-abc", user_id=3, ttl=900)
        assert await token_store.consume_reset_token("reset-abc") == 3
        assert await token_store.consume_reset_token("reset-abc") is None

    async def test_unknown_token(self) -> None:
        assert await token_store.consume_reset_token("reset-nope") is None
