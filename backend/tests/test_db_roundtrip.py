"""Database round-trip test for the Packet model (requires PostgreSQL)."""

from __future__ import annotations

import asyncpg
import pytest
from app.core.config import settings
from app.db.session import async_session_factory, engine
from app.models.packet import Packet


async def _db_available() -> bool:
    try:
        connection = await asyncpg.connect(settings.DATABASE_URL, timeout=3)
    except Exception:
        return False
    await connection.close()
    return True


async def test_packet_roundtrip() -> None:
    if not await _db_available():
        pytest.skip("PostgreSQL not reachable - skipping DB round-trip test")

    async with async_session_factory() as session:
        packet = Packet(
            src_ip="192.0.2.1",
            src_port=12345,
            dst_ip="192.0.2.2",
            dst_port=80,
            proto="TCP",
            length=512,
        )
        session.add(packet)
        await session.commit()
        await session.refresh(packet)
        packet_id = packet.id
        packet_ts = packet.ts

    assert packet_id is not None
    assert packet_ts is not None

    async with async_session_factory() as session:
        loaded = await session.get(Packet, (packet_id, packet_ts))
        assert loaded is not None
        assert loaded.src_ip == "192.0.2.1"
        assert loaded.dst_port == 80

    await engine.dispose()
