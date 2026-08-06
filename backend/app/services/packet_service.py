"""Packet ingestion service (Phase 5)."""

from __future__ import annotations

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.packet import Packet
from app.schemas.packet import PacketCreate


async def ingest(db: AsyncSession, packets: list[PacketCreate]) -> int:
    """Bulk-insert packets into the TimescaleDB hypertable.

    Columns left as ``None`` (e.g. server-side ``ts``) are omitted so their
    server defaults apply.
    """
    if not packets:
        return 0
    records = [
        {k: v for k, v in packet.model_dump().items() if v is not None} for packet in packets
    ]
    await db.execute(pg_insert(Packet), records)
    await db.commit()
    return len(records)
