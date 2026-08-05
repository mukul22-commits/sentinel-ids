"""Packet ingestion service (interface stub, implemented in Phase 5)."""

from __future__ import annotations

from app.schemas.packet import PacketCreate


class PacketService:
    """Interface for packet ingestion."""

    async def ingest(self, packets: list[PacketCreate]) -> int:
        raise NotImplementedError("Packet ingestion is implemented in Phase 5")


packet_service = PacketService()
