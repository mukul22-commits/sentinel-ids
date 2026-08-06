"""Capture adapter interface (Phase 6)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.schemas.packet import PacketCreate


class CaptureAdapter(ABC):
    """Produces normalized packet records from a live capture source."""

    name: str

    @abstractmethod
    def enabled(self) -> bool:
        """Whether this adapter has a usable source (interface, log files)."""

    @abstractmethod
    async def collect(self) -> list[PacketCreate]:
        """Collect the current batch of packet records (never raises)."""
