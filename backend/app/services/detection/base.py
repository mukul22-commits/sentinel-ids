"""Detector interface shared by signature and ML detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.alert import AlertCreate


class Detector(ABC):
    """Produces alerts from normalized network records.

    A record is a flat mapping of packet/flow attributes (``src_ip``,
    ``dst_ip``, ``src_port``, ``dst_port``, ``proto``, ``length``, ``flags``,
    optional ``payload_text``/``ts``).
    """

    name: str

    @abstractmethod
    def enabled(self) -> bool:
        """Whether the detector has something to run (rules/model loaded)."""

    @abstractmethod
    async def detect(self, db: AsyncSession, records: list[dict[str, Any]]) -> list[AlertCreate]:
        """Return alerts (not yet persisted) for the given records."""
