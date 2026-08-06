"""Live packet sniffing via Scapy (Phase 6)."""

from __future__ import annotations

import asyncio
import logging

from app.core.config import settings
from app.core.constants import CAPTURE_ADAPTER_SNIFF
from app.schemas.packet import PacketCreate
from app.services.capture.base import CaptureAdapter
from app.services.packet_capture import packet_to_record

logger = logging.getLogger("sentinel.capture.sniff")

try:
    from scapy.sendrecv import sniff as scapy_sniff
except ImportError:  # pragma: no cover - scapy is an optional runtime dep
    scapy_sniff = None  # type: ignore[assignment]


class SniffCaptureAdapter(CaptureAdapter):
    """Captures packets from a live network interface for a bounded window.

    Requires ``SNIFF_INTERFACE`` to be configured (plus Scapy and a capture
    backend such as Npcap on Windows or libpcap on Linux).
    """

    name = CAPTURE_ADAPTER_SNIFF

    def __init__(
        self,
        interface: str | None = None,
        count: int | None = None,
        timeout: int | None = None,
    ) -> None:
        self.interface = interface if interface is not None else settings.SNIFF_INTERFACE
        self.count = count if count is not None else settings.SNIFF_COUNT
        self.timeout = timeout if timeout is not None else settings.SNIFF_TIMEOUT

    def enabled(self) -> bool:
        return bool(settings.CAPTURE_ENABLED and self.interface and scapy_sniff is not None)

    async def collect(self) -> list[PacketCreate]:
        if not self.enabled() or scapy_sniff is None:
            return []

        def _sniff() -> list[PacketCreate]:
            captured = scapy_sniff(
                iface=self.interface,
                count=self.count,
                timeout=self.timeout,
            )
            records: list[PacketCreate] = []
            for packet in captured:
                record = packet_to_record(packet, source_name=f"sniff:{self.interface}")
                if record is not None:
                    records.append(record)
            return records

        logger.info("sniffing %s (count=%d, timeout=%ds)", self.interface, self.count, self.timeout)
        try:
            return await asyncio.to_thread(_sniff)
        except Exception as exc:  # noqa: BLE001 - adapters report failures, never raise
            logger.warning("sniff on %s failed: %s", self.interface, exc)
            return []
