"""Live capture adapters: sniff, Suricata EVE, and Zeek logs (Phase 6).

Each adapter implements :class:`CaptureAdapter` and produces normalized
:class:`~app.schemas.packet.PacketCreate` records that flow through the same
ingestion + detection pipeline as uploaded pcap files.
"""

from app.services.capture.base import CaptureAdapter
from app.services.capture.manager import CaptureManager, capture_manager
from app.services.capture.sniff import SniffCaptureAdapter
from app.services.capture.suricata_eve import SuricataEveAdapter
from app.services.capture.zeek_log import ZeekLogAdapter

__all__ = [
    "CaptureAdapter",
    "CaptureManager",
    "SniffCaptureAdapter",
    "SuricataEveAdapter",
    "ZeekLogAdapter",
    "capture_manager",
]
