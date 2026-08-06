"""Suricata EVE JSON log ingestion (Phase 6).

Reads the trailing lines of Suricata's ``eve.json`` (or every ``*.json`` file
in a directory) and normalizes flow/packet events into packet records. Each
event's ``timestamp`` is preserved so detection history stays accurate.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.constants import CAPTURE_ADAPTER_SURICATA
from app.schemas.packet import PacketCreate
from app.services.capture.base import CaptureAdapter

logger = logging.getLogger("sentinel.capture.suricata")

_MAX_LINES_PER_FILE = 5_000


class SuricataEveAdapter(CaptureAdapter):
    """Adapter over Suricata EVE JSON logs (file or directory)."""

    name = CAPTURE_ADAPTER_SURICATA

    def __init__(self, path: str | None = None) -> None:
        self.path = path if path is not None else (settings.SURICATA_EVE_PATH or "")

    def enabled(self) -> bool:
        if not (settings.CAPTURE_ENABLED and self.path):
            return False
        return bool(self._paths())

    def _paths(self) -> list[Path]:
        path = Path(self.path)
        if path.is_file():
            return [path]
        if path.is_dir():
            return sorted(path.glob("*.json"))
        return []

    def _to_packet(self, event: dict[str, Any], source: Path) -> PacketCreate | None:
        src_ip = event.get("src_ip")
        dst_ip = event.get("dest_ip")
        if not src_ip or not dst_ip:
            return None
        flow = event.get("flow") or {}
        length = int(flow.get("bytes_toclient") or 0) + int(flow.get("bytes_toserver") or 0)

        timestamp = event.get("timestamp")
        if timestamp:
            try:
                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.now(UTC)
        else:
            ts = datetime.now(UTC)

        return PacketCreate(
            src_ip=str(src_ip),
            src_port=event.get("src_port"),
            dst_ip=str(dst_ip),
            dst_port=event.get("dest_port"),
            proto=str(event.get("proto") or "other").lower(),
            length=length,
            flags=None,
            payload_hash=None,
            raw_ref=f"suricata:{source.name}",
            ts=ts,
        )

    async def collect(self) -> list[PacketCreate]:
        records: list[PacketCreate] = []
        for path in self._paths():
            try:
                lines = self._tail(path, _MAX_LINES_PER_FILE)
            except OSError as exc:
                logger.warning("cannot read %s: %s", path, exc)
                continue
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                record = self._to_packet(event, path)
                if record is not None:
                    records.append(record)
        return records

    @staticmethod
    def _tail(path: Path, max_lines: int) -> list[str]:
        with path.open(encoding="utf-8", errors="replace") as handle:
            return handle.readlines()[-max_lines:]
