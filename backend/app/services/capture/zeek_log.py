"""Zeek connection log (``conn.log``) ingestion (Phase 6).

Parses Zeek's tab-separated ``conn.log`` header/rows and normalizes each
connection into a packet record, preserving the flow timestamp. Handles the
``#separator``/``#fields`` metadata lines Zeek emits.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.constants import CAPTURE_ADAPTER_ZEEK
from app.schemas.packet import PacketCreate
from app.services.capture.base import CaptureAdapter

logger = logging.getLogger("sentinel.capture.zeek")


class ZeekLogAdapter(CaptureAdapter):
    """Adapter over a Zeek ``conn.log`` file."""

    name = CAPTURE_ADAPTER_ZEEK

    def __init__(self, path: str | None = None) -> None:
        self.path = path if path is not None else (settings.ZEEK_CONN_LOG_PATH or "")

    def enabled(self) -> bool:
        if not (settings.CAPTURE_ENABLED and self.path):
            return False
        return Path(self.path).is_file()

    @staticmethod
    def _parse_ts(raw: str) -> datetime | None:
        try:
            return datetime.fromtimestamp(float(raw), tz=UTC)
        except ValueError:
            return None

    @staticmethod
    def _as_int(raw: str) -> int | None:
        if not raw or raw in ("-", "(empty)"):
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    def _to_packet(self, row: dict[str, Any], source: Path) -> PacketCreate | None:
        src_ip = row.get("id.orig_h")
        dst_ip = row.get("id.resp_h")
        if not src_ip or not dst_ip:
            return None
        ts = self._parse_ts(row.get("ts", "0"))
        orig_bytes = self._as_int(row.get("orig_bytes", "0")) or 0
        resp_bytes = self._as_int(row.get("resp_bytes", "0")) or 0
        return PacketCreate(
            src_ip=str(src_ip),
            src_port=self._as_int(row.get("id.orig_p", "0")),
            dst_ip=str(dst_ip),
            dst_port=self._as_int(row.get("id.resp_p", "0")),
            proto=str(row.get("proto") or "other").lower(),
            length=orig_bytes + resp_bytes,
            flags=None,
            payload_hash=None,
            raw_ref=f"zeek:{source.name}",
            ts=ts if ts is not None else datetime.now(UTC),
        )

    async def collect(self) -> list[PacketCreate]:
        path = Path(self.path)
        if not path.is_file():
            return []
        separator = "\t"
        fields: list[str] = []
        rows: list[dict[str, Any]] = []
        try:
            with path.open(encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = raw_line.rstrip("\n")
                    if line.startswith("#separator"):
                        separator = line.split(" ", 1)[1].encode().decode("unicode_escape")
                    elif line.startswith("#fields"):
                        fields = line[len("#fields") :].lstrip(separator).split(separator)
                    elif line.startswith("#"):
                        continue
                    elif fields:
                        parts = line.split(separator)
                        if len(parts) == len(fields):
                            rows.append(dict(zip(fields, parts, strict=False)))
        except OSError as exc:
            logger.warning("cannot read %s: %s", path, exc)
            return []

        records: list[PacketCreate] = []
        for row in rows:
            record = self._to_packet(row, path)
            if record is not None:
                records.append(record)
        return records
