"""Capture manager: runs enabled adapters through ingest + detection (Phase 6)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.capture_run import CaptureRun
from app.services.capture.base import CaptureAdapter
from app.services.capture.sniff import SniffCaptureAdapter
from app.services.capture.suricata_eve import SuricataEveAdapter
from app.services.capture.zeek_log import ZeekLogAdapter
from app.services.detection import detection_engine
from app.services.detection.records import to_detection_record
from app.services.packet_service import ingest

logger = logging.getLogger("sentinel.capture")


class CaptureManager:
    """Runs every enabled adapter for one capture cycle.

    Each adapter's batch is ingested into the ``packets`` hypertable, fed to
    the detection engine, and recorded as a :class:`CaptureRun` for audit and
    observability.
    """

    def __init__(self, adapters: list[CaptureAdapter] | None = None) -> None:
        self.adapters = (
            adapters
            if adapters is not None
            else [
                SniffCaptureAdapter(),
                SuricataEveAdapter(),
                ZeekLogAdapter(),
            ]
        )

    def enabled_adapters(self) -> list[CaptureAdapter]:
        return [adapter for adapter in self.adapters if adapter.enabled()]

    def adapter_status(self) -> list[dict[str, Any]]:
        return [{"name": adapter.name, "enabled": adapter.enabled()} for adapter in self.adapters]

    async def run_cycle(self, db: AsyncSession) -> list[CaptureRun]:
        runs: list[CaptureRun] = []
        for adapter in self.enabled_adapters():
            started_at = datetime.now(UTC)
            try:
                records = await adapter.collect()
                ingested = await ingest(db, records)
                alerts = (
                    await detection_engine.run(
                        db, [to_detection_record(record) for record in records]
                    )
                    if records
                    else []
                )
                run = CaptureRun(
                    adapter=adapter.name,
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                    packets_ingested=ingested,
                    alerts_raised=len(alerts),
                    status="succeeded",
                )
            except Exception as exc:  # noqa: BLE001 - record failures, keep the cycle running
                logger.exception("capture adapter %s failed", adapter.name)
                run = CaptureRun(
                    adapter=adapter.name,
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                    packets_ingested=0,
                    alerts_raised=0,
                    status="failed",
                    error=str(exc),
                )
            db.add(run)
            await db.commit()
            await db.refresh(run)
            runs.append(run)
        return runs


capture_manager = CaptureManager()
