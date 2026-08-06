"""Celery task running one live-capture cycle (Phase 6/8).

With no registered fleet, a single local cycle runs as before. When online
sensors exist, one cycle is run per sensor with adapters built from that
sensor's own config, attributing runs and alerts to it (distributed capture).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import async_session_factory
from app.schemas.capture import CaptureRunRead
from app.services.capture import capture_manager
from app.services.sensors.service import list_enabled_sensors

logger = logging.getLogger("sentinel.tasks")


def _run_capture_cycle() -> dict[str, list[object]]:
    async def _inner() -> dict[str, list[object]]:
        async with async_session_factory() as db:
            sensors = await list_enabled_sensors(db)
            runs: list[Any] = []
            if sensors:
                for sensor in sensors:
                    runs.extend(await capture_manager.run_cycle(db, sensor=sensor))
            else:
                runs = await capture_manager.run_cycle(db)
        return {"runs": [CaptureRunRead.model_validate(run).model_dump() for run in runs]}

    result = asyncio.run(_inner())
    logger.info("capture.cycle completed with %d run(s)", len(result["runs"]))
    return result


capture_cycle = celery_app.task(name="capture.cycle")(_run_capture_cycle)
