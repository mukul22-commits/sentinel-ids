"""Celery task for fleet health: marks stale sensors offline (Phase 8)."""

from __future__ import annotations

import asyncio
import logging

from app.core.celery_app import celery_app
from app.core.config import settings
from app.db.session import async_session_factory
from app.services.sensors.service import mark_stale_sensors

logger = logging.getLogger("sentinel.tasks")


def _run_sensor_watchdog() -> dict[str, int]:
    async def _inner() -> dict[str, int]:
        async with async_session_factory() as db:
            offlined = await mark_stale_sensors(db, settings.SENSOR_STALE_AFTER_SECONDS)
        return {"offlined": offlined}

    result = asyncio.run(_inner())
    logger.info("sensors.watchdog marked %d stale sensor(s) offline", result["offlined"])
    return result


sensor_watchdog = celery_app.task(name="sensors.watchdog")(_run_sensor_watchdog)
