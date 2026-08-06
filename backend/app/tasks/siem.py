"""Celery task exporting pending alerts to the external SIEM (Phase 7)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import async_session_factory
from app.services.siem import export_alerts_to_siem

logger = logging.getLogger("sentinel.tasks")


def _run_siem_export() -> dict[str, Any]:
    async def _inner() -> dict[str, Any]:
        async with async_session_factory() as db:
            return await export_alerts_to_siem(db)

    result = asyncio.run(_inner())
    logger.info("siem.export_alerts completed with status %r", result.get("status"))
    return result


siem_export_alerts = celery_app.task(name="siem.export_alerts")(_run_siem_export)
