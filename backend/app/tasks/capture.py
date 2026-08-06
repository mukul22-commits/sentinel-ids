"""Celery task running one live-capture cycle (Phase 6)."""

from __future__ import annotations

import asyncio
import logging

from app.core.celery_app import celery_app
from app.db.session import async_session_factory
from app.schemas.capture import CaptureRunRead
from app.services.capture import capture_manager

logger = logging.getLogger("sentinel.tasks")


def _run_capture_cycle() -> dict[str, list[object]]:
    async def _inner() -> dict[str, list[object]]:
        async with async_session_factory() as db:
            runs = await capture_manager.run_cycle(db)
        return {"runs": [CaptureRunRead.model_validate(run).model_dump() for run in runs]}

    result = asyncio.run(_inner())
    logger.info("capture.cycle completed with %d run(s)", len(result["runs"]))
    return result


capture_cycle = celery_app.task(name="capture.cycle")(_run_capture_cycle)
