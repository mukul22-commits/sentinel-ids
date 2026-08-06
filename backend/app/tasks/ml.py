"""Celery task retraining the ML anomaly detector (Phase 6)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import async_session_factory
from app.services.detection.retrain import retrain_ml_model

logger = logging.getLogger("sentinel.tasks")


def _run_ml_retrain() -> dict[str, Any]:
    async def _inner() -> dict[str, Any]:
        async with async_session_factory() as db:
            return await retrain_ml_model(db)

    result = asyncio.run(_inner())
    logger.info("ml.retrain completed with status %r", result.get("status"))
    return result


ml_retrain = celery_app.task(name="ml.retrain")(_run_ml_retrain)
