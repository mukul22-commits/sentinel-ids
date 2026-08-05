"""Demo Celery task proving worker/broker/DB/Redis integration."""

from __future__ import annotations

import asyncio
import logging

from app.core.celery_app import celery_app
from app.db.session import check_database
from app.services.cache import check_redis

logger = logging.getLogger("sentinel.tasks")


async def _collect_health() -> dict[str, str]:
    database = await check_database()
    redis_status = await check_redis()
    return {"database": database, "redis": redis_status}


def _run_demo_health_check() -> dict[str, str]:
    """Ping PostgreSQL and Redis from within the worker."""
    result = asyncio.run(_collect_health())
    logger.info("demo.health_check completed", extra=result)
    return result


demo_health_check = celery_app.task(name="demo.health_check")(_run_demo_health_check)
