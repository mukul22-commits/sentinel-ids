"""Health, readiness, and liveness endpoints (root namespace, unenveloped)."""

from __future__ import annotations

from fastapi import APIRouter, Response

from app.core.config import settings
from app.db.session import check_database
from app.services.cache import check_redis

router = APIRouter(tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    """Compatibility probe from Phase 1: always 200 when the process is up."""
    db_status = await check_database()
    redis_status = await check_redis()
    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "database": db_status,
        "redis": redis_status,
    }


@router.get("/health/ready")
async def health_ready(response: Response) -> dict[str, str]:
    """Readiness probe: 200 only when PostgreSQL and Redis are reachable."""
    db_status = await check_database()
    redis_status = await check_redis()
    ready = db_status == "connected" and redis_status == "connected"
    response.status_code = 200 if ready else 503
    return {
        "status": "ready" if ready else "not_ready",
        "database": db_status,
        "redis": redis_status,
    }


@router.get("/health/live")
async def health_live() -> dict[str, str]:
    """Liveness probe: always 200 while the process is alive."""
    return {"status": "alive", "version": settings.APP_VERSION}
