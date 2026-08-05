"""System info and statistics endpoints."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Response

from app.api.v1.deps import get_request_id
from app.core.config import settings
from app.schemas.common import Envelope
from app.schemas.system import SystemInfo, SystemStats
from app.services import cache

router = APIRouter(prefix="/system", tags=["system"])

APP_START_TIME = time.monotonic()
STATS_CACHE_KEY = "system:stats"


def _current_info() -> SystemInfo:
    return SystemInfo(
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        uptime_seconds=int(time.monotonic() - APP_START_TIME),
    )


def _current_stats() -> SystemStats:
    return SystemStats(**_current_info().model_dump())


@router.get("/info", response_model=Envelope[SystemInfo])
async def system_info(request_id: str = Depends(get_request_id)) -> Envelope[SystemInfo]:
    """Report application metadata."""
    return Envelope(success=True, data=_current_info(), request_id=request_id)


@router.get("/stats", response_model=Envelope[SystemStats])
async def system_stats(
    response: Response, request_id: str = Depends(get_request_id)
) -> Envelope[SystemStats]:
    """Return cached system stats; cache the result for REDIS_CACHE_TTL_SECONDS."""
    cached = await cache.get_json(STATS_CACHE_KEY)
    if cached is not None:
        response.headers["X-Cache"] = "HIT"
        return Envelope(
            success=True,
            data=SystemStats.model_validate(cached),
            request_id=request_id,
        )

    stats = _current_stats()
    await cache.set_json(
        STATS_CACHE_KEY,
        stats.model_dump(mode="json"),
        ttl=settings.REDIS_CACHE_TTL_SECONDS,
    )
    response.headers["X-Cache"] = "MISS"
    return Envelope(success=True, data=stats, request_id=request_id)
