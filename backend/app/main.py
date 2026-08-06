"""Sentinel IDS Platform FastAPI application entrypoint."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Gauge
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi.errors import RateLimitExceeded

from app.api.v1.endpoints.health import router as health_router
from app.api.v1.errors import (
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from app.api.v1.router import api_router
from app.api.v1.routes.ws import ws_router
from app.core.config import settings
from app.core.limiter import limiter, rate_limit_exceeded_handler
from app.core.logging import configure_logging
from app.core.middleware import (
    ProcessTimeMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
)
from app.db.session import engine

logger = logging.getLogger("sentinel.app")

SENTINEL_APP_INFO = Gauge(
    "sentinel_app_info",
    "Sentinel IDS Platform metadata",
    labelnames=["app", "version"],
)
SENTINEL_APP_INFO.labels("sentinel-ids", settings.APP_VERSION).set(1)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown lifecycle hooks."""
    configure_logging()
    logger.info(
        "Sentinel IDS Platform starting",
        extra={
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        },
    )
    yield
    await engine.dispose()
    logger.info("Sentinel IDS Platform stopped")


def create_app() -> FastAPI:
    """Build the FastAPI application with routes, middleware, and metrics."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(ProcessTimeMiddleware)
    app.add_middleware(RequestIdMiddleware)

    app.include_router(health_router)
    app.include_router(api_router)
    app.include_router(ws_router)

    app.state.limiter = limiter
    app.add_exception_handler(
        RateLimitExceeded, rate_limit_exceeded_handler  # type: ignore[arg-type]
    )
    app.add_exception_handler(HTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(
        RequestValidationError, validation_exception_handler  # type: ignore[arg-type]
    )
    app.add_exception_handler(Exception, unhandled_exception_handler)

    Instrumentator().instrument(app).expose(app, endpoint="/metrics")

    return app


app = create_app()
