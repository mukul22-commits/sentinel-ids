"""Celery application instance (Redis broker and result backend)."""

from __future__ import annotations

from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "sentinel_ids",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.tasks.demo", "app.tasks.capture", "app.tasks.ml"],
)

celery_app.conf.update(
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
    worker_concurrency=settings.CELERY_WORKER_CONCURRENCY,
    beat_schedule=(
        {
            "health-check-every-30s": {
                "task": "demo.health_check",
                "schedule": 30.0,
            },
            "capture-cycle": {
                "task": "capture.cycle",
                "schedule": settings.CAPTURE_CYCLE_SECONDS,
            },
            "ml-retrain-daily": {
                "task": "ml.retrain",
                "schedule": 86_400.0,
            },
        }
        if settings.CELERY_BEAT_SCHEDULE_ENABLED
        else {}
    ),
)
