"""Celery application instance (Redis broker and result backend)."""

from __future__ import annotations

from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "sentinel_ids",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.tasks.demo",
        "app.tasks.capture",
        "app.tasks.ml",
        "app.tasks.siem",
        "app.tasks.sensors",
    ],
)

celery_app.conf.update(
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
    task_acks_late=True,
    worker_concurrency=settings.CELERY_WORKER_CONCURRENCY,
    worker_max_tasks_per_child=settings.CELERY_WORKER_MAX_TASKS_PER_CHILD,
    worker_prefetch_multiplier=1,
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
            "siem-export-cycle": {
                "task": "siem.export_alerts",
                "schedule": settings.SIEM_EXPORT_SECONDS,
            },
            "sensors-watchdog": {
                "task": "sensors.watchdog",
                "schedule": settings.SENSOR_WATCHDOG_SECONDS,
            },
        }
        if settings.CELERY_BEAT_SCHEDULE_ENABLED
        else {}
    ),
)
