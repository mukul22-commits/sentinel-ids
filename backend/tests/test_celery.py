"""Celery demo task tests (eager mode, no broker required)."""

from __future__ import annotations

from app.core.celery_app import celery_app
from app.tasks.demo import demo_health_check


def test_demo_health_check_runs_eager() -> None:
    celery_app.conf.task_always_eager = True
    result = demo_health_check.delay().get()
    assert result["database"] in {"connected", "disconnected"}
    assert result["redis"] in {"connected", "disconnected"}
