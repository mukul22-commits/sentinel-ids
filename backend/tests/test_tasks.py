"""Tests for the Celery task wrappers (capture/ml/siem/sensors).

The task bodies run their own event loop via ``asyncio.run`` and only touch
the database session factory and a couple of service entry points, which are
stubbed here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from app.models.capture_run import CaptureRun
from app.tasks import capture as capture_tasks
from app.tasks import ml as ml_tasks
from app.tasks import sensors as sensors_tasks
from app.tasks import siem as siem_tasks


class _FakeSession:
    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False


def _fake_factory() -> _FakeSession:
    return _FakeSession()


def _async_returning(result: Any) -> Any:
    async def stub(*args: Any, **kwargs: Any) -> Any:
        return result

    return stub


def _capture_run() -> CaptureRun:
    return CaptureRun(
        id=1,
        adapter="demo",
        status="completed",
        started_at=datetime.now(UTC),
        finished_at=None,
        packets_ingested=10,
        alerts_raised=2,
    )


class TestCaptureTask:
    def test_single_cycle_without_sensors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(capture_tasks, "async_session_factory", _fake_factory)
        monkeypatch.setattr(capture_tasks, "list_enabled_sensors", _async_returning([]))
        monkeypatch.setattr(capture_tasks.capture_manager, "run_cycle", _async_returning([]))

        result = capture_tasks._run_capture_cycle()

        assert result == {"runs": []}

    def test_cycle_per_sensor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(capture_tasks, "async_session_factory", _fake_factory)
        monkeypatch.setattr(
            capture_tasks,
            "list_enabled_sensors",
            _async_returning([{"id": 1, "name": "s1"}]),
        )
        run = _capture_run()

        async def fake_run_cycle(db: Any, sensor: Any = None) -> list[CaptureRun]:
            assert sensor == {"id": 1, "name": "s1"}
            return [run]

        monkeypatch.setattr(capture_tasks.capture_manager, "run_cycle", fake_run_cycle)

        result = capture_tasks._run_capture_cycle()

        assert len(result["runs"]) == 1
        assert result["runs"][0]["adapter"] == "demo"
        assert result["runs"][0]["status"] == "completed"

    def test_task_registered_name(self) -> None:
        assert capture_tasks.capture_cycle.name == "capture.cycle"


class TestMlTask:
    def test_retrain_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ml_tasks, "async_session_factory", _fake_factory)

        async def fake_retrain(db: Any) -> dict[str, Any]:
            return {"status": "completed", "retrained": True}

        monkeypatch.setattr(ml_tasks, "retrain_ml_model", fake_retrain)
        assert ml_tasks._run_ml_retrain() == {"status": "completed", "retrained": True}
        assert ml_tasks.ml_retrain.name == "ml.retrain"


class TestSiemTask:
    def test_export_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(siem_tasks, "async_session_factory", _fake_factory)

        async def fake_export(db: Any) -> dict[str, Any]:
            return {"status": "completed", "exported": 3}

        monkeypatch.setattr(siem_tasks, "export_alerts_to_siem", fake_export)
        assert siem_tasks._run_siem_export() == {"status": "completed", "exported": 3}
        assert siem_tasks.siem_export_alerts.name == "siem.export_alerts"


class TestSensorsTask:
    def test_watchdog_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sensors_tasks, "async_session_factory", _fake_factory)

        async def fake_mark(db: Any, stale_after: int) -> int:
            assert stale_after == sensors_tasks.settings.SENSOR_STALE_AFTER_SECONDS
            return 2

        monkeypatch.setattr(sensors_tasks, "mark_stale_sensors", fake_mark)
        assert sensors_tasks._run_sensor_watchdog() == {"offlined": 2}
        assert sensors_tasks.sensor_watchdog.name == "sensors.watchdog"
