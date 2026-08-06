"""Database round-trip test for Phase 4 models (requires PostgreSQL)."""

from __future__ import annotations

import asyncpg
import pytest
from app.core.config import settings
from app.db.session import async_session_factory, engine
from app.models.incident import Incident
from app.models.notification import Notification
from app.models.response_action import ResponseAction


async def _db_available() -> bool:
    try:
        connection = await asyncpg.connect(settings.DATABASE_URL, timeout=3)
    except Exception:
        return False
    await connection.close()
    return True


async def test_incident_roundtrip() -> None:
    if not await _db_available():
        pytest.skip("PostgreSQL not reachable - skipping DB round-trip test")

    async with async_session_factory() as session:
        incident = Incident(
            title="Suspicious scanning",
            severity="high",
            status="open",
            alert_ids=[1, 2],
            timeline=[{"ts": "2026-08-06T12:00:00Z", "actor": "alice", "action": "created"}],
        )
        session.add(incident)
        await session.commit()
        await session.refresh(incident)
        incident_id = incident.id

        action = ResponseAction(
            incident_id=incident_id,
            action_type="block",
            target_type="ip",
            target_value="203.0.113.5",
        )
        session.add(action)
        await session.commit()
        await session.refresh(action)
        action_id = action.id

        notification = Notification(
            user_id=1,
            incident_id=incident_id,
            title="New high incident",
            severity="high",
        )
        session.add(notification)
        await session.commit()
        await session.refresh(notification)
        notification_id = notification.id

    assert incident_id is not None
    assert action_id is not None
    assert notification_id is not None

    async with async_session_factory() as session:
        loaded = await session.get(Incident, incident_id)
        assert loaded is not None
        assert loaded.alert_ids == [1, 2]
        assert loaded.timeline[0]["action"] == "created"

        loaded_action = await session.get(ResponseAction, action_id)
        assert loaded_action is not None
        assert loaded_action.status == "pending"
        assert loaded_action.incident_id == incident_id

        loaded_notification = await session.get(Notification, notification_id)
        assert loaded_notification is not None
        assert loaded_notification.read is False

    await engine.dispose()
