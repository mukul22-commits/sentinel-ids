"""Unit tests for incident/action/notification schemas and constants (Phase 4)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app.core.constants import (
    INCIDENT_ALERTING_SEVERITIES,
    INCIDENT_SEVERITIES,
    INCIDENT_STATUSES,
    RESPONSE_ACTION_TARGET_TYPES,
    RESPONSE_ACTION_TYPES,
)
from app.schemas.incident import (
    IncidentCreate,
    IncidentRead,
    TimelineEntry,
)
from app.schemas.notification import NotificationRead
from app.schemas.response_action import ResponseActionRead
from pydantic import ValidationError


class TestConstants:
    def test_severities(self) -> None:
        assert INCIDENT_SEVERITIES == ("low", "medium", "high", "critical")
        assert INCIDENT_ALERTING_SEVERITIES == ("high", "critical")

    def test_statuses(self) -> None:
        assert "open" in INCIDENT_STATUSES
        assert "closed" in INCIDENT_STATUSES

    def test_action_types(self) -> None:
        assert "block" in RESPONSE_ACTION_TYPES
        assert "notify" in RESPONSE_ACTION_TYPES

    def test_target_types(self) -> None:
        assert "ip" in RESPONSE_ACTION_TARGET_TYPES
        assert "email" in RESPONSE_ACTION_TARGET_TYPES


class TestIncidentSchemas:
    def test_create_defaults(self) -> None:
        incident = IncidentCreate(title="Suspicious scanning")
        assert incident.severity == "medium"
        assert incident.alert_ids == []

    def test_create_rejects_blank_title(self) -> None:
        with pytest.raises(ValidationError):
            IncidentCreate(title="  ")

    def test_timeline_entry_coerces_raw_dict(self) -> None:
        entry = TimelineEntry.model_validate(
            {
                "ts": "2026-08-06T12:00:00Z",
                "actor": "analyst",
                "action": "created",
                "note": None,
                "details": {"severity": "high"},
            }
        )
        assert entry.action == "created"
        assert entry.ts == datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
        assert entry.details == {"severity": "high"}

    def test_incident_read_coerces_jsonb_timeline(self) -> None:
        incident = IncidentRead(
            id=1,
            title="Suspicious scanning",
            severity="high",
            status="open",
            assignee_id=None,
            alert_ids=[10, 11],
            timeline=[{"ts": "2026-08-06T12:00:00Z", "actor": "alice", "action": "created"}],
            created_at="2026-08-06T12:00:00Z",
            updated_at="2026-08-06T12:00:00Z",
        )
        assert incident.alert_ids == [10, 11]
        assert incident.timeline[0].action == "created"


class TestActionAndNotificationSchemas:
    def test_action_read_defaults(self) -> None:
        action = ResponseActionRead(
            id=1,
            incident_id=1,
            action_type="block",
            target_type="ip",
            target_value="203.0.113.5",
            status="pending",
            created_by=None,
            executed_at=None,
            created_at="2026-08-06T12:00:00Z",
        )
        assert action.details == []
        assert action.status == "pending"

    def test_notification_read(self) -> None:
        notification = NotificationRead(
            id=1,
            incident_id=2,
            title="New incident",
            body="details",
            severity="high",
            read=False,
            created_at="2026-08-06T12:00:00Z",
        )
        assert notification.title == "New incident"
        assert notification.read is False
