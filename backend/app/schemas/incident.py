"""Incident schemas (response orchestration lands in Phase 4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class IncidentBase(BaseModel):
    title: str
    severity: str
    status: str = "open"
    assignee_id: int | None = None
    alert_ids: list[int] = []
    timeline: list[dict[str, Any]] = []


class IncidentCreate(IncidentBase):
    pass


class IncidentRead(IncidentBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
