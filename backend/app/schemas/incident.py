"""Incident schemas (response orchestration lands in Phase 4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TimelineEntry(BaseModel):
    ts: datetime
    actor: str
    action: str
    note: str | None = None
    details: dict[str, Any] | None = None


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    severity: str = "medium"
    alert_ids: list[int] = []
    note: str | None = Field(default=None, max_length=2000)


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=255)
    severity: str | None = None
    assignee_id: int | None = None


class IncidentStatusUpdate(BaseModel):
    status: str


class TimelineEntryCreate(BaseModel):
    action: str = Field(min_length=1, max_length=100)
    note: str | None = Field(default=None, max_length=2000)
    details: dict[str, Any] | None = None


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    severity: str
    status: str
    assignee_id: int | None
    alert_ids: list[int]
    timeline: list[TimelineEntry]
    created_at: datetime
    updated_at: datetime


class IncidentList(BaseModel):
    items: list[IncidentRead]
    total: int
    page: int
    page_size: int
