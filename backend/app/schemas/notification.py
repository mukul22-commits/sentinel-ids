"""Notification schemas (Phase 4)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class NotificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int | None
    title: str
    body: str | None
    severity: str | None
    read: bool
    created_at: datetime


class NotificationList(BaseModel):
    items: list[NotificationRead]
    total: int
    page: int
    page_size: int
