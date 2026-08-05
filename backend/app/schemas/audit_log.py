"""Audit log schemas (tracking lands in Phase 3+)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditLogCreate(BaseModel):
    user_id: int | None = None
    action: str
    resource: str
    ip: str | None = None
    user_agent: str | None = None


class AuditLogRead(AuditLogCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
