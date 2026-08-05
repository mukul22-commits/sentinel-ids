"""Alert schemas (detection engine lands in Phase 5)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AlertBase(BaseModel):
    rule_id: int | None = None
    severity: str
    category: str
    src_ip: str
    src_port: int | None = None
    dst_ip: str
    dst_port: int | None = None
    risk_score: float
    status: str = "new"


class AlertCreate(AlertBase):
    pass


class AlertRead(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
