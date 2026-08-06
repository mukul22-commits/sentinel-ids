"""Alert schemas (detection engine, Phase 5)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AlertBase(BaseModel):
    title: str | None = None
    rule_id: int | None = None
    detector: str | None = None
    severity: str
    category: str
    src_ip: str
    src_port: int | None = None
    dst_ip: str
    dst_port: int | None = None
    risk_score: float
    status: str = "new"
    details: dict[str, Any] | None = None


class AlertCreate(AlertBase):
    pass


class AlertRead(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime


class AlertList(BaseModel):
    items: list[AlertRead]
    total: int
    page: int
    page_size: int


class AlertStatusUpdate(BaseModel):
    status: str
