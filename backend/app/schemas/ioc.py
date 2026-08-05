"""IOC schemas (threat intel lands in Phase 5)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class IOCBase(BaseModel):
    type: str
    value: str
    source: str | None = None
    confidence: float


class IOCCreate(IOCBase):
    pass


class IOCRead(IOCBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    first_seen: datetime
    last_seen: datetime
