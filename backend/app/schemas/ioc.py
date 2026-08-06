"""IOC schemas (threat intel, Phase 5)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IOCBase(BaseModel):
    type: str
    value: str
    source: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class IOCCreate(IOCBase):
    pass


class IOCUpdate(BaseModel):
    source: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class IOCBulkCreate(BaseModel):
    items: list[IOCCreate] = Field(min_length=1, max_length=500)


class IOCRead(IOCBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    first_seen: datetime
    last_seen: datetime


class IOCList(BaseModel):
    items: list[IOCRead]
    total: int
    page: int
    page_size: int
