"""Response action schemas (Phase 4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ResponseActionCreate(BaseModel):
    action_type: str
    target_type: str
    target_value: str = Field(min_length=1, max_length=512)


class ResponseActionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    action_type: str
    target_type: str
    target_value: str
    status: str
    details: list[dict[str, Any]] = []
    created_by: int | None
    executed_at: datetime | None
    created_at: datetime
