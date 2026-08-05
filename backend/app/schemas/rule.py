"""Detection rule schemas (rules engine lands in Phase 5)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RuleBase(BaseModel):
    name: str
    description: str | None = None
    yaml_content: str
    category: str
    severity: str
    enabled: bool = True
    version: int = 1


class RuleCreate(RuleBase):
    pass


class RuleRead(RuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
