"""Detection rule schemas (rules engine, Phase 5)."""

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


class RuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    yaml_content: str | None = None
    category: str | None = None
    severity: str | None = None
    enabled: bool | None = None


class RuleRead(RuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class RuleList(BaseModel):
    items: list[RuleRead]
    total: int
    page: int
    page_size: int
