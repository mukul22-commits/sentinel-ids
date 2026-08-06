"""Capture run and adapter status schemas (Phase 6)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class CaptureRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    adapter: str
    started_at: datetime
    finished_at: datetime | None
    packets_ingested: int
    alerts_raised: int
    status: str
    error: str | None


class CaptureRunList(BaseModel):
    items: list[CaptureRunRead]
    total: int
    page: int
    page_size: int


class AdapterStatus(BaseModel):
    name: str
    enabled: bool


class CaptureStatus(BaseModel):
    adapters: list[AdapterStatus]
    last_runs: dict[str, CaptureRunRead | None]
