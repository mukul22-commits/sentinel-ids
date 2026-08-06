"""Sensor / fleet schemas (Phase 8)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SensorBase(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    hostname: str | None = None
    ip_address: str | None = None
    version: str | None = None


class SensorCreate(SensorBase):
    config: dict[str, Any] = Field(default_factory=dict)


class SensorUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    hostname: str | None = None
    ip_address: str | None = None
    version: str | None = None
    enabled: bool | None = None
    config: dict[str, Any] | None = None


class SensorRead(SensorBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: str
    enabled: bool
    config: dict[str, Any]
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime


class SensorList(BaseModel):
    items: list[SensorRead]
    total: int
    page: int
    page_size: int


class SensorRegistered(BaseModel):
    """Registration response: the sensor plus its one-time plaintext token."""

    sensor: SensorRead
    token: str


class SensorHeartbeat(BaseModel):
    version: str | None = None
    hostname: str | None = None
    ip_address: str | None = None


class SensorConfig(BaseModel):
    """Effective capture config a sensor pulls from the central API."""

    sensor_id: int
    capture_enabled: bool
    capture_cycle_seconds: int
    adapters: dict[str, dict[str, Any]]


class FleetSummary(BaseModel):
    total: int
    online: int
    offline: int
    disabled: int
    alerts_last_24h: int
    alerts_by_sensor: dict[str, int]
    captures_by_sensor: dict[str, int]
