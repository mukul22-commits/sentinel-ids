"""System info/stats schemas."""

from __future__ import annotations

from pydantic import BaseModel


class SystemInfo(BaseModel):
    app: str
    version: str
    environment: str
    uptime_seconds: int


class SystemStats(BaseModel):
    app: str
    version: str
    environment: str
    uptime_seconds: int
