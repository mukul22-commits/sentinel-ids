"""Packet schemas (capture, Phase 5)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class PacketBase(BaseModel):
    src_ip: str
    src_port: int | None = None
    dst_ip: str
    dst_port: int | None = None
    proto: str
    length: int = Field(ge=0)
    flags: str | None = None
    payload_hash: str | None = None
    raw_ref: str | None = None


class PacketCreate(PacketBase):
    ts: datetime | None = None


class PacketRead(PacketBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime


class PacketList(BaseModel):
    items: list[PacketRead]
    total: int
    page: int
    page_size: int


class PacketIngestSummary(BaseModel):
    ingested: int
    alerts: int
