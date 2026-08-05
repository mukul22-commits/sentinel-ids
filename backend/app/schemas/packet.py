"""Packet schemas (capture lands in Phase 5)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class PacketBase(BaseModel):
    src_ip: str
    src_port: int | None = None
    dst_ip: str
    dst_port: int | None = None
    proto: str
    length: int
    flags: str | None = None
    payload_hash: str | None = None
    raw_ref: str | None = None


class PacketCreate(PacketBase):
    pass


class PacketRead(PacketBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
