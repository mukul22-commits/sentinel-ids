"""Sensor ORM model for the distributed fleet (Phase 8).

A sensor is a registered capture node that authenticates with an opaque token,
reports heartbeats, and pulls its capture configuration from the central API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, Identity, Index, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

SENSOR_STATUS_OFFLINE = "offline"
SENSOR_STATUS_ONLINE = "online"
SENSOR_STATUS_DISABLED = "disabled"
SENSOR_STATUSES = (SENSOR_STATUS_ONLINE, SENSOR_STATUS_OFFLINE, SENSOR_STATUS_DISABLED)


class Sensor(Base):
    __tablename__ = "sensors"
    __table_args__ = (
        Index("ix_sensors_status", "status"),
        Index("ix_sensors_name", "name", unique=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[str] = mapped_column(Text)
    hostname: Mapped[str | None] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default=text("'offline'"))
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
