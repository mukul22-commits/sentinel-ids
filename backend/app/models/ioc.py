"""Indicator of Compromise (IOC) ORM model (Phase 5)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float, Identity, Index, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        Index("ix_iocs_type_value", "type", "value", unique=True),
        Index("ix_iocs_first_seen", "first_seen"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    type: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
