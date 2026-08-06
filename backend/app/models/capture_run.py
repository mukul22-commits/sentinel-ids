"""CaptureRun ORM model recording live capture cycles (Phase 6)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Identity, Index, Integer, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CaptureRun(Base):
    __tablename__ = "capture_runs"
    __table_args__ = (
        Index("ix_capture_runs_adapter", "adapter"),
        Index("ix_capture_runs_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    adapter: Mapped[str] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    packets_ingested: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    alerts_raised: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    status: Mapped[str] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
