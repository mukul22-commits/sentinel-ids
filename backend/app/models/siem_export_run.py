"""SiemExportRun ORM model recording external SIEM export cycles (Phase 7)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Identity, Index, Integer, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SiemExportRun(Base):
    __tablename__ = "siem_exports"
    __table_args__ = (
        Index("ix_siem_exports_status", "status"),
        Index("ix_siem_exports_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alerts_exported: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    status: Mapped[str] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
