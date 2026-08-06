"""Alert ORM model (detection engine lands in Phase 5)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Float, Identity, Index, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_src_ip", "src_ip"),
        Index("ix_alerts_dst_ip", "dst_ip"),
        Index("ix_alerts_rule_id", "rule_id"),
        Index("ix_alerts_detector", "detector"),
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    title: Mapped[str | None] = mapped_column(Text)
    rule_id: Mapped[int | None] = mapped_column(BigInteger)
    detector: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text)
    src_ip: Mapped[str] = mapped_column(Text)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_ip: Mapped[str] = mapped_column(Text)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    risk_score: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(Text, server_default=text("'new'"))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
