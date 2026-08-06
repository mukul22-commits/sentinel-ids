"""ResponsePolicy ORM model for automated response orchestration (Phase 6)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, Identity, Index, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ResponsePolicy(Base):
    __tablename__ = "response_policies"
    __table_args__ = (Index("ix_response_policies_name", "name"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    conditions: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    actions: Mapped[list[Any]] = mapped_column(JSONB, server_default=text("'[]'::jsonb"))
    cooldown_seconds: Mapped[int] = mapped_column(Integer, server_default=text("3600"))
    created_by: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
