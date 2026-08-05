"""Packet ORM model backed by a TimescaleDB hypertable."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Identity, Index, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Packet(Base):
    __tablename__ = "packets"
    __table_args__ = (
        Index("ix_packets_ts", "ts"),
        Index("ix_packets_src_ip", "src_ip"),
        Index("ix_packets_dst_ip", "dst_ip"),
        Index("ix_packets_proto", "proto"),
        Index("ix_packets_payload_hash", "payload_hash"),
        Index("ix_packets_ts_src_ip_dst_ip", "ts", "src_ip", "dst_ip"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), primary_key=True
    )
    src_ip: Mapped[str] = mapped_column(Text)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_ip: Mapped[str] = mapped_column(Text)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(Text)
    length: Mapped[int] = mapped_column(Integer)
    flags: Mapped[str | None] = mapped_column(Text)
    payload_hash: Mapped[str | None] = mapped_column(Text)
    raw_ref: Mapped[str | None] = mapped_column(Text)
