"""SQLAlchemy 2.0 declarative base for all ORM models."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for every Sentinel IDS ORM model (Phase 2+)."""
