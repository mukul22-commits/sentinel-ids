"""Async SQLAlchemy engine and session factory for PostgreSQL."""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings

logger = logging.getLogger("sentinel.db")

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=settings.DB_POOL_PRE_PING,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_recycle=settings.DB_POOL_RECYCLE_SECONDS,
)

async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield a database session for FastAPI dependency injection."""
    async with async_session_factory() as session:
        yield session


async def check_database() -> str:
    """Check PostgreSQL connectivity using a fresh, non-pooled connection."""
    probe_engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
    try:
        async with probe_engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return "connected"
    except Exception as exc:
        logger.warning("database connectivity check failed: %s", exc)
        return "disconnected"
    finally:
        await probe_engine.dispose()
