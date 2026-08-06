"""Threat intel service: IOC CRUD with type+value dedupe (Phase 5)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ioc import IOC


class IOCValidationError(ValueError):
    """Raised when an IOC is invalid."""


async def upsert_ioc(
    db: AsyncSession,
    *,
    type: str,
    value: str,
    source: str | None,
    confidence: float,
) -> IOC:
    """Insert an IOC or refresh ``last_seen`` on a duplicate (type, value)."""
    stmt = pg_insert(IOC).values(type=type, value=value, source=source, confidence=confidence)
    stmt = stmt.on_conflict_do_update(
        index_elements=["type", "value"],
        set_={
            "last_seen": func.now(),
            "source": source,
            "confidence": confidence,
        },
    )
    await db.execute(stmt)
    await db.commit()

    ioc = await db.scalar(select(IOC).where(IOC.type == type, IOC.value == value))
    if ioc is None:  # pragma: no cover - defensive
        raise IOCValidationError("IOC could not be resolved after upsert")
    return ioc


async def list_iocs(
    db: AsyncSession,
    *,
    type: str | None = None,
    source: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[IOC], int]:
    """Return a page of IOCs and the total count matching the filters."""
    stmt = select(IOC)
    if type is not None:
        stmt = stmt.where(IOC.type == type)
    if source is not None:
        stmt = stmt.where(IOC.source == source)
    if search:
        stmt = stmt.where(IOC.value.ilike(f"%{search}%"))

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(IOC.last_seen.desc()).offset((page - 1) * page_size).limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def get_ioc(db: AsyncSession, ioc_id: int) -> IOC | None:
    return await db.get(IOC, ioc_id)


async def update_ioc(
    db: AsyncSession,
    ioc: IOC,
    *,
    source: str | None = None,
    confidence: float | None = None,
) -> IOC:
    if source is not None:
        ioc.source = source
    if confidence is not None:
        ioc.confidence = confidence
    ioc.last_seen = datetime.now(UTC)
    await db.commit()
    await db.refresh(ioc)
    return ioc


async def delete_ioc(db: AsyncSession, ioc: IOC) -> None:
    await db.delete(ioc)
    await db.commit()
