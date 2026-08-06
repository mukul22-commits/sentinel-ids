"""Alert service: persistence and realtime broadcast (Phase 5)."""

from __future__ import annotations

from prometheus_client import Counter
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.schemas.alert import AlertCreate, AlertRead
from app.services.realtime import manager

ALERTS_CREATED = Counter(
    "sentinel_alerts_created_total",
    "Total alerts produced by the detection engine",
    labelnames=["severity", "detector"],
)


async def create_many(db: AsyncSession, alerts: list[AlertCreate]) -> list[Alert]:
    """Persist multiple alerts and broadcast a single ``alerts.created`` event."""
    if not alerts:
        return []
    rows = [Alert(**alert.model_dump()) for alert in alerts]
    db.add_all(rows)
    await db.commit()
    for row in rows:
        await db.refresh(row)
    for alert in alerts:
        ALERTS_CREATED.labels(severity=alert.severity, detector=alert.detector or "unknown").inc()
    await manager.broadcast(
        {
            "type": "alerts.created",
            "payload": [AlertRead.model_validate(row).model_dump() for row in rows],
        }
    )
    return rows
