"""Notification service: durable user notifications + realtime push (Phase 4)."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.notification import Notification
from app.schemas.notification import NotificationRead
from app.services.realtime import manager


async def create_notification(
    db: AsyncSession,
    *,
    user_id: int,
    title: str,
    body: str | None = None,
    incident_id: int | None = None,
    severity: str | None = None,
) -> Notification:
    """Persist a notification for ``user_id`` and push it over WebSocket."""
    notification = Notification(
        user_id=user_id,
        incident_id=incident_id,
        title=title,
        body=body,
        severity=severity,
    )
    db.add(notification)
    await db.commit()
    await db.refresh(notification)
    await manager.send_to_user(
        user_id,
        {
            "type": "notification.created",
            "payload": NotificationRead.model_validate(notification).model_dump(),
        },
    )
    return notification
