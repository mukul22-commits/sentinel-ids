"""Notification endpoints: personal inbox for the current user (Phase 4)."""

from __future__ import annotations

from typing import Annotated

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_VIEW_NOTIFICATIONS
from app.models.notification import Notification
from app.models.user import User
from app.schemas.common import Envelope
from app.schemas.notification import NotificationList, NotificationRead
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select

router = APIRouter(prefix="/notifications", tags=["notifications"])

NotifViewer = Annotated[User, Depends(require_permission(PERMISSION_VIEW_NOTIFICATIONS))]


@router.get("", response_model=Envelope[NotificationList])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_notifications(
    request: Request,
    actor: NotifViewer,
    db: DbSession,
    unread_only: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Envelope[NotificationList]:
    request_id = get_request_id(request)
    stmt = select(Notification).where(Notification.user_id == actor.id)
    if unread_only:
        stmt = stmt.where(Notification.read.is_(False))
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(Notification.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    items = [NotificationRead.model_validate(n) for n in rows]
    return Envelope(
        success=True,
        data=NotificationList(items=items, total=total, page=page, page_size=page_size),
        request_id=request_id,
    )


@router.get("/unread-count", response_model=Envelope[int])
@limiter.limit(settings.RATE_LIMIT_API)
async def unread_count(
    request: Request,
    actor: NotifViewer,
    db: DbSession,
) -> Envelope[int]:
    count = (
        await db.scalar(
            select(func.count(Notification.id)).where(
                Notification.user_id == actor.id, Notification.read.is_(False)
            )
        )
        or 0
    )
    return Envelope(success=True, data=count, request_id=get_request_id(request))


@router.post("/{notification_id}/read", response_model=Envelope[NotificationRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def mark_read(
    request: Request,
    notification_id: int,
    actor: NotifViewer,
    db: DbSession,
) -> Envelope[NotificationRead]:
    request_id = get_request_id(request)
    notification = await db.get(Notification, notification_id)
    if notification is None or notification.user_id != actor.id:
        raise HTTPException(status_code=404, detail="Notification not found")
    if not notification.read:
        notification.read = True
        await db.commit()
        await db.refresh(notification)
    return Envelope(
        success=True, data=NotificationRead.model_validate(notification), request_id=request_id
    )


@router.post("/read-all", response_model=Envelope[int])
@limiter.limit(settings.RATE_LIMIT_API)
async def mark_all_read(
    request: Request,
    actor: NotifViewer,
    db: DbSession,
) -> Envelope[int]:
    marked = (
        await db.scalar(
            select(func.count(Notification.id)).where(
                Notification.user_id == actor.id, Notification.read.is_(False)
            )
        )
        or 0
    )
    if marked:
        unread = (
            await db.scalars(
                select(Notification).where(
                    Notification.user_id == actor.id, Notification.read.is_(False)
                )
            )
        ).all()
        for notification in unread:
            notification.read = True
        await db.commit()
    return Envelope(success=True, data=marked, request_id=get_request_id(request))
