"""Alert API endpoints (detection engine, Phase 5)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.constants import ALERT_STATUSES, RULE_SEVERITIES
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_ALERTS, PERMISSION_VIEW_ALERTS
from app.models.alert import Alert
from app.models.user import User
from app.schemas.alert import AlertCreate, AlertList, AlertRead, AlertStatusUpdate
from app.schemas.common import Envelope
from app.services.alert_service import create_many

router = APIRouter(prefix="/alerts", tags=["alerts"])

AlertViewer = Annotated[User, Depends(require_permission(PERMISSION_VIEW_ALERTS))]
AlertManager = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_ALERTS))]

SinceParam = Annotated[datetime | None, Query()]


@router.get("", response_model=Envelope[AlertList])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_alerts(
    request: Request,
    _actor: AlertViewer,
    db: DbSession,
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    detector: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    category: str | None = Query(default=None),
    since: SinceParam = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Envelope[AlertList]:
    request_id = get_request_id(request)
    if severity is not None and severity not in RULE_SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity filter")
    if status is not None and status not in ALERT_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status filter")

    stmt = select(Alert)
    if severity is not None:
        stmt = stmt.where(Alert.severity == severity)
    if status is not None:
        stmt = stmt.where(Alert.status == status)
    if detector is not None:
        stmt = stmt.where(Alert.detector == detector)
    if src_ip is not None:
        stmt = stmt.where(Alert.src_ip == src_ip)
    if category is not None:
        stmt = stmt.where(Alert.category == category)
    if since is not None:
        stmt = stmt.where(Alert.created_at >= since)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(Alert.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return Envelope(
        success=True,
        data=AlertList(
            items=[AlertRead.model_validate(a) for a in rows],
            total=total,
            page=page,
            page_size=page_size,
        ),
        request_id=request_id,
    )


@router.post("", response_model=Envelope[AlertList])
@limiter.limit(settings.RATE_LIMIT_API)
async def create_alerts(
    request: Request,
    payload: list[AlertCreate],
    _actor: AlertManager,
    db: DbSession,
) -> Envelope[AlertList]:
    request_id = get_request_id(request)
    if not payload:
        raise HTTPException(status_code=422, detail="Alert list must not be empty")
    if len(payload) > 500:
        raise HTTPException(status_code=422, detail="Too many alerts in one request")
    for alert in payload:
        if alert.severity not in RULE_SEVERITIES:
            raise HTTPException(status_code=422, detail="Invalid severity")
    rows = await create_many(db, payload)
    return Envelope(
        success=True,
        data=AlertList(
            items=[AlertRead.model_validate(a) for a in rows],
            total=len(rows),
            page=1,
            page_size=len(rows),
        ),
        request_id=request_id,
    )


@router.get("/{alert_id}", response_model=Envelope[AlertRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def get_alert(
    request: Request,
    alert_id: int,
    _actor: AlertViewer,
    db: DbSession,
) -> Envelope[AlertRead]:
    request_id = get_request_id(request)
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return Envelope(success=True, data=AlertRead.model_validate(alert), request_id=request_id)


@router.patch("/{alert_id}/status", response_model=Envelope[AlertRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def set_alert_status(
    request: Request,
    alert_id: int,
    payload: AlertStatusUpdate,
    _actor: AlertManager,
    db: DbSession,
) -> Envelope[AlertRead]:
    request_id = get_request_id(request)
    if payload.status not in ALERT_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status == payload.status:
        raise HTTPException(status_code=400, detail=f"Alert is already {alert.status}")
    alert.status = payload.status
    await db.commit()
    await db.refresh(alert)
    return Envelope(success=True, data=AlertRead.model_validate(alert), request_id=request_id)
