"""External SIEM export endpoints: status, connectivity test, manual export (Phase 7)."""

from __future__ import annotations

from typing import Annotated, Any

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_SYSTEM
from app.models.siem_export_run import SiemExportRun
from app.models.user import User
from app.schemas.common import Envelope
from app.services.siem import (
    export_alerts_to_siem,
    pending_alert_count,
    send_test_event,
    siem_configured,
)
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select

router = APIRouter(prefix="/system/siem", tags=["system"])

SystemOperator = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_SYSTEM))]


@router.get("/status", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def siem_status(
    request: Request,
    _actor: SystemOperator,
    db: DbSession,
) -> Envelope[dict[str, Any]]:
    request_id = get_request_id(request)
    last_run = (
        await db.scalars(select(SiemExportRun).order_by(SiemExportRun.id.desc()).limit(1))
    ).first()
    data = {
        "enabled": settings.SIEM_EXPORT_ENABLED,
        "endpoint_configured": bool(settings.SIEM_CEF_ENDPOINT_URL),
        "endpoint": settings.SIEM_CEF_ENDPOINT_URL,
        "batch_size": settings.SIEM_BATCH_SIZE,
        "configured": siem_configured(),
        "pending_alerts": await pending_alert_count(db),
        "last_run": (
            {
                "id": last_run.id,
                "status": last_run.status,
                "alerts_exported": last_run.alerts_exported,
                "started_at": last_run.started_at,
                "finished_at": last_run.finished_at,
                "error": last_run.error,
            }
            if last_run is not None
            else None
        ),
    }
    return Envelope(success=True, data=data, request_id=request_id)


@router.post("/test", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def siem_test(
    request: Request,
    _actor: SystemOperator,
    db: DbSession,
) -> Envelope[dict[str, Any]]:
    request_id = get_request_id(request)
    result = await send_test_event(db)
    if result.get("status") == "failed":
        raise HTTPException(status_code=502, detail=result.get("error", "SIEM test failed"))
    return Envelope(success=True, data=result, request_id=request_id)


@router.post("/export", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def siem_export(
    request: Request,
    _actor: SystemOperator,
    db: DbSession,
) -> Envelope[dict[str, Any]]:
    request_id = get_request_id(request)
    result = await export_alerts_to_siem(db)
    return Envelope(success=True, data=result, request_id=request_id)
