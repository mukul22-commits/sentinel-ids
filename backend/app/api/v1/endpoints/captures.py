"""Live capture API endpoints: run history, adapter status, manual cycle (Phase 6)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.constants import CAPTURE_RUN_STATUSES
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_SYSTEM, PERMISSION_READ
from app.models.capture_run import CaptureRun
from app.models.user import User
from app.schemas.capture import AdapterStatus, CaptureRunList, CaptureRunRead, CaptureStatus
from app.schemas.common import Envelope
from app.services.capture import capture_manager

router = APIRouter(prefix="/captures", tags=["captures"])

CaptureReader = Annotated[User, Depends(require_permission(PERMISSION_READ))]
CaptureOperator = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_SYSTEM))]


@router.get("", response_model=Envelope[CaptureRunList])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_capture_runs(
    request: Request,
    _actor: CaptureReader,
    db: DbSession,
    adapter: str | None = Query(default=None),
    status: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Envelope[CaptureRunList]:
    request_id = get_request_id(request)
    if status is not None and status not in CAPTURE_RUN_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status filter")

    stmt = select(CaptureRun)
    if adapter is not None:
        stmt = stmt.where(CaptureRun.adapter == adapter)
    if status is not None:
        stmt = stmt.where(CaptureRun.status == status)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(CaptureRun.started_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return Envelope(
        success=True,
        data=CaptureRunList(
            items=[CaptureRunRead.model_validate(run) for run in rows],
            total=total,
            page=page,
            page_size=page_size,
        ),
        request_id=request_id,
    )


@router.get("/status", response_model=Envelope[CaptureStatus])
@limiter.limit(settings.RATE_LIMIT_API)
async def capture_status(
    request: Request,
    _actor: CaptureReader,
    db: DbSession,
) -> Envelope[CaptureStatus]:
    request_id = get_request_id(request)
    adapters = [AdapterStatus(**item) for item in capture_manager.adapter_status()]

    recent = (
        (await db.execute(select(CaptureRun).order_by(CaptureRun.started_at.desc()).limit(50)))
        .scalars()
        .all()
    )
    last_runs: dict[str, CaptureRunRead | None] = {
        adapter.name: None for adapter in capture_manager.adapters
    }
    for run in recent:
        if last_runs.get(run.adapter) is None:
            last_runs[run.adapter] = CaptureRunRead.model_validate(run)

    return Envelope(
        success=True,
        data=CaptureStatus(adapters=adapters, last_runs=last_runs),
        request_id=request_id,
    )


@router.post("/run", response_model=Envelope[list[CaptureRunRead]])
@limiter.limit(settings.RATE_LIMIT_API)
async def run_capture_cycle(
    request: Request,
    _actor: CaptureOperator,
    db: DbSession,
) -> Envelope[list[CaptureRunRead]]:
    request_id = get_request_id(request)
    runs = await capture_manager.run_cycle(db)
    return Envelope(
        success=True,
        data=[CaptureRunRead.model_validate(run) for run in runs],
        request_id=request_id,
    )
