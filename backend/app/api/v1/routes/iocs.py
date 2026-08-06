"""Threat intel (IOC) management endpoints (Phase 5)."""

from __future__ import annotations

from typing import Annotated

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.constants import IOC_TYPES
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_IOCS, PERMISSION_VIEW_IOCS
from app.models.user import User
from app.schemas.common import Envelope
from app.schemas.ioc import IOCBulkCreate, IOCCreate, IOCList, IOCRead, IOCUpdate
from app.services.audit import audit, client_ip_from
from app.services.ioc_service import (
    delete_ioc,
    get_ioc,
    list_iocs,
    update_ioc,
    upsert_ioc,
)
from app.services.realtime import manager
from fastapi import APIRouter, Depends, HTTPException, Query, Request

router = APIRouter(prefix="/iocs", tags=["iocs"])

IocViewer = Annotated[User, Depends(require_permission(PERMISSION_VIEW_IOCS))]
IocManager = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_IOCS))]


def _validate_ioc_type(type: str) -> None:
    if type not in IOC_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid IOC type '{type}' (expected one of {', '.join(IOC_TYPES)})",
        )


@router.get("", response_model=Envelope[IOCList])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_iocs_endpoint(
    request: Request,
    _actor: IocViewer,
    db: DbSession,
    type: str | None = Query(default=None),
    source: str | None = Query(default=None),
    q: str | None = Query(default=None, alias="search"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Envelope[IOCList]:
    request_id = get_request_id(request)
    if type is not None:
        _validate_ioc_type(type)
    items, total = await list_iocs(
        db,
        type=type,
        source=source,
        search=q,
        page=page,
        page_size=page_size,
    )
    return Envelope(
        success=True,
        data=IOCList(
            items=[IOCRead.model_validate(i) for i in items],
            total=total,
            page=page,
            page_size=page_size,
        ),
        request_id=request_id,
    )


@router.post("", response_model=Envelope[IOCRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def create_ioc_endpoint(
    request: Request,
    payload: IOCCreate,
    actor: IocManager,
    db: DbSession,
) -> Envelope[IOCRead]:
    request_id = get_request_id(request)
    _validate_ioc_type(payload.type)
    ioc = await upsert_ioc(
        db,
        type=payload.type,
        value=payload.value,
        source=payload.source,
        confidence=payload.confidence,
    )
    await audit(
        db,
        action="ioc.upsert",
        resource=f"ioc:{ioc.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"type": ioc.type, "value": ioc.value, "source": ioc.source},
    )
    await manager.broadcast(
        {"type": "ioc.updated", "payload": IOCRead.model_validate(ioc).model_dump()}
    )
    return Envelope(success=True, data=IOCRead.model_validate(ioc), request_id=request_id)


@router.post("/bulk", response_model=Envelope[IOCList])
@limiter.limit(settings.RATE_LIMIT_API)
async def bulk_create_iocs_endpoint(
    request: Request,
    payload: IOCBulkCreate,
    actor: IocManager,
    db: DbSession,
) -> Envelope[IOCList]:
    request_id = get_request_id(request)
    for item in payload.items:
        _validate_ioc_type(item.type)
    created = [
        await upsert_ioc(
            db,
            type=item.type,
            value=item.value,
            source=item.source,
            confidence=item.confidence,
        )
        for item in payload.items
    ]
    await audit(
        db,
        action="ioc.bulk_upsert",
        resource="iocs",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"count": len(created)},
    )
    return Envelope(
        success=True,
        data=IOCList(
            items=[IOCRead.model_validate(i) for i in created],
            total=len(created),
            page=1,
            page_size=len(created),
        ),
        request_id=request_id,
    )


@router.get("/{ioc_id}", response_model=Envelope[IOCRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def get_ioc_endpoint(
    request: Request,
    ioc_id: int,
    _actor: IocViewer,
    db: DbSession,
) -> Envelope[IOCRead]:
    request_id = get_request_id(request)
    ioc = await get_ioc(db, ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    return Envelope(success=True, data=IOCRead.model_validate(ioc), request_id=request_id)


@router.patch("/{ioc_id}", response_model=Envelope[IOCRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def update_ioc_endpoint(
    request: Request,
    ioc_id: int,
    payload: IOCUpdate,
    actor: IocManager,
    db: DbSession,
) -> Envelope[IOCRead]:
    request_id = get_request_id(request)
    ioc = await get_ioc(db, ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    ioc = await update_ioc(db, ioc, source=payload.source, confidence=payload.confidence)
    await audit(
        db,
        action="ioc.update",
        resource=f"ioc:{ioc.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"type": ioc.type, "value": ioc.value},
    )
    await manager.broadcast(
        {"type": "ioc.updated", "payload": IOCRead.model_validate(ioc).model_dump()}
    )
    return Envelope(success=True, data=IOCRead.model_validate(ioc), request_id=request_id)


@router.delete("/{ioc_id}", response_model=Envelope[None])
@limiter.limit(settings.RATE_LIMIT_API)
async def delete_ioc_endpoint(
    request: Request,
    ioc_id: int,
    actor: IocManager,
    db: DbSession,
) -> Envelope[None]:
    request_id = get_request_id(request)
    ioc = await get_ioc(db, ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    await delete_ioc(db, ioc)
    await audit(
        db,
        action="ioc.delete",
        resource=f"ioc:{ioc_id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
    )
    await manager.broadcast({"type": "ioc.deleted", "payload": {"id": ioc_id}})
    return Envelope(success=True, data=None, request_id=request_id)
