"""Response policy management endpoints (Phase 6)."""

from __future__ import annotations

from typing import Annotated

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_POLICIES, PERMISSION_VIEW_POLICIES
from app.models.response_policy import ResponsePolicy
from app.models.user import User
from app.schemas.common import Envelope
from app.schemas.response_policy import (
    ResponsePolicyCreate,
    ResponsePolicyList,
    ResponsePolicyRead,
    ResponsePolicyUpdate,
)
from app.services.audit import audit, client_ip_from
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select

router = APIRouter(prefix="/policies", tags=["response-policies"])

PolicyViewer = Annotated[User, Depends(require_permission(PERMISSION_VIEW_POLICIES))]
PolicyManager = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_POLICIES))]


@router.get("", response_model=Envelope[ResponsePolicyList])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_policies(
    request: Request,
    _actor: PolicyViewer,
    db: DbSession,
    enabled: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Envelope[ResponsePolicyList]:
    request_id = get_request_id(request)
    stmt = select(ResponsePolicy)
    if enabled is not None:
        stmt = stmt.where(ResponsePolicy.enabled.is_(enabled))

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(ResponsePolicy.name).offset((page - 1) * page_size).limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return Envelope(
        success=True,
        data=ResponsePolicyList(
            items=[ResponsePolicyRead.model_validate(p) for p in rows],
            total=total,
            page=page,
            page_size=page_size,
        ),
        request_id=request_id,
    )


@router.post("", response_model=Envelope[ResponsePolicyRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def create_policy(
    request: Request,
    payload: ResponsePolicyCreate,
    actor: PolicyManager,
    db: DbSession,
) -> Envelope[ResponsePolicyRead]:
    request_id = get_request_id(request)
    policy = ResponsePolicy(
        name=payload.name,
        enabled=payload.enabled,
        conditions=payload.conditions.model_dump(),
        actions=[action.model_dump() for action in payload.actions],
        cooldown_seconds=payload.cooldown_seconds,
        created_by=actor.id,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    await audit(
        db,
        action="policy.create",
        resource=f"policy:{policy.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"name": policy.name, "enabled": policy.enabled},
    )
    return Envelope(
        success=True, data=ResponsePolicyRead.model_validate(policy), request_id=request_id
    )


@router.get("/{policy_id}", response_model=Envelope[ResponsePolicyRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def get_policy(
    request: Request,
    policy_id: int,
    _actor: PolicyViewer,
    db: DbSession,
) -> Envelope[ResponsePolicyRead]:
    request_id = get_request_id(request)
    policy = await db.get(ResponsePolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return Envelope(
        success=True, data=ResponsePolicyRead.model_validate(policy), request_id=request_id
    )


@router.patch("/{policy_id}", response_model=Envelope[ResponsePolicyRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def update_policy(
    request: Request,
    policy_id: int,
    payload: ResponsePolicyUpdate,
    actor: PolicyManager,
    db: DbSession,
) -> Envelope[ResponsePolicyRead]:
    request_id = get_request_id(request)
    policy = await db.get(ResponsePolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    if payload.name is not None:
        policy.name = payload.name
    if payload.enabled is not None:
        policy.enabled = payload.enabled
    if payload.conditions is not None:
        policy.conditions = payload.conditions.model_dump()
    if payload.actions is not None:
        policy.actions = [action.model_dump() for action in payload.actions]
    if payload.cooldown_seconds is not None:
        policy.cooldown_seconds = payload.cooldown_seconds

    await db.commit()
    await db.refresh(policy)
    await audit(
        db,
        action="policy.update",
        resource=f"policy:{policy.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"name": policy.name, "enabled": policy.enabled},
    )
    return Envelope(
        success=True, data=ResponsePolicyRead.model_validate(policy), request_id=request_id
    )


@router.delete("/{policy_id}", response_model=Envelope[None])
@limiter.limit(settings.RATE_LIMIT_API)
async def delete_policy(
    request: Request,
    policy_id: int,
    actor: PolicyManager,
    db: DbSession,
) -> Envelope[None]:
    request_id = get_request_id(request)
    policy = await db.get(ResponsePolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    await db.delete(policy)
    await db.commit()
    await audit(
        db,
        action="policy.delete",
        resource=f"policy:{policy_id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"name": policy.name},
    )
    return Envelope(success=True, data=None, request_id=request_id)
