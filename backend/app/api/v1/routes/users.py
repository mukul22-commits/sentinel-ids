"""User management endpoints (admin-only, Phase 3)."""

from __future__ import annotations

from typing import Annotated

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_USERS, valid_role
from app.core.token_store import token_store
from app.models.user import User
from app.schemas.common import Envelope
from app.schemas.user import UserList, UserRead, UserUpdate
from app.services.audit import audit, client_ip_from
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select

router = APIRouter(prefix="/users", tags=["users"])

Admin = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_USERS))]


@router.get("", response_model=Envelope[UserList])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_users(
    request: Request,
    _actor: Admin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Envelope[UserList]:
    request_id = get_request_id(request)
    total = await db.scalar(select(func.count(User.id))) or 0
    stmt = select(User).order_by(User.id).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(stmt)).scalars().all()
    items = [UserRead.model_validate(u) for u in rows]
    data = UserList(items=items, total=total, page=page, page_size=page_size)
    return Envelope(success=True, data=data, request_id=request_id)


@router.get("/{user_id}", response_model=Envelope[UserRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def get_user(
    request: Request,
    user_id: int,
    _actor: Admin,
    db: DbSession,
) -> Envelope[UserRead]:
    request_id = get_request_id(request)
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return Envelope(success=True, data=UserRead.model_validate(user), request_id=request_id)


@router.patch("/{user_id}", response_model=Envelope[UserRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def update_user(
    request: Request,
    user_id: int,
    payload: UserUpdate,
    actor: Admin,
    db: DbSession,
) -> Envelope[UserRead]:
    request_id = get_request_id(request)
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.role is not None and payload.role != user.role:
        if not valid_role(payload.role):
            raise HTTPException(status_code=422, detail="Invalid role")
        if user.id == actor.id:
            raise HTTPException(status_code=400, detail="Cannot change your own role")
        user.role = payload.role
    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.is_active is not None:
        if user.id == actor.id and not payload.is_active:
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
        user.is_active = payload.is_active

    await db.commit()
    await db.refresh(user)
    await audit(
        db,
        action="user.update",
        resource=f"user:{user.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Envelope(success=True, data=UserRead.model_validate(user), request_id=request_id)


@router.delete("/{user_id}", response_model=Envelope[bool])
@limiter.limit(settings.RATE_LIMIT_API)
async def delete_user(
    request: Request,
    user_id: int,
    actor: Admin,
    db: DbSession,
) -> Envelope[bool]:
    request_id = get_request_id(request)
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == actor.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    await db.delete(user)
    await db.commit()
    await token_store.revoke_user_tokens(user.id)
    await audit(
        db,
        action="user.delete",
        resource=f"user:{user.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Envelope(success=True, data=True, request_id=request_id)
