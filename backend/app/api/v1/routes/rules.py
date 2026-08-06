"""Detection rules management endpoints (Phase 5)."""

from __future__ import annotations

from typing import Annotated

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.constants import RULE_SEVERITIES
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_RULES, PERMISSION_VIEW_RULES
from app.models.rule import Rule
from app.models.user import User
from app.schemas.common import Envelope
from app.schemas.rule import RuleCreate, RuleList, RuleRead, RuleUpdate
from app.services.audit import audit, client_ip_from
from app.services.realtime import manager
from app.services.rule_service import (
    RuleValidationError,
    create_rule,
    delete_rule,
    get_rule,
    list_rules,
    update_rule,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request

router = APIRouter(prefix="/rules", tags=["rules"])

RuleViewer = Annotated[User, Depends(require_permission(PERMISSION_VIEW_RULES))]
RuleManager = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_RULES))]


async def _broadcast_rule(kind: str, rule: Rule) -> None:
    await manager.broadcast({"type": kind, "payload": RuleRead.model_validate(rule).model_dump()})


@router.get("", response_model=Envelope[RuleList])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_rules_endpoint(
    request: Request,
    _actor: RuleViewer,
    db: DbSession,
    enabled: bool | None = Query(default=None),
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Envelope[RuleList]:
    request_id = get_request_id(request)
    if severity is not None and severity not in RULE_SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity filter")
    rules, total = await list_rules(
        db,
        enabled=enabled,
        category=category,
        severity=severity,
        search=search,
        page=page,
        page_size=page_size,
    )
    return Envelope(
        success=True,
        data=RuleList(
            items=[RuleRead.model_validate(r) for r in rules],
            total=total,
            page=page,
            page_size=page_size,
        ),
        request_id=request_id,
    )


@router.post("", response_model=Envelope[RuleRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def create_rule_endpoint(
    request: Request,
    payload: RuleCreate,
    actor: RuleManager,
    db: DbSession,
) -> Envelope[RuleRead]:
    request_id = get_request_id(request)
    try:
        rule = await create_rule(
            db,
            name=payload.name,
            description=payload.description,
            yaml_content=payload.yaml_content,
            category=payload.category,
            severity=payload.severity,
            enabled=payload.enabled,
        )
    except RuleValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await audit(
        db,
        action="rule.create",
        resource=f"rule:{rule.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"name": rule.name, "category": rule.category, "severity": rule.severity},
    )
    await _broadcast_rule("rule.created", rule)
    return Envelope(success=True, data=RuleRead.model_validate(rule), request_id=request_id)


@router.get("/{rule_id}", response_model=Envelope[RuleRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def get_rule_endpoint(
    request: Request,
    rule_id: int,
    _actor: RuleViewer,
    db: DbSession,
) -> Envelope[RuleRead]:
    request_id = get_request_id(request)
    rule = await get_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return Envelope(success=True, data=RuleRead.model_validate(rule), request_id=request_id)


@router.patch("/{rule_id}", response_model=Envelope[RuleRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def update_rule_endpoint(
    request: Request,
    rule_id: int,
    payload: RuleUpdate,
    actor: RuleManager,
    db: DbSession,
) -> Envelope[RuleRead]:
    request_id = get_request_id(request)
    rule = await get_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    try:
        rule = await update_rule(
            db,
            rule,
            name=payload.name,
            description=payload.description,
            yaml_content=payload.yaml_content,
            category=payload.category,
            severity=payload.severity,
            enabled=payload.enabled,
        )
    except RuleValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await audit(
        db,
        action="rule.update",
        resource=f"rule:{rule.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"name": rule.name, "version": rule.version, "enabled": rule.enabled},
    )
    await _broadcast_rule("rule.updated", rule)
    return Envelope(success=True, data=RuleRead.model_validate(rule), request_id=request_id)


@router.delete("/{rule_id}", response_model=Envelope[None])
@limiter.limit(settings.RATE_LIMIT_API)
async def delete_rule_endpoint(
    request: Request,
    rule_id: int,
    actor: RuleManager,
    db: DbSession,
) -> Envelope[None]:
    request_id = get_request_id(request)
    rule = await get_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    await delete_rule(db, rule)
    await audit(
        db,
        action="rule.delete",
        resource=f"rule:{rule_id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
    )
    await manager.broadcast({"type": "rule.deleted", "payload": {"id": rule_id}})
    return Envelope(success=True, data=None, request_id=request_id)
