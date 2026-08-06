"""Incident management and response orchestration endpoints (Phase 4)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.constants import (
    INCIDENT_ALERTING_SEVERITIES,
    INCIDENT_SEVERITIES,
    INCIDENT_STATUSES,
    RESPONSE_ACTION_TARGET_TYPES,
    RESPONSE_ACTION_TYPES,
)
from app.core.limiter import limiter
from app.core.rbac import (
    PERMISSION_MANAGE_INCIDENTS,
    PERMISSION_RESPOND,
    PERMISSION_VIEW_INCIDENTS,
    ROLE_ADMIN,
    ROLE_ANALYST,
)
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.models.user import User
from app.schemas.common import Envelope
from app.schemas.incident import (
    IncidentCreate,
    IncidentList,
    IncidentRead,
    IncidentStatusUpdate,
    IncidentUpdate,
    TimelineEntryCreate,
)
from app.schemas.response_action import ResponseActionCreate, ResponseActionRead
from app.services.audit import audit, client_ip_from
from app.services.notification_service import create_notification
from app.services.realtime import manager
from app.services.response_action_service import execute_response_action
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select

router = APIRouter(prefix="/incidents", tags=["incidents"])

IncidentViewer = Annotated[User, Depends(require_permission(PERMISSION_VIEW_INCIDENTS))]
IncidentManager = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_INCIDENTS))]
Responder = Annotated[User, Depends(require_permission(PERMISSION_RESPOND))]


def _timeline_entry(
    actor: str, action: str, *, note: str | None = None, details: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "ts": datetime.now(UTC),
        "actor": actor,
        "action": action,
        "note": note,
        "details": details,
    }


async def _notify_staff(db: DbSession, *, title: str, body: str, incident_id: int) -> None:
    """Alert all active admins/analysts (staff response channels)."""
    user_ids = (
        await db.scalars(
            select(User.id).where(
                User.is_active.is_(True), User.role.in_([ROLE_ADMIN, ROLE_ANALYST])
            )
        )
    ).all()
    for user_id in user_ids:
        await create_notification(
            db,
            user_id=user_id,
            incident_id=incident_id,
            title=title,
            body=body,
        )


async def _broadcast_incident(kind: str, incident: Incident) -> None:
    payload = IncidentRead.model_validate(incident).model_dump()
    await manager.broadcast({"type": kind, "payload": payload})


async def _notify_assignee(
    db: DbSession,
    incident: Incident,
    *,
    title: str,
    body: str,
) -> None:
    if incident.assignee_id is not None:
        await create_notification(
            db,
            user_id=incident.assignee_id,
            incident_id=incident.id,
            title=title,
            body=body,
            severity=incident.severity,
        )


@router.get("", response_model=Envelope[IncidentList])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_incidents(
    request: Request,
    _actor: IncidentViewer,
    db: DbSession,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    assignee_id: int | None = Query(default=None, ge=1),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Envelope[IncidentList]:
    request_id = get_request_id(request)
    if status is not None and status not in INCIDENT_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status filter")
    if severity is not None and severity not in INCIDENT_SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity filter")

    stmt = select(Incident)
    if status is not None:
        stmt = stmt.where(Incident.status == status)
    if severity is not None:
        stmt = stmt.where(Incident.severity == severity)
    if assignee_id is not None:
        stmt = stmt.where(Incident.assignee_id == assignee_id)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(Incident.updated_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    items = [IncidentRead.model_validate(i) for i in rows]
    return Envelope(
        success=True,
        data=IncidentList(items=items, total=total, page=page, page_size=page_size),
        request_id=request_id,
    )


@router.post("", response_model=Envelope[IncidentRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def create_incident(
    request: Request,
    payload: IncidentCreate,
    actor: IncidentManager,
    db: DbSession,
) -> Envelope[IncidentRead]:
    request_id = get_request_id(request)
    if payload.severity not in INCIDENT_SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity")

    if payload.alert_ids:
        found = (
            await db.scalar(select(func.count(Alert.id)).where(Alert.id.in_(payload.alert_ids)))
            or 0
        )
        if found != len(payload.alert_ids):
            raise HTTPException(status_code=400, detail="One or more alert IDs not found")

    incident = Incident(
        title=payload.title,
        severity=payload.severity,
        status="open",
        alert_ids=list(payload.alert_ids),
        timeline=[
            _timeline_entry(
                actor.username,
                "created",
                note=payload.note,
                details={"severity": payload.severity, "alert_ids": list(payload.alert_ids)},
            )
        ],
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    await audit(
        db,
        action="incident.create",
        resource=f"incident:{incident.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"severity": incident.severity, "alert_ids": incident.alert_ids},
    )
    await _broadcast_incident("incident.created", incident)
    if incident.severity in INCIDENT_ALERTING_SEVERITIES:
        await _notify_staff(
            db,
            title=f"New {incident.severity} incident",
            body=incident.title,
            incident_id=incident.id,
        )
    return Envelope(success=True, data=IncidentRead.model_validate(incident), request_id=request_id)


@router.get("/{incident_id}", response_model=Envelope[IncidentRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def get_incident(
    request: Request,
    incident_id: int,
    _actor: IncidentViewer,
    db: DbSession,
) -> Envelope[IncidentRead]:
    request_id = get_request_id(request)
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return Envelope(success=True, data=IncidentRead.model_validate(incident), request_id=request_id)


@router.patch("/{incident_id}", response_model=Envelope[IncidentRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def update_incident(
    request: Request,
    incident_id: int,
    payload: IncidentUpdate,
    actor: IncidentManager,
    db: DbSession,
) -> Envelope[IncidentRead]:
    request_id = get_request_id(request)
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if payload.severity is not None and payload.severity not in INCIDENT_SEVERITIES:
        raise HTTPException(status_code=422, detail="Invalid severity")

    changed: list[str] = []
    if payload.title is not None and payload.title != incident.title:
        incident.title = payload.title
        changed.append("title")
    if payload.severity is not None and payload.severity != incident.severity:
        incident.severity = payload.severity
        changed.append("severity")
    if payload.assignee_id is not None and payload.assignee_id != incident.assignee_id:
        assignee = await db.get(User, payload.assignee_id)
        if assignee is None or not assignee.is_active:
            raise HTTPException(status_code=400, detail="Assignee not found or inactive")
        incident.assignee_id = payload.assignee_id
        changed.append("assignee")

    if "assignee" in changed:
        incident.timeline.append(
            _timeline_entry(
                actor.username, "assigned", details={"assignee_id": payload.assignee_id}
            )
        )
    elif changed:
        incident.timeline.append(
            _timeline_entry(actor.username, "updated", details={"fields": changed})
        )

    if not changed:
        raise HTTPException(status_code=400, detail="No changes provided")

    await db.commit()
    await db.refresh(incident)
    await audit(
        db,
        action="incident.update",
        resource=f"incident:{incident.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"fields": changed},
    )
    await _broadcast_incident("incident.updated", incident)
    if payload.assignee_id is not None:
        await _notify_assignee(
            db,
            incident,
            title="Incident assigned to you",
            body=incident.title,
        )
    return Envelope(success=True, data=IncidentRead.model_validate(incident), request_id=request_id)


@router.post("/{incident_id}/timeline", response_model=Envelope[IncidentRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def add_timeline_entry(
    request: Request,
    incident_id: int,
    payload: TimelineEntryCreate,
    actor: IncidentManager,
    db: DbSession,
) -> Envelope[IncidentRead]:
    request_id = get_request_id(request)
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.timeline.append(
        _timeline_entry(
            actor.username,
            payload.action,
            note=payload.note,
            details=payload.details,
        )
    )
    await db.commit()
    await db.refresh(incident)
    await audit(
        db,
        action="incident.timeline",
        resource=f"incident:{incident.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"entry": payload.action},
    )
    await _broadcast_incident("incident.updated", incident)
    return Envelope(success=True, data=IncidentRead.model_validate(incident), request_id=request_id)


@router.patch("/{incident_id}/status", response_model=Envelope[IncidentRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def set_incident_status(
    request: Request,
    incident_id: int,
    payload: IncidentStatusUpdate,
    actor: IncidentManager,
    db: DbSession,
) -> Envelope[IncidentRead]:
    request_id = get_request_id(request)
    if payload.status not in INCIDENT_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status")
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.status == payload.status:
        raise HTTPException(status_code=400, detail=f"Incident is already {incident.status}")

    previous = incident.status
    incident.status = payload.status
    incident.timeline.append(
        _timeline_entry(
            actor.username,
            "status_changed",
            details={"from": previous, "to": payload.status},
        )
    )
    await db.commit()
    await db.refresh(incident)
    await audit(
        db,
        action="incident.status",
        resource=f"incident:{incident.id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"from": previous, "to": payload.status},
    )
    await _broadcast_incident("incident.updated", incident)
    if payload.status in ("resolved", "closed"):
        await _notify_assignee(
            db,
            incident,
            title=f"Incident {payload.status}",
            body=incident.title,
        )
    return Envelope(success=True, data=IncidentRead.model_validate(incident), request_id=request_id)


@router.get("/{incident_id}/actions", response_model=Envelope[list[ResponseActionRead]])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_actions(
    request: Request,
    incident_id: int,
    _actor: IncidentViewer,
    db: DbSession,
) -> Envelope[list[ResponseActionRead]]:
    request_id = get_request_id(request)
    if await db.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    rows = (
        (
            await db.execute(
                select(ResponseAction)
                .where(ResponseAction.incident_id == incident_id)
                .order_by(ResponseAction.id)
            )
        )
        .scalars()
        .all()
    )
    return Envelope(
        success=True,
        data=[ResponseActionRead.model_validate(a) for a in rows],
        request_id=request_id,
    )


@router.post("/{incident_id}/actions", response_model=Envelope[ResponseActionRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def create_action(
    request: Request,
    incident_id: int,
    payload: ResponseActionCreate,
    actor: Responder,
    db: DbSession,
) -> Envelope[ResponseActionRead]:
    request_id = get_request_id(request)
    if payload.action_type not in RESPONSE_ACTION_TYPES:
        raise HTTPException(status_code=422, detail="Invalid action type")
    if payload.target_type not in RESPONSE_ACTION_TARGET_TYPES:
        raise HTTPException(status_code=422, detail="Invalid target type")
    if await db.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    action = ResponseAction(
        incident_id=incident_id,
        action_type=payload.action_type,
        target_type=payload.target_type,
        target_value=payload.target_value,
        status="pending",
        created_by=actor.id,
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    await audit(
        db,
        action="incident.action_created",
        resource=f"incident:{incident_id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={
            "action_type": action.action_type,
            "target": f"{action.target_type}:{action.target_value}",
        },
    )
    await manager.broadcast(
        {
            "type": "incident.action_created",
            "payload": ResponseActionRead.model_validate(action).model_dump(),
        }
    )
    return Envelope(
        success=True, data=ResponseActionRead.model_validate(action), request_id=request_id
    )


@router.post(
    "/{incident_id}/actions/{action_id}/execute", response_model=Envelope[ResponseActionRead]
)
@limiter.limit(settings.RATE_LIMIT_API)
async def execute_action(
    request: Request,
    incident_id: int,
    action_id: int,
    actor: Responder,
    db: DbSession,
) -> Envelope[ResponseActionRead]:
    request_id = get_request_id(request)
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    action = await db.get(ResponseAction, action_id)
    if action is None or action.incident_id != incident_id:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.status not in ("pending", "failed"):
        raise HTTPException(status_code=400, detail="Action is not executable")

    action = await execute_response_action(db, action)
    incident.timeline.append(
        _timeline_entry(
            actor.username,
            "action_executed",
            details={
                "action_type": action.action_type,
                "target": f"{action.target_type}:{action.target_value}",
                "status": action.status,
            },
        )
    )
    await db.commit()
    await db.refresh(incident)
    await audit(
        db,
        action="incident.action_executed",
        resource=f"incident:{incident_id}",
        actor_id=actor.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
        details={"action_id": action.id, "status": action.status},
    )
    await _notify_assignee(
        db,
        incident,
        title=f"Response action {action.action_type} succeeded",
        body=f"{action.target_type}:{action.target_value}",
    )
    await manager.broadcast(
        {
            "type": "incident.action_executed",
            "payload": ResponseActionRead.model_validate(action).model_dump(),
        }
    )
    await _broadcast_incident("incident.updated", incident)
    return Envelope(
        success=True, data=ResponseActionRead.model_validate(action), request_id=request_id
    )
