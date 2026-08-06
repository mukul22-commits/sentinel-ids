"""Connector plugin status and connectivity-test endpoints (Phase 7)."""

from __future__ import annotations

from typing import Annotated, Any

from app.api.v1.deps import get_request_id, require_permission
from app.core.config import settings
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_SYSTEM
from app.models.user import User
from app.schemas.common import Envelope
from app.services.connectors import ConnectorError, connector_registry
from fastapi import APIRouter, Depends, HTTPException, Request

router = APIRouter(prefix="/system/connectors", tags=["system"])

SystemOperator = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_SYSTEM))]


@router.get("", response_model=Envelope[list[dict[str, Any]]])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_connectors(
    request: Request,
    _actor: SystemOperator,
) -> Envelope[list[dict[str, Any]]]:
    request_id = get_request_id(request)
    data = [
        {
            "name": connector.name,
            "kind": connector.kind,
            "enabled": connector.enabled(),
            "description": connector.description,
        }
        for connector in connector_registry.list()
    ]
    return Envelope(success=True, data=data, request_id=request_id)


@router.post("/{connector_name}/test", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def test_connector(
    request: Request,
    connector_name: str,
    _actor: SystemOperator,
) -> Envelope[dict[str, Any]]:
    request_id = get_request_id(request)
    connector = connector_registry.get(connector_name)
    if connector is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    try:
        result = await connector.test()
    except ConnectorError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return Envelope(success=True, data=result, request_id=request_id)
