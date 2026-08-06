"""ML model status and retraining endpoints (Phase 6)."""

from __future__ import annotations

from typing import Annotated, Any

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_SYSTEM, PERMISSION_READ
from app.models.user import User
from app.schemas.common import Envelope
from app.services.detection.retrain import model_metadata, retrain_ml_model
from fastapi import APIRouter, Depends, HTTPException, Request

router = APIRouter(prefix="/system/ml", tags=["ml"])

MlReader = Annotated[User, Depends(require_permission(PERMISSION_READ))]
MlOperator = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_SYSTEM))]


@router.get("", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def get_ml_status(
    request: Request,
    _actor: MlReader,
) -> Envelope[dict[str, Any]]:
    request_id = get_request_id(request)
    return Envelope(success=True, data=model_metadata(), request_id=request_id)


@router.post("/retrain", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def retrain(
    request: Request,
    _actor: MlOperator,
    db: DbSession,
) -> Envelope[dict[str, Any]]:
    request_id = get_request_id(request)
    try:
        result = await retrain_ml_model(db)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Retraining unavailable: {exc}") from exc
    return Envelope(success=True, data=result, request_id=request_id)
