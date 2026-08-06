"""Advanced detection status: YARA rules introspection (Phase 9)."""

from __future__ import annotations

from typing import Annotated, Any

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_SYSTEM, PERMISSION_READ
from app.models.user import User
from app.schemas.common import Envelope
from app.services.detection import YaraDetector
from app.services.detection.yara import _payload_bytes
from app.services.ueba import profiles_metadata, retrain_ueba_profiles
from fastapi import APIRouter, Depends, HTTPException, Request

router = APIRouter(prefix="/system/detection", tags=["detection"])

DetectionReader = Annotated[User, Depends(require_permission(PERMISSION_READ))]
DetectionOperator = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_SYSTEM))]


@router.get("/yara", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def yara_status(request: Request, _actor: DetectionReader) -> Envelope[dict[str, Any]]:
    request_id = get_request_id(request)
    detector = YaraDetector()
    return Envelope(
        success=True,
        data={
            "enabled": detector.enabled(),
            "rules_dir": str(detector.rules_dir),
            "max_payload_bytes": detector.max_payload_bytes,
            "rule_count": len(detector.rules()),
            "rules": [{"file": path, "name": name} for path, name in detector.rules()],
            "load_errors": [
                {"file": path, "error": message} for path, message in detector.rule_errors()
            ],
        },
        request_id=request_id,
    )


@router.post("/yara/reload", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def yara_reload(request: Request, _actor: DetectionOperator) -> Envelope[dict[str, Any]]:
    request_id = get_request_id(request)
    detector = YaraDetector()
    return Envelope(
        success=True,
        data={
            "rule_count": len(detector.rules()),
            "load_errors": [
                {"file": path, "error": message} for path, message in detector.rule_errors()
            ],
        },
        request_id=request_id,
    )


@router.post("/payload", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def inspect_payload_extraction(
    request: Request,
    payload: dict[str, Any],
    _actor: DetectionOperator,
) -> Envelope[dict[str, Any]]:
    request_id = get_request_id(request)
    data = _payload_bytes(payload, 1_048_576)
    return Envelope(
        success=True,
        data={"extracted": data is not None, "bytes": len(data) if data else 0},
        request_id=request_id,
    )


@router.get("/ueba", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def ueba_status(request: Request, _actor: DetectionReader) -> Envelope[dict[str, Any]]:
    request_id = get_request_id(request)
    return Envelope(success=True, data=profiles_metadata(), request_id=request_id)


@router.post("/ueba/retrain", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def ueba_retrain(
    request: Request,
    _actor: DetectionOperator,
    db: DbSession,
) -> Envelope[dict[str, Any]]:
    request_id = get_request_id(request)
    try:
        result = await retrain_ueba_profiles(db)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"UEBA retraining unavailable: {exc}") from exc
    return Envelope(success=True, data=result, request_id=request_id)
