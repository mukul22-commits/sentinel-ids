"""Alert API endpoints (stubs until Phase 5)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.v1.deps import get_request_id
from app.schemas.alert import AlertRead
from app.schemas.common import Envelope

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=Envelope[list[AlertRead]])
async def list_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    request_id: str = Depends(get_request_id),
) -> Envelope[list[AlertRead]]:
    """List alerts (placeholder until Phase 5)."""
    return Envelope(success=True, data=[], request_id=request_id)
