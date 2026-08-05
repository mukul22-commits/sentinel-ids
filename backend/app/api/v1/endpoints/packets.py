"""Packet API endpoints (stubs until Phase 5)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.v1.deps import get_request_id
from app.schemas.common import Envelope
from app.schemas.packet import PacketRead

router = APIRouter(prefix="/packets", tags=["packets"])


@router.get("", response_model=Envelope[list[PacketRead]])
async def list_packets(
    limit: int = Query(default=50, ge=1, le=500),
    request_id: str = Depends(get_request_id),
) -> Envelope[list[PacketRead]]:
    """List captured packets (placeholder until Phase 5)."""
    return Envelope(success=True, data=[], request_id=request_id)
