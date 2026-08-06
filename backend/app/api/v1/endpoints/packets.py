"""Packet API endpoints: query, bulk ingest, and pcap import (Phase 5)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile
from sqlalchemy import func, select

from app.api.v1.deps import DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_ALERTS, PERMISSION_VIEW_ALERTS
from app.models.packet import Packet
from app.models.user import User
from app.schemas.common import Envelope
from app.schemas.packet import (
    PacketCreate,
    PacketIngestSummary,
    PacketList,
    PacketRead,
)
from app.services.detection import detection_engine
from app.services.detection.records import to_detection_record
from app.services.packet_capture import CaptureUnavailableError, parse_pcap_bytes
from app.services.packet_service import ingest as ingest_packets

router = APIRouter(prefix="/packets", tags=["packets"])

PacketViewer = Annotated[User, Depends(require_permission(PERMISSION_VIEW_ALERTS))]
PacketManager = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_ALERTS))]

SinceParam = Annotated[datetime | None, Query()]
UntilParam = Annotated[datetime | None, Query()]

_VALID_PROTOCOLS = ("tcp", "udp", "icmp", "other")


@router.get("", response_model=Envelope[PacketList])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_packets(
    request: Request,
    _actor: PacketViewer,
    db: DbSession,
    src_ip: str | None = Query(default=None),
    dst_ip: str | None = Query(default=None),
    proto: str | None = Query(default=None),
    since: SinceParam = None,
    until: UntilParam = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
) -> Envelope[PacketList]:
    request_id = get_request_id(request)
    if proto is not None and proto not in _VALID_PROTOCOLS:
        raise HTTPException(status_code=422, detail="Invalid protocol filter")

    stmt = select(Packet)
    if src_ip is not None:
        stmt = stmt.where(Packet.src_ip == src_ip)
    if dst_ip is not None:
        stmt = stmt.where(Packet.dst_ip == dst_ip)
    if proto is not None:
        stmt = stmt.where(Packet.proto == proto)
    if since is not None:
        stmt = stmt.where(Packet.ts >= since)
    if until is not None:
        stmt = stmt.where(Packet.ts <= until)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(Packet.ts.desc()).offset((page - 1) * page_size).limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return Envelope(
        success=True,
        data=PacketList(
            items=[PacketRead.model_validate(p) for p in rows],
            total=total,
            page=page,
            page_size=page_size,
        ),
        request_id=request_id,
    )


@router.post("", response_model=Envelope[PacketIngestSummary])
@limiter.limit(settings.RATE_LIMIT_API)
async def ingest_packets_endpoint(
    request: Request,
    payload: list[PacketCreate],
    _actor: PacketManager,
    db: DbSession,
) -> Envelope[PacketIngestSummary]:
    request_id = get_request_id(request)
    if not payload:
        raise HTTPException(status_code=422, detail="Packet list must not be empty")
    if len(payload) > 10_000:
        raise HTTPException(status_code=422, detail="Too many packets in one request")
    for packet in payload:
        if packet.proto not in _VALID_PROTOCOLS:
            raise HTTPException(status_code=422, detail=f"Invalid protocol '{packet.proto}'")

    ingested = await ingest_packets(db, payload)
    alerts = await detection_engine.run(db, [to_detection_record(p) for p in payload])
    return Envelope(
        success=True,
        data=PacketIngestSummary(ingested=ingested, alerts=len(alerts)),
        request_id=request_id,
    )


@router.post("/import", response_model=Envelope[PacketIngestSummary])
@limiter.limit(settings.RATE_LIMIT_API)
async def import_pcap(
    request: Request,
    file: UploadFile,
    _actor: PacketManager,
    db: DbSession,
) -> Envelope[PacketIngestSummary]:
    request_id = get_request_id(request)
    if file.content_type not in ("application/vnd.tcpdump.pcap", "application/octet-stream", None):
        raise HTTPException(status_code=422, detail="Unsupported pcap content type")
    try:
        packets = parse_pcap_bytes(await file.read(), source_name=file.filename)
    except CaptureUnavailableError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if not packets:
        raise HTTPException(status_code=422, detail="No IP packets found in pcap")

    ingested = await ingest_packets(db, packets)
    alerts = await detection_engine.run(db, [to_detection_record(p) for p in packets])
    return Envelope(
        success=True,
        data=PacketIngestSummary(ingested=ingested, alerts=len(alerts)),
        request_id=request_id,
    )
