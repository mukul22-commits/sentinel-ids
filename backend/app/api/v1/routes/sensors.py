"""Fleet / multi-sensor endpoints: management (RBAC) + sensor agent (token) (Phase 8).

Management routes (``GET/POST/PATCH/DELETE /sensors``) are guarded by the
``view_sensors``/``manage_sensors`` permissions. Sensor-agent routes
(``/sensors/heartbeat``, ``/sensors/config``) authenticate the node itself via
its ``X-Sensor-Token``.
"""

from __future__ import annotations

from typing import Annotated, Any

from app.api.v1.deps import CurrentSensor, DbSession, get_request_id, require_permission
from app.core.config import settings
from app.core.constants import SENSOR_STATUSES
from app.core.limiter import limiter
from app.core.rbac import PERMISSION_MANAGE_SENSORS, PERMISSION_VIEW_SENSORS
from app.models.user import User
from app.schemas.common import Envelope
from app.schemas.sensor import (
    FleetSummary,
    SensorConfig,
    SensorCreate,
    SensorHeartbeat,
    SensorList,
    SensorRead,
    SensorRegistered,
    SensorUpdate,
)
from app.services.sensors.service import (
    SENSOR_NOT_FOUND,
    create_sensor,
    delete_sensor,
    effective_config,
    fleet_summary,
    get_sensor,
    list_sensors,
    record_heartbeat,
    rotate_sensor_token,
    update_sensor,
)
from fastapi import APIRouter, Depends, HTTPException, Query, Request

router = APIRouter(prefix="/sensors", tags=["sensors"])

SensorViewer = Annotated[User, Depends(require_permission(PERMISSION_VIEW_SENSORS))]
SensorManager = Annotated[User, Depends(require_permission(PERMISSION_MANAGE_SENSORS))]


@router.get("/fleet", response_model=Envelope[FleetSummary])
@limiter.limit(settings.RATE_LIMIT_API)
async def fleet_overview(
    request: Request,
    _actor: SensorViewer,
    db: DbSession,
) -> Envelope[FleetSummary]:
    request_id = get_request_id(request)
    return Envelope(
        success=True,
        data=FleetSummary(**await fleet_summary(db)),
        request_id=request_id,
    )


@router.post("/heartbeat", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def sensor_heartbeat(
    request: Request,
    sensor: CurrentSensor,
    db: DbSession,
    heartbeat: SensorHeartbeat,
) -> Envelope[dict[str, Any]]:
    """Sensor health report; refreshes ``last_seen_at`` and marks the node online."""
    request_id = get_request_id(request)
    await record_heartbeat(db, sensor, heartbeat)
    return Envelope(
        success=True,
        data={"status": "online", "server_time": sensor.last_seen_at},
        request_id=request_id,
    )


@router.get("/config", response_model=Envelope[SensorConfig])
@limiter.limit(settings.RATE_LIMIT_API)
async def sensor_config(
    request: Request,
    sensor: CurrentSensor,
) -> Envelope[SensorConfig]:
    """Return the effective capture config this sensor should run."""
    request_id = get_request_id(request)
    config = effective_config(sensor)
    data = SensorConfig(
        sensor_id=sensor.id,
        capture_enabled=bool(config.get("capture_enabled")),
        capture_cycle_seconds=int(config.get("capture_cycle_seconds") or 0),
        adapters=config.get("adapters") or {},
    )
    return Envelope(success=True, data=data, request_id=request_id)


@router.get("", response_model=Envelope[SensorList])
@limiter.limit(settings.RATE_LIMIT_API)
async def list_all_sensors(
    request: Request,
    _actor: SensorViewer,
    db: DbSession,
    status: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Envelope[SensorList]:
    request_id = get_request_id(request)
    if status is not None and status not in SENSOR_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid status filter")
    rows, total = await list_sensors(db, page=page, page_size=page_size, status=status)
    return Envelope(
        success=True,
        data=SensorList(
            items=[SensorRead.model_validate(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
        ),
        request_id=request_id,
    )


@router.post("", response_model=Envelope[SensorRegistered], status_code=201)
@limiter.limit(settings.RATE_LIMIT_API)
async def register_sensor(
    request: Request,
    _actor: SensorManager,
    db: DbSession,
    create: SensorCreate,
) -> Envelope[SensorRegistered]:
    """Register a sensor; the response contains the one-time plaintext token."""
    request_id = get_request_id(request)
    sensor, token = await create_sensor(db, create)
    return Envelope(
        success=True,
        data=SensorRegistered(sensor=SensorRead.model_validate(sensor), token=token),
        request_id=request_id,
    )


@router.get("/{sensor_id}", response_model=Envelope[SensorRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def get_sensor_detail(
    request: Request,
    _actor: SensorViewer,
    db: DbSession,
    sensor_id: int,
) -> Envelope[SensorRead]:
    request_id = get_request_id(request)
    sensor = await get_sensor(db, sensor_id)
    if sensor is None:
        raise SENSOR_NOT_FOUND
    return Envelope(
        success=True,
        data=SensorRead.model_validate(sensor),
        request_id=request_id,
    )


@router.patch("/{sensor_id}", response_model=Envelope[SensorRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def patch_sensor(
    request: Request,
    _actor: SensorManager,
    db: DbSession,
    sensor_id: int,
    update: SensorUpdate,
) -> Envelope[SensorRead]:
    request_id = get_request_id(request)
    sensor = await get_sensor(db, sensor_id)
    if sensor is None:
        raise SENSOR_NOT_FOUND
    sensor = await update_sensor(db, sensor, update)
    return Envelope(
        success=True,
        data=SensorRead.model_validate(sensor),
        request_id=request_id,
    )


@router.post("/{sensor_id}/rotate-token", response_model=Envelope[dict[str, Any]])
@limiter.limit(settings.RATE_LIMIT_API)
async def rotate_token(
    request: Request,
    _actor: SensorManager,
    db: DbSession,
    sensor_id: int,
) -> Envelope[dict[str, Any]]:
    """Rotate a sensor's token; the previous token is invalidated immediately."""
    request_id = get_request_id(request)
    sensor = await get_sensor(db, sensor_id)
    if sensor is None:
        raise SENSOR_NOT_FOUND
    token = await rotate_sensor_token(db, sensor)
    return Envelope(
        success=True,
        data={"token": token},
        request_id=request_id,
    )


@router.delete("/{sensor_id}", response_model=Envelope[dict[str, bool]])
@limiter.limit(settings.RATE_LIMIT_API)
async def remove_sensor(
    request: Request,
    _actor: SensorManager,
    db: DbSession,
    sensor_id: int,
) -> Envelope[dict[str, bool]]:
    request_id = get_request_id(request)
    sensor = await get_sensor(db, sensor_id)
    if sensor is None:
        raise SENSOR_NOT_FOUND
    await delete_sensor(db, sensor)
    return Envelope(success=True, data={"deleted": True}, request_id=request_id)
