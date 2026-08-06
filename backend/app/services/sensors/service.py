"""Fleet / multi-sensor service: registration, tokens, heartbeat, watchdog (Phase 8).

Sensors authenticate to the central API with an opaque token (only its SHA-256
hash is stored, so the database never holds usable credentials). Heartbeats keep
a sensor ``online``; a Celery watchdog flips stale sensors back to ``offline``.
Each sensor pulls an effective capture config that the capture cycle uses to run
distributed, per-sensor adapters.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.alert import Alert
from app.models.capture_run import CaptureRun
from app.models.sensor import (
    SENSOR_STATUS_OFFLINE,
    SENSOR_STATUS_ONLINE,
    Sensor,
)
from app.schemas.sensor import SensorCreate, SensorHeartbeat, SensorUpdate

SENSOR_NOT_FOUND = HTTPException(status_code=404, detail="Sensor not found")
SENSOR_NAME_TAKEN = HTTPException(status_code=409, detail="Sensor name already registered")


def generate_sensor_token() -> str:
    """Return a fresh opaque sensor token (url-safe, ``SENSOR_TOKEN_BYTES`` entropy)."""
    return secrets.token_urlsafe(settings.SENSOR_TOKEN_BYTES)


def hash_sensor_token(token: str) -> str:
    """Return the SHA-256 hex digest stored in place of the raw token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def _sensor_name_available(
    db: AsyncSession, name: str, exclude_id: int | None = None
) -> bool:
    stmt = select(Sensor.id).where(func.lower(Sensor.name) == name.lower())
    if exclude_id is not None:
        stmt = stmt.where(Sensor.id != exclude_id)
    return (await db.scalar(stmt)) is None


async def create_sensor(db: AsyncSession, create: SensorCreate) -> tuple[Sensor, str]:
    """Register a new sensor and return it with its one-time plaintext token."""
    if not await _sensor_name_available(db, create.name):
        raise SENSOR_NAME_TAKEN
    token = generate_sensor_token()
    sensor = Sensor(
        name=create.name,
        token_hash=hash_sensor_token(token),
        hostname=create.hostname,
        ip_address=create.ip_address,
        version=create.version,
        config=create.config or {},
    )
    db.add(sensor)
    await db.commit()
    await db.refresh(sensor)
    return sensor, token


async def list_sensors(
    db: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 50,
    status: str | None = None,
) -> tuple[list[Sensor], int]:
    """Return a page of sensors plus the total matching count."""
    stmt = select(Sensor)
    if status is not None:
        stmt = stmt.where(Sensor.status == status)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(Sensor.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def get_sensor(db: AsyncSession, sensor_id: int) -> Sensor | None:
    return await db.get(Sensor, sensor_id)


async def update_sensor(db: AsyncSession, sensor: Sensor, update: SensorUpdate) -> Sensor:
    """Apply the provided updates; ``None`` fields are left untouched."""
    fields = update.model_dump(exclude_unset=True)
    if (
        "name" in fields
        and fields["name"] is not None
        and not await _sensor_name_available(db, fields["name"], exclude_id=sensor.id)
    ):
        raise SENSOR_NAME_TAKEN
    for key, value in fields.items():
        if value is not None:
            setattr(sensor, key, value)
    await db.commit()
    await db.refresh(sensor)
    return sensor


async def rotate_sensor_token(db: AsyncSession, sensor: Sensor) -> str:
    """Regenerate a sensor's token; the old token is invalidated immediately."""
    token = generate_sensor_token()
    sensor.token_hash = hash_sensor_token(token)
    await db.commit()
    await db.refresh(sensor)
    return token


async def delete_sensor(db: AsyncSession, sensor: Sensor) -> None:
    await db.delete(sensor)
    await db.commit()


async def find_sensor_by_token(db: AsyncSession, token: str) -> Sensor | None:
    """Resolve a sensor by its raw token (constant hash lookup)."""
    result = await db.scalar(select(Sensor).where(Sensor.token_hash == hash_sensor_token(token)))
    return result if isinstance(result, Sensor) else None


async def record_heartbeat(
    db: AsyncSession,
    sensor: Sensor,
    heartbeat: SensorHeartbeat,
) -> None:
    """Mark the sensor online and refresh its reported identity + timestamp."""
    sensor.status = SENSOR_STATUS_ONLINE
    sensor.last_seen_at = datetime.now(UTC)
    if heartbeat.version is not None:
        sensor.version = heartbeat.version
    if heartbeat.hostname is not None:
        sensor.hostname = heartbeat.hostname
    if heartbeat.ip_address is not None:
        sensor.ip_address = heartbeat.ip_address
    await db.commit()
    await db.refresh(sensor)


async def mark_stale_sensors(db: AsyncSession, max_age_seconds: int) -> int:
    """Flip enabled sensors that missed their heartbeat window to ``offline``.

    Sensors that never heartbeated (``last_seen_at`` null) are left alone so a
    freshly registered sensor only goes offline after its first missed window.
    """
    cutoff = datetime.now(UTC) - timedelta(seconds=max_age_seconds)
    rows = (
        (
            await db.execute(
                select(Sensor).where(
                    Sensor.enabled.is_(True),
                    Sensor.last_seen_at.is_not(None),
                    Sensor.last_seen_at < cutoff,
                )
            )
        )
        .scalars()
        .all()
    )
    for sensor in rows:
        sensor.status = SENSOR_STATUS_OFFLINE
    if rows:
        await db.commit()
    return len(rows)


async def list_enabled_sensors(db: AsyncSession) -> list[Sensor]:
    return list(
        (
            await db.execute(
                select(Sensor).where(
                    Sensor.enabled.is_(True), Sensor.status == SENSOR_STATUS_ONLINE
                )
            )
        )
        .scalars()
        .all()
    )


def effective_config(sensor: Sensor) -> dict[str, Any]:
    """Resolve a sensor's capture config: stored overrides on top of defaults.

    Top-level keys merge shallowly; a stored adapter override replaces that
    adapter's defaults wholesale so operators can pin an exact adapter config.
    """
    defaults: dict[str, Any] = {
        "capture_enabled": bool(settings.CAPTURE_ENABLED),
        "capture_cycle_seconds": settings.CAPTURE_CYCLE_SECONDS,
        "adapters": {
            "scapy_sniff": {
                "enabled": True,
                "interface": settings.SNIFF_INTERFACE,
                "count": settings.SNIFF_COUNT,
                "timeout": settings.SNIFF_TIMEOUT,
            },
            "suricata_eve": {
                "enabled": True,
                "path": settings.SURICATA_EVE_PATH,
            },
            "zeek_conn": {
                "enabled": True,
                "path": settings.ZEEK_CONN_LOG_PATH,
            },
        },
    }
    overrides = sensor.config or {}
    merged = {**defaults, **overrides}
    if isinstance(merged.get("adapters"), dict) and isinstance(defaults.get("adapters"), dict):
        merged["adapters"] = {
            **defaults["adapters"],
            **overrides.get("adapters", {}),
        }
    return merged


async def fleet_summary(db: AsyncSession) -> dict[str, Any]:
    """Return fleet-wide counters and per-sensor alert/capture tallies."""
    sensors = list((await db.scalars(select(Sensor))).all())
    name_by_id = {sensor.id: sensor.name for sensor in sensors}
    total = len(sensors)
    online = sum(1 for s in sensors if s.enabled and s.status == SENSOR_STATUS_ONLINE)
    offline = sum(1 for s in sensors if s.enabled and s.status == SENSOR_STATUS_OFFLINE)
    disabled = sum(1 for s in sensors if not s.enabled)

    since = datetime.now(UTC) - timedelta(hours=24)
    alert_counts = (
        await db.execute(
            select(Alert.sensor_id, func.count(Alert.id))
            .where(Alert.created_at >= since)
            .group_by(Alert.sensor_id)
        )
    ).all()
    capture_counts = (
        await db.execute(
            select(CaptureRun.sensor_id, func.count(CaptureRun.id))
            .where(CaptureRun.started_at >= since)
            .group_by(CaptureRun.sensor_id)
        )
    ).all()

    return {
        "total": total,
        "online": online,
        "offline": offline,
        "disabled": disabled,
        "alerts_last_24h": sum(count for _, count in alert_counts),
        "alerts_by_sensor": {
            name_by_id.get(sensor_id, "unknown"): count
            for sensor_id, count in alert_counts
            if sensor_id is not None
        },
        "captures_by_sensor": {
            name_by_id.get(sensor_id, "unknown"): count
            for sensor_id, count in capture_counts
            if sensor_id is not None
        },
    }
