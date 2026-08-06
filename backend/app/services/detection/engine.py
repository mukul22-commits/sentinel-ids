"""Detection engine: runs detectors over records, dedupes, persists (Phase 5)."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import INCIDENT_ALERTING_SEVERITIES
from app.core.rbac import ROLE_ADMIN, ROLE_ANALYST
from app.models.alert import Alert
from app.models.user import User
from app.schemas.alert import AlertCreate
from app.services.alert_service import create_many
from app.services.automation_service import trigger_automation
from app.services.detection.autoencoder import AutoencoderDetector
from app.services.detection.base import Detector
from app.services.detection.ml import MLDetector
from app.services.detection.signature import SignatureDetector
from app.services.detection.ueba import UebaDetector
from app.services.detection.yara import YaraDetector
from app.services.notification_service import create_notification

logger = logging.getLogger("sentinel.detection.engine")


def _dedupe(alerts: Sequence[AlertCreate]) -> list[AlertCreate]:
    """Collapse duplicate detections within a single batch."""
    seen: set[tuple[Any, ...]] = set()
    unique: list[AlertCreate] = []
    for alert in alerts:
        key = (
            alert.rule_id,
            alert.detector,
            alert.src_ip,
            alert.src_port,
            alert.dst_ip,
            alert.dst_port,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(alert)
    return unique


class DetectionEngine:
    """Runs the configured detectors over a batch of records."""

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors = (
            detectors
            if detectors is not None
            else [
                SignatureDetector(),
                YaraDetector(),
                MLDetector(),
                AutoencoderDetector(),
                UebaDetector(),
            ]
        )

    async def run(
        self,
        db: AsyncSession,
        records: list[dict[str, Any]],
        *,
        sensor_id: int | None = None,
    ) -> list[Alert]:
        """Detect, persist, and broadcast alerts for the given records.

        ``sensor_id`` attributes the raised alerts to a fleet sensor.
        """
        if not records:
            return []
        collected: list[AlertCreate] = []
        for detector in self.detectors:
            if not detector.enabled():
                continue
            try:
                collected.extend(await detector.detect(db, records))
            except Exception:
                logger.exception("detector %s failed", detector.name)

        alerts = await create_many(db, _dedupe(collected))
        if alerts and sensor_id is not None:
            for alert in alerts:
                alert.sensor_id = sensor_id
            await db.commit()
        if alerts:
            logger.info("detection engine raised %d alert(s)", len(alerts))
            await self._notify_staff(db, alerts)
            try:
                await trigger_automation(db, alerts)
            except Exception:
                logger.exception("response automation failed")
        return alerts

    @staticmethod
    async def _notify_staff(db: AsyncSession, alerts: list[Alert]) -> None:
        urgent = [a for a in alerts if a.severity in INCIDENT_ALERTING_SEVERITIES]
        if not urgent:
            return
        user_ids = (
            await db.scalars(
                select(User.id).where(
                    User.is_active.is_(True), User.role.in_([ROLE_ADMIN, ROLE_ANALYST])
                )
            )
        ).all()
        for alert in urgent:
            for user_id in user_ids:
                await create_notification(
                    db,
                    user_id=int(user_id),
                    title=f"{alert.severity} alert: {alert.title or alert.category}",
                    body=f"{alert.src_ip} -> {alert.dst_ip}",
                    severity=alert.severity,
                )


detection_engine = DetectionEngine()
