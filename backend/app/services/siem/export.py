"""External SIEM export service (ArcSight CEF) with a durable watermark (Phase 7).

Alerts are exported in batches (newest-first order by id) to a configured CEF
collector endpoint. Successful exports stamp ``alerts.siem_exported_at``; the
partial index ``ix_alerts_siem_pending`` keeps the pending scan fast. A
``SELECT ... FOR UPDATE SKIP LOCKED`` batch query makes concurrent workers safe
(HA): each un-exported alert is claimed by exactly one exporter.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import func, select

from app.core.config import settings
from app.models.alert import Alert
from app.models.siem_export_run import SiemExportRun
from app.services.siem.cef import build_test_cef_event, format_alert_cef

logger = logging.getLogger("sentinel.siem")

SIEM_RUN_STATUS_RUNNING = "running"
SIEM_RUN_STATUS_SUCCEEDED = "succeeded"
SIEM_RUN_STATUS_FAILED = "failed"


def siem_configured() -> bool:
    return settings.SIEM_EXPORT_ENABLED and bool(settings.SIEM_CEF_ENDPOINT_URL)


async def pending_alert_count(db: Any) -> int:
    """Return the number of alerts not yet exported to the SIEM."""
    return (
        await db.scalar(select(func.count(Alert.id)).where(Alert.siem_exported_at.is_(None))) or 0
    )


async def _send_cef_payload(payload: str) -> None:
    """POST a newline-delimited CEF payload to the configured endpoint."""
    url = settings.SIEM_CEF_ENDPOINT_URL
    if url is None:
        raise ValueError("SIEM_CEF_ENDPOINT_URL is not configured")
    headers = {"Content-Type": "text/plain"}
    if settings.SIEM_AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {settings.SIEM_AUTH_TOKEN}"
    async with httpx.AsyncClient(timeout=settings.SIEM_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.post(url, content=payload, headers=headers)
        response.raise_for_status()


async def export_alerts_to_siem(db: Any, *, batch_size: int | None = None) -> dict[str, Any]:
    """Export one batch of pending alerts to the external SIEM.

    Returns a status dict. Skipped results mean the feature is off or an
    endpoint is not configured; failed results leave alerts un-exported so the
    next cycle retries them.
    """
    if not settings.SIEM_EXPORT_ENABLED:
        return {"status": "skipped", "reason": "SIEM_EXPORT_ENABLED is false"}
    if not settings.SIEM_CEF_ENDPOINT_URL:
        return {"status": "skipped", "reason": "SIEM_CEF_ENDPOINT_URL is not configured"}

    size = batch_size or settings.SIEM_BATCH_SIZE
    run = SiemExportRun(status=SIEM_RUN_STATUS_RUNNING, started_at=datetime.now(UTC))
    db.add(run)
    await db.flush()

    try:
        rows = (
            (
                await db.execute(
                    select(Alert)
                    .where(Alert.siem_exported_at.is_(None))
                    .order_by(Alert.id)
                    .limit(size)
                    .with_for_update(skip_locked=True)
                )
            )
            .scalars()
            .all()
        )

        if not rows:
            run.status = SIEM_RUN_STATUS_SUCCEEDED
            run.finished_at = datetime.now(UTC)
            run.alerts_exported = 0
            await db.commit()
            return {"status": "succeeded", "exported": 0, "pending": await pending_alert_count(db)}

        payload = "\n".join(format_alert_cef(alert) for alert in rows) + "\n"
        await _send_cef_payload(payload)

        exported_at = datetime.now(UTC)
        for alert in rows:
            alert.siem_exported_at = exported_at
        run.status = SIEM_RUN_STATUS_SUCCEEDED
        run.finished_at = exported_at
        run.alerts_exported = len(rows)
        await db.commit()
        logger.info("SIEM export pushed %d alert(s)", len(rows))
        return {
            "status": "succeeded",
            "exported": len(rows),
            "pending": await pending_alert_count(db),
        }
    except Exception as exc:  # noqa: BLE001 - record failures, retry next cycle
        await db.rollback()
        logger.exception("SIEM export batch failed")
        failed = SiemExportRun(
            status=SIEM_RUN_STATUS_FAILED,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            alerts_exported=0,
            error=str(exc),
        )
        db.add(failed)
        await db.commit()
        return {"status": "failed", "exported": 0, "error": str(exc)}


async def send_test_event(db: Any) -> dict[str, Any]:
    """Send one fixed CEF test event to the endpoint to validate connectivity."""
    if not settings.SIEM_CEF_ENDPOINT_URL:
        return {"status": "skipped", "reason": "SIEM_CEF_ENDPOINT_URL is not configured"}
    event = build_test_cef_event()
    try:
        await _send_cef_payload(event + "\n")
    except httpx.HTTPError as exc:
        return {"status": "failed", "error": str(exc)}
    return {"status": "ok", "event": event}
