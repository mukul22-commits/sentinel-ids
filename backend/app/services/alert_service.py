"""Alert service (interface stub, implemented in Phase 5)."""

from __future__ import annotations

from app.schemas.alert import AlertCreate


class AlertService:
    """Interface for alert creation and management."""

    async def create(self, alert: AlertCreate) -> int:
        raise NotImplementedError("Alert creation is implemented in Phase 5")


alert_service = AlertService()
