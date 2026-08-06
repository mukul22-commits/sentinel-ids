"""Response action orchestration: planning and connector-based execution (Phase 4/7).

``plan_response_action`` produces a deterministic, simulated plan used by the
log connector as the default when no real enforcement integration is
configured. ``execute_response_action`` dispatches through the connector plugin
registry (webhook for block/quarantine, SMTP email for notify, log fallback) so
response actions are enforced end to end.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.response_action import ResponseAction

logger = logging.getLogger("sentinel.response_actions")


def plan_response_action(
    action_type: str, target_type: str, target_value: str
) -> list[dict[str, Any]]:
    """Return a deterministic, simulated response plan for an action."""
    target = f"{target_type}:{target_value}"
    if action_type == "block":
        return [
            {"step": "validate_target", "target": target, "result": "ok"},
            {"step": "apply_firewall_deny", "target": target, "result": "applied"},
            {"step": "verify_block", "target": target, "result": "verified"},
        ]
    if action_type == "quarantine":
        return [
            {"step": "validate_target", "target": target, "result": "ok"},
            {"step": "isolate_host", "target": target, "result": "isolated"},
            {"step": "verify_quarantine", "target": target, "result": "verified"},
        ]
    if action_type == "notify":
        return [
            {"step": "resolve_recipients", "target": target, "result": "resolved"},
            {"step": "send_alert_email", "target": target, "result": "sent"},
        ]
    return [{"step": "unknown_action", "target": target, "result": "skipped"}]


async def execute_response_action(
    db: AsyncSession,
    action: ResponseAction,
    *,
    context: dict[str, Any] | None = None,
) -> ResponseAction:
    """Execute a pending/failed action through the best connector and persist it.

    The connector is selected from the plugin registry; the log connector is the
    always-available fallback. Connector failures mark the action ``failed``
    without raising, so automation and manual execution never break.
    """
    from app.services.connectors import ConnectorError, select_connector

    action.status = "executing"
    await db.flush()

    connector = select_connector(action.action_type)
    try:
        steps = await connector.execute(
            action_type=action.action_type,
            target_type=action.target_type,
            target_value=action.target_value,
            context=context or {},
        )
        action.details = steps
        action.status = "succeeded"
    except ConnectorError as exc:
        logger.warning("connector %s failed for action %s: %s", connector.name, action.id, exc)
        action.details = [
            {"step": "execute", "connector": connector.name, "result": "failed", "error": str(exc)}
        ]
        action.status = "failed"
    action.executed_at = datetime.now(UTC)

    await db.commit()
    await db.refresh(action)
    return action
