"""Response action orchestration: planning and simulated execution (Phase 4).

Real enforcement (firewall/EDR/email) is deferred; the executor records a
deterministic plan of steps in ``details`` so the orchestration flow is fully
exercised end-to-end until connectors land in Phase 5.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.response_action import ResponseAction


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


async def execute_response_action(db: AsyncSession, action: ResponseAction) -> ResponseAction:
    """Simulate execution of a pending/failed action and persist the result."""
    action.status = "executing"
    await db.flush()

    action.details = plan_response_action(
        action.action_type, action.target_type, action.target_value
    )
    action.status = "succeeded"
    action.executed_at = datetime.now(UTC)

    await db.commit()
    await db.refresh(action)
    return action
