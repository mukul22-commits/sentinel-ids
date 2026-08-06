"""Response automation: policy-driven auto-incidents + response actions (Phase 6).

When an alert matches an enabled :class:`ResponsePolicy`, the automation
service creates an incident, plans and executes the policy's response actions
(block/quarantine/notify), and notifies staff — deduplicated per
``(policy, target)`` by a Redis-backed cooldown.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import INCIDENT_ALERTING_SEVERITIES
from app.core.rbac import ROLE_ADMIN, ROLE_ANALYST
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.models.response_policy import ResponsePolicy
from app.models.user import User
from app.services.cache import acquire
from app.services.notification_service import create_notification
from app.services.realtime import manager
from app.services.response_action_service import execute_response_action

logger = logging.getLogger("sentinel.automation")

AUTOMATION_ACTOR = "automation"


def policy_matches(policy: ResponsePolicy, alert: Alert) -> bool:
    """Return True when ``alert`` satisfies every condition of ``policy``."""
    conditions = policy.conditions or {}
    severities = conditions.get("severity") or []
    if severities and alert.severity not in severities:
        return False
    detectors = conditions.get("detectors") or []
    if detectors and (alert.detector or "unknown") not in detectors:
        return False
    categories = conditions.get("categories") or []
    if categories and alert.category not in categories:
        return False
    min_risk = float(conditions.get("min_risk_score") or 0)
    return not (min_risk > 0 and alert.risk_score < min_risk)


def render_target(template: str, alert: Alert) -> str:
    """Substitute alert fields into a target template (``{{src_ip}}``/``{{dst_ip}}``)."""
    return template.replace("{{src_ip}}", alert.src_ip).replace("{{dst_ip}}", alert.dst_ip)


def cooldown_key(policy_id: int, target: str) -> str:
    return f"automation:cooldown:{policy_id}:{target}"


def _timeline_entry(
    actor: str, action: str, *, note: str | None = None, details: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "ts": datetime.now(UTC),
        "actor": actor,
        "action": action,
        "note": note,
        "details": details,
    }


async def _notify_staff(db: AsyncSession, *, title: str, body: str, incident_id: int) -> None:
    user_ids = (
        await db.scalars(
            select(User.id).where(
                User.is_active.is_(True), User.role.in_([ROLE_ADMIN, ROLE_ANALYST])
            )
        )
    ).all()
    for user_id in user_ids:
        await create_notification(
            db,
            user_id=int(user_id),
            incident_id=incident_id,
            title=title,
            body=body,
        )


async def _create_incident(
    db: AsyncSession, policy: ResponsePolicy, alert: Alert, target: str
) -> Incident:
    incident = Incident(
        title=f"Automated: {alert.title or alert.category}",
        severity=alert.severity,
        status="open",
        alert_ids=[alert.id],
        timeline=[
            _timeline_entry(
                AUTOMATION_ACTOR,
                "auto_created",
                note=f"triggered by policy {policy.name!r}",
                details={
                    "policy_id": policy.id,
                    "alert_id": alert.id,
                    "severity": alert.severity,
                    "target": target,
                },
            )
        ],
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    await manager.broadcast({"type": "incident.created", "payload": _incident_payload(incident)})
    return incident


def _incident_payload(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "assignee_id": incident.assignee_id,
        "alert_ids": list(incident.alert_ids),
        "timeline": list(incident.timeline),
    }


async def _create_actions(
    db: AsyncSession,
    policy: ResponsePolicy,
    alert: Alert,
    target: str,
    incident: Incident,
) -> list[ResponseAction]:
    actions: list[ResponseAction] = []
    for spec in policy.actions or []:
        action_dict = dict(spec)
        if render_target(str(action_dict.get("target_value", "")), alert) != target:
            continue
        action = ResponseAction(
            incident_id=incident.id,
            action_type=str(action_dict.get("action_type", "notify")),
            target_type=str(action_dict.get("target_type", "ip")),
            target_value=target,
            status="pending",
            created_by=None,
        )
        db.add(action)
        await db.commit()
        await db.refresh(action)
        await manager.broadcast(
            {"type": "incident.action_created", "payload": _action_payload(action)}
        )
        actions.append(action)
    return actions


def _action_payload(action: ResponseAction) -> dict[str, Any]:
    return {
        "id": action.id,
        "incident_id": action.incident_id,
        "action_type": action.action_type,
        "target_type": action.target_type,
        "target_value": action.target_value,
        "status": action.status,
        "details": list(action.details),
    }


async def _execute_actions(
    db: AsyncSession, incident: Incident, actions: list[ResponseAction]
) -> None:
    for action in actions:
        executed = await execute_response_action(db, action)
        incident.timeline.append(
            _timeline_entry(
                AUTOMATION_ACTOR,
                "action_executed",
                details={
                    "action_type": executed.action_type,
                    "target": f"{executed.target_type}:{executed.target_value}",
                    "status": executed.status,
                },
            )
        )
        await db.commit()
        await manager.broadcast(
            {"type": "incident.action_executed", "payload": _action_payload(executed)}
        )
    await db.refresh(incident)
    await manager.broadcast({"type": "incident.updated", "payload": _incident_payload(incident)})


async def _announce(db: AsyncSession, incident: Incident) -> None:
    if incident.severity in INCIDENT_ALERTING_SEVERITIES:
        await _notify_staff(
            db,
            title=f"Automated {incident.severity} incident",
            body=incident.title,
            incident_id=incident.id,
        )


async def trigger_automation(db: AsyncSession, alerts: list[Alert]) -> list[dict[str, Any]]:
    """Evaluate policies against newly created alerts and execute matches."""
    if not alerts:
        return []
    policies = (
        await db.scalars(select(ResponsePolicy).where(ResponsePolicy.enabled.is_(True)))
    ).all()
    if not policies:
        return []

    triggered: list[dict[str, Any]] = []
    for alert in alerts:
        for policy in policies:
            if not policy_matches(policy, alert):
                continue
            targets = {
                render_target(str(spec.get("target_value", "")), alert) for spec in policy.actions
            }
            for target in targets:
                if not target:
                    continue
                if policy.cooldown_seconds > 0 and not await acquire(
                    cooldown_key(policy.id, target), ttl=policy.cooldown_seconds
                ):
                    continue
                incident = await _create_incident(db, policy, alert, target)
                actions = await _create_actions(db, policy, alert, target, incident)
                await _execute_actions(db, incident, actions)
                await _announce(db, incident)
                triggered.append(
                    {
                        "policy_id": policy.id,
                        "alert_id": alert.id,
                        "incident_id": incident.id,
                        "target": target,
                        "actions": len(actions),
                    }
                )
    if triggered:
        logger.info("response automation triggered %d response(s)", len(triggered))
    return triggered
