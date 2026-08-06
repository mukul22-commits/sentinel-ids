"""Audit logging helpers: one durable row per auth/sensitive action."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

logger = logging.getLogger("sentinel.audit")


async def audit(
    db: AsyncSession,
    *,
    action: str,
    resource: str,
    actor_id: int | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Persist an audit-log row and commit it immediately.

    Committing here guarantees the event survives even if the surrounding
    request later fails (auth success/failures are security-relevant).
    """
    entry = AuditLog(
        user_id=actor_id,
        action=action,
        resource=resource,
        ip=ip,
        user_agent=user_agent,
        details=json.dumps(details) if details else None,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


def client_ip_from(request: Any) -> str:
    """Best-effort client IP, honoring X-Forwarded-For."""
    forwarded = request.headers.get("x-forwarded-for")
    if isinstance(forwarded, str) and forwarded:
        return forwarded.split(",")[0].strip()
    client = getattr(request, "client", None)
    host = getattr(client, "host", None)
    return host if isinstance(host, str) else ""
