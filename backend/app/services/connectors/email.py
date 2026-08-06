"""SMTP email connector: delivers notify actions to a recipient inbox.

Uses the stdlib ``smtplib`` (executed on a thread pool) so no extra dependency
is required. Supports STARTTLS or implicit TLS and optional authentication.
Disabled when no SMTP host is configured.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from app.core.config import settings
from app.services.connectors.base import Connector, ConnectorError

logger = logging.getLogger("sentinel.connectors")

SMTP_TIMEOUT_SECONDS = 10


def _open_smtp() -> smtplib.SMTP:
    host = settings.EMAIL_SMTP_HOST
    if not host:
        raise ConnectorError("EMAIL_SMTP_HOST is not configured")
    port = settings.EMAIL_SMTP_PORT
    if settings.EMAIL_SMTP_USE_TLS and port == 465:
        client: smtplib.SMTP = smtplib.SMTP_SSL(
            host, port, timeout=SMTP_TIMEOUT_SECONDS, context=ssl.create_default_context()
        )
    else:
        client = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_SECONDS)
        client.ehlo()
        if settings.EMAIL_SMTP_USE_TLS:
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
    if settings.EMAIL_SMTP_USERNAME:
        client.login(settings.EMAIL_SMTP_USERNAME, settings.EMAIL_SMTP_PASSWORD or "")
    return client


def _deliver(recipient: str, subject: str, body: str) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.EMAIL_FROM_ADDR
    message["To"] = recipient
    message.set_content(body)
    try:
        with _open_smtp() as client:
            client.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise ConnectorError(f"SMTP delivery failed: {exc}") from exc


class EmailConnector(Connector):
    name = "smtp_email"
    kind = "email"
    description = "Delivers notify actions as email via SMTP (STARTTLS/implicit TLS)."

    def enabled(self) -> bool:
        return bool(settings.EMAIL_SMTP_HOST)

    async def execute(
        self,
        *,
        action_type: str,
        target_type: str,
        target_value: str,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        subject = (
            f"[Sentinel IDS] {context.get('severity', '').upper() or 'ALERT'}: "
            f"{context.get('title') or 'Security alert'}"
        )
        lines = [
            f"Sentinel IDS response notification ({action_type}).",
            "",
            f"Target: {target_type}:{target_value}",
        ]
        for key in ("title", "severity", "category", "src_ip", "dst_ip", "risk_score"):
            if key in context:
                lines.append(f"{key}: {context[key]}")
        body = "\n".join(lines)

        await asyncio.to_thread(_deliver, target_value, subject, body)
        return [
            {"step": "resolve_recipient", "recipient": target_value, "result": "ok"},
            {
                "step": "send_email",
                "connector": self.name,
                "from": settings.EMAIL_FROM_ADDR,
                "subject": subject,
                "result": "sent",
            },
        ]

    async def test(self) -> dict[str, Any]:
        def _probe() -> None:
            with _open_smtp() as client:
                client.noop()

        await asyncio.to_thread(_probe)
        return {"status": "ok", "connector": self.name}
