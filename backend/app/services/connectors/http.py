"""HTTP/webhook connector: real enforcement for block/quarantine actions.

Posts a JSON payload to a configured enforcement endpoint (firewall, EDR, or
SOAR webhook). Authorization is via a bearer token when ``HTTP_CONNECTOR_TOKEN``
is set. Disabled when no endpoint URL is configured.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.config import settings
from app.services.connectors.base import Connector, ConnectorError

logger = logging.getLogger("sentinel.connectors")

PAYLOAD_FIELDS = (
    "title",
    "severity",
    "category",
    "src_ip",
    "dst_ip",
    "risk_score",
)


class HttpConnector(Connector):
    name = "http_webhook"
    kind = "http"
    description = "Sends block/quarantine actions to an HTTP/S webhook enforcement endpoint."

    def enabled(self) -> bool:
        return bool(settings.HTTP_CONNECTOR_URL)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if settings.HTTP_CONNECTOR_TOKEN:
            headers["Authorization"] = f"Bearer {settings.HTTP_CONNECTOR_TOKEN}"
        return headers

    async def execute(
        self,
        *,
        action_type: str,
        target_type: str,
        target_value: str,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        target = f"{target_type}:{target_value}"
        payload = {
            "action_type": action_type,
            "target_type": target_type,
            "target_value": target_value,
            "context": {key: context.get(key) for key in PAYLOAD_FIELDS if key in context},
        }
        try:
            async with httpx.AsyncClient(timeout=settings.HTTP_CONNECTOR_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    settings.HTTP_CONNECTOR_URL or "", json=payload, headers=self._headers()
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ConnectorError(f"webhook request failed: {exc}") from exc

        return [
            {"step": "validate_target", "target": target, "result": "ok"},
            {
                "step": "send_webhook",
                "connector": self.name,
                "url": settings.HTTP_CONNECTOR_URL,
                "action_type": action_type,
                "http_status": response.status_code,
                "result": "ok",
            },
        ]

    async def test(self) -> dict[str, Any]:
        url = settings.HTTP_CONNECTOR_URL
        if not url:
            raise ConnectorError("HTTP_CONNECTOR_URL is not configured")
        try:
            async with httpx.AsyncClient(timeout=settings.HTTP_CONNECTOR_TIMEOUT_SECONDS) as client:
                response = await client.get(url, headers=self._headers())
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ConnectorError(f"webhook connectivity check failed: {exc}") from exc
        return {"status": "ok", "connector": self.name, "http_status": response.status_code}
