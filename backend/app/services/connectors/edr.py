"""Generic EDR connector: host isolation and IP blocking via REST.

Posts enforcement commands to a configurable EDR/RSO platform using bearer-token
auth. ``quarantine`` on a host issues an isolation command; ``block`` on an IP
adds it to the EDR's blocking feed. Disabled when no ``EDR_CONNECTOR_URL`` is
configured.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.config import settings
from app.services.connectors.base import Connector, ConnectorError

logger = logging.getLogger("sentinel.connectors")


class EdrConnector(Connector):
    name = "edr_endpoint"
    kind = "edr"
    description = "Isolates hosts and blocks IPs through a generic EDR REST API."

    def enabled(self) -> bool:
        return bool(settings.EDR_CONNECTOR_URL)

    def _base_url(self) -> str:
        return (settings.EDR_CONNECTOR_URL or "").rstrip("/")

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if settings.EDR_CONNECTOR_TOKEN:
            headers["Authorization"] = f"Bearer {settings.EDR_CONNECTOR_TOKEN}"
        return headers

    async def execute(
        self,
        *,
        action_type: str,
        target_type: str,
        target_value: str,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        if action_type == "quarantine" and target_type == "host":
            path = "/api/v1/enforcement/isolate"
            payload = {"host": target_value}
        elif action_type == "block" and target_type in {"ip", "subnet"}:
            path = "/api/v1/enforcement/block"
            payload = {"ip": target_value}
        else:
            return [
                {
                    "step": "unsupported_action",
                    "connector": self.name,
                    "action_type": action_type,
                    "target_type": target_type,
                    "result": "skipped",
                }
            ]
        target = f"{target_type}:{target_value}"
        try:
            async with httpx.AsyncClient(timeout=settings.EDR_CONNECTOR_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    f"{self._base_url()}{path}",
                    json=payload,
                    headers=self._headers(),
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ConnectorError(f"EDR request failed: {exc}") from exc

        return [
            {"step": "validate_target", "target": target, "result": "ok"},
            {
                "step": path.rsplit("/", 1)[-1],
                "connector": self.name,
                "target": target,
                "http_status": response.status_code,
                "result": "ok",
            },
        ]

    async def test(self) -> dict[str, Any]:
        if not self.enabled():
            raise ConnectorError("EDR_CONNECTOR_URL is not configured")
        try:
            async with httpx.AsyncClient(timeout=settings.EDR_CONNECTOR_TIMEOUT_SECONDS) as client:
                response = await client.get(
                    f"{self._base_url()}/api/v1/status",
                    headers=self._headers(),
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ConnectorError(f"EDR connectivity check failed: {exc}") from exc
        return {"status": "ok", "connector": self.name, "http_status": response.status_code}
