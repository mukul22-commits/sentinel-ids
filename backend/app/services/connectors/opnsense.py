"""OPNsense firewall connector: real block enforcement via the REST API.

Implements OPNsense's API authentication (``X-API-Key`` plus an HMAC-SHA512
``X-API-Signature`` over ``path + body``) and the Firewall Alias Util
endpoints. Blocking an IP adds it to the configured blocklist alias and then
reconfigures the firewall so the change takes effect. Disabled when no
``OPNSENSE_CONNECTOR_URL`` is configured.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any

import httpx

from app.core.config import settings
from app.services.connectors.base import Connector, ConnectorError

logger = logging.getLogger("sentinel.connectors")

DEFAULT_BLOCKLIST_ALIAS = "sentinel_blocklist"


class OpnsenseConnector(Connector):
    name = "opnsense_firewall"
    kind = "firewall"
    description = "Blocks IPs via the OPNsense Firewall Alias Util REST API."

    def enabled(self) -> bool:
        return bool(settings.OPNSENSE_CONNECTOR_URL)

    def _base_url(self) -> str:
        return (settings.OPNSENSE_CONNECTOR_URL or "").rstrip("/")

    def _headers(self, path: str, body: str) -> dict[str, str]:
        key = settings.OPNSENSE_CONNECTOR_KEY or ""
        secret = settings.OPNSENSE_CONNECTOR_SECRET or ""
        signature = hmac.new(
            secret.encode("utf-8"), (path + body).encode("utf-8"), hashlib.sha512
        ).hexdigest()
        return {
            "X-API-Key": key,
            "X-API-Signature": signature,
            "Content-Type": "application/json",
        }

    async def _add_to_alias(self, client: httpx.AsyncClient, ip: str) -> httpx.Response:
        alias = settings.OPNSENSE_BLOCKLIST_ALIAS or DEFAULT_BLOCKLIST_ALIAS
        path = f"/api/firewall/alias_util/add/{alias}/{ip}"
        response = await client.put(
            f"{self._base_url()}{path}",
            json={},
            headers=self._headers(path, ""),
        )
        response.raise_for_status()
        return response

    async def _reconfigure(self, client: httpx.AsyncClient) -> httpx.Response:
        path = "/api/firewall/alias/reconfigure"
        response = await client.post(
            f"{self._base_url()}{path}",
            json={},
            headers=self._headers(path, ""),
        )
        response.raise_for_status()
        return response

    async def execute(
        self,
        *,
        action_type: str,
        target_type: str,
        target_value: str,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        if action_type != "block" or target_type not in {"ip", "subnet"}:
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
            async with httpx.AsyncClient(
                timeout=settings.OPNSENSE_CONNECTOR_TIMEOUT_SECONDS
            ) as client:
                add_response = await self._add_to_alias(client, target_value)
                reconfigure_response = await self._reconfigure(client)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"OPNsense request failed: {exc}") from exc

        return [
            {"step": "validate_target", "target": target, "result": "ok"},
            {
                "step": "add_to_alias",
                "connector": self.name,
                "alias": settings.OPNSENSE_BLOCKLIST_ALIAS or DEFAULT_BLOCKLIST_ALIAS,
                "http_status": add_response.status_code,
                "result": "ok",
            },
            {
                "step": "apply_config",
                "connector": self.name,
                "http_status": reconfigure_response.status_code,
                "result": "ok",
            },
        ]

    async def test(self) -> dict[str, Any]:
        if not self.enabled():
            raise ConnectorError("OPNSENSE_CONNECTOR_URL is not configured")
        path = "/api/firewall/alias/get/current"
        try:
            async with httpx.AsyncClient(
                timeout=settings.OPNSENSE_CONNECTOR_TIMEOUT_SECONDS
            ) as client:
                response = await client.get(
                    f"{self._base_url()}{path}",
                    headers=self._headers(path, ""),
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ConnectorError(f"OPNsense connectivity check failed: {exc}") from exc
        return {"status": "ok", "connector": self.name, "http_status": response.status_code}
