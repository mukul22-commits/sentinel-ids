"""Connector plugin base class for response enforcement (Phase 7).

Connectors turn a response action (block/quarantine/notify) into real-world
enforcement: webhook calls to firewalls/EDR, SMTP mail delivery, or a
deterministic log-only plan when no real integration is configured.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ConnectorError(Exception):
    """Raised when a connector cannot reach or be handled by its endpoint."""


class Connector(ABC):
    """A single enforcement back-end that can execute response actions."""

    name: str = ""
    kind: str = ""
    description: str = ""

    @abstractmethod
    def enabled(self) -> bool:
        """Return True when this connector is configured and usable."""

    @abstractmethod
    async def execute(
        self,
        *,
        action_type: str,
        target_type: str,
        target_value: str,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Execute an action and return the recorded plan of steps.

        Raises :class:`ConnectorError` when the enforcement call itself fails so
        the caller can mark the action as failed without breaking the flow.
        """

    @abstractmethod
    async def test(self) -> dict[str, Any]:
        """Probe connectivity to the endpoint.

        Returns a status dict or raises :class:`ConnectorError`.
        """
