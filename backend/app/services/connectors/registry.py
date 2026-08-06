"""Connector registry: discovers and resolves response connectors (Phase 7)."""

from __future__ import annotations

from app.services.connectors.base import Connector


class ConnectorRegistry:
    """Registry of connectors keyed by their unique ``name``."""

    def __init__(self) -> None:
        self._connectors: dict[str, Connector] = {}

    def register(self, connector: Connector) -> None:
        self._connectors[connector.name] = connector

    def get(self, name: str) -> Connector | None:
        return self._connectors.get(name)

    def names(self) -> list[str]:
        return list(self._connectors)

    def list(self) -> list[Connector]:
        return list(self._connectors.values())


connector_registry = ConnectorRegistry()
