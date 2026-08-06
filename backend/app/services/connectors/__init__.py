"""Connector plugins: registry bootstrap and action dispatch (Phase 7)."""

from __future__ import annotations

from app.services.connectors.base import Connector, ConnectorError
from app.services.connectors.email import EmailConnector
from app.services.connectors.http import HttpConnector
from app.services.connectors.log import LogConnector
from app.services.connectors.registry import connector_registry

__all__ = [
    "Connector",
    "ConnectorError",
    "EmailConnector",
    "HttpConnector",
    "LogConnector",
    "connector_registry",
    "select_connector",
]

# Preferred connector kind for each response action type.
ACTION_KIND: dict[str, str] = {
    "block": "http",
    "quarantine": "http",
    "notify": "email",
}

_DEFAULT_CONNECTORS = (HttpConnector(), EmailConnector(), LogConnector())

for _connector in _DEFAULT_CONNECTORS:
    connector_registry.register(_connector)


def select_connector(action_type: str) -> Connector:
    """Return the best connector for ``action_type``.

    Prefers the enabled connector matching the action's kind (webhook for
    block/quarantine, email for notify) and falls back to the always-available
    log connector so response automation never stops.
    """
    kind = ACTION_KIND.get(action_type)
    if kind:
        for connector in connector_registry.list():
            if connector.kind == kind and connector.enabled():
                return connector
    log_connector = connector_registry.get("log_plan")
    if log_connector is None:
        raise RuntimeError("log_plan connector is not registered")
    return log_connector
