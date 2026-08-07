"""Connector plugins: registry bootstrap and action dispatch (Phase 7/9).

Action dispatch preference per response action type:
  - ``block``      -> OPNsense firewall (firewall), then generic webhook
  - ``quarantine`` -> EDR isolation (edr), then generic webhook
  - ``notify``     -> SMTP email
The always-available log connector is the final fallback so response
automation never stops.
"""

from __future__ import annotations

from app.services.connectors.base import Connector, ConnectorError
from app.services.connectors.edr import EdrConnector
from app.services.connectors.email import EmailConnector
from app.services.connectors.http import HttpConnector
from app.services.connectors.log import LogConnector
from app.services.connectors.opnsense import OpnsenseConnector
from app.services.connectors.registry import connector_registry

__all__ = [
    "Connector",
    "ConnectorError",
    "EdrConnector",
    "EmailConnector",
    "HttpConnector",
    "LogConnector",
    "OpnsenseConnector",
    "connector_registry",
    "select_connector",
]

# Preferred connector kinds for each response action type, in priority order.
ACTION_KIND: dict[str, list[str]] = {
    "block": ["firewall", "http"],
    "quarantine": ["edr", "http"],
    "notify": ["email"],
}

_DEFAULT_CONNECTORS = (
    HttpConnector(),
    EmailConnector(),
    LogConnector(),
    OpnsenseConnector(),
    EdrConnector(),
)

for _connector in _DEFAULT_CONNECTORS:
    connector_registry.register(_connector)


def select_connector(action_type: str) -> Connector:
    """Return the best connector for ``action_type``.

    Prefers the first enabled connector matching one of the action's preferred
    kinds (firewall/EDR for enforcement, webhook fallback, email for notify)
    and falls back to the always-available log connector so response
    automation never stops.
    """
    for kind in ACTION_KIND.get(action_type, []):
        for connector in connector_registry.list():
            if connector.kind == kind and connector.enabled():
                return connector
    log_connector = connector_registry.get("log_plan")
    if log_connector is None:
        raise RuntimeError("log_plan connector is not registered")
    return log_connector
