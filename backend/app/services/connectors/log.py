"""Log connector: records a deterministic plan when no real integration exists.

This is the always-available fallback so response actions keep working end to
end in dev and in default (unconfigured) deployments.
"""

from __future__ import annotations

from typing import Any

from app.services.connectors.base import Connector
from app.services.response_action_service import plan_response_action


class LogConnector(Connector):
    name = "log_plan"
    kind = "log"
    description = "Records a deterministic response plan without external enforcement."

    def enabled(self) -> bool:
        return True

    async def execute(
        self,
        *,
        action_type: str,
        target_type: str,
        target_value: str,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        steps = plan_response_action(action_type, target_type, target_value)
        return [{"connector": self.name, "kind": self.kind}, *steps]

    async def test(self) -> dict[str, Any]:
        return {"status": "ok", "connector": self.name}
