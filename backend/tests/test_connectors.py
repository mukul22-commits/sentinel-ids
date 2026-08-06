"""Unit tests for the connector plugin framework (Phase 7)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from app.core.config import settings
from app.models.response_action import ResponseAction
from app.services.connectors import (
    connector_registry,
    select_connector,
)
from app.services.connectors.base import ConnectorError
from app.services.connectors.email import EmailConnector
from app.services.connectors.http import HttpConnector
from app.services.connectors.log import LogConnector
from app.services.response_action_service import execute_response_action


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "") -> None:
        self.status_code = status_code
        self.text = text

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}", request=httpx.Request("POST", "http://x"), response=self
            )


class _FakeAsyncClient:
    """Async context-manager client capturing the last HTTP call."""

    def __init__(self, *, status_code: int = 200, raise_connect: bool = False) -> None:
        self.status_code = status_code
        self.raise_connect = raise_connect
        self.posts: list[tuple[Any, dict[str, Any]]] = []

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def post(self, url: Any, **kwargs: Any) -> _FakeResponse:
        if self.raise_connect:
            raise httpx.ConnectError("boom")
        self.posts.append((url, kwargs))
        return _FakeResponse(self.status_code)

    async def get(self, url: Any, **kwargs: Any) -> _FakeResponse:
        if self.raise_connect:
            raise httpx.ConnectError("boom")
        self.posts.append((url, kwargs))
        return _FakeResponse(self.status_code)


class _FakeSmtp:
    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []
        self.noops = 0

    def __enter__(self) -> _FakeSmtp:
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def send_message(self, message: Any) -> None:
        self.sent.append({"subject": message["Subject"], "to": message["To"]})

    def noop(self) -> None:
        self.noops += 1


class _FakeDb:
    def __init__(self) -> None:
        self.commits = 0

    async def flush(self) -> None:
        pass

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, obj: Any) -> None:
        return None


class TestConnectorRegistry:
    def test_default_connectors_registered(self) -> None:
        names = set(connector_registry.names())
        assert {"http_webhook", "smtp_email", "log_plan"} <= names

    def test_log_connector_always_enabled(self) -> None:
        assert LogConnector().enabled()

    def test_select_falls_back_to_log_when_unconfigured(self) -> None:
        assert select_connector("block").name == "log_plan"
        assert select_connector("quarantine").name == "log_plan"
        assert select_connector("notify").name == "log_plan"

    def test_select_prefers_http_when_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "HTTP_CONNECTOR_URL", "http://webhook.local")
        assert select_connector("block").name == "http_webhook"
        assert select_connector("quarantine").name == "http_webhook"

    def test_select_prefers_email_when_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "EMAIL_SMTP_HOST", "smtp.local")
        assert select_connector("notify").name == "smtp_email"


class TestLogConnector:
    @pytest.mark.asyncio
    async def test_execute_returns_deterministic_plan(self) -> None:
        connector = LogConnector()
        steps = await connector.execute(
            action_type="block",
            target_type="ip",
            target_value="203.0.113.5",
            context={},
        )
        assert steps[0] == {"connector": "log_plan", "kind": "log"}
        assert [step["step"] for step in steps[1:]] == [
            "validate_target",
            "apply_firewall_deny",
            "verify_block",
        ]

    @pytest.mark.asyncio
    async def test_test_reports_ok(self) -> None:
        assert (await LogConnector().test())["status"] == "ok"


class TestHttpConnector:
    @pytest.mark.asyncio
    async def test_disabled_without_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "HTTP_CONNECTOR_URL", None)
        assert not HttpConnector().enabled()

    @pytest.mark.asyncio
    async def test_execute_posts_json_with_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _FakeAsyncClient(status_code=200)
        monkeypatch.setattr(settings, "HTTP_CONNECTOR_URL", "http://webhook.local")
        monkeypatch.setattr(settings, "HTTP_CONNECTOR_TOKEN", "sekret")
        monkeypatch.setattr(
            "app.services.connectors.http.httpx.AsyncClient", lambda *a, **k: client
        )

        connector = HttpConnector()
        steps = await connector.execute(
            action_type="block",
            target_type="ip",
            target_value="203.0.113.5",
            context={"severity": "high", "title": "Port scan"},
        )
        assert steps[-1]["result"] == "ok"
        assert steps[-1]["http_status"] == 200
        url, kwargs = client.posts[-1]
        assert url == "http://webhook.local"
        assert kwargs["json"]["action_type"] == "block"
        assert kwargs["headers"]["Authorization"] == "Bearer sekret"
        assert kwargs["json"]["context"]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_execute_raises_connector_error_on_http_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _FakeAsyncClient(status_code=500)
        monkeypatch.setattr(settings, "HTTP_CONNECTOR_URL", "http://webhook.local")
        monkeypatch.setattr(
            "app.services.connectors.http.httpx.AsyncClient", lambda *a, **k: client
        )
        with pytest.raises(ConnectorError):
            await HttpConnector().execute(
                action_type="block", target_type="ip", target_value="1.2.3.4", context={}
            )

    @pytest.mark.asyncio
    async def test_execute_raises_connector_error_on_transport_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _FakeAsyncClient(raise_connect=True)
        monkeypatch.setattr(settings, "HTTP_CONNECTOR_URL", "http://webhook.local")
        monkeypatch.setattr(
            "app.services.connectors.http.httpx.AsyncClient", lambda *a, **k: client
        )
        with pytest.raises(ConnectorError):
            await HttpConnector().execute(
                action_type="quarantine", target_type="host", target_value="h1", context={}
            )


class TestEmailConnector:
    @pytest.mark.asyncio
    async def test_disabled_without_host(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "EMAIL_SMTP_HOST", None)
        assert not EmailConnector().enabled()

    @pytest.mark.asyncio
    async def test_execute_sends_message(self, monkeypatch: pytest.MonkeyPatch) -> None:
        smtp = _FakeSmtp()
        monkeypatch.setattr(settings, "EMAIL_SMTP_HOST", "smtp.local")
        monkeypatch.setattr(settings, "EMAIL_FROM_ADDR", "alerts@sentinel.local")
        monkeypatch.setattr("app.services.connectors.email._open_smtp", lambda: smtp)

        connector = EmailConnector()
        steps = await connector.execute(
            action_type="notify",
            target_type="email",
            target_value="soc@example.com",
            context={"severity": "critical", "title": "Ransomware"},
        )
        assert steps[-1]["result"] == "sent"
        assert smtp.sent[-1]["to"] == "soc@example.com"
        assert "Ransomware" in smtp.sent[-1]["subject"]

    @pytest.mark.asyncio
    async def test_test_probes_smtp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        smtp = _FakeSmtp()
        monkeypatch.setattr(settings, "EMAIL_SMTP_HOST", "smtp.local")
        monkeypatch.setattr("app.services.connectors.email._open_smtp", lambda: smtp)

        result = await EmailConnector().test()
        assert result["status"] == "ok"
        assert smtp.noops == 1


class TestExecuteResponseActionDispatch:
    @pytest.mark.asyncio
    async def test_log_connector_used_by_default(self) -> None:
        action = ResponseAction(
            incident_id=1,
            action_type="block",
            target_type="ip",
            target_value="203.0.113.5",
            status="pending",
        )
        executed = await execute_response_action(_FakeDb(), action)
        assert executed.status == "succeeded"
        assert executed.details[0]["connector"] == "log_plan"
        assert executed.executed_at is not None

    @pytest.mark.asyncio
    async def test_http_connector_used_when_configured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _FakeAsyncClient(status_code=200)
        monkeypatch.setattr(settings, "HTTP_CONNECTOR_URL", "http://webhook.local")
        monkeypatch.setattr(
            "app.services.connectors.http.httpx.AsyncClient", lambda *a, **k: client
        )
        action = ResponseAction(
            incident_id=1,
            action_type="block",
            target_type="ip",
            target_value="203.0.113.5",
            status="pending",
        )
        executed = await execute_response_action(_FakeDb(), action)
        assert executed.status == "succeeded"
        assert executed.details[0]["step"] == "validate_target"
        assert executed.details[-1]["http_status"] == 200

    @pytest.mark.asyncio
    async def test_connector_failure_marks_action_failed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _FakeAsyncClient(status_code=503)
        monkeypatch.setattr(settings, "HTTP_CONNECTOR_URL", "http://webhook.local")
        monkeypatch.setattr(
            "app.services.connectors.http.httpx.AsyncClient", lambda *a, **k: client
        )
        action = ResponseAction(
            incident_id=1,
            action_type="block",
            target_type="ip",
            target_value="203.0.113.5",
            status="pending",
        )
        executed = await execute_response_action(_FakeDb(), action)
        assert executed.status == "failed"
        assert executed.details[0]["result"] == "failed"
