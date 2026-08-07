"""Unit tests for the connector plugin framework (Phase 7/9)."""

from __future__ import annotations

import hashlib
import hmac
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
from app.services.connectors.edr import EdrConnector
from app.services.connectors.email import EmailConnector
from app.services.connectors.http import HttpConnector
from app.services.connectors.log import LogConnector
from app.services.connectors.opnsense import OpnsenseConnector
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


class _FakeRestClient:
    """Async context-manager client capturing all HTTP verbs."""

    def __init__(self, *, status_code: int = 200, raise_connect: bool = False) -> None:
        self.status_code = status_code
        self.raise_connect = raise_connect
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def __aenter__(self) -> _FakeRestClient:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    def _record(self, method: str, url: str, **kwargs: Any) -> _FakeResponse:
        if self.raise_connect:
            raise httpx.ConnectError("boom")
        self.calls.append((method, url, kwargs))
        return _FakeResponse(self.status_code)

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        return self._record("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        return self._record("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> _FakeResponse:
        return self._record("PUT", url, **kwargs)


def _expected_opnsense_signature(path: str) -> str:
    return hmac.new(
        settings.OPNSENSE_CONNECTOR_SECRET.encode("utf-8"),
        path.encode("utf-8"),
        hashlib.sha512,
    ).hexdigest()


class TestOpnsenseConnector:
    async def test_disabled_without_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_URL", None)
        assert not OpnsenseConnector().enabled()

    async def test_registered(self) -> None:
        assert connector_registry.get("opnsense_firewall") is not None

    async def test_execute_block_adds_to_alias(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _FakeRestClient(status_code=200)
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_URL", "https://fw.local")
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_KEY", "key-1")
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_SECRET", "secret-1")
        monkeypatch.setattr(
            "app.services.connectors.opnsense.httpx.AsyncClient",
            lambda *a, **k: client,
        )

        steps = await OpnsenseConnector().execute(
            action_type="block",
            target_type="ip",
            target_value="203.0.113.5",
            context={},
        )
        methods = [method for method, _, _ in client.calls]
        assert methods == ["PUT", "POST"]
        put_method, put_url, put_kwargs = client.calls[0]
        assert (
            put_url == "https://fw.local/api/firewall/alias_util/add/sentinel_blocklist/203.0.113.5"
        )
        assert put_kwargs["headers"]["X-API-Key"] == "key-1"
        assert put_kwargs["headers"]["X-API-Signature"] == _expected_opnsense_signature(
            "/api/firewall/alias_util/add/sentinel_blocklist/203.0.113.5"
        )
        assert steps[-1]["result"] == "ok"
        assert steps[-1]["http_status"] == 200

    async def test_execute_reconfigures_firewall(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _FakeRestClient(status_code=200)
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_URL", "https://fw.local")
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_KEY", "key-1")
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_SECRET", "secret-1")
        monkeypatch.setattr(
            "app.services.connectors.opnsense.httpx.AsyncClient",
            lambda *a, **k: client,
        )

        await OpnsenseConnector().execute(
            action_type="block",
            target_type="subnet",
            target_value="10.0.0.0/24",
            context={},
        )
        _, post_url, _ = client.calls[1]
        assert post_url == "https://fw.local/api/firewall/alias/reconfigure"

    async def test_execute_skips_non_block(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_URL", "https://fw.local")
        steps = await OpnsenseConnector().execute(
            action_type="quarantine",
            target_type="host",
            target_value="h1",
            context={},
        )
        assert steps[0]["result"] == "skipped"

    async def test_execute_raises_on_http_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _FakeRestClient(status_code=500)
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_URL", "https://fw.local")
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_KEY", "key-1")
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_SECRET", "secret-1")
        monkeypatch.setattr(
            "app.services.connectors.opnsense.httpx.AsyncClient",
            lambda *a, **k: client,
        )
        with pytest.raises(ConnectorError):
            await OpnsenseConnector().execute(
                action_type="block",
                target_type="ip",
                target_value="203.0.113.5",
                context={},
            )

    async def test_test_probes_api(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _FakeRestClient(status_code=200)
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_URL", "https://fw.local")
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_KEY", "key-1")
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_SECRET", "secret-1")
        monkeypatch.setattr(
            "app.services.connectors.opnsense.httpx.AsyncClient",
            lambda *a, **k: client,
        )
        result = await OpnsenseConnector().test()
        assert result["status"] == "ok"
        assert client.calls[0][0] == "GET"


class TestEdrConnector:
    async def test_disabled_without_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "EDR_CONNECTOR_URL", None)
        assert not EdrConnector().enabled()

    async def test_registered(self) -> None:
        assert connector_registry.get("edr_endpoint") is not None

    async def test_execute_quarantine_host(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _FakeRestClient(status_code=200)
        monkeypatch.setattr(settings, "EDR_CONNECTOR_URL", "https://edr.local")
        monkeypatch.setattr(settings, "EDR_CONNECTOR_TOKEN", "tok")
        monkeypatch.setattr(
            "app.services.connectors.edr.httpx.AsyncClient",
            lambda *a, **k: client,
        )

        steps = await EdrConnector().execute(
            action_type="quarantine",
            target_type="host",
            target_value="h1",
            context={},
        )
        assert steps[-1]["result"] == "ok"
        method, url, kwargs = client.calls[-1]
        assert (method, url) == ("POST", "https://edr.local/api/v1/enforcement/isolate")
        assert kwargs["json"] == {"host": "h1"}
        assert kwargs["headers"]["Authorization"] == "Bearer tok"

    async def test_execute_block_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _FakeRestClient(status_code=200)
        monkeypatch.setattr(settings, "EDR_CONNECTOR_URL", "https://edr.local")
        monkeypatch.setattr(
            "app.services.connectors.edr.httpx.AsyncClient",
            lambda *a, **k: client,
        )
        await EdrConnector().execute(
            action_type="block",
            target_type="ip",
            target_value="198.51.100.9",
            context={},
        )
        _, url, kwargs = client.calls[-1]
        assert url == "https://edr.local/api/v1/enforcement/block"
        assert kwargs["json"] == {"ip": "198.51.100.9"}

    async def test_execute_skips_unsupported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "EDR_CONNECTOR_URL", "https://edr.local")
        steps = await EdrConnector().execute(
            action_type="notify",
            target_type="email",
            target_value="a@b.c",
            context={},
        )
        assert steps[0]["result"] == "skipped"

    async def test_execute_raises_on_transport_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _FakeRestClient(raise_connect=True)
        monkeypatch.setattr(settings, "EDR_CONNECTOR_URL", "https://edr.local")
        monkeypatch.setattr(
            "app.services.connectors.edr.httpx.AsyncClient",
            lambda *a, **k: client,
        )
        with pytest.raises(ConnectorError):
            await EdrConnector().execute(
                action_type="quarantine",
                target_type="host",
                target_value="h1",
                context={},
            )

    async def test_test_probes_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _FakeRestClient(status_code=200)
        monkeypatch.setattr(settings, "EDR_CONNECTOR_URL", "https://edr.local")
        monkeypatch.setattr(
            "app.services.connectors.edr.httpx.AsyncClient",
            lambda *a, **k: client,
        )
        result = await EdrConnector().test()
        assert result["status"] == "ok"
        assert client.calls[0][1] == "https://edr.local/api/v1/status"


class TestSoarDispatchPreference:
    def test_block_prefers_opnsense_when_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_URL", "https://fw.local")
        assert select_connector("block").name == "opnsense_firewall"

    def test_quarantine_prefers_edr_when_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "EDR_CONNECTOR_URL", "https://edr.local")
        assert select_connector("quarantine").name == "edr_endpoint"

    def test_block_falls_back_to_http_without_firewall(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "HTTP_CONNECTOR_URL", "http://webhook.local")
        monkeypatch.setattr(settings, "OPNSENSE_CONNECTOR_URL", None)
        assert select_connector("block").name == "http_webhook"

    def test_quarantine_falls_back_to_http_without_edr(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "HTTP_CONNECTOR_URL", "http://webhook.local")
        monkeypatch.setattr(settings, "EDR_CONNECTOR_URL", None)
        assert select_connector("quarantine").name == "http_webhook"
