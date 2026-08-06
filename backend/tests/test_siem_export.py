"""Unit tests for the external SIEM export service (Phase 7)."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from app.core.config import settings
from app.models.alert import Alert
from app.models.siem_export_run import SiemExportRun
from app.services.siem import export_alerts_to_siem, pending_alert_count, send_test_event
from app.services.siem.export import _send_cef_payload, siem_configured


def _alert(alert_id: int) -> Alert:
    return Alert(
        id=alert_id,
        title="Port scan",
        detector="signature",
        severity="high",
        category="scan",
        src_ip="10.0.0.1",
        src_port=1234,
        dst_ip="10.0.0.2",
        dst_port=80,
        risk_score=72.5,
        status="new",
        created_at=datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC),
        siem_exported_at=None,
    )


class _Scalars:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def all(self) -> list[object]:
        return self._rows


class _Result:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalars(self) -> _Scalars:
        return _Scalars(self._rows)


class FakeSession:
    """In-memory stand-in for AsyncSession covering the exporter's usage."""

    def __init__(self, rows: list[object], *, pending: int = 0) -> None:
        self._rows = rows
        self._pending = pending
        self.added: list[object] = []
        self.stmts: list[object] = []
        self.rolled_back = False

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        pass

    async def execute(self, stmt: object) -> _Result:
        self.stmts.append(stmt)
        return _Result(self._rows)

    async def scalar(self, stmt: object) -> int:
        self.stmts.append(stmt)
        return self._pending

    async def commit(self) -> None:
        pass

    async def rollback(self) -> None:
        self.rolled_back = True


def _first_run(db: FakeSession) -> SiemExportRun:
    runs = [obj for obj in db.added if isinstance(obj, SiemExportRun)]
    assert runs, "no SiemExportRun was recorded"
    return runs[-1]


class TestExportDisabled:
    @pytest.mark.asyncio
    async def test_skipped_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "SIEM_EXPORT_ENABLED", False)
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", "http://siem.local/cef")
        db = FakeSession([])
        result = await export_alerts_to_siem(db)
        assert result == {"status": "skipped", "reason": "SIEM_EXPORT_ENABLED is false"}
        assert db.added == []

    @pytest.mark.asyncio
    async def test_skipped_without_endpoint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "SIEM_EXPORT_ENABLED", True)
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", None)
        result = await export_alerts_to_siem(FakeSession([]))
        assert result == {"status": "skipped", "reason": "SIEM_CEF_ENDPOINT_URL is not configured"}


class TestExportSuccess:
    @pytest.mark.asyncio
    async def test_exports_batch_and_stamps_watermark(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "SIEM_EXPORT_ENABLED", True)
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", "http://siem.local/cef")

        payloads: list[str] = []

        async def _fake_send(payload: str) -> None:
            payloads.append(payload)

        monkeypatch.setattr("app.services.siem.export._send_cef_payload", _fake_send)

        rows = [_alert(1), _alert(2)]
        db = FakeSession(rows, pending=0)
        result = await export_alerts_to_siem(db)

        assert result["status"] == "succeeded"
        assert result["exported"] == 2
        assert rows[0].siem_exported_at is not None
        assert rows[1].siem_exported_at is not None

        run = _first_run(db)
        assert run.status == "succeeded"
        assert run.alerts_exported == 2
        assert len(payloads) == 1
        assert payloads[0].count("\n") == 2

    @pytest.mark.asyncio
    async def test_batch_query_uses_skip_locked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "SIEM_EXPORT_ENABLED", True)
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", "http://siem.local/cef")

        async def _fake_send(payload: str) -> None:
            pass

        monkeypatch.setattr("app.services.siem.export._send_cef_payload", _fake_send)

        db = FakeSession([_alert(1)])
        await export_alerts_to_siem(db)
        stmt = db.stmts[0]
        assert stmt._for_update_arg.skip_locked is True

    @pytest.mark.asyncio
    async def test_no_pending_rows_is_success_with_zero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "SIEM_EXPORT_ENABLED", True)
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", "http://siem.local/cef")
        db = FakeSession([])
        result = await export_alerts_to_siem(db)
        assert result == {"status": "succeeded", "exported": 0, "pending": 0}
        assert _first_run(db).alerts_exported == 0


class TestExportFailure:
    @pytest.mark.asyncio
    async def test_send_failure_rolls_back_and_records_failed_run(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "SIEM_EXPORT_ENABLED", True)
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", "http://siem.local/cef")

        async def _boom(payload: str) -> None:
            raise httpx.HTTPStatusError(
                "503", request=httpx.Request("POST", "http://siem.local/cef"), response=None
            )

        monkeypatch.setattr("app.services.siem.export._send_cef_payload", _boom)

        rows = [_alert(1)]
        db = FakeSession(rows)
        result = await export_alerts_to_siem(db)
        assert result["status"] == "failed"
        assert rows[0].siem_exported_at is None
        assert db.rolled_back is True
        run = _first_run(db)
        assert run.status == "failed"
        assert "503" in (run.error or "")


class TestSendPayloadAndTestEvent:
    @pytest.mark.asyncio
    async def test_send_cef_payload_posts_text_with_auth(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Resp:
            def raise_for_status(self) -> None:
                pass

        class _Client:
            async def __aenter__(self) -> _Client:
                return self

            async def __aexit__(self, *exc: object) -> bool:
                return False

            async def post(self, url: str, *, content: str, headers: dict[str, str]) -> _Resp:
                self.url = url
                self.content = content
                self.headers = headers
                return _Resp()

        client = _Client()
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", "http://siem.local/cef")
        monkeypatch.setattr(settings, "SIEM_AUTH_TOKEN", "tok")
        monkeypatch.setattr("app.services.siem.export.httpx.AsyncClient", lambda *a, **k: client)

        await _send_cef_payload("CEF:0|test\n")
        assert client.url == "http://siem.local/cef"
        assert client.content == "CEF:0|test\n"
        assert client.headers["Authorization"] == "Bearer tok"
        assert client.headers["Content-Type"] == "text/plain"

    @pytest.mark.asyncio
    async def test_send_test_event(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Resp:
            def raise_for_status(self) -> None:
                pass

        class _Client:
            async def __aenter__(self) -> _Client:
                return self

            async def __aexit__(self, *exc: object) -> bool:
                return False

            async def post(self, url: str, **kwargs: object) -> _Resp:
                self.payload = kwargs["content"]
                return _Resp()

        client = _Client()
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", "http://siem.local/cef")
        monkeypatch.setattr("app.services.siem.export.httpx.AsyncClient", lambda *a, **k: client)

        result = await send_test_event(FakeSession([]))
        assert result["status"] == "ok"
        assert str(client.payload).startswith("CEF:0|Sentinel IDS")

    @pytest.mark.asyncio
    async def test_send_test_event_skipped_without_endpoint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", None)
        result = await send_test_event(FakeSession([]))
        assert result == {"status": "skipped", "reason": "SIEM_CEF_ENDPOINT_URL is not configured"}


class TestHelpers:
    @pytest.mark.asyncio
    async def test_pending_alert_count(self) -> None:
        db = FakeSession([], pending=7)
        assert await pending_alert_count(db) == 7

    def test_siem_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "SIEM_EXPORT_ENABLED", True)
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", "http://siem.local/cef")
        assert siem_configured() is True
        monkeypatch.setattr(settings, "SIEM_EXPORT_ENABLED", False)
        assert siem_configured() is False
