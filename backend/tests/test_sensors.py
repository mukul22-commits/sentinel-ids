"""Unit tests for the fleet / multi-sensor service and endpoints (Phase 8)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from app.main import app
from app.models.alert import Alert
from app.models.capture_run import CaptureRun
from app.models.sensor import Sensor
from app.schemas.sensor import SensorCreate, SensorHeartbeat, SensorUpdate
from app.services.sensors.service import (
    create_sensor,
    delete_sensor,
    effective_config,
    find_sensor_by_token,
    fleet_summary,
    generate_sensor_token,
    get_sensor,
    hash_sensor_token,
    list_enabled_sensors,
    list_sensors,
    mark_stale_sensors,
    record_heartbeat,
    rotate_sensor_token,
    update_sensor,
)
from fastapi.testclient import TestClient
from sqlalchemy import sql as sa_sql
from sqlalchemy.sql import functions as sa_functions


def _sensor(
    *,
    name: str = "sensor-a",
    status: str = "online",
    enabled: bool = True,
    last_seen_at: datetime | None = None,
    config: dict[str, Any] | None = None,
    sensor_id: int = 1,
) -> Sensor:
    return Sensor(
        id=sensor_id,
        name=name,
        token_hash=hash_sensor_token("tok-" + name),
        hostname="host-1",
        ip_address="10.0.0.10",
        version="1.2.3",
        status=status,
        enabled=enabled,
        config=config or {},
        last_seen_at=last_seen_at,
        created_at=datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC),
        updated_at=datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC),
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


def _selects_entity(stmt: object, entity: type[Any]) -> bool:
    descriptions = getattr(stmt, "column_descriptions", [])
    return any(description.get("entity") is entity for description in descriptions)


def _value(node: object) -> Any:
    if isinstance(node, sa_sql.elements.BindParameter):
        return node.value
    if isinstance(node, sa_sql.elements.True_):
        return True
    if isinstance(node, sa_sql.elements.False_):
        return False
    return node


def _left_attr(node: object) -> tuple[str | None, str | None]:
    """Return (attribute key, function name) for a binary-expression operand."""
    if isinstance(node, sa_functions.FunctionElement):
        clauses = list(node.clauses)
        inner = clauses[0] if clauses else None
        return getattr(inner, "key", None), getattr(node, "name", None)
    if isinstance(node, sa_sql.elements.ColumnClause):
        return node.key, None
    return None, None


def _matches(obj: object, criterion: object) -> bool:
    op = getattr(criterion, "operator", None)
    if op is None:
        return True
    left = getattr(criterion, "left", None)
    right = getattr(criterion, "right", None)
    key, func_name = _left_attr(left)
    if key is None or not hasattr(obj, key):
        return True
    lvalue = getattr(obj, key)
    if func_name == "lower":
        lvalue = lvalue.lower() if isinstance(lvalue, str) else lvalue
    rvalue = _value(right)
    opname = getattr(op, "__name__", "")
    if lvalue is None and opname not in ("is_", "is_not"):
        return False
    if opname in ("eq", "eq_"):
        return lvalue == rvalue
    if opname in ("ne", "ne_"):
        return lvalue != rvalue
    if opname == "is_":
        return lvalue is rvalue
    if opname == "is_not":
        return lvalue is not rvalue
    if opname in ("lt", "lt_"):
        return lvalue < rvalue
    if opname in ("le", "le_"):
        return lvalue <= rvalue
    if opname in ("gt", "gt_"):
        return lvalue > rvalue
    if opname in ("ge", "ge_"):
        return lvalue >= rvalue
    if opname in ("in_",):
        return lvalue in rvalue
    if opname in ("not_in_",):
        return lvalue not in rvalue
    return True


class FakeSession:
    """In-memory AsyncSession that evaluates the service's simple selects."""

    def __init__(
        self,
        sensors: list[Sensor] | None = None,
        *,
        alert_rows: list[tuple[int | None, int]] | None = None,
        capture_rows: list[tuple[int | None, int]] | None = None,
    ) -> None:
        self.sensors = list(sensors or [])
        self.alert_rows = list(alert_rows or [])
        self.capture_rows = list(capture_rows or [])
        self.added: list[object] = []
        self._next_id = 100
        self.commits = 0

    def add(self, obj: object) -> None:
        self.added.append(obj)
        if isinstance(obj, Sensor) and obj.id is None:
            obj.id = self._next_id
            self._next_id += 1
            self.sensors.append(obj)
        self._apply_defaults(obj)

    def _apply_defaults(self, obj: object) -> None:
        if not isinstance(obj, Sensor):
            return
        now = datetime.now(UTC)
        if obj.status is None:
            obj.status = "offline"
        if obj.enabled is None:
            obj.enabled = True
        if obj.config is None:
            obj.config = {}
        if obj.created_at is None:
            obj.created_at = now
        if obj.updated_at is None:
            obj.updated_at = now

    async def delete(self, obj: object) -> None:
        if isinstance(obj, Sensor):
            self.sensors = [s for s in self.sensors if s.id != obj.id]

    async def get(self, model: type[Any], ident: object) -> object | None:
        if model is Sensor:
            return next((s for s in self.sensors if s.id == ident), None)
        return None

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, obj: object) -> None:
        self._apply_defaults(obj)

    def _filter_sensors(self, stmt: object) -> list[Sensor]:
        criteria = getattr(stmt, "_where_criteria", ())
        rows = [s for s in self.sensors if all(_matches(s, c) for c in criteria)]
        offset = getattr(stmt, "_offset", None) or 0
        limit = getattr(stmt, "_limit", None)
        if offset:
            rows = rows[offset:]
        if limit:
            rows = rows[:limit]
        return rows

    async def execute(self, stmt: object) -> _Result:
        if _selects_entity(stmt, Sensor):
            return _Result(self._filter_sensors(stmt))
        return _Result([])

    async def scalar(self, stmt: object) -> object:
        if _selects_entity(stmt, Sensor):
            matches = self._filter_sensors(stmt)
            return matches[0] if matches else None
        return len(self.sensors)

    async def scalars(self, stmt: object) -> _Scalars:
        return _Scalars(self._filter_sensors(stmt))


class _AggResult:
    def __init__(self, rows: list[tuple[int | None, int]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[int | None, int]]:
        return self._rows


class FakeFleetSession(FakeSession):
    """FakeSession variant that also answers the fleet summary aggregate queries."""

    async def execute(self, stmt: object) -> _AggResult | _Result:
        if _selects_entity(stmt, Sensor):
            return _Result(self._filter_sensors(stmt))
        descriptions = getattr(stmt, "column_descriptions", [])
        entities = {description.get("entity") for description in descriptions}
        if Alert in entities:
            return _AggResult(self.alert_rows)
        if CaptureRun in entities:
            return _AggResult(self.capture_rows)
        return _Result([])


class TestTokens:
    def test_generated_tokens_are_urlsafe_and_unique(self) -> None:
        token_a = generate_sensor_token()
        token_b = generate_sensor_token()
        assert token_a != token_b
        alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
        assert len(token_a) >= 32
        assert set(token_a) <= alphabet
        assert set(token_b) <= alphabet

    def test_hash_is_deterministic_and_irreversible(self) -> None:
        token = generate_sensor_token()
        assert hash_sensor_token(token) == hash_sensor_token(token)
        assert hash_sensor_token(token) != token
        assert len(hash_sensor_token(token)) == 64


class TestRegistration:
    @pytest.mark.asyncio
    async def test_create_sensor_returns_token_and_stores_hash(self) -> None:
        db = FakeSession([])
        sensor, token = await create_sensor(db, SensorCreate(name="edge-1"))
        assert token
        assert sensor.token_hash == hash_sensor_token(token)
        assert sensor.token_hash != token
        assert sensor.status == "offline"
        assert sensor.enabled is True
        assert sensor.config == {}
        assert sensor in db.sensors
        assert db.commits == 1

    @pytest.mark.asyncio
    async def test_duplicate_name_rejected(self) -> None:
        db = FakeSession([_sensor(name="edge-1")])
        with pytest.raises(Exception) as excinfo:
            await create_sensor(db, SensorCreate(name="EDGE-1"))
        assert excinfo.value.status_code == 409

    @pytest.mark.asyncio
    async def test_find_by_token(self) -> None:
        sensor = _sensor()
        db = FakeSession([sensor])
        found = await find_sensor_by_token(db, "tok-sensor-a")
        assert found is sensor
        assert await find_sensor_by_token(db, "tok-unknown") is None


class TestHeartbeatAndWatchdog:
    @pytest.mark.asyncio
    async def test_record_heartbeat_marks_online_and_updates_identity(self) -> None:
        sensor = _sensor(status="offline", last_seen_at=None)
        db = FakeSession([sensor])
        await record_heartbeat(
            db, sensor, SensorHeartbeat(version="2.0.0", hostname="edge-1", ip_address="10.1.1.1")
        )
        assert sensor.status == "online"
        assert sensor.last_seen_at is not None
        assert sensor.version == "2.0.0"
        assert sensor.hostname == "edge-1"
        assert sensor.ip_address == "10.1.1.1"
        assert db.commits == 1

    @pytest.mark.asyncio
    async def test_mark_stale_flips_old_sensors_offline(self) -> None:
        stale = _sensor(
            name="stale", last_seen_at=datetime.now(UTC) - timedelta(hours=1), sensor_id=1
        )
        fresh = _sensor(
            name="fresh",
            last_seen_at=datetime.now(UTC) - timedelta(seconds=5),
            sensor_id=2,
        )
        never = _sensor(name="never", last_seen_at=None, sensor_id=3)
        db = FakeSession([stale, fresh, never])
        offlined = await mark_stale_sensors(db, max_age_seconds=90)
        assert offlined == 1
        assert stale.status == "offline"
        assert fresh.status == "online"
        assert never.status == "online"
        assert db.commits == 1

    @pytest.mark.asyncio
    async def test_mark_stale_skips_disabled_sensors(self) -> None:
        disabled = _sensor(
            name="retired",
            enabled=False,
            last_seen_at=datetime.now(UTC) - timedelta(hours=3),
            sensor_id=1,
        )
        db = FakeSession([disabled])
        offlined = await mark_stale_sensors(db, max_age_seconds=90)
        assert offlined == 0
        assert disabled.status == "online"

    @pytest.mark.asyncio
    async def test_list_enabled_online_sensors(self) -> None:
        online = _sensor(name="a", sensor_id=1)
        offline = _sensor(name="b", status="offline", sensor_id=2)
        disabled = _sensor(name="c", enabled=False, sensor_id=3)
        db = FakeSession([online, offline, disabled])
        enabled = await list_enabled_sensors(db)
        assert enabled == [online]


class TestConfig:
    def test_effective_config_defaults(self) -> None:
        sensor = _sensor(config={})
        config = effective_config(sensor)
        assert set(config) >= {"capture_enabled", "capture_cycle_seconds", "adapters"}
        assert set(config["adapters"]) == {"scapy_sniff", "suricata_eve", "zeek_conn"}
        assert config["adapters"]["scapy_sniff"]["enabled"] is True

    def test_effective_config_merges_overrides(self) -> None:
        sensor = _sensor(
            config={
                "capture_enabled": False,
                "adapters": {
                    "scapy_sniff": {"enabled": False, "interface": "eth9"},
                    "suricata_eve": {"path": "/var/log/suricata/eve.json"},
                },
            }
        )
        config = effective_config(sensor)
        assert config["capture_enabled"] is False
        assert config["adapters"]["scapy_sniff"] == {
            "enabled": False,
            "interface": "eth9",
        }
        assert config["adapters"]["suricata_eve"]["path"] == "/var/log/suricata/eve.json"
        assert "interface" in config["adapters"]["scapy_sniff"]


class TestManagement:
    @pytest.mark.asyncio
    async def test_get_sensor(self) -> None:
        sensor = _sensor()
        db = FakeSession([sensor])
        assert await get_sensor(db, 1) is sensor
        assert await get_sensor(db, 999) is None

    @pytest.mark.asyncio
    async def test_update_applies_fields_and_commits(self) -> None:
        sensor = _sensor()
        db = FakeSession([sensor])
        updated = await update_sensor(db, sensor, SensorUpdate(enabled=False, version="9.9.9"))
        assert updated.enabled is False
        assert updated.version == "9.9.9"
        assert db.commits == 1

    @pytest.mark.asyncio
    async def test_update_name_conflict_rejected(self) -> None:
        existing = _sensor(name="taken", sensor_id=1)
        target = _sensor(name="mine", sensor_id=2)
        db = FakeSession([existing, target])
        with pytest.raises(Exception) as excinfo:
            await update_sensor(db, target, SensorUpdate(name="TAKEN"))
        assert excinfo.value.status_code == 409

    @pytest.mark.asyncio
    async def test_rotate_token_changes_hash(self) -> None:
        sensor = _sensor()
        db = FakeSession([sensor])
        old_hash = sensor.token_hash
        new_token = await rotate_sensor_token(db, sensor)
        assert new_token
        assert sensor.token_hash != old_hash
        assert sensor.token_hash == hash_sensor_token(new_token)

    @pytest.mark.asyncio
    async def test_delete_sensor_removes_row(self) -> None:
        sensor = _sensor()
        db = FakeSession([sensor])
        await delete_sensor(db, sensor)
        assert sensor not in db.sensors
        assert db.commits == 1

    @pytest.mark.asyncio
    async def test_list_sensors_pagination_and_filter(self) -> None:
        offline = _sensor(name="off", status="offline", sensor_id=1)
        online = _sensor(name="on", status="online", sensor_id=2)
        db = FakeSession([offline, online])
        rows, total = await list_sensors(db, page=1, page_size=10, status="offline")
        assert total == 2
        assert rows == [offline]


class TestFleetSummary:
    @pytest.mark.asyncio
    async def test_summary_counts_and_tallies(self) -> None:
        online = _sensor(name="edge-a", sensor_id=1)
        offline = _sensor(name="edge-b", status="offline", sensor_id=2)
        disabled = _sensor(name="edge-c", enabled=False, sensor_id=3)
        db = FakeFleetSession(
            [online, offline, disabled],
            alert_rows=[(1, 5), (2, 2)],
            capture_rows=[(1, 4)],
        )
        summary = await fleet_summary(db)
        assert summary["total"] == 3
        assert summary["online"] == 1
        assert summary["offline"] == 1
        assert summary["disabled"] == 1
        assert summary["alerts_last_24h"] == 7
        assert summary["alerts_by_sensor"] == {"edge-a": 5, "edge-b": 2}
        assert summary["captures_by_sensor"] == {"edge-a": 4}


class TestEndpointsAuth:
    def test_sensor_routes_require_auth(self) -> None:
        with TestClient(app) as client:
            assert client.get("/api/v1/sensors").status_code == 401
            assert client.get("/api/v1/sensors/fleet").status_code == 401
            assert client.get("/api/v1/sensors/1").status_code == 401
            assert client.post("/api/v1/sensors", json={"name": "edge-1"}).status_code == 401
            assert client.post("/api/v1/sensors/heartbeat", json={}).status_code == 401
            assert client.get("/api/v1/sensors/config").status_code == 401
            assert client.patch("/api/v1/sensors/1", json={}).status_code == 401
            assert client.post("/api/v1/sensors/1/rotate-token").status_code == 401
            assert client.delete("/api/v1/sensors/1").status_code == 401

    def test_sensor_agent_routes_reject_without_token(self) -> None:
        with TestClient(app) as client:
            assert client.get("/api/v1/sensors/config").status_code == 401
            assert client.post("/api/v1/sensors/heartbeat", json={}).status_code == 401
