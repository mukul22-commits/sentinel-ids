"""Pytest bootstrap: force the test environment before app modules load.

Also provides an in-memory SQLite session factory for tests of models that are
free of PostgreSQL-only JSONB columns.
"""

from __future__ import annotations

import json
import os
import uuid as uuid_mod
from collections import defaultdict
from collections.abc import AsyncGenerator
from datetime import UTC, date, datetime, time
from itertools import count
from typing import Any

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6390/0")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")

# Force the settings field falsy (env vars beat the .env file) so the
# PROMETHEUS_MULTIPROC_DIR from the dev .env is ignored in tests, then drop
# the env var again before prometheus_client is first imported. That keeps
# tests on the single-process default registry (matching the pre-.env
# baseline) instead of multiprocess mode, and avoids POSIX /tmp paths that
# don't exist on Windows.
os.environ["PROMETHEUS_MULTIPROC_DIR"] = ""

import app.core.config as config_mod  # noqa: E402  (loads settings with falsy value)

os.environ.pop("PROMETHEUS_MULTIPROC_DIR", None)
os.environ.pop("prometheus_multiproc_dir", None)
del config_mod

import pytest  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.alert import Alert  # noqa: E402
from app.models.audit_log import AuditLog  # noqa: E402
from app.models.capture_run import CaptureRun  # noqa: E402
from app.models.incident import Incident  # noqa: E402
from app.models.ioc import IOC  # noqa: E402
from app.models.notification import Notification  # noqa: E402
from app.models.packet import Packet  # noqa: E402
from app.models.response_action import ResponseAction  # noqa: E402
from app.models.response_policy import ResponsePolicy  # noqa: E402
from app.models.rule import Rule  # noqa: E402
from app.models.sensor import Sensor  # noqa: E402
from app.models.siem_export_run import SiemExportRun  # noqa: E402
from app.models.user import User  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import JSON, Integer  # noqa: E402
from sqlalchemy.dialects.sqlite.base import DATETIME as SQLiteDateTime  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool  # noqa: E402

SQLITE_MODEL_TABLES = [
    User.__table__,
    Alert.__table__,
    AuditLog.__table__,
    CaptureRun.__table__,
    Incident.__table__,
    IOC.__table__,
    Notification.__table__,
    Packet.__table__,
    ResponseAction.__table__,
    ResponsePolicy.__table__,
    Rule.__table__,
    Sensor.__table__,
    SiemExportRun.__table__,
]


class _TzSqliteDateTime(SQLiteDateTime):
    """SQLite ``DATETIME`` that round-trips tzinfo.

    SQLite stores datetimes as naive strings; this restores UTC awareness so
    code comparing ``DateTime(timezone=True)`` columns behaves as it does on
    PostgreSQL. Subclassing the dialect impl means ``adapt_type`` keeps this
    type (and its processors) instead of swapping in a plain ``DATETIME``.
    """

    def bind_processor(self, dialect):  # type: ignore[no-untyped-def]
        def process(value):  # type: ignore[no-untyped-def]
            if isinstance(value, datetime) and value.tzinfo is not None:
                return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
            return value

        return process

    def result_processor(self, dialect, coltype):  # type: ignore[no-untyped-def]
        def process(value):  # type: ignore[no-untyped-def]
            if isinstance(value, str):
                text = value.strip()
                if "." in text:
                    parsed = datetime.strptime(text[:26], "%Y-%m-%d %H:%M:%S.%f")
                else:
                    parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
                return parsed.replace(tzinfo=UTC)
            return value

        return process


def _json_default(value: Any) -> Any:
    """JSON-fallback used by the SQLite JSON columns.

    App models store ``datetime``/``UUID`` values inside ``JSONB`` columns
    (e.g. ``Incident.timeline``); on PostgreSQL the driver serializes those
    itself, so the SQLite stand-in needs an equivalent fallback.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date | time):
        return value.isoformat()
    if isinstance(value, uuid_mod.UUID):
        return str(value)
    if isinstance(value, set | frozenset):
        return list(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


class _DateTimeJson(JSON):
    """SQLite ``JSON`` that serializes datetimes/UUIDs like PostgreSQL JSONB."""

    json_serializer = staticmethod(lambda obj: json.dumps(obj, default=_json_default))  # type: ignore[misc]
    json_deserializer = staticmethod(json.loads)  # type: ignore[misc]


_pk_counters: defaultdict[str, Any] = defaultdict(lambda: count(1))


def _make_pk_default(table_name: str) -> Any:
    counter = _pk_counters[table_name]

    def _next_pk() -> int:
        return next(counter)

    return _next_pk


def _patch_sqlite_tables(tables: list[Any]) -> dict[Any, tuple[Any, Any, Any]]:
    """Adapt PostgreSQL-oriented columns for the SQLite test database.

    The shared ORM ``Table`` objects are mutated in place, so every changed
    column is snapshotted (type, server_default, default) and the caller must
    restore them afterwards. Without restoration the SQLite-specific types and
    Python-side PK defaults leak into tests that hit the real PostgreSQL engine
    (e.g. the DB round-trip tests), breaking type handling and PK generation.
    """
    from sqlalchemy import DateTime, text
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.sql.schema import ColumnDefault, DefaultClause

    snapshots: dict[Any, tuple[Any, Any, Any]] = {}
    for table in tables:
        for column in table.c.values():
            snapshots[column] = (column.type, column.server_default, column.default)
            if "BIGINT" in str(column.type).upper():
                column.type = Integer()
            elif isinstance(column.type, DateTime) and column.type.timezone:
                column.type = _TzSqliteDateTime()
            elif isinstance(column.type, JSONB):
                column.type = _DateTimeJson()
                column.server_default = DefaultClause(text("'[]'"))
            if column.identity is not None:
                # SQLite only auto-generates single-column INTEGER PRIMARY KEYs;
                # give composite-PK identity columns (e.g. ``packets.id``) a
                # Python-side generator so bulk inserts still assign ids.
                column.default = ColumnDefault(_make_pk_default(table.name))
    return snapshots


@pytest.fixture
async def sqlite_db_factory() -> AsyncGenerator[Any, None]:
    """In-memory SQLite session factory for JSONB-free model tables.

    ``BigInteger`` identity ids render as ``BIGINT`` on SQLite, which does not
    auto-increment; patching them to ``INTEGER`` restores rowid aliasing.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
        json_serializer=lambda obj: json.dumps(obj, default=_json_default),
        json_deserializer=json.loads,
    )
    _pk_counters.clear()
    snapshots = _patch_sqlite_tables(SQLITE_MODEL_TABLES)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(
                lambda sync_conn: Base.metadata.create_all(sync_conn, tables=SQLITE_MODEL_TABLES)
            )
        factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
        yield factory
    finally:
        for column, (type_, server_default, default) in snapshots.items():
            column.type = type_
            column.server_default = server_default
            column.default = default
        await engine.dispose()


@pytest.fixture
def sqlite_app_client(sqlite_db_factory: Any) -> AsyncGenerator[TestClient, None]:
    """TestClient whose ``get_db`` dependency resolves to the SQLite factory."""

    async def _override_db() -> AsyncGenerator[AsyncSession, None]:
        async with sqlite_db_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.pop(get_db, None)
