"""Database round-trip test for Phase 5 models (requires PostgreSQL)."""

from __future__ import annotations

import asyncpg
import pytest
from app.core.config import settings
from app.db.session import async_session_factory, engine
from app.models.alert import Alert


async def _db_available() -> bool:
    try:
        connection = await asyncpg.connect(
            settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://"),
            timeout=3,
        )
    except Exception:
        return False
    await connection.close()
    return True


async def test_alert_roundtrip_with_details() -> None:
    if not await _db_available():
        pytest.skip("PostgreSQL not reachable - skipping DB round-trip test")

    async with async_session_factory() as session:
        alert = Alert(
            title="Suspicious SSH login",
            rule_id=1,
            detector="signature",
            severity="high",
            category="brute-force",
            src_ip="198.51.100.5",
            src_port=4444,
            dst_ip="10.0.0.2",
            dst_port=22,
            risk_score=75.0,
            details={"proto": "tcp", "flags": "S", "rule_version": 1},
        )
        session.add(alert)
        await session.commit()
        await session.refresh(alert)
        alert_id = alert.id

    assert alert_id is not None

    async with async_session_factory() as session:
        loaded = await session.get(Alert, alert_id)
        assert loaded is not None
        assert loaded.detector == "signature"
        assert loaded.title == "Suspicious SSH login"
        assert loaded.details == {"proto": "tcp", "flags": "S", "rule_version": 1}
        assert loaded.status == "new"

    await engine.dispose()
