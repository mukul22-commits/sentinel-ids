"""Service-level tests for the IOC (threat intel) service."""

from __future__ import annotations

from typing import Any

import pytest
from app.models.ioc import IOC
from app.services.ioc_service import (
    delete_ioc,
    get_ioc,
    list_iocs,
    update_ioc,
    upsert_ioc,
)
from sqlalchemy import select


@pytest.fixture
async def ioc_db(sqlite_db_factory: Any) -> Any:
    async with sqlite_db_factory() as session:
        yield session


class TestUpsertIoc:
    async def test_insert_new_ioc(self, ioc_db: Any) -> None:
        ioc = await upsert_ioc(ioc_db, type="ip", value="1.2.3.4", source="feed-a", confidence=0.9)
        assert ioc.id is not None
        assert ioc.type == "ip"
        assert ioc.value == "1.2.3.4"
        assert ioc.source == "feed-a"

    async def test_duplicate_refreshes_metadata(self, ioc_db: Any) -> None:
        await upsert_ioc(ioc_db, type="ip", value="1.2.3.4", source="feed-a", confidence=0.9)
        await upsert_ioc(ioc_db, type="ip", value="1.2.3.4", source="feed-b", confidence=0.4)
        rows = (await ioc_db.execute(select(IOC))).scalars().all()
        assert len(rows) == 1
        assert rows[0].source == "feed-b"
        assert rows[0].confidence == 0.4


class TestListIocs:
    async def test_list_and_total(self, ioc_db: Any) -> None:
        await upsert_ioc(ioc_db, type="ip", value="1.1.1.1", source="a", confidence=0.5)
        await upsert_ioc(ioc_db, type="domain", value="evil.example", source="b", confidence=0.8)
        iocs, total = await list_iocs(ioc_db)
        assert total == 2
        assert {ioc.type for ioc in iocs} == {"ip", "domain"}

    async def test_filters(self, ioc_db: Any) -> None:
        await upsert_ioc(ioc_db, type="ip", value="1.1.1.1", source="a", confidence=0.5)
        await upsert_ioc(ioc_db, type="domain", value="evil.example", source="b", confidence=0.8)
        _, total = await list_iocs(ioc_db, type="ip")
        assert total == 1
        _, total = await list_iocs(ioc_db, source="b")
        assert total == 1
        _, total = await list_iocs(ioc_db, search="evil")
        assert total == 1

    async def test_pagination(self, ioc_db: Any) -> None:
        for i in range(3):
            await upsert_ioc(ioc_db, type="ip", value=f"10.0.0.{i}", source="a", confidence=0.5)
        iocs, total = await list_iocs(ioc_db, page=1, page_size=2)
        assert total == 3
        assert len(iocs) == 2


class TestGetUpdateDelete:
    async def test_get_returns_none_for_missing(self, ioc_db: Any) -> None:
        assert await get_ioc(ioc_db, 999) is None

    async def test_get_returns_ioc(self, ioc_db: Any) -> None:
        ioc = await upsert_ioc(ioc_db, type="ip", value="1.1.1.1", source="a", confidence=0.5)
        found = await get_ioc(ioc_db, ioc.id)
        assert found is not None
        assert found.value == "1.1.1.1"

    async def test_update_partial(self, ioc_db: Any) -> None:
        ioc = await upsert_ioc(ioc_db, type="ip", value="1.1.1.1", source="a", confidence=0.5)
        updated = await update_ioc(ioc_db, ioc, confidence=0.95)
        assert updated.confidence == 0.95
        assert updated.source == "a"
        assert updated.last_seen is not None

    async def test_update_source(self, ioc_db: Any) -> None:
        ioc = await upsert_ioc(ioc_db, type="ip", value="1.1.1.1", source="a", confidence=0.5)
        updated = await update_ioc(ioc_db, ioc, source="c")
        assert updated.source == "c"

    async def test_delete(self, ioc_db: Any) -> None:
        ioc = await upsert_ioc(ioc_db, type="ip", value="1.1.1.1", source="a", confidence=0.5)
        await delete_ioc(ioc_db, ioc)
        rows = (await ioc_db.execute(select(IOC))).scalars().all()
        assert rows == []
