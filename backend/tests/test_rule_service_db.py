"""Service-level tests for rule CRUD against an in-memory SQLite database."""

from __future__ import annotations

from typing import Any

import pytest
from app.models.rule import Rule
from app.services.rule_service import (
    RuleValidationError,
    create_rule,
    delete_rule,
    get_rule,
    list_rules,
    set_enabled,
    update_rule,
)

YAML = """
name: Test Rule
description: A rule for testing
match:
  proto: tcp
  dst_port: 22
"""


@pytest.fixture
async def rule_db(sqlite_db_factory: Any) -> Any:
    async with sqlite_db_factory() as session:
        yield session


async def _create(session: Any, **overrides: Any) -> Rule:
    params = {
        "name": "Test Rule",
        "description": "desc",
        "yaml_content": YAML,
        "category": "auth",
        "severity": "medium",
        "enabled": True,
    }
    params.update(overrides)
    return await create_rule(session, **params)


class TestCreateRule:
    async def test_create_returns_persisted_rule(self, rule_db: Any) -> None:
        rule = await _create(rule_db)
        assert rule.id is not None
        assert rule.version == 1
        assert rule.enabled is True
        fresh = await get_rule(rule_db, rule.id)
        assert fresh is not None
        assert fresh.name == "Test Rule"

    async def test_duplicate_name_rejected(self, rule_db: Any) -> None:
        await _create(rule_db)
        with pytest.raises(RuleValidationError):
            await _create(rule_db, name="Test Rule", yaml_content=YAML)

    async def test_empty_name_rejected(self, rule_db: Any) -> None:
        with pytest.raises(RuleValidationError):
            await _create(rule_db, name="   ")

    async def test_invalid_severity_rejected(self, rule_db: Any) -> None:
        with pytest.raises(RuleValidationError):
            await _create(rule_db, severity="extreme")

    async def test_empty_category_rejected(self, rule_db: Any) -> None:
        with pytest.raises(RuleValidationError):
            await _create(rule_db, category=" ")


class TestUpdateRule:
    async def test_partial_update_preserves_fields(self, rule_db: Any) -> None:
        rule = await _create(rule_db)
        updated = await update_rule(rule_db, rule, enabled=False)
        assert updated.enabled is False
        assert updated.name == "Test Rule"
        assert updated.version == 1

    async def test_content_change_bumps_version(self, rule_db: Any) -> None:
        rule = await _create(rule_db)
        updated = await update_rule(
            rule_db,
            rule,
            yaml_content="match:\n  proto: udp\n",
            name="Test Rule",
            category="auth",
            severity="medium",
        )
        assert updated.version == 2

    async def test_rename_requires_unique_name(self, rule_db: Any) -> None:
        rule = await _create(rule_db)
        await _create(rule_db, name="Second Rule", yaml_content="match:\n  proto: udp\n")
        with pytest.raises(RuleValidationError):
            await update_rule(
                rule_db,
                rule,
                name="Second Rule",
                category="auth",
                severity="medium",
                yaml_content=YAML,
            )

    async def test_rename_to_own_name_is_allowed(self, rule_db: Any) -> None:
        rule = await _create(rule_db)
        updated = await update_rule(rule_db, rule, name="Test Rule")
        assert updated.name == "Test Rule"

    async def test_invalid_update_rejected(self, rule_db: Any) -> None:
        rule = await _create(rule_db)
        with pytest.raises(RuleValidationError):
            await update_rule(rule_db, rule, severity="bogus", category="auth", yaml_content=YAML)


class TestSetEnabled:
    async def test_toggle_enabled(self, rule_db: Any) -> None:
        rule = await _create(rule_db)
        disabled = await set_enabled(rule_db, rule, False)
        assert disabled.enabled is False
        fetched = await get_rule(rule_db, rule.id)
        assert fetched is not None
        assert fetched.enabled is False


class TestDeleteRule:
    async def test_delete_removes_rule(self, rule_db: Any) -> None:
        rule = await _create(rule_db)
        await delete_rule(rule_db, rule)
        assert await get_rule(rule_db, rule.id) is None


class TestListRules:
    async def test_list_returns_page_and_total(self, rule_db: Any) -> None:
        await _create(rule_db, name="Alpha Rule", yaml_content="match:\n  proto: tcp\n")
        await _create(
            rule_db,
            name="Beta Rule",
            category="net",
            severity="low",
            enabled=False,
            yaml_content="match:\n  proto: udp\n",
        )
        rules, total = await list_rules(rule_db)
        assert total == 2
        assert len(rules) == 2

    async def test_filter_by_enabled(self, rule_db: Any) -> None:
        await _create(rule_db, name="Alpha Rule", yaml_content="match:\n  proto: tcp\n")
        await _create(
            rule_db,
            name="Beta Rule",
            enabled=False,
            yaml_content="match:\n  proto: udp\n",
        )
        _, total = await list_rules(rule_db, enabled=True)
        assert total == 1

    async def test_filter_by_category_severity_search(self, rule_db: Any) -> None:
        await _create(rule_db, name="Alpha Rule", yaml_content="match:\n  proto: tcp\n")
        await _create(
            rule_db,
            name="Beta Rule",
            category="net",
            severity="low",
            yaml_content="match:\n  proto: udp\n",
        )
        _, total = await list_rules(rule_db, category="net", severity="low")
        assert total == 1
        _, total = await list_rules(rule_db, search="beta")
        assert total == 1

    async def test_pagination(self, rule_db: Any) -> None:
        for i in range(5):
            await _create(
                rule_db, name=f"Rule {i}", yaml_content=f"match:\n  proto: tcp\n  length: {i}"
            )
        rules, total = await list_rules(rule_db, page=1, page_size=2)
        assert total == 5
        assert len(rules) == 2

    async def test_list_empty(self, rule_db: Any) -> None:
        rules, total = await list_rules(rule_db)
        assert rules == []
        assert total == 0
