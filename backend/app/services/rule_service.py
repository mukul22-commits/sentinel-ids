"""Rules engine: YAML rule parsing/validation and CRUD (Phase 5)."""

from __future__ import annotations

from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import RULE_SEVERITIES
from app.models.rule import Rule


class RuleValidationError(ValueError):
    """Raised when a rule's YAML content or metadata is invalid."""


def parse_rule_yaml(content: str) -> dict[str, Any]:
    """Parse rule YAML into a mapping, raising ``RuleValidationError`` on bad input."""
    try:
        loaded = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise RuleValidationError(f"Invalid YAML: {exc}") from exc
    if not isinstance(loaded, dict):
        raise RuleValidationError("Rule YAML must be a mapping")
    return loaded


def validate_rule_payload(
    *,
    name: str,
    category: str,
    severity: str,
    yaml_content: str,
) -> dict[str, Any]:
    """Validate rule metadata and YAML match logic. Returns the parsed YAML."""
    if not name.strip():
        raise RuleValidationError("Rule name is required")
    if severity not in RULE_SEVERITIES:
        raise RuleValidationError(
            f"Invalid severity '{severity}' (expected one of {', '.join(RULE_SEVERITIES)})"
        )
    if not category.strip():
        raise RuleValidationError("Rule category is required")

    parsed = parse_rule_yaml(yaml_content)
    parsed_name = parsed.get("name")
    if isinstance(parsed_name, str) and parsed_name != name:
        raise RuleValidationError(f"Rule name in YAML ('{parsed_name}') must match the rule name")
    if "match" not in parsed:
        raise RuleValidationError("Rule YAML must include a 'match' section")
    if not isinstance(parsed["match"], dict):
        raise RuleValidationError("Rule 'match' section must be a mapping")
    return parsed


async def list_rules(
    db: AsyncSession,
    *,
    enabled: bool | None = None,
    category: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[Rule], int]:
    """Return a page of rules and the total count matching the filters."""
    stmt = select(Rule)
    if enabled is not None:
        stmt = stmt.where(Rule.enabled.is_(enabled))
    if category is not None:
        stmt = stmt.where(Rule.category == category)
    if severity is not None:
        stmt = stmt.where(Rule.severity == severity)
    if search:
        stmt = stmt.where(Rule.name.ilike(f"%{search}%"))

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        (
            await db.execute(
                stmt.order_by(Rule.updated_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def get_rule(db: AsyncSession, rule_id: int) -> Rule | None:
    return await db.get(Rule, rule_id)


async def _name_taken(db: AsyncSession, name: str, exclude_id: int | None = None) -> bool:
    stmt = select(Rule.id).where(Rule.name == name)
    if exclude_id is not None:
        stmt = stmt.where(Rule.id != exclude_id)
    return (await db.scalar(stmt)) is not None


async def create_rule(
    db: AsyncSession,
    *,
    name: str,
    description: str | None,
    yaml_content: str,
    category: str,
    severity: str,
    enabled: bool,
) -> Rule:
    """Validate and persist a new rule (version 1)."""
    validate_rule_payload(
        name=name, category=category, severity=severity, yaml_content=yaml_content
    )
    if await _name_taken(db, name):
        raise RuleValidationError(f"A rule named '{name}' already exists")

    rule = Rule(
        name=name,
        description=description,
        yaml_content=yaml_content,
        category=category,
        severity=severity,
        enabled=enabled,
        version=1,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


async def update_rule(
    db: AsyncSession,
    rule: Rule,
    *,
    name: str | None = None,
    description: str | None = None,
    yaml_content: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    enabled: bool | None = None,
) -> Rule:
    """Apply a partial update, bumping ``version`` when match logic changes."""
    new_name = name if name is not None else rule.name
    new_category = category if category is not None else rule.category
    new_severity = severity if severity is not None else rule.severity
    new_yaml = yaml_content if yaml_content is not None else rule.yaml_content

    validate_rule_payload(
        name=new_name, category=new_category, severity=new_severity, yaml_content=new_yaml
    )
    if new_name != rule.name and await _name_taken(db, new_name, exclude_id=rule.id):
        raise RuleValidationError(f"A rule named '{new_name}' already exists")

    content_changed = new_yaml != rule.yaml_content
    rule.name = new_name
    rule.category = new_category
    rule.severity = new_severity
    if description is not None:
        rule.description = description
    if enabled is not None:
        rule.enabled = enabled
    if yaml_content is not None:
        rule.yaml_content = new_yaml
    if content_changed:
        rule.version = rule.version + 1

    await db.commit()
    await db.refresh(rule)
    return rule


async def set_enabled(db: AsyncSession, rule: Rule, enabled: bool) -> Rule:
    rule.enabled = enabled
    await db.commit()
    await db.refresh(rule)
    return rule


async def delete_rule(db: AsyncSession, rule: Rule) -> None:
    await db.delete(rule)
    await db.commit()
