"""Signature detection: deterministic rule matching against records (Phase 5).

Rules are YAML documents carrying a ``match`` mapping. The matcher evaluates
constraints over normalized record fields:

- bare scalar:  ``proto: tcp``  -> equality (proto compares case-insensitively)
- list:         ``flags: [S, SA]`` -> record value is one of the listed values
- operator map: ``dst_port: {gt: 1024, lt: 65536}``
- ``in`` on IP fields supports CIDR prefixes: ``src_ip: {in: ["10.0.0.0/8"]}``
- ``contains``: substring check (e.g. against ``payload_text``)
- ``regex``:    re.search against the string form of a field
- combinators:  ``any`` (OR), ``all`` (AND), ``not`` (negation)
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import DETECTOR_SIGNATURE
from app.models.rule import Rule
from app.schemas.alert import AlertCreate
from app.services.detection.base import Detector
from app.services.rule_service import parse_rule_yaml

_SEVERITY_SCORES = {"low": 25.0, "medium": 50.0, "high": 75.0, "critical": 100.0}
_IP_FIELDS = ("src_ip", "dst_ip")


def _eq(record_value: Any, expected: Any) -> bool:
    if record_value is None:
        return False
    if isinstance(record_value, str) and isinstance(expected, str):
        return record_value.lower() == expected.lower()
    try:
        return bool(record_value == expected)
    except Exception:
        return False


def _numeric(record_value: Any) -> float | None:
    try:
        return float(record_value)
    except (TypeError, ValueError):
        return None


def _in_check(record_value: Any, values: Any, *, field: str) -> bool:
    if isinstance(values, str):
        values = [values]
    for candidate in values:
        if field in _IP_FIELDS and isinstance(candidate, str) and "/" in candidate:
            try:
                network = ipaddress.ip_network(candidate, strict=False)
                address = ipaddress.ip_address(str(record_value))
                if address in network:
                    return True
            except ValueError:
                continue
        if _eq(record_value, candidate):
            return True
    return False


def _contains(record_value: Any, needles: Any) -> bool:
    if record_value is None:
        return False
    haystack = str(record_value)
    if isinstance(needles, str):
        needles = [needles]
    return any(needle in haystack for needle in needles)


def _apply_operator(field: str, record_value: Any, op: str, operand: Any) -> bool:
    if op == "eq":
        return _eq(record_value, operand)
    if op == "ne":
        return not _eq(record_value, operand)
    if op == "in":
        return _in_check(record_value, operand, field=field)
    if op == "not_in":
        return not _in_check(record_value, operand, field=field)
    if op == "contains":
        return _contains(record_value, operand)
    if op == "regex":
        return record_value is not None and re.search(str(operand), str(record_value)) is not None
    if op == "exists":
        return record_value is not None
    if op in ("gt", "lt", "ge", "le"):
        number = _numeric(record_value)
        if number is None:
            return False
        try:
            target = float(operand)
        except (TypeError, ValueError):
            return False
        if op == "gt":
            return number > target
        if op == "lt":
            return number < target
        if op == "ge":
            return number >= target
        return number <= target
    return False


def _evaluate_constraint(field: str, value: Any, record: Mapping[str, Any]) -> bool:
    record_value = record.get(field)
    if isinstance(value, Mapping):
        checks = (
            _apply_operator(field, record_value, op, operand) for op, operand in value.items()
        )
        return all(checks)
    if isinstance(value, list):
        return any(_eq(record_value, item) for item in value)
    return _eq(record_value, value)


def _evaluate_node(node: Mapping[str, Any], record: Mapping[str, Any]) -> bool:
    for key, value in node.items():
        if key == "any":
            if not isinstance(value, list) or not any(
                _evaluate_node(item, record) for item in value if isinstance(item, Mapping)
            ):
                return False
            continue
        if key == "all":
            if not isinstance(value, list) or not all(
                _evaluate_node(item, record) for item in value if isinstance(item, Mapping)
            ):
                return False
            continue
        if key == "not":
            if isinstance(value, Mapping) and _evaluate_node(value, record):
                return False
            continue
        if not _evaluate_constraint(key, value, record):
            return False
    return True


def match_record(match: Mapping[str, Any], record: Mapping[str, Any]) -> bool:
    """Evaluate a rule's ``match`` mapping against a single record."""
    return _evaluate_node(match, record)


class SignatureDetector(Detector):
    """Detector that matches enabled rules against each record."""

    name = DETECTOR_SIGNATURE

    async def detect(self, db: AsyncSession, records: list[dict[str, Any]]) -> list[AlertCreate]:
        rules = (await db.execute(select(Rule).where(Rule.enabled.is_(True)))).scalars().all()
        parsed = [(rule, parse_rule_yaml(rule.yaml_content)) for rule in rules]

        alerts: list[AlertCreate] = []
        for record in records:
            for rule, content in parsed:
                match = content.get("match")
                if not isinstance(match, dict) or not match_record(match, record):
                    continue
                title = content.get("name")
                alerts.append(
                    AlertCreate(
                        title=str(title) if isinstance(title, str) else rule.name,
                        rule_id=rule.id,
                        detector=self.name,
                        severity=rule.severity,
                        category=rule.category,
                        src_ip=str(record.get("src_ip", "")),
                        src_port=record.get("src_port"),
                        dst_ip=str(record.get("dst_ip", "")),
                        dst_port=record.get("dst_port"),
                        risk_score=_SEVERITY_SCORES.get(rule.severity, 50.0),
                        details={
                            "proto": record.get("proto"),
                            "length": record.get("length"),
                            "flags": record.get("flags"),
                            "rule_version": rule.version,
                        },
                    )
                )
        return alerts

    def enabled(self) -> bool:
        return True
