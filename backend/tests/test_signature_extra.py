"""Additional matcher edge cases and the ``SignatureDetector`` pipeline."""

from __future__ import annotations

from typing import Any

import pytest
from app.models.rule import Rule
from app.services.detection.signature import SignatureDetector, match_record
from app.services.rule_service import RuleValidationError

RECORD = {
    "src_ip": "10.1.1.5",
    "src_port": 54321,
    "dst_ip": "203.0.113.10",
    "dst_port": 22,
    "proto": "tcp",
    "length": 48,
    "flags": "S",
    "payload_text": "root:x:0:0:root:/root:/bin/bash",
}


class _RaisingEq:
    def __eq__(self, other: Any) -> bool:  # type: ignore[override]
        raise RuntimeError("boom")


class TestOperatorMaps:
    def test_eq_operator(self) -> None:
        assert match_record({"proto": {"eq": "TCP"}}, RECORD)
        assert not match_record({"proto": {"eq": "udp"}}, RECORD)

    def test_ne_operator(self) -> None:
        assert match_record({"proto": {"ne": "udp"}}, RECORD)
        assert not match_record({"proto": {"ne": "tcp"}}, RECORD)

    def test_not_in_operator(self) -> None:
        assert match_record({"dst_ip": {"not_in": ["10.0.0.0/8"]}}, RECORD)
        assert not match_record({"dst_ip": {"not_in": ["203.0.113.10"]}}, RECORD)

    def test_contains_operator_with_string_needle(self) -> None:
        assert match_record({"payload_text": {"contains": "root:x"}}, RECORD)

    def test_exists_operator(self) -> None:
        assert match_record({"proto": {"exists": True}}, RECORD)
        assert not match_record({"missing_field": {"exists": True}}, RECORD)

    def test_gt_on_non_numeric_value(self) -> None:
        assert not match_record({"length": {"gt": 100}}, {**RECORD, "length": "n/a"})
        assert not match_record({"length": {"gt": 100}}, {**RECORD, "length": None})
        assert not match_record({"length": {"gt": 100}}, {**RECORD, "length": ["1"]})

    def test_gt_with_non_numeric_operand(self) -> None:
        assert not match_record({"length": {"gt": "many"}}, RECORD)

    def test_ge_and_le(self) -> None:
        assert match_record({"length": {"ge": 48}}, RECORD)
        assert match_record({"length": {"le": 48}}, RECORD)
        assert not match_record({"length": {"ge": 49}}, RECORD)

    def test_lt_and_le_boundaries(self) -> None:
        assert match_record({"length": {"lt": 49}}, RECORD)
        assert not match_record({"length": {"lt": 48}}, RECORD)

    def test_unknown_operator_is_false(self) -> None:
        assert not match_record({"proto": {"bogus": "tcp"}}, RECORD)

    def test_mapping_with_multiple_ops(self) -> None:
        assert match_record({"length": {"ge": 40, "le": 50}}, RECORD)
        assert not match_record({"length": {"ge": 40, "le": 45}}, RECORD)


class TestInCheck:
    def test_in_skips_invalid_cidr_and_matches_plain(self) -> None:
        match = {"src_ip": {"in": ["not-a-cidr", "10.1.1.5"]}}
        assert match_record(match, RECORD)

    def test_in_cidr_match(self) -> None:
        assert match_record({"src_ip": {"in": ["10.0.0.0/8"]}}, RECORD)

    def test_in_string_value_is_singleton(self) -> None:
        assert match_record({"proto": {"in": "tcp"}}, RECORD)

    def test_in_missing_field(self) -> None:
        assert not match_record({"payload_hash": {"in": ["abc"]}}, RECORD)


class TestContainsEdge:
    def test_contains_missing_field(self) -> None:
        assert not match_record({"payload_hash": {"contains": "x"}}, RECORD)

    def test_eq_exception_is_caught(self) -> None:
        assert not match_record({"proto": 1}, {"proto": _RaisingEq()})


class TestCombinators:
    def test_any_non_list_is_false(self) -> None:
        assert not match_record({"any": "proto"}, RECORD)

    def test_any_non_mapping_items_is_false(self) -> None:
        assert not match_record({"any": ["proto"]}, RECORD)

    def test_all_non_mapping_items_vacuously_true(self) -> None:
        assert match_record({"all": ["proto"]}, RECORD)

    def test_not_with_missing_value(self) -> None:
        assert match_record({"not": {"bogus_key": "x"}}, RECORD)


class TestSignatureDetector:
    async def test_detect_only_matches_enabled_rules(self, sqlite_db_factory: Any) -> None:
        enabled_yaml = """
name: SSH Login
match:
  dst_port: 22
  proto: tcp
"""
        async with sqlite_db_factory() as session:
            session.add_all(
                [
                    Rule(
                        name="SSH Login",
                        category="auth",
                        severity="high",
                        yaml_content=enabled_yaml,
                        enabled=True,
                        version=3,
                    ),
                    Rule(
                        name="UDP Only",
                        category="net",
                        severity="low",
                        yaml_content="match:\n  proto: udp\n",
                        enabled=True,
                        version=1,
                    ),
                    Rule(
                        name="Disabled Match",
                        category="auth",
                        severity="critical",
                        yaml_content=enabled_yaml,
                        enabled=False,
                        version=1,
                    ),
                    Rule(
                        name="No Match Section",
                        category="misc",
                        severity="low",
                        yaml_content="name: No Match Section\n",
                        enabled=True,
                        version=1,
                    ),
                ]
            )
            await session.commit()
            detector = SignatureDetector()
            alerts = await detector.detect(session, [RECORD])

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.title == "SSH Login"
        assert alert.severity == "high"
        assert alert.category == "auth"
        assert alert.risk_score == 75.0
        assert alert.rule_id is not None
        assert alert.src_ip == "10.1.1.5"
        assert alert.dst_port == 22
        assert alert.details["rule_version"] == 3

    async def test_detect_uses_rule_name_when_yaml_name_not_a_string(
        self, sqlite_db_factory: Any
    ) -> None:
        async with sqlite_db_factory() as session:
            session.add(
                Rule(
                    name="Fallback Name",
                    category="auth",
                    severity="medium",
                    yaml_content="name: 42\nmatch:\n  proto: tcp\n",
                    enabled=True,
                    version=1,
                )
            )
            await session.commit()
            detector = SignatureDetector()
            alerts = await detector.detect(session, [RECORD])
        assert len(alerts) == 1
        assert alerts[0].title == "Fallback Name"

    async def test_detect_no_rules(self, sqlite_db_factory: Any) -> None:
        async with sqlite_db_factory() as session:
            detector = SignatureDetector()
            assert await detector.detect(session, [RECORD]) == []

    def test_detector_enabled(self) -> None:
        assert SignatureDetector().enabled() is True

    def test_match_record_is_exported(self) -> None:
        assert callable(match_record)

    async def test_detect_propagates_invalid_yaml(self, sqlite_db_factory: Any) -> None:
        async with sqlite_db_factory() as session:
            session.add(
                Rule(
                    name="Broken",
                    category="misc",
                    severity="low",
                    yaml_content="name: [unclosed",
                    enabled=True,
                    version=1,
                )
            )
            await session.commit()
            detector = SignatureDetector()
            with pytest.raises(RuleValidationError):
                await detector.detect(session, [RECORD])

    async def test_list_filter_uses_any_semantics(self, sqlite_db_factory: Any) -> None:
        record = {**RECORD, "flags": "S"}
        assert match_record({"flags": ["A", "S"]}, record)
        assert not match_record({"flags": ["A", "R"]}, record)
