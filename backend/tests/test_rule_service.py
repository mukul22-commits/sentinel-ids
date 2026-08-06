"""Unit tests for the rules engine: YAML validation and matching (Phase 5)."""

from __future__ import annotations

import pytest
from app.core.constants import RULE_SEVERITIES
from app.services.detection.signature import match_record
from app.services.rule_service import (
    RuleValidationError,
    parse_rule_yaml,
    validate_rule_payload,
)

VALID_YAML = """
name: Suspicious SSH Login
description: Detect brute-force attempts on SSH
match:
  proto: tcp
  dst_port: 22
  flags: [S]
"""


class TestParseRuleYaml:
    def test_parses_valid_yaml(self) -> None:
        parsed = parse_rule_yaml(VALID_YAML)
        assert parsed["match"]["dst_port"] == 22

    def test_invalid_yaml_raises(self) -> None:
        with pytest.raises(RuleValidationError):
            parse_rule_yaml("name: [unclosed")

    def test_non_mapping_raises(self) -> None:
        with pytest.raises(RuleValidationError):
            parse_rule_yaml("- just\n- a list\n")


class TestValidateRulePayload:
    def test_accepts_valid_payload(self) -> None:
        parsed = validate_rule_payload(
            name="Suspicious SSH Login",
            category="brute-force",
            severity="medium",
            yaml_content=VALID_YAML,
        )
        assert parsed["match"]["proto"] == "tcp"

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(RuleValidationError):
            validate_rule_payload(
                name="x", category="c", severity="extreme", yaml_content=VALID_YAML
            )

    def test_yaml_name_mismatch_raises(self) -> None:
        with pytest.raises(RuleValidationError):
            validate_rule_payload(
                name="Different Name",
                category="c",
                severity="medium",
                yaml_content=VALID_YAML,
            )

    def test_missing_match_raises(self) -> None:
        with pytest.raises(RuleValidationError):
            validate_rule_payload(
                name="x",
                category="c",
                severity="medium",
                yaml_content="name: x\n",
            )

    def test_all_severities_are_accepted(self) -> None:
        nameless_yaml = "match:\n  proto: tcp\n"
        for severity in RULE_SEVERITIES:
            validate_rule_payload(
                name="x", category="c", severity=severity, yaml_content=nameless_yaml
            )


class TestMatchRecord:
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

    def test_scalar_equality(self) -> None:
        assert match_record({"proto": "tcp"}, self.RECORD)
        assert not match_record({"proto": "udp"}, self.RECORD)

    def test_proto_case_insensitive(self) -> None:
        assert match_record({"proto": "TCP"}, self.RECORD)

    def test_list_means_any(self) -> None:
        assert match_record({"flags": ["A", "S"]}, self.RECORD)
        assert not match_record({"flags": ["A", "R"]}, self.RECORD)

    def test_numeric_operators(self) -> None:
        assert match_record({"length": {"gt": 40, "lt": 60}}, self.RECORD)
        assert not match_record({"length": {"gt": 100}}, self.RECORD)

    def test_ip_cidr_in(self) -> None:
        assert match_record({"src_ip": {"in": ["10.0.0.0/8", "192.168.0.0/16"]}}, self.RECORD)
        assert not match_record({"src_ip": {"in": ["172.16.0.0/12"]}}, self.RECORD)

    def test_contains_on_payload_text(self) -> None:
        assert match_record({"payload_text": {"contains": ["root:x", "bash"]}}, self.RECORD)
        assert not match_record({"payload_text": {"contains": ["powershell"]}}, self.RECORD)

    def test_regex(self) -> None:
        assert match_record({"payload_text": {"regex": r"root:x:\d+:\d+"}}, self.RECORD)

    def test_any_combinator(self) -> None:
        match = {"any": [{"dst_port": 22}, {"dst_port": 80}]}
        assert match_record(match, self.RECORD)

    def test_all_combinator(self) -> None:
        match = {"all": [{"proto": "tcp"}, {"dst_port": 22}]}
        assert match_record(match, self.RECORD)

    def test_not_combinator(self) -> None:
        assert match_record({"not": {"proto": "udp"}}, self.RECORD)
        assert not match_record({"not": {"proto": "tcp"}}, self.RECORD)

    def test_missing_field_does_not_match(self) -> None:
        assert not match_record({"payload_hash": "abc"}, self.RECORD)

    def test_multiple_constraints_and(self) -> None:
        match = {"proto": "tcp", "dst_port": 22, "length": {"ge": 40}}
        assert match_record(match, self.RECORD)
