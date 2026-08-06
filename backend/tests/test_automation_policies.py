"""Unit tests for response policy schemas, matching, and automation helpers (Phase 6)."""

from __future__ import annotations

import pytest
from app.models.alert import Alert
from app.models.response_policy import ResponsePolicy
from app.schemas.response_policy import PolicyAction, PolicyConditions, ResponsePolicyCreate
from app.services.automation_service import cooldown_key, policy_matches, render_target
from pydantic import ValidationError


def _policy(**conditions) -> ResponsePolicy:
    return ResponsePolicy(
        name="test",
        enabled=True,
        conditions=conditions,
        actions=[],
        cooldown_seconds=3600,
    )


def _alert(**overrides) -> Alert:
    fields = {
        "title": "Test alert",
        "rule_id": 1,
        "detector": "signature",
        "severity": "high",
        "category": "malware",
        "src_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "risk_score": 75.0,
        "status": "new",
        "details": None,
    }
    fields.update(overrides)
    return Alert(**fields)


class TestPolicyMatches:
    def test_empty_conditions_match_everything(self) -> None:
        assert policy_matches(_policy(), _alert()) is True

    def test_severity_match(self) -> None:
        assert policy_matches(_policy(severity=["high", "critical"]), _alert()) is True

    def test_severity_mismatch(self) -> None:
        assert policy_matches(_policy(severity=["critical"]), _alert()) is False

    def test_detector_filter(self) -> None:
        assert policy_matches(_policy(detectors=["signature"]), _alert()) is True
        assert policy_matches(_policy(detectors=["ml"]), _alert()) is False

    def test_category_filter(self) -> None:
        assert policy_matches(_policy(categories=["malware"]), _alert()) is True
        assert policy_matches(_policy(categories=["scan"]), _alert()) is False

    def test_min_risk_score(self) -> None:
        assert policy_matches(_policy(min_risk_score=80), _alert(risk_score=90.0)) is True
        assert policy_matches(_policy(min_risk_score=80), _alert(risk_score=50.0)) is False


class TestRenderTarget:
    def test_substitutes_ip_templates(self) -> None:
        assert render_target("block {{src_ip}}", _alert()) == "block 10.0.0.1"
        assert render_target("quarantine {{dst_ip}}", _alert()) == "quarantine 10.0.0.2"

    def test_literal_target_unchanged(self) -> None:
        assert render_target("ops@example.com", _alert()) == "ops@example.com"


class TestCooldownKey:
    def test_format(self) -> None:
        assert cooldown_key(7, "10.0.0.1") == "automation:cooldown:7:10.0.0.1"


class TestPolicySchema:
    def test_valid_policy(self) -> None:
        policy = ResponsePolicyCreate(
            name="Block scanners",
            conditions=PolicyConditions(severity=["high", "critical"], min_risk_score=60),
            actions=[
                PolicyAction(action_type="block", target_type="ip", target_value="{{src_ip}}")
            ],
            cooldown_seconds=600,
        )
        assert policy.cooldown_seconds == 600
        assert policy.actions[0].target_value == "{{src_ip}}"

    def test_invalid_action_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ResponsePolicyCreate(
                name="bad",
                actions=[
                    PolicyAction(action_type="drop", target_type="ip", target_value="1.2.3.4")
                ],
            )

    def test_invalid_target_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ResponsePolicyCreate(
                name="bad",
                actions=[PolicyAction(action_type="block", target_type="mac", target_value="aa")],
            )

    def test_invalid_severity_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ResponsePolicyCreate(
                name="bad",
                conditions=PolicyConditions(severity=["critical", "urgent"]),
                actions=[PolicyAction(action_type="notify", target_type="email", target_value="x")],
            )
