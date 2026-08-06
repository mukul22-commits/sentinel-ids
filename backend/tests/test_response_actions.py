"""Unit tests for the response action planner (Phase 4)."""

from __future__ import annotations

from app.services.response_action_service import plan_response_action


class TestPlanResponseAction:
    def test_block_plan(self) -> None:
        steps = plan_response_action("block", "ip", "203.0.113.5")
        actions = [step["step"] for step in steps]
        assert actions == ["validate_target", "apply_firewall_deny", "verify_block"]
        assert steps[1]["target"] == "ip:203.0.113.5"
        assert steps[1]["result"] == "applied"

    def test_quarantine_plan(self) -> None:
        steps = plan_response_action("quarantine", "host", "workstation-42")
        assert steps[0]["step"] == "validate_target"
        assert steps[-1]["result"] == "verified"

    def test_notify_plan(self) -> None:
        steps = plan_response_action("notify", "email", "soc@example.com")
        assert [step["step"] for step in steps] == [
            "resolve_recipients",
            "send_alert_email",
        ]
        assert steps[-1]["result"] == "sent"

    def test_unknown_action_returns_skipped_plan(self) -> None:
        steps = plan_response_action("nuke", "ip", "1.2.3.4")
        assert steps == [{"step": "unknown_action", "target": "ip:1.2.3.4", "result": "skipped"}]

    def test_plans_are_deterministic(self) -> None:
        assert plan_response_action("block", "ip", "203.0.113.5") == plan_response_action(
            "block", "ip", "203.0.113.5"
        )
