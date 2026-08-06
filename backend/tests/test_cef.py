"""Unit tests for ArcSight CEF alert formatting (Phase 7)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.alert import Alert
from app.services.siem.cef import (
    build_test_cef_event,
    cef_escape_extension,
    cef_escape_header,
    format_alert_cef,
)


def _alert(**overrides: object) -> Alert:
    defaults: dict[str, object] = {
        "id": 42,
        "title": "Port scan",
        "rule_id": None,
        "detector": "signature",
        "severity": "high",
        "category": "scan",
        "src_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "risk_score": 72.5,
        "status": "new",
        "created_at": datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Alert(**defaults)


class TestCefFormatting:
    def test_full_event_line(self) -> None:
        alert = _alert()
        line = format_alert_cef(alert)
        parts = line.split("|")
        assert parts[0] == "CEF:0"
        assert parts[1] == "Sentinel IDS"
        assert parts[2] == "Sentinel"
        assert parts[3] == "3.0.0"
        assert parts[4] == "signature"
        assert parts[5] == "Port scan"
        assert parts[6] == "8"
        assert "src=10.0.0.1" in line
        assert "spt=1234" in line
        assert "dst=10.0.0.2" in line
        assert "dpt=80" in line
        assert "deviceExternalId=42" in line
        assert "cs1=signature" in line
        assert "cs1Label=Detector" in line
        assert "cs2=scan" in line
        assert "cn1=72.5" in line
        assert f"rt={int(alert.created_at.timestamp() * 1000)}" in line

    def test_severity_mapping(self) -> None:
        assert format_alert_cef(_alert(severity="low")).split("|")[6] == "2"
        assert format_alert_cef(_alert(severity="medium")).split("|")[6] == "5"
        assert format_alert_cef(_alert(severity="high")).split("|")[6] == "8"
        assert format_alert_cef(_alert(severity="critical")).split("|")[6] == "10"

    def test_unknown_severity_falls_back(self) -> None:
        assert format_alert_cef(_alert(severity="bogus")).split("|")[6] == "3"

    def test_rule_id_preferred_over_detector(self) -> None:
        line = format_alert_cef(_alert(rule_id=7, detector="signature"))
        assert line.split("|")[4] == "7"

    def test_no_ports_emit_zero(self) -> None:
        line = format_alert_cef(_alert(src_port=None, dst_port=None))
        assert "spt=0" in line
        assert "dpt=0" in line

    def test_header_pipes_and_backslashes_escaped(self) -> None:
        line = format_alert_cef(_alert(title="scan|evil\\", category="cmd=scan"))
        assert "scan\\|evil\\\\" in line
        assert "cs2=cmd\\=scan" in line

    def test_extension_equals_and_newlines_escaped(self) -> None:
        assert cef_escape_extension("a=b\nc\rd") == "a\\=b\\nc\\rd"
        assert cef_escape_extension("back\\slash") == "back\\\\slash"
        assert cef_escape_header("a|b\\c") == "a\\|b\\\\c"

    def test_test_event_is_fixed(self) -> None:
        event = build_test_cef_event()
        assert event.startswith("CEF:0|Sentinel IDS|Sentinel|3.0.0|sentinel-ids-test|")
        assert "cs1Label=Source" in event
