"""Tests for the YARA detector: rule loading, payload scanning, errors."""

from __future__ import annotations

import asyncio

from app.services.detection.yara import YaraDetector, _payload_bytes


def _write_rule(dir_path, name: str, content: str):
    path = dir_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_payload_text_extraction() -> None:
    assert _payload_bytes({"payload_text": "hello"}, 1024) == b"hello"


def test_payload_hex_extraction() -> None:
    assert _payload_bytes({"payload_hex": "4d5a9090"}, 1024) == bytes.fromhex("4d5a9090")


def test_payload_b64_extraction() -> None:
    import base64

    assert _payload_bytes({"payload_b64": base64.b64encode(b"abc").decode()}, 1024) == b"abc"


def test_payload_bytes_truncation() -> None:
    assert _payload_bytes({"payload_text": "abcdef"}, 3) == b"abc"


def test_missing_payload_returns_none() -> None:
    assert _payload_bytes({"src_ip": "1.1.1.1"}, 1024) is None


def test_loads_rules_and_matches(tmp_path) -> None:
    _write_rule(
        tmp_path,
        "web.yar",
        r"""
rule webshell {
  meta:
    severity = "critical"
    category = "webshell"
  strings:
    $a = "eval(" nocase
    $b = "base64_decode"
  condition:
    any of them
}
""",
    )
    detector = YaraDetector(rules_dir=str(tmp_path), max_payload_bytes=1024)
    assert detector.enabled() is True
    assert detector.rules() == [(str(tmp_path / "web.yar"), "webshell")]

    record = {
        "src_ip": "10.0.0.1",
        "src_port": 4444,
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "proto": "tcp",
        "payload_text": "if (EVAL($_GET)) {}",
    }
    alerts = asyncio.run(detector.detect(None, [record]))  # type: ignore[arg-type]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.title == "webshell"
    assert alert.detector == "yara"
    assert alert.severity == "critical"
    assert alert.category == "webshell"
    assert alert.src_ip == "10.0.0.1"


def test_no_match_no_alert(tmp_path) -> None:
    _write_rule(tmp_path, "web.yar", r"""rule x { strings: $a = "evil" condition: $a }""")
    detector = YaraDetector(rules_dir=str(tmp_path), max_payload_bytes=1024)
    alerts = asyncio.run(detector.detect(None, [{"payload_text": "clean"}]))  # type: ignore[arg-type]
    assert alerts == []


def test_disabled_without_rules_dir(tmp_path) -> None:
    detector = YaraDetector(rules_dir=str(tmp_path / "nope"), max_payload_bytes=1024)
    assert detector.enabled() is False


def test_invalid_rule_reported_as_error(tmp_path) -> None:
    _write_rule(tmp_path, "bad.yar", r"""rule broken { condition: "literal" }""")
    detector = YaraDetector(rules_dir=str(tmp_path), max_payload_bytes=1024)
    assert detector.enabled() is False
    assert len(detector.rule_errors()) == 1


def test_invalid_payload_hex_skipped(tmp_path) -> None:
    _write_rule(tmp_path, "web.yar", r"""rule x { strings: $a = "evil" condition: $a }""")
    detector = YaraDetector(rules_dir=str(tmp_path), max_payload_bytes=1024)
    alerts = asyncio.run(detector.detect(None, [{"payload_hex": "not-hex!"}]))  # type: ignore[arg-type]
    assert alerts == []
