"""YARA detector: scans record payloads with the subset rule engine (Phase 9).

Rules are plain ``.yar`` / ``.yara`` files in ``settings.YARA_RULES_DIR``.
Records carrying byte-ish payloads (``payload_text``, ``payload_hex``,
``payload_b64`` or raw ``payload`` bytes) are scanned against every loaded
rule; each rule that fires produces an alert with severity/category taken from
the rule ``meta`` (defaults: medium / ``yara``).
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.constants import DETECTOR_YARA
from app.schemas.alert import AlertCreate
from app.services.detection.base import Detector
from app.services.detection.yara_engine import YaraRule, YaraRuleError, parse_rules

logger = logging.getLogger("sentinel.detection.yara")

_SEVERITY_SCORES = {"low": 25.0, "medium": 50.0, "high": 75.0, "critical": 100.0}
_VALID_SEVERITIES = frozenset(_SEVERITY_SCORES)
_RULE_SUFFIXES = (".yar", ".yara")


def _payload_bytes(record: dict[str, Any], max_bytes: int) -> bytes | None:
    """Extract up to ``max_bytes`` of payload content from a record, if any."""
    payload = record.get("payload")
    if isinstance(payload, bytes):
        return payload[:max_bytes]
    if isinstance(payload, str):
        return payload.encode("utf-8", errors="replace")[:max_bytes]

    text = record.get("payload_text")
    if isinstance(text, str):
        return text.encode("utf-8", errors="replace")[:max_bytes]

    hex_value = record.get("payload_hex")
    if isinstance(hex_value, str):
        try:
            return bytes.fromhex(hex_value)[:max_bytes]
        except ValueError:
            return None

    b64 = record.get("payload_b64")
    if isinstance(b64, str):
        try:
            return base64.b64decode(b64)[:max_bytes]
        except ValueError:
            return None
    return None


class YaraDetector(Detector):
    """Detector that matches file-based YARA rules against record payloads."""

    name = DETECTOR_YARA

    def __init__(
        self,
        rules_dir: str | None = None,
        max_payload_bytes: int | None = None,
    ) -> None:
        self.rules_dir = Path(rules_dir or settings.YARA_RULES_DIR)
        self.max_payload_bytes = max_payload_bytes or settings.YARA_MAX_PAYLOAD_BYTES
        self._rules: list[tuple[str, YaraRule]] = []
        self._errors: list[tuple[str, str]] = []
        self._load_rules()

    def _load_rules(self) -> None:
        if not self.rules_dir.is_dir():
            logger.warning("YARA rules dir %s not found; detector disabled", self.rules_dir)
            return
        for path in sorted(self.rules_dir.rglob("*")):
            if not path.is_file() or not path.name.endswith(_RULE_SUFFIXES):
                continue
            try:
                rules = parse_rules(path.read_text(encoding="utf-8"))
            except (YaraRuleError, OSError, UnicodeDecodeError) as exc:
                self._errors.append((str(path), str(exc)))
                logger.warning("skipping YARA rule file %s: %s", path, exc)
                continue
            for rule in rules:
                self._rules.append((str(path), rule))
        logger.info("loaded %d YARA rule(s) from %s", len(self._rules), self.rules_dir)

    def enabled(self) -> bool:
        return settings.YARA_DETECTOR_ENABLED and bool(self._rules)

    def rules(self) -> list[tuple[str, str]]:
        """(source file, rule name) pairs for introspection/UI."""
        return [(path, rule.name) for path, rule in self._rules]

    def rule_errors(self) -> list[tuple[str, str]]:
        return list(self._errors)

    async def detect(self, _db: AsyncSession, records: list[dict[str, Any]]) -> list[AlertCreate]:
        alerts: list[AlertCreate] = []
        for record in records:
            data = _payload_bytes(record, self.max_payload_bytes)
            if data is None:
                continue
            for path, rule in self._rules:
                try:
                    matched = rule.matches(data)
                except YaraRuleError:
                    logger.exception("YARA rule %s failed to evaluate", rule.name)
                    continue
                if not matched:
                    continue
                severity = str(rule.meta.get("severity", "medium")).lower()
                if severity not in _VALID_SEVERITIES:
                    severity = "medium"
                category = str(rule.meta.get("category") or (rule.tags[0] if rule.tags else "yara"))
                alerts.append(
                    AlertCreate(
                        title=rule.name,
                        rule_id=None,
                        detector=self.name,
                        severity=severity,
                        category=category,
                        src_ip=str(record.get("src_ip", "")),
                        src_port=record.get("src_port"),
                        dst_ip=str(record.get("dst_ip", "")),
                        dst_port=record.get("dst_port"),
                        risk_score=_SEVERITY_SCORES.get(severity, 50.0),
                        details={
                            "rule": rule.name,
                            "rule_file": path,
                            "tags": rule.tags,
                            "proto": record.get("proto"),
                            "length": record.get("length"),
                            "payload_bytes": len(data),
                        },
                    )
                )
        return alerts
