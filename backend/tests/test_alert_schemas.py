"""Schema and constant tests for Phase 5 alerting (Phase 5)."""

from __future__ import annotations

import pytest
from app.core.constants import (
    ALERT_STATUSES,
    DETECTOR_ML,
    DETECTOR_SIGNATURE,
    IOC_TYPES,
    RULE_SEVERITIES,
)
from app.schemas.alert import AlertCreate, AlertStatusUpdate
from app.schemas.ioc import IOCBulkCreate, IOCCreate
from pydantic import ValidationError


class TestAlertSchemas:
    def test_alert_create_accepts_details(self) -> None:
        alert = AlertCreate(
            title="Scan",
            rule_id=3,
            detector=DETECTOR_SIGNATURE,
            severity="high",
            category="scan",
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            risk_score=75.0,
            details={"proto": "tcp"},
        )
        assert alert.status == "new"
        assert alert.details == {"proto": "tcp"}

    def test_alert_requires_core_fields(self) -> None:
        with pytest.raises(ValidationError):
            AlertCreate(severity="high", category="scan")

    def test_status_update_accepts_known_statuses(self) -> None:
        for status in ALERT_STATUSES:
            assert AlertStatusUpdate(status=status).status == status


class TestIOCSchemas:
    def test_ioc_create_bounds_confidence(self) -> None:
        with pytest.raises(ValidationError):
            IOCCreate(type="ipv4", value="1.2.3.4", confidence=1.5)
        assert IOCCreate(type="ipv4", value="1.2.3.4", confidence=0.9).confidence == 0.9

    def test_bulk_create_rejects_empty(self) -> None:
        with pytest.raises(ValidationError):
            IOCBulkCreate(items=[])

    def test_bulk_create_limits_size(self) -> None:
        items = [IOCCreate(type="ipv4", value=f"1.1.1.{i}", confidence=0.5) for i in range(501)]
        with pytest.raises(ValidationError):
            IOCBulkCreate(items=items)


class TestDetectionConstants:
    def test_detector_names(self) -> None:
        assert DETECTOR_SIGNATURE == "signature"
        assert DETECTOR_ML == "ml"

    def test_severity_and_ioc_types(self) -> None:
        assert "high" in RULE_SEVERITIES
        assert "ipv4" in IOC_TYPES
        assert "file_hash_sha256" in IOC_TYPES
