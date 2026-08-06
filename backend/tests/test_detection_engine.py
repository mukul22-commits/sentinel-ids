"""Unit tests for the detection engine: dedupe, ML features, ML detector (Phase 5)."""

from __future__ import annotations

from app.core.constants import DETECTOR_ML, DETECTOR_SIGNATURE
from app.schemas.alert import AlertCreate
from app.services.detection.engine import _dedupe
from app.services.detection.ml import MLDetector, flow_features
from sklearn.ensemble import IsolationForest


def _alert(**overrides: object) -> AlertCreate:
    defaults: dict[str, object] = {
        "rule_id": 1,
        "detector": DETECTOR_SIGNATURE,
        "severity": "medium",
        "category": "test",
        "src_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "risk_score": 50.0,
    }
    defaults.update(overrides)
    return AlertCreate(**defaults)


class TestDedupe:
    def test_exact_duplicate_collapsed(self) -> None:
        alerts = [_alert(rule_id=1), _alert(rule_id=1)]
        assert len(_dedupe(alerts)) == 1

    def test_different_rule_ids_kept(self) -> None:
        alerts = [_alert(rule_id=1), _alert(rule_id=2)]
        assert len(_dedupe(alerts)) == 2

    def test_different_detector_kept(self) -> None:
        alerts = [_alert(rule_id=1), _alert(rule_id=1, detector=DETECTOR_ML)]
        assert len(_dedupe(alerts)) == 2

    def test_different_destination_kept(self) -> None:
        alerts = [_alert(rule_id=1), _alert(rule_id=1, dst_ip="10.0.0.9")]
        assert len(_dedupe(alerts)) == 2


class TestFlowFeatures:
    def test_fixed_dimension(self) -> None:
        features = flow_features(
            {
                "length": 100,
                "src_port": 2000,
                "dst_port": 80,
                "proto": "tcp",
                "flags": "PA",
            }
        )
        assert len(features) == 5
        assert features[0] == 100.0
        assert features[1] == 2000.0
        assert features[2] == 80.0
        assert features[3] == 1.0
        assert features[4] == 2.0

    def test_missing_fields_default_to_zero(self) -> None:
        features = flow_features({"proto": "udp"})
        assert features == [0.0, 0.0, 0.0, 2.0, 0.0]


class TestMLDetector:
    def test_disabled_without_model(self) -> None:
        detector = MLDetector()
        assert detector.enabled() is False

    def test_detect_flags_anomalous_flow(self) -> None:
        normal = [
            flow_features(
                {
                    "length": 400 + (i % 20) * 10,
                    "src_port": 50000,
                    "dst_port": 443,
                    "proto": "tcp",
                    "flags": "PA",
                }
            )
            for i in range(300)
        ]
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=0).fit(normal)
        detector = MLDetector(model=model)
        assert detector.enabled() is True

        outlier = {
            "src_ip": "10.0.0.1",
            "src_port": 1,
            "dst_ip": "10.0.0.2",
            "dst_port": 23,
            "proto": "tcp",
            "flags": "S",
            "length": 3,
        }

        import asyncio

        alerts = asyncio.run(
            detector.detect(
                None,  # type: ignore[arg-type]
                [outlier],
            )
        )
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.detector == DETECTOR_ML
        assert alert.src_ip == "10.0.0.1"
        assert alert.risk_score >= 0.0
