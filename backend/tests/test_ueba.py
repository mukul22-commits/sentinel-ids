"""Tests for UEBA: profile building, scoring, detector behavior."""

from __future__ import annotations

import asyncio

from app.core.constants import DETECTOR_UEBA
from app.services.detection.ueba import UebaDetector
from app.services.ueba import (
    batch_statistics,
    build_profile,
    build_profiles,
    save_profiles,
    score_batch,
)


def _flow(src: str, dst: str, port: int, length: int, proto: str = "tcp") -> dict[str, object]:
    return {
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "src_port": 50000,
        "proto": proto,
        "length": length,
    }


def _normal_flow(i: int, actor: str = "10.0.0.1") -> dict[str, object]:
    return _flow(actor, "10.0.1.5", 443, 400 + (i % 20) * 10)


def _baseline_profile() -> dict[str, object]:
    return build_profile([_normal_flow(i) for i in range(200)])


class TestProfiles:
    def test_build_profile_stats(self) -> None:
        profile = build_profile([_flow("a", "b", 443, 100), _flow("a", "c", 80, 200)])
        assert profile["samples"] == 2
        assert profile["mean_length"] == 150.0
        assert profile["std_length"] > 0
        assert profile["dst_ports"] == {"443", "80"}
        assert profile["protos"] == {"tcp"}

    def test_build_profiles_groups_by_actor(self) -> None:
        profiles = build_profiles([_normal_flow(1), _normal_flow(2, actor="10.0.0.9")])
        assert set(profiles) == {"10.0.0.1", "10.0.0.9"}

    def test_save_profiles_roundtrip(self, tmp_path) -> None:
        profiles = {"10.0.0.1": _baseline_profile()}
        path = save_profiles(profiles, tmp_path / "baselines.joblib")
        assert path.exists()
        from joblib import load

        assert load(path) == profiles

    def test_batch_statistics(self) -> None:
        stats = batch_statistics(
            [
                _flow("a", "b", 443, 100),
                _flow("a", "c", 80, 200),
                _flow("a", "b", 443, 300),
            ]
        )
        assert stats["count"] == 3
        assert stats["mean_length"] == 200.0
        assert stats["dst_ips"] == {"b", "c"}
        assert stats["dst_ports"] == {"443", "80"}


class TestScoring:
    def test_normal_batch_scores_low(self) -> None:
        profile = _baseline_profile()
        stats = batch_statistics([_normal_flow(i) for i in range(10)])
        assert score_batch(profile, stats) < 1.0

    def test_volume_surge_scores_high(self) -> None:
        profile = _baseline_profile()
        stats = batch_statistics([_normal_flow(i) for i in range(300)])
        assert score_batch(profile, stats) >= 1.0

    def test_novel_destinations_score_high(self) -> None:
        profile = _baseline_profile()
        stats = batch_statistics(
            [
                _flow("10.0.0.1", "10.9.9.9", 445, 500),
                _flow("10.0.0.1", "10.8.8.8", 23, 700),
            ]
        )
        assert score_batch(profile, stats) >= 2.0


class TestUebaDetector:
    def test_disabled_without_profiles(self) -> None:
        detector = UebaDetector()
        assert detector.enabled() is False

    def test_flags_deviation(self) -> None:
        profiles = {"10.0.0.1": _baseline_profile()}
        detector = UebaDetector(profiles=profiles)
        assert detector.enabled() is True

        records = [
            _flow("10.0.0.1", "10.9.9.9", 445, 7000),
            _flow("10.0.0.1", "10.8.8.8", 23, 9000),
        ]
        alerts = asyncio.run(detector.detect(None, records))  # type: ignore[arg-type]
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.detector == DETECTOR_UEBA
        assert alert.src_ip == "10.0.0.1"
        assert alert.category == "ueba_anomaly"
        assert alert.details["actor"] == "10.0.0.1"

    def test_no_alert_for_normal_traffic(self) -> None:
        profiles = {"10.0.0.1": _baseline_profile()}
        detector = UebaDetector(profiles=profiles)
        records = [_normal_flow(i) for i in range(5)]
        alerts = asyncio.run(detector.detect(None, records))  # type: ignore[arg-type]
        assert alerts == []

    def test_unknown_actor_skipped(self) -> None:
        profiles = {"10.0.0.1": _baseline_profile()}
        detector = UebaDetector(profiles=profiles)
        records = [_flow("10.0.0.99", "10.9.9.9", 445, 9999)]
        alerts = asyncio.run(detector.detect(None, records))  # type: ignore[arg-type]
        assert alerts == []

    def test_loaded_from_disk(self, tmp_path, monkeypatch) -> None:
        from app.core import config

        profiles = {"10.0.0.1": _baseline_profile()}
        path = save_profiles(profiles, tmp_path / "baselines.joblib")
        monkeypatch.setattr(config.settings, "UEBA_PROFILES_PATH", str(path))
        monkeypatch.setattr(config.settings, "UEBA_ENABLED", True)
        detector = UebaDetector()
        assert detector.enabled() is True
