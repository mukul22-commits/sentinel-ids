"""Tests for the autoencoder detector: training, loading, anomaly detection."""

from __future__ import annotations

import asyncio

from app.core.constants import DETECTOR_AUTOENCODER
from app.services.detection.autoencoder import (
    AutoencoderDetector,
    reconstruction_error,
    train_flow_autoencoder,
)


def _normal_flows(n: int) -> list[dict[str, object]]:
    return [
        {
            "length": 400 + (i % 20) * 10,
            "src_port": 50000,
            "dst_port": 443,
            "proto": "tcp",
            "flags": "PA",
        }
        for i in range(n)
    ]


def test_train_and_reconstruct_normals() -> None:
    from app.services.detection.ml import flow_features

    flows = _normal_flows(200)
    pipeline = train_flow_autoencoder(flows, hidden=(16, 4, 16), max_iter=200)
    errors = reconstruction_error(pipeline, [flow_features(flow) for flow in flows])
    assert len(errors) == 200
    assert all(0.0 <= error < 5.0 for error in errors)


def test_detector_flags_outlier(tmp_path) -> None:
    from app.services.detection.autoencoder import save_autoencoder

    pipeline = train_flow_autoencoder(_normal_flows(200), hidden=(16, 4, 16), max_iter=200)
    path = save_autoencoder(pipeline, tmp_path / "ae.joblib")

    detector = AutoencoderDetector(pipeline=pipeline)
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
    alerts = asyncio.run(detector.detect(None, [outlier]))  # type: ignore[arg-type]
    assert len(alerts) == 1
    assert alerts[0].detector == DETECTOR_AUTOENCODER
    assert alerts[0].src_ip == "10.0.0.1"
    assert "reconstruction_error" in alerts[0].details

    assert path.exists()


def test_disabled_when_flag_off(monkeypatch) -> None:
    from app.core import config

    monkeypatch.setattr(config.settings, "AUTOENCODER_DETECTOR_ENABLED", False)
    detector = AutoencoderDetector()
    assert detector.enabled() is False
