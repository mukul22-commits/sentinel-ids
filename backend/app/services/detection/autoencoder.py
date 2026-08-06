"""Autoencoder detector: reconstruction-error anomaly scoring (Phase 9).

A dense autoencoder is trained to reproduce the standardized flow feature
vector; flows that reconstruct poorly (high mean-squared error) are treated as
anomalous. The persisted artifact is a ``{"model", "scaler"}`` joblib dict and
the detector is disabled by default (``AUTOENCODER_DETECTOR_ENABLED``).
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.constants import DETECTOR_AUTOENCODER
from app.schemas.alert import AlertCreate
from app.services.detection.base import Detector
from app.services.detection.ml import flow_features

logger = logging.getLogger("sentinel.detection.autoencoder")

try:
    from joblib import dump as joblib_dump
    from joblib import load as joblib_load
except ImportError:  # pragma: no cover
    joblib_dump = None
    joblib_load = None


def reconstruction_error(pipeline: dict[str, Any], features: list[list[float]]) -> list[float]:
    """Per-row mean-squared reconstruction error on standardized features."""
    import numpy as np

    model = pipeline["model"]
    scaler = pipeline["scaler"]
    scaled = scaler.transform(features)
    predictions = np.asarray(model.predict(scaled))
    errors = ((predictions - scaled) ** 2).mean(axis=1)
    return [float(value) for value in errors]


def train_flow_autoencoder(
    flows: list[dict[str, Any]],
    *,
    hidden: tuple[int, ...] = (32, 8, 32),
    max_iter: int = 400,
    random_state: int = 42,
) -> dict[str, Any]:
    """Fit a StandardScaler + autoencoder (MLPRegressor) pipeline."""
    from sklearn.neural_network import MLPRegressor
    from sklearn.preprocessing import StandardScaler

    features = [flow_features(flow) for flow in flows]
    if not features:
        raise ValueError("no flows to train on")
    scaler = StandardScaler().fit(features)
    scaled = scaler.transform(features)
    model = MLPRegressor(
        hidden_layer_sizes=hidden,
        activation="relu",
        solver="adam",
        max_iter=max_iter,
        learning_rate_init=0.001,
        early_stopping=True,
        n_iter_no_change=20,
        random_state=random_state,
    )
    model.fit(scaled, scaled)
    return {"model": model, "scaler": scaler}


def save_autoencoder(model: Any, path: Path) -> Path:
    """Atomically persist the autoencoder model via temp file + rename."""
    if joblib_dump is None:
        raise RuntimeError("joblib is not installed")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    os.close(fd)
    try:
        joblib_dump(model, tmp_name)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return path


class AutoencoderDetector(Detector):
    """Flags flows whose reconstruction error exceeds the configured threshold."""

    name = DETECTOR_AUTOENCODER

    def __init__(self, pipeline: dict[str, Any] | None = None) -> None:
        self._pipeline: dict[str, Any] | None = pipeline
        self._loaded = pipeline is not None

    def _load_model(self) -> dict[str, Any] | None:
        if self._loaded:
            return self._pipeline
        if not settings.AUTOENCODER_DETECTOR_ENABLED:
            self._loaded = True
            return None
        if joblib_load is None:
            self._loaded = True
            return None
        path = Path(settings.ML_AE_MODEL_PATH)
        if not path.exists():
            logger.info("no autoencoder model at %s; detector disabled", path)
            self._loaded = True
            return None
        try:
            self._pipeline = joblib_load(path)
            logger.info("loaded autoencoder model from %s", path)
        except Exception:
            logger.exception("failed to load autoencoder model from %s", path)
            self._pipeline = None
        self._loaded = True
        return self._pipeline

    def enabled(self) -> bool:
        return self._load_model() is not None

    async def detect(self, _db: AsyncSession, records: list[dict[str, Any]]) -> list[AlertCreate]:
        pipeline = self._load_model()
        if pipeline is None:
            return []
        features = [flow_features(record) for record in records]
        if not features:
            return []

        errors = reconstruction_error(pipeline, features)
        threshold = settings.AUTOENCODER_THRESHOLD

        alerts: list[AlertCreate] = []
        for index, (record, error) in enumerate(zip(records, errors, strict=False)):
            if error <= threshold:
                continue
            risk_score = round(min(100.0, error * 25.0), 2)
            alerts.append(
                AlertCreate(
                    title="Autoencoder anomaly detected",
                    rule_id=None,
                    detector=self.name,
                    severity="medium",
                    category="flow_anomaly",
                    src_ip=str(record.get("src_ip", "")),
                    src_port=record.get("src_port"),
                    dst_ip=str(record.get("dst_ip", "")),
                    dst_port=record.get("dst_port"),
                    risk_score=risk_score,
                    details={
                        "proto": record.get("proto"),
                        "length": record.get("length"),
                        "flags": record.get("flags"),
                        "reconstruction_error": round(error, 6),
                        "threshold": threshold,
                        "features": features[index],
                    },
                )
            )
        return alerts
