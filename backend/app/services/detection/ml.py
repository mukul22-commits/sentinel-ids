"""ML detector: sklearn anomaly detection over normalized flow features (Phase 5).

The detector loads a serialized IsolationForest model (see
``scripts/train_ml_detector.py``). It is disabled until a model exists and
``ML_DETECTOR_ENABLED`` is true, keeping tests hermetic.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.constants import DETECTOR_ML
from app.schemas.alert import AlertCreate
from app.services.detection.base import Detector

logger = logging.getLogger("sentinel.detection.ml")

try:
    from joblib import load as joblib_load
except ImportError:  # pragma: no cover
    joblib_load = None

_PROTO_CODES = {"tcp": 1.0, "udp": 2.0, "icmp": 3.0}


def flow_features(record: dict[str, Any]) -> list[float]:
    """Fixed-dimension feature vector shared by training and inference."""
    flags = record.get("flags")
    flag_count = float(len(flags)) if isinstance(flags, str) else 0.0
    return [
        float(record.get("length", 0) or 0),
        float(record.get("src_port", 0) or 0),
        float(record.get("dst_port", 0) or 0),
        _PROTO_CODES.get(str(record.get("proto", "")).lower(), 0.0),
        flag_count,
    ]


class MLDetector(Detector):
    """Anomaly detector powered by an unsupervised sklearn model."""

    name = DETECTOR_ML

    def __init__(self, model: Any | None = None) -> None:
        self._model: Any | None = model
        self._loaded = model is not None

    def _load_model(self) -> Any | None:
        if self._loaded or not settings.ML_DETECTOR_ENABLED:
            return self._model
        if joblib_load is None:
            return None
        path = Path(settings.ML_MODEL_PATH)
        if not path.exists():
            logger.info("no ML model at %s; ML detector disabled", path)
            self._loaded = True
            return None
        try:
            self._model = joblib_load(path)
            logger.info("loaded ML model from %s", path)
        except Exception:
            logger.exception("failed to load ML model from %s", path)
            self._model = None
        self._loaded = True
        return self._model

    def enabled(self) -> bool:
        return self._load_model() is not None

    async def detect(self, _db: AsyncSession, records: list[dict[str, Any]]) -> list[AlertCreate]:
        model = self._load_model()
        if model is None:
            return []
        features = [flow_features(record) for record in records]
        if not features:
            return []

        predictions = model.predict(features)
        decision = model.decision_function(features)

        alerts: list[AlertCreate] = []
        for record, label, score in zip(records, predictions, decision, strict=False):
            if int(label) != -1:
                continue
            score_value = -float(score)
            risk_score = round(min(100.0, max(0.0, score_value * 100.0)), 2)
            alerts.append(
                AlertCreate(
                    title="Behavioral anomaly detected",
                    rule_id=None,
                    detector=self.name,
                    severity="medium",
                    category="behavioral_anomaly",
                    src_ip=str(record.get("src_ip", "")),
                    src_port=record.get("src_port"),
                    dst_ip=str(record.get("dst_ip", "")),
                    dst_port=record.get("dst_port"),
                    risk_score=risk_score,
                    details={
                        "proto": record.get("proto"),
                        "length": record.get("length"),
                        "flags": record.get("flags"),
                        "anomaly_score": round(score_value, 6),
                        "features": flow_features(record),
                    },
                )
            )
        return alerts
