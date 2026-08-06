"""ML retraining pipeline: retrain the flow anomaly detector from packet history.

Phase 6 extends the Phase 5 training script with a service that fits an
IsolationForest over recently captured flows from the ``packets`` hypertable
and atomically swaps the serialized model so inference never reads a partial
file.
"""

from __future__ import annotations

import logging
import os
import random
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.services.detection.autoencoder import save_autoencoder, train_flow_autoencoder
from app.services.detection.ml import flow_features

logger = logging.getLogger("sentinel.detection.retrain")

_SEED = 42
_NORMAL_PORTS = {80, 443, 8080, 53, 22, 123}
_ANOMALOUS_PORTS = {3389, 445, 139, 23, 21, 2323, 6667, 4444}


def synthetic_flows(normal: int = 2_000, anomalous: int = 2_000) -> list[dict[str, Any]]:
    """Generate a labeled synthetic corpus (normal browsing + anomalous flows)."""
    flows: list[dict[str, Any]] = []
    for i in range(normal):
        rng = random.Random(_SEED + i)
        flows.append(
            {
                "length": rng.randint(60, 1400),
                "src_port": rng.randint(1024, 65535),
                "dst_port": rng.choice(list(_NORMAL_PORTS)),
                "proto": "tcp",
                "flags": "PA",
            }
        )
    for i in range(anomalous):
        rng = random.Random(_SEED + 10_000 + i)
        flows.append(
            {
                "length": rng.choice([rng.randint(0, 30), rng.randint(4000, 12000)]),
                "src_port": rng.randint(1, 1024),
                "dst_port": rng.choice(list(_ANOMALOUS_PORTS)),
                "proto": "tcp",
                "flags": "S" if i % 2 else "A",
            }
        )
    return flows


def train_model_from_flows(
    flows: list[dict[str, Any]],
    *,
    n_estimators: int = 200,
    contamination: float = 0.1,
    random_state: int = _SEED,
) -> Any:
    """Fit an IsolationForest over the fixed-dimension flow feature vector."""
    from sklearn.ensemble import IsolationForest

    features = [flow_features(flow) for flow in flows]
    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples="auto",
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(features)
    return model


def save_model(model: Any, path: Path) -> Path:
    """Atomically serialize ``model`` to ``path`` via temp file + rename."""
    from joblib import dump

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    os.close(fd)
    try:
        dump(model, tmp_name)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return path


def model_metadata() -> dict[str, Any]:
    """Describe the current ML model artifact and retraining configuration."""
    path = Path(settings.ML_MODEL_PATH)
    info: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file(),
        "enabled": settings.ML_DETECTOR_ENABLED,
        "min_samples": settings.ML_RETRAIN_MIN_SAMPLES,
        "contamination": settings.ML_RETRAIN_CONTAMINATION,
    }
    if path.is_file():
        stat = path.stat()
        info["size_bytes"] = stat.st_size
        info["modified_at"] = datetime.fromtimestamp(stat.st_mtime, tz=UTC)
    return info


async def _fetch_recent_flows(db: AsyncSession, limit: int) -> list[dict[str, Any]]:
    from app.models.packet import Packet

    rows = (
        await db.execute(
            select(
                Packet.length,
                Packet.src_port,
                Packet.dst_port,
                Packet.proto,
                Packet.flags,
            )
            .order_by(Packet.ts.desc())
            .limit(limit)
        )
    ).all()
    return [
        {
            "length": row.length,
            "src_port": row.src_port,
            "dst_port": row.dst_port,
            "proto": row.proto,
            "flags": row.flags,
        }
        for row in rows
    ]


async def retrain_ml_model(
    db: AsyncSession,
    *,
    min_samples: int | None = None,
    contamination: float | None = None,
) -> dict[str, Any]:
    """Retrain the anomaly detector from recent packet flows.

    Returns ``{"status": "trained", ...}`` when at least ``min_samples`` flows
    exist, otherwise ``{"status": "skipped", ...}`` so the pipeline never
    overwrites a working model with a synthetic one.
    """
    threshold = min_samples if min_samples is not None else settings.ML_RETRAIN_MIN_SAMPLES
    contamination = (
        contamination if contamination is not None else settings.ML_RETRAIN_CONTAMINATION
    )
    limit = max(threshold * 10, 1_000)
    flows = await _fetch_recent_flows(db, limit)
    if len(flows) < threshold:
        return {
            "status": "skipped",
            "reason": f"only {len(flows)} recent flows; need at least {threshold}",
            "metadata": model_metadata(),
        }

    model = train_model_from_flows(flows, contamination=contamination)
    path = save_model(model, Path(settings.ML_MODEL_PATH))
    predicted = model.predict([flow_features(flow) for flow in flows])
    anomaly_rate = sum(1 for label in predicted if int(label) == -1) / len(flows)
    result = {
        "status": "trained",
        "samples": len(flows),
        "path": str(path),
        "anomaly_rate": round(float(anomaly_rate), 4),
        "metadata": model_metadata(),
    }
    logger.info("retrained ML model on %d flows -> %s", len(flows), path)
    return result


def autoencoder_metadata() -> dict[str, Any]:
    """Describe the current autoencoder artifact and configuration."""
    path = Path(settings.ML_AE_MODEL_PATH)
    info: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file(),
        "enabled": settings.AUTOENCODER_DETECTOR_ENABLED,
        "threshold": settings.AUTOENCODER_THRESHOLD,
    }
    if path.is_file():
        stat = path.stat()
        info["size_bytes"] = stat.st_size
        info["modified_at"] = datetime.fromtimestamp(stat.st_mtime, tz=UTC)
    return info


async def retrain_autoencoder_model(
    db: AsyncSession,
    *,
    min_samples: int | None = None,
) -> dict[str, Any]:
    """Fit the flow autoencoder from recent packet flows.

    Uses the same minimum-samples guard as the isolation-forest retraining so a
    small corpus can never overwrite a working model with an undertrained one.
    """
    threshold = min_samples if min_samples is not None else settings.ML_RETRAIN_MIN_SAMPLES
    limit = max(threshold * 10, 1_000)
    flows = await _fetch_recent_flows(db, limit)
    if len(flows) < threshold:
        return {
            "status": "skipped",
            "reason": f"only {len(flows)} recent flows; need at least {threshold}",
            "metadata": autoencoder_metadata(),
        }

    model = train_flow_autoencoder(flows)
    path = save_autoencoder(model, Path(settings.ML_AE_MODEL_PATH))
    from app.services.detection.autoencoder import reconstruction_error

    errors = reconstruction_error(model, [flow_features(flow) for flow in flows])
    anomaly_rate = sum(1 for error in errors if error > settings.AUTOENCODER_THRESHOLD) / len(flows)
    result = {
        "status": "trained",
        "samples": len(flows),
        "path": str(path),
        "anomaly_rate": round(float(anomaly_rate), 4),
        "mean_reconstruction_error": round(float(sum(errors) / len(errors)), 6),
        "metadata": autoencoder_metadata(),
    }
    logger.info("retrained autoencoder on %d flows -> %s", len(flows), path)
    return result
