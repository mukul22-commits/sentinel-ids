"""Train and serialize the flow autoencoder used by the autoencoder detector.

Generates a synthetic corpus of normal web-browsing flows plus anomalous flows,
fits a StandardScaler + dense autoencoder over the fixed-dimension feature
vector (see ``app/services/detection/ml.py::flow_features``), and persists the
``{"model", "scaler"}`` pipeline to ``settings.ML_AE_MODEL_PATH`` via joblib.

Run from the backend directory:
    .venv\\Scripts\\python.exe scripts/train_autoencoder.py
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings
from app.services.detection.autoencoder import (
    reconstruction_error,
    save_autoencoder,
    train_flow_autoencoder,
)
from app.services.detection.ml import flow_features

SEED = 42
N_SAMPLES = 2_000
NORMAL_PORTS = {80, 443, 8080, 53, 22, 123}
ANOMALOUS_PORTS = {3389, 445, 139, 23, 21, 2323, 6667, 4444}


def _normal_flow(i: int) -> dict:
    rng = random.Random(SEED + i)
    return {
        "length": rng.randint(60, 1400),
        "src_port": rng.randint(1024, 65535),
        "dst_port": rng.choice(list(NORMAL_PORTS)),
        "proto": "tcp",
        "flags": "PA",
    }


def _anomalous_flow(i: int) -> dict:
    rng = random.Random(SEED + 10_000 + i)
    return {
        "length": rng.choice([rng.randint(0, 30), rng.randint(4000, 12000)]),
        "src_port": rng.randint(1, 1024),
        "dst_port": rng.choice(list(ANOMALOUS_PORTS)),
        "proto": "tcp",
        "flags": "S" if i % 2 else "A",
    }


def main() -> None:
    flows = [_normal_flow(i) for i in range(N_SAMPLES)]
    flows += [_anomalous_flow(i) for i in range(N_SAMPLES)]

    pipeline = train_flow_autoencoder(flows)
    path = save_autoencoder(pipeline, Path(settings.ML_AE_MODEL_PATH))

    sample = [flow_features(flow) for flow in flows[:200]]
    errors = reconstruction_error(pipeline, sample)
    print(f"trained autoencoder on {len(flows)} flows")
    print(f"saved pipeline to {path}")
    print(f"mean reconstruction error on training sample: {sum(errors) / len(errors):.3f}")


if __name__ == "__main__":
    main()
