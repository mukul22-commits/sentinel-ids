"""Train and serialize the flow anomaly detector used by the ML detector.

Generates a labeled synthetic corpus of normal web-browsing flows and
anomalous flows (port scans, data exfiltration), fits an unsupervised
IsolationForest over the fixed-dimension feature vector (see
``app/services/detection/ml.py::flow_features``), and persists it to
``settings.ML_MODEL_PATH`` via joblib.

Run from the backend directory:
    .venv\\Scripts\\python.exe scripts/train_ml_detector.py
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from joblib import dump
from sklearn.ensemble import IsolationForest

from app.core.config import settings
from app.services.detection.ml import flow_features

SEED = 42
N_SAMPLES = 2_000
NORMAL_SEED_PORTS = {80, 443, 8080, 53}
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
    features = [flow_features(flow) for flow in flows]

    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=0.1,
        random_state=SEED,
    )
    model.fit(features)

    path = Path(settings.ML_MODEL_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    dump(model, path)

    print(f"trained IsolationForest on {len(features)} flows")
    print(f"saved model to {path}")

    expected_anomalies = sum(1 for i in range(N_SAMPLES) if int(model.predict([features[i]])[0]) == -1)
    print(f"contamination rate on training set: {expected_anomalies / len(features):.3f}")


if __name__ == "__main__":
    main()
