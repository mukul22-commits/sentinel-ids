"""Build and persist synthetic UEBA actor baselines.

Generates a corpus of "normal" per-actor flows and persists the resulting
profiles to ``settings.UEBA_PROFILES_PATH`` so the UEBA detector has a baseline
to score against in environments with no live packet history.

Run from the backend directory:
    .venv\\Scripts\\python.exe scripts/train_ueba.py
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings
from app.services.ueba import build_profiles, save_profiles

SEED = 42
ACTORS = 20
FLOWS_PER_ACTOR = 200
TARGET_PORTS = {80, 443, 8080, 53, 22, 123}


def _actor_flows(seed: int) -> list[dict]:
    rng = random.Random(seed)
    targets = rng.sample(list(TARGET_PORTS), k=3)
    host = f"10.1.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    flows = []
    for _ in range(FLOWS_PER_ACTOR):
        flows.append(
            {
                "src_ip": f"10.0.{rng.randint(0, 15)}.{rng.randint(2, 254)}",
                "dst_ip": host,
                "dst_port": rng.choice(targets),
                "proto": "tcp",
                "length": rng.randint(60, 1400),
            }
        )
    return flows


def main() -> None:
    records = [flow for i in range(ACTORS) for flow in _actor_flows(SEED + i)]
    profiles = build_profiles(records)
    path = save_profiles(profiles, Path(settings.UEBA_PROFILES_PATH))

    print(f"built profiles for {len(profiles)} actors from {len(records)} flows")
    print(f"saved baselines to {path}")


if __name__ == "__main__":
    main()
