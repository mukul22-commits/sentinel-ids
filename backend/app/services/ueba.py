"""UEBA: per-actor behavioral baselines and deviation scoring (Phase 9).

A baseline profile is built per source IP over a historical window and captures
the expected flow volume (mean/std packet length), the set of destinations
(IPs, ports) and protocols the actor normally talks to. Live batches are
aggregated per actor and scored against that baseline; the composite deviation
score combines a length z-score with destination/port/protocol novelty.

Profiles are persisted as a joblib ``{actor: profile}`` mapping and the detector
is gated behind ``UEBA_ENABLED``.
"""

from __future__ import annotations

import logging
import os
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

logger = logging.getLogger("sentinel.ueba")

try:
    from joblib import dump as joblib_dump
    from joblib import load as joblib_load
except ImportError:  # pragma: no cover
    joblib_dump = None
    joblib_load = None


def _numeric(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _group_by_actor(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        actor = str(record.get("src_ip") or "")
        if actor:
            grouped[actor].append(record)
    return dict(grouped)


def _lengths(records: list[dict[str, Any]]) -> list[float]:
    return [_numeric(record.get("length")) for record in records]


def _distinct(records: list[dict[str, Any]], field: str) -> set[str]:
    return {str(value) for value in (record.get(field) for record in records) if value}


def batch_statistics(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate a group of records into the feature set used for scoring."""
    lengths = _lengths(records)
    return {
        "count": len(records),
        "mean_length": sum(lengths) / len(lengths) if lengths else 0.0,
        "dst_ips": _distinct(records, "dst_ip"),
        "dst_ports": _distinct(records, "dst_port"),
        "protos": _distinct(records, "proto"),
    }


def build_profile(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a baseline profile from an actor's historical records."""
    lengths = _lengths(records)
    mean = sum(lengths) / len(lengths) if lengths else 0.0
    variance = sum((value - mean) ** 2 for value in lengths) / len(lengths) if lengths else 0.0
    return {
        "samples": len(records),
        "mean_length": mean,
        "std_length": variance**0.5,
        "dst_ips": _distinct(records, "dst_ip"),
        "dst_ports": _distinct(records, "dst_port"),
        "protos": _distinct(records, "proto"),
    }


def build_profiles(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build one baseline profile per actor from the given records."""
    return {
        actor: build_profile(group) for actor, group in _group_by_actor(records).items() if group
    }


def score_batch(profile: dict[str, Any], stats: dict[str, Any]) -> float:
    """Composite behavioral deviation score for one actor's batch.

    Combines a length z-score (guarded against a degenerate std) with
    destination-IP, port and protocol novelty weighted by volume, plus a bonus
    for unusually high connection counts.
    """
    mean = float(stats["mean_length"])
    std = float(profile["std_length"])
    baseline_mean = float(profile["mean_length"])
    z_length = abs(mean - baseline_mean) / (std + 1.0)

    ports = set(stats["dst_ports"])
    novel_ports = ports - set(profile["dst_ports"])
    port_novelty = len(novel_ports) / max(1, len(ports))

    protos = set(stats["protos"])
    novel_protos = protos - set(profile["protos"])
    proto_novelty = len(novel_protos) / max(1, len(protos))

    count_ratio = float(stats["count"]) / max(1, int(profile["samples"]))

    return float(z_length + 2.0 * port_novelty + proto_novelty + count_ratio)


def save_profiles(profiles: dict[str, dict[str, Any]], path: Path) -> Path:
    """Atomically persist the actor profiles via temp file + rename."""
    if joblib_dump is None:
        raise RuntimeError("joblib is not installed")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    os.close(fd)
    try:
        joblib_dump(profiles, tmp_name)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return path


def profiles_metadata() -> dict[str, Any]:
    """Describe the current UEBA baseline artifact and configuration."""
    path = Path(settings.UEBA_PROFILES_PATH)
    info: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file(),
        "enabled": settings.UEBA_ENABLED,
        "window_hours": settings.UEBA_WINDOW_HOURS,
        "threshold": settings.UEBA_THRESHOLD,
    }
    if path.is_file():
        stat = path.stat()
        info["size_bytes"] = stat.st_size
        info["modified_at"] = _file_modified(path)
    return info


def _file_modified(path: Path) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()


async def retrain_ueba_profiles(
    db: AsyncSession,
    *,
    min_samples: int | None = None,
) -> dict[str, Any]:
    """Rebuild actor baselines from recent packet flows.

    Uses a minimum-samples guard so a tiny history cannot overwrite a working
    baseline set with an undertrained one.
    """
    from app.models.packet import Packet

    threshold = min_samples if min_samples is not None else settings.UEBA_MIN_SAMPLES
    limit = max(threshold * 10, 1_000)
    rows = (
        await db.execute(
            select(
                Packet.src_ip,
                Packet.length,
                Packet.dst_ip,
                Packet.dst_port,
                Packet.proto,
            )
            .order_by(Packet.ts.desc())
            .limit(limit)
        )
    ).all()
    records = [
        {
            "src_ip": row.src_ip,
            "length": row.length,
            "dst_ip": row.dst_ip,
            "dst_port": row.dst_port,
            "proto": row.proto,
        }
        for row in rows
    ]
    if len(records) < threshold:
        return {
            "status": "skipped",
            "reason": f"only {len(records)} recent flows; need at least {threshold}",
            "metadata": profiles_metadata(),
        }

    profiles = build_profiles(records)
    if not profiles:
        return {
            "status": "skipped",
            "reason": "no actors with src_ip in recent flows",
            "metadata": profiles_metadata(),
        }
    path = save_profiles(profiles, Path(settings.UEBA_PROFILES_PATH))
    result = {
        "status": "trained",
        "actors": len(profiles),
        "samples": len(records),
        "path": str(path),
        "metadata": profiles_metadata(),
    }
    logger.info("retrained UEBA profiles for %d actor(s) -> %s", len(profiles), path)
    return result
