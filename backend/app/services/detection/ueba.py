"""UEBA detector: raises alerts for per-actor behavioral deviations (Phase 9).

Wraps the profile/score primitives in ``app.services.ueba`` (kept separate to
avoid a package import cycle) into a ``Detector`` that loads persisted actor
baselines and flags live batches that deviate beyond ``UEBA_THRESHOLD``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.constants import DETECTOR_UEBA
from app.schemas.alert import AlertCreate
from app.services.detection.base import Detector
from app.services.ueba import _group_by_actor, batch_statistics, score_batch

logger = logging.getLogger("sentinel.ueba")

try:
    from joblib import load as joblib_load
except ImportError:  # pragma: no cover
    joblib_load = None


class UebaDetector(Detector):
    """Flags actors whose live flow behavior deviates from their baseline."""

    name = DETECTOR_UEBA

    def __init__(self, profiles: dict[str, dict[str, Any]] | None = None) -> None:
        self._profiles: dict[str, dict[str, Any]] | None = profiles
        self._loaded = profiles is not None

    def _load_profiles(self) -> dict[str, dict[str, Any]] | None:
        if self._loaded:
            return self._profiles
        if not settings.UEBA_ENABLED:
            self._loaded = True
            return None
        if joblib_load is None:
            self._loaded = True
            return None
        path = Path(settings.UEBA_PROFILES_PATH)
        if not path.exists():
            logger.info("no UEBA profiles at %s; detector disabled", path)
            self._loaded = True
            return None
        try:
            loaded = joblib_load(path)
            self._profiles = loaded if isinstance(loaded, dict) else None
            logger.info("loaded UEBA profiles from %s", path)
        except Exception:
            logger.exception("failed to load UEBA profiles from %s", path)
            self._profiles = None
        self._loaded = True
        return self._profiles

    def enabled(self) -> bool:
        return self._load_profiles() is not None

    async def detect(self, _db: AsyncSession, records: list[dict[str, Any]]) -> list[AlertCreate]:
        profiles = self._load_profiles()
        if profiles is None:
            return []

        alerts: list[AlertCreate] = []
        for actor, group in _group_by_actor(records).items():
            profile = profiles.get(actor)
            if profile is None:
                continue
            stats = batch_statistics(group)
            score = score_batch(profile, stats)
            if score < settings.UEBA_THRESHOLD:
                continue
            risk_score = round(min(100.0, score * 25.0), 2)
            record = group[0]
            alerts.append(
                AlertCreate(
                    title="Behavioral profile deviation",
                    rule_id=None,
                    detector=self.name,
                    severity="medium",
                    category="ueba_anomaly",
                    src_ip=actor,
                    src_port=record.get("src_port"),
                    dst_ip=str(record.get("dst_ip", "")),
                    dst_port=record.get("dst_port"),
                    risk_score=risk_score,
                    details={
                        "actor": actor,
                        "deviation_score": round(score, 4),
                        "threshold": settings.UEBA_THRESHOLD,
                        "samples": stats["count"],
                        "baseline_samples": profile["samples"],
                        "mean_length": round(stats["mean_length"], 2),
                        "baseline_mean_length": round(profile["mean_length"], 2),
                        "novel_dst_ports": sorted(stats["dst_ports"] - profile["dst_ports"]),
                        "novel_dst_ips": sorted(stats["dst_ips"] - profile["dst_ips"]),
                    },
                )
            )
        return alerts
