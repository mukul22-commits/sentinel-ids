"""Adapter factory: build a capture adapter set from a sensor config (Phase 8)."""

from __future__ import annotations

from typing import Any

from app.core.constants import (
    CAPTURE_ADAPTER_SNIFF,
    CAPTURE_ADAPTER_SURICATA,
    CAPTURE_ADAPTER_ZEEK,
)
from app.services.capture.base import CaptureAdapter
from app.services.capture.sniff import SniffCaptureAdapter
from app.services.capture.suricata_eve import SuricataEveAdapter
from app.services.capture.zeek_log import ZeekLogAdapter


def build_adapters(config: dict[str, Any] | None = None) -> list[CaptureAdapter]:
    """Instantiate adapters from a (sensor) config's ``adapters`` mapping.

    An adapter runs when its entry is absent, enabled, or lacks an ``enabled``
    key; ``enabled: false`` removes it. Per-adapter fields (interface, paths,
    counts) override the process-level settings so each sensor can capture from
    its own sources.
    """
    cfg = config or {}
    sniff_cfg = cfg.get(CAPTURE_ADAPTER_SNIFF) or {}
    suricata_cfg = cfg.get(CAPTURE_ADAPTER_SURICATA) or {}
    zeek_cfg = cfg.get(CAPTURE_ADAPTER_ZEEK) or {}

    adapters: list[CaptureAdapter] = []
    if sniff_cfg.get("enabled", True):
        adapters.append(
            SniffCaptureAdapter(
                interface=sniff_cfg.get("interface"),
                count=sniff_cfg.get("count"),
                timeout=sniff_cfg.get("timeout"),
            )
        )
    if suricata_cfg.get("enabled", True):
        adapters.append(SuricataEveAdapter(path=suricata_cfg.get("path")))
    if zeek_cfg.get("enabled", True):
        adapters.append(ZeekLogAdapter(path=zeek_cfg.get("path")))
    return adapters
