"""Normalization helpers shared by packet ingestion and capture (Phase 5-6)."""

from __future__ import annotations

from typing import Any

from app.schemas.packet import PacketCreate


def to_detection_record(packet: PacketCreate) -> dict[str, Any]:
    """Normalize a packet into a flat detection record."""
    return {
        "src_ip": packet.src_ip,
        "src_port": packet.src_port,
        "dst_ip": packet.dst_ip,
        "dst_port": packet.dst_port,
        "proto": packet.proto,
        "length": packet.length,
        "flags": packet.flags,
    }
