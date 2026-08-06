"""Packet capture: pcap parsing via Scapy (Phase 5)."""

from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import UTC, datetime

from app.schemas.packet import PacketCreate

try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.packet import Packet, Raw
    from scapy.utils import rdpcap
except ImportError:  # pragma: no cover - scapy is an optional runtime dep
    ICMP = None  # type: ignore[misc,assignment]
    IP = None  # type: ignore[misc,assignment]
    TCP = None  # type: ignore[misc,assignment]
    UDP = None  # type: ignore[misc,assignment]
    Raw = None  # type: ignore[misc,assignment]
    rdpcap = None  # type: ignore[assignment]


class CaptureUnavailableError(RuntimeError):
    """Raised when scapy is not installed."""


_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",  # microsecond, little-endian
    b"\xa1\xb2\xc3\xd4",  # microsecond, big-endian
    b"\x4d\x3c\xb2\xa1",  # nanosecond, little-endian
    b"\xa1\xb2\x3c\x4d",  # nanosecond, big-endian
}


class InvalidPcapError(ValueError):
    """Raised when input bytes are not a pcap capture file."""


def _protocol(packet: Packet) -> str:
    if TCP is not None and packet.haslayer(TCP):
        return "tcp"
    if UDP is not None and packet.haslayer(UDP):
        return "udp"
    if ICMP is not None and packet.haslayer(ICMP):
        return "icmp"
    return "other"


def _payload_hash(packet: Packet) -> str | None:
    if Raw is None or not packet.haslayer(Raw):
        return None
    raw = packet.getlayer(Raw)
    if raw is None:
        return None
    data = bytes(getattr(raw, "load", b""))
    if not data:
        return None
    return hashlib.sha256(data).hexdigest()


def _tcp_flags(packet: Packet) -> str | None:
    if TCP is None:
        return None
    tcp = packet.getlayer(TCP)
    if tcp is None:
        return None
    flags = getattr(tcp, "flags", None)
    return str(flags) if flags else None


def packet_to_record(packet: Packet, source_name: str | None = None) -> PacketCreate | None:
    """Normalize a Scapy packet into a ``PacketCreate`` record (IP only)."""
    ip = packet.getlayer(IP)
    if ip is None:
        return None
    src_ip = str(getattr(ip, "src", ""))
    dst_ip = str(getattr(ip, "dst", ""))
    src_port = dst_port = None
    if TCP is not None and packet.haslayer(TCP):
        tcp = packet.getlayer(TCP)
        src_port = int(getattr(tcp, "sport", 0)) or None
        dst_port = int(getattr(tcp, "dport", 0)) or None
    elif UDP is not None and packet.haslayer(UDP):
        udp = packet.getlayer(UDP)
        src_port = int(getattr(udp, "sport", 0)) or None
        dst_port = int(getattr(udp, "dport", 0)) or None

    packet_time = float(getattr(packet, "time", 0) or 0)
    return PacketCreate(
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=_protocol(packet),
        length=int(len(bytes(packet))),
        flags=_tcp_flags(packet),
        payload_hash=_payload_hash(packet),
        raw_ref=source_name,
        ts=datetime.fromtimestamp(packet_time, tz=UTC),
    )


def parse_pcap_bytes(data: bytes, source_name: str | None = None) -> list[PacketCreate]:
    """Parse a pcap byte stream into ``PacketCreate`` records."""
    if IP is None or rdpcap is None:
        raise CaptureUnavailableError("scapy is not installed (add it to requirements)")
    if len(data) < 24 or data[:4] not in _PCAP_MAGICS:
        raise InvalidPcapError("Not a valid pcap capture file (bad magic bytes)")

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        packets = rdpcap(tmp_path)
    finally:
        os.unlink(tmp_path)

    records: list[PacketCreate] = []
    for packet in packets:
        record = packet_to_record(packet, source_name=source_name)
        if record is not None:
            records.append(record)
    return records
