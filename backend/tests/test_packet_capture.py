"""Unit tests for pcap parsing via Scapy (Phase 5)."""

from __future__ import annotations

import os
import tempfile

import pytest
from app.services.packet_capture import InvalidPcapError, parse_pcap_bytes
from scapy.all import IP, TCP, UDP, wrpcap


def _pcap_bytes(*packets: object) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        wrpcap(tmp.name, list(packets))
        tmp.flush()
        tmp.seek(0)
        data = tmp.read()
    os.unlink(tmp.name)
    return data


class TestParsePcapBytes:
    def test_parses_tcp_packet(self) -> None:
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")
        records = parse_pcap_bytes(_pcap_bytes(packet), source_name="capture.pcap")
        assert len(records) == 1
        record = records[0]
        assert record.src_ip == "10.0.0.1"
        assert record.dst_ip == "10.0.0.2"
        assert record.src_port == 12345
        assert record.dst_port == 80
        assert record.proto == "tcp"
        assert record.flags == "S"
        assert record.raw_ref == "capture.pcap"
        assert record.ts is not None

    def test_parses_udp_packet(self) -> None:
        packet = IP(src="192.168.1.10", dst="192.168.1.255") / UDP(sport=5353, dport=5353)
        records = parse_pcap_bytes(_pcap_bytes(packet))
        assert len(records) == 1
        assert records[0].proto == "udp"
        assert records[0].dst_port == 5353

    def test_empty_pcap_yields_no_records(self) -> None:
        records = parse_pcap_bytes(_pcap_bytes())
        assert records == []

    def test_garbage_bytes_raise(self) -> None:
        with pytest.raises(InvalidPcapError):
            parse_pcap_bytes(b"\x00\x01\x02not-a-pcap")
