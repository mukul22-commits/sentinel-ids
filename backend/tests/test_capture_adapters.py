"""Unit tests for live capture adapters and the capture manager (Phase 6)."""

from __future__ import annotations

import asyncio
import json

from app.schemas.packet import PacketCreate
from app.services.capture.base import CaptureAdapter
from app.services.capture.manager import CaptureManager
from app.services.capture.sniff import SniffCaptureAdapter
from app.services.capture.suricata_eve import SuricataEveAdapter
from app.services.capture.zeek_log import ZeekLogAdapter


class TestZeekLogAdapter:
    def test_parse_conn_log(self, tmp_path) -> None:
        log = tmp_path / "conn.log"
        log.write_text(
            "#separator \\x09\n"
            "#set_separator\t,\n"
            "#empty_field\t(empty)\n"
            "#unset_field\t-\n"
            "#path\tconn\n"
            "#open\t2026-01-01-00-00-00\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\t"
            "orig_bytes\tresp_bytes\n"
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tcount\tcount\n"
            "1735689600.123456\tC1\t192.168.1.5\t49152\t10.0.0.1\t443\ttcp\tssl\t1200\t800\n"
            "1735689601.000000\tC2\t192.168.1.5\t-\t10.0.0.1\t-\tudp\t-\t0\t0\n"
        )
        adapter = ZeekLogAdapter(path=str(log))
        assert adapter.enabled() is True
        records = asyncio.run(adapter.collect())
        assert len(records) == 2

        first = records[0]
        assert first.src_ip == "192.168.1.5"
        assert first.src_port == 49152
        assert first.dst_ip == "10.0.0.1"
        assert first.dst_port == 443
        assert first.proto == "tcp"
        assert first.length == 2000
        assert first.ts is not None

        second = records[1]
        assert second.src_port is None
        assert second.dst_port is None
        assert second.proto == "udp"

    def test_disabled_when_file_missing(self) -> None:
        adapter = ZeekLogAdapter(path="C:/nope/conn.log")
        assert adapter.enabled() is False


class TestSuricataEveAdapter:
    def test_parse_eve_flow(self, tmp_path) -> None:
        eve = tmp_path / "eve.json"
        events = [
            {
                "timestamp": "2026-01-01T00:00:00.000000+0000",
                "event_type": "flow",
                "src_ip": "203.0.113.9",
                "src_port": 31337,
                "dest_ip": "10.0.0.2",
                "dest_port": 4444,
                "proto": "TCP",
                "flow": {"bytes_toclient": 500, "bytes_toserver": 1200},
            },
            {"event_type": "stats", "uptime": 42},
        ]
        eve.write_text("\n".join(json.dumps(event) for event in events) + "\n")
        adapter = SuricataEveAdapter(path=str(eve))
        assert adapter.enabled() is True
        records = asyncio.run(adapter.collect())
        assert len(records) == 1

        record = records[0]
        assert record.src_ip == "203.0.113.9"
        assert record.src_port == 31337
        assert record.dst_ip == "10.0.0.2"
        assert record.dst_port == 4444
        assert record.proto == "tcp"
        assert record.length == 1700

    def test_reads_directory_of_eve_files(self, tmp_path) -> None:
        for name in ("a.json", "b.json"):
            (tmp_path / name).write_text(
                json.dumps(
                    {
                        "timestamp": "2026-01-01T00:00:00.000000+0000",
                        "event_type": "flow",
                        "src_ip": "1.1.1.1",
                        "src_port": 80,
                        "dest_ip": "2.2.2.2",
                        "dest_port": 443,
                        "proto": "TCP",
                    }
                )
                + "\n"
            )
        adapter = SuricataEveAdapter(path=str(tmp_path))
        records = asyncio.run(adapter.collect())
        assert len(records) == 2


class TestSniffCaptureAdapter:
    def test_disabled_without_interface(self) -> None:
        adapter = SniffCaptureAdapter(interface=None)
        assert adapter.enabled() is False

    def test_disabled_when_capture_turned_off(self, monkeypatch) -> None:
        from app.core.config import settings

        monkeypatch.setattr(settings, "CAPTURE_ENABLED", False)
        adapter = SniffCaptureAdapter(interface="eth0")
        assert adapter.enabled() is False


class _FakeAdapter(CaptureAdapter):
    def __init__(self, name: str, enabled: bool) -> None:
        self.name = name
        self._enabled = enabled

    def enabled(self) -> bool:
        return self._enabled

    async def collect(self) -> list[PacketCreate]:
        return []


class TestCaptureManager:
    def test_enabled_adapters_filters(self) -> None:
        manager = CaptureManager(
            adapters=[
                _FakeAdapter("on_a", True),
                _FakeAdapter("off", False),
                _FakeAdapter("on_b", True),
            ]
        )
        names = [adapter.name for adapter in manager.enabled_adapters()]
        assert names == ["on_a", "on_b"]

    def test_adapter_status(self) -> None:
        manager = CaptureManager(adapters=[_FakeAdapter("on", True), _FakeAdapter("off", False)])
        status = manager.adapter_status()
        assert status == [{"name": "on", "enabled": True}, {"name": "off", "enabled": False}]

    def test_default_manager_exposes_known_adapters(self) -> None:
        names = {adapter.name for adapter in CaptureManager().adapters}
        assert names == {"scapy_sniff", "suricata_eve", "zeek_conn"}
