"""End-to-end tests for the management route groups (alerts, packets, captures,
incidents, policies, notifications, sensors, users, iocs, rules, siem).

These exercise the full request -> route -> DB -> response pipeline against an
in-memory SQLite database (JSONB columns adapted in ``conftest``).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from app.api.v1.endpoints import captures as captures_mod
from app.core.config import settings
from app.core.token_store import token_store
from app.models.capture_run import CaptureRun
from app.models.user import User
from sqlalchemy import select

PASSWORD = "Str0ng!Passw0rd"
API = "/api/v1"

_ip_counter = 0


def _ip() -> str:
    global _ip_counter
    _ip_counter += 1
    return f"10.8.{_ip_counter // 250}.{_ip_counter % 250}"


def _headers() -> dict[str, str]:
    return {"X-Forwarded-For": _ip()}


def _register(client: Any, email: str, username: str) -> Any:
    return client.post(
        f"{API}/auth/register",
        json={"email": email, "username": username, "password": PASSWORD},
        headers=_headers(),
    )


def _login(client: Any, identifier: str) -> Any:
    return client.post(
        f"{API}/auth/login",
        json={"identifier": identifier, "password": PASSWORD},
        headers=_headers(),
    )


def _tokens(client: Any, identifier: str) -> dict[str, Any]:
    return _login(client, identifier).json()["data"]


async def _set_role(db_factory: Any, email: str, role: str) -> None:
    async with db_factory() as session:
        user = await session.scalar(select(User).where(User.email == email))
        assert user is not None
        user.role = role
        await session.commit()


def _register_admin(client: Any, db_factory: Any, email: str, username: str) -> dict[str, Any]:
    _register(client, email, username)
    asyncio.run(_set_role(db_factory, email, "admin"))
    return _tokens(client, email)


async def _register_admin_async(
    client: Any, db_factory: Any, email: str, username: str
) -> dict[str, Any]:
    _register(client, email, username)
    await _set_role(db_factory, email, "admin")
    return _tokens(client, email)


def _auth(tokens: dict[str, Any]) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _uuid() -> str:
    return uuid.uuid4().hex


@pytest.fixture(autouse=True)
async def _clean_token_store() -> None:
    await token_store.reset()


class TestAlerts:
    def test_create_list_get_patch_status(
        self, sqlite_app_client: Any, sqlite_db_factory: Any
    ) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"alerts.{_uuid()}@example.com", "alertsadmin"
        )
        headers = _auth(admin)

        created = sqlite_app_client.post(
            f"{API}/alerts",
            json=[
                {
                    "title": "Port scan",
                    "severity": "high",
                    "category": "scan",
                    "src_ip": "10.0.0.5",
                    "src_port": 5555,
                    "dst_ip": "10.0.0.9",
                    "dst_port": 22,
                    "risk_score": 75.0,
                    "detector": "signature",
                    "rule_id": 1,
                }
            ],
            headers=headers,
        )
        assert created.status_code == 200
        alert = created.json()["data"]["items"][0]
        assert alert["severity"] == "high"

        listed = sqlite_app_client.get(
            f"{API}/alerts?severity=high&status=new&src_ip=10.0.0.5", headers=headers
        )
        assert listed.status_code == 200
        assert listed.json()["data"]["total"] == 1

        invalid = sqlite_app_client.get(f"{API}/alerts?severity=extreme", headers=headers)
        assert invalid.status_code == 422

        single = sqlite_app_client.get(f"{API}/alerts/{alert['id']}", headers=headers)
        assert single.status_code == 200
        assert single.json()["data"]["id"] == alert["id"]

        patched = sqlite_app_client.patch(
            f"{API}/alerts/{alert['id']}/status", json={"status": "acknowledged"}, headers=headers
        )
        assert patched.status_code == 200
        assert patched.json()["data"]["status"] == "acknowledged"

        duplicate = sqlite_app_client.patch(
            f"{API}/alerts/{alert['id']}/status",
            json={"status": "acknowledged"},
            headers=headers,
        )
        assert duplicate.status_code == 400

    def test_validation_errors(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"valert.{_uuid()}@example.com", "valert"
        )
        headers = _auth(admin)

        empty = sqlite_app_client.post(f"{API}/alerts", json=[], headers=headers)
        assert empty.status_code == 422

        bad_severity = sqlite_app_client.post(
            f"{API}/alerts",
            json=[
                {
                    "severity": "boom",
                    "category": "c",
                    "src_ip": "1.1.1.1",
                    "dst_ip": "2.2.2.2",
                    "risk_score": 1.0,
                }
            ],
            headers=headers,
        )
        assert bad_severity.status_code == 422

        missing = sqlite_app_client.get(f"{API}/alerts/99999", headers=headers)
        assert missing.status_code == 404

        bad_status = sqlite_app_client.patch(
            f"{API}/alerts/99999/status", json={"status": "weird"}, headers=headers
        )
        assert bad_status.status_code == 422

        not_found = sqlite_app_client.patch(
            f"{API}/alerts/99999/status", json={"status": "new"}, headers=headers
        )
        assert not_found.status_code == 404


class TestPackets:
    def test_ingest_list_and_detection(
        self, sqlite_app_client: Any, sqlite_db_factory: Any
    ) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"pkt.{_uuid()}@example.com", "pktadmin"
        )
        headers = _auth(admin)

        rule = sqlite_app_client.post(
            f"{API}/rules",
            json={
                "name": "TCP Beacon",
                "category": "c2",
                "severity": "high",
                "yaml_content": "name: TCP Beacon\nmatch:\n  proto: tcp\n",
                "enabled": True,
            },
            headers=headers,
        )
        assert rule.status_code == 200

        ingest = sqlite_app_client.post(
            f"{API}/packets",
            json=[
                {
                    "src_ip": "10.1.1.1",
                    "src_port": 12345,
                    "dst_ip": "203.0.113.9",
                    "dst_port": 443,
                    "proto": "tcp",
                    "length": 512,
                    "flags": "S",
                }
            ],
            headers=headers,
        )
        assert ingest.status_code == 200
        summary = ingest.json()["data"]
        assert summary["ingested"] == 1
        assert summary["alerts"] == 1

        listed = sqlite_app_client.get(
            f"{API}/packets?proto=tcp&src_ip=10.1.1.1&dst_ip=203.0.113.9", headers=headers
        )
        assert listed.status_code == 200
        assert listed.json()["data"]["total"] == 1

    def test_validation_errors(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"vpkt.{_uuid()}@example.com", "vpkt"
        )
        headers = _auth(admin)

        empty = sqlite_app_client.post(f"{API}/packets", json=[], headers=headers)
        assert empty.status_code == 422

        bad_proto = sqlite_app_client.post(
            f"{API}/packets",
            json=[
                {
                    "src_ip": "1.1.1.1",
                    "dst_ip": "2.2.2.2",
                    "proto": "sctp",
                    "length": 10,
                }
            ],
            headers=headers,
        )
        assert bad_proto.status_code == 422

        bad_filter = sqlite_app_client.get(f"{API}/packets?proto=sctp", headers=headers)
        assert bad_filter.status_code == 422

    def test_pcap_import_error_paths(
        self, sqlite_app_client: Any, sqlite_db_factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"pcap.{_uuid()}@example.com", "pcap"
        )
        headers = _auth(admin)
        files = {"file": ("capture.pcap", b"\xd4\xc3\xb2\xa1", "application/vnd.tcpdump.pcap")}

        bad_type = sqlite_app_client.post(
            f"{API}/packets/import",
            files={"file": ("capture.txt", b"nope", "text/plain")},
            headers=headers,
        )
        assert bad_type.status_code == 422

        from app.api.v1.endpoints import packets as packets_mod
        from app.services.packet_capture import CaptureUnavailableError

        def no_support(source: bytes, source_name: str | None = None) -> list[Any]:
            raise CaptureUnavailableError("no libpcap on this host")

        monkeypatch.setattr(packets_mod, "parse_pcap_bytes", no_support)
        unsupported = sqlite_app_client.post(f"{API}/packets/import", files=files, headers=headers)
        assert unsupported.status_code == 501

        def empty_pcap(source: bytes, source_name: str | None = None) -> list[Any]:
            return []

        monkeypatch.setattr(packets_mod, "parse_pcap_bytes", empty_pcap)
        empty = sqlite_app_client.post(f"{API}/packets/import", files=files, headers=headers)
        assert empty.status_code == 422

        def bad_pcap(source: bytes, source_name: str | None = None) -> list[Any]:
            raise ValueError("truncated pcap")

        monkeypatch.setattr(packets_mod, "parse_pcap_bytes", bad_pcap)
        truncated = sqlite_app_client.post(f"{API}/packets/import", files=files, headers=headers)
        assert truncated.status_code == 422


class TestCaptures:
    def test_list_and_status(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"cap.{_uuid()}@example.com", "capadmin"
        )
        headers = _auth(admin)

        listed = sqlite_app_client.get(f"{API}/captures", headers=headers)
        assert listed.status_code == 200

        status = sqlite_app_client.get(f"{API}/captures/status", headers=headers)
        assert status.status_code == 200
        assert "adapters" in status.json()["data"]

        invalid = sqlite_app_client.get(f"{API}/captures?status=bogus", headers=headers)
        assert invalid.status_code == 422

    async def test_run_cycle(
        self, sqlite_app_client: Any, sqlite_db_factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        admin = await _register_admin_async(
            sqlite_app_client, sqlite_db_factory, f"caprun.{_uuid()}@example.com", "caprun"
        )
        headers = _auth(admin)

        async with sqlite_db_factory() as session:
            run = CaptureRun(
                adapter="scapy_sniff",
                started_at=datetime.now(UTC),
                finished_at=datetime.now(UTC),
                packets_ingested=3,
                alerts_raised=0,
                status="succeeded",
            )
            session.add(run)
            await session.commit()
            await session.refresh(run)

        async def fake_run_cycle(db: Any) -> list[CaptureRun]:
            return [run]

        monkeypatch.setattr(captures_mod.capture_manager, "run_cycle", fake_run_cycle)
        response = sqlite_app_client.post(f"{API}/captures/run", headers=headers)
        assert response.status_code == 200
        assert response.json()["data"][0]["adapter"] == "scapy_sniff"


class TestIncidents:
    def test_full_lifecycle(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"inc.{_uuid()}@example.com", "incadmin"
        )
        headers = _auth(admin)

        created = sqlite_app_client.post(
            f"{API}/incidents",
            json={
                "title": "Suspicious outbound traffic",
                "severity": "high",
                "note": "investigate",
            },
            headers=headers,
        )
        assert created.status_code == 200
        incident = created.json()["data"]
        assert incident["status"] == "open"
        incident_id = incident["id"]

        listed = sqlite_app_client.get(
            f"{API}/incidents?status=open&severity=high", headers=headers
        )
        assert listed.status_code == 200
        assert listed.json()["data"]["total"] == 1

        single = sqlite_app_client.get(f"{API}/incidents/{incident_id}", headers=headers)
        assert single.status_code == 200
        assert single.json()["data"]["title"] == "Suspicious outbound traffic"

        updated = sqlite_app_client.patch(
            f"{API}/incidents/{incident_id}",
            json={"title": "Confirmed C2 beacon"},
            headers=headers,
        )
        assert updated.status_code == 200
        assert updated.json()["data"]["title"] == "Confirmed C2 beacon"

        entry = sqlite_app_client.post(
            f"{API}/incidents/{incident_id}/timeline",
            json={"action": "noted", "note": "analyst review complete"},
            headers=headers,
        )
        assert entry.status_code == 200

        status = sqlite_app_client.patch(
            f"{API}/incidents/{incident_id}/status",
            json={"status": "in_progress"},
            headers=headers,
        )
        assert status.status_code == 200
        assert status.json()["data"]["status"] == "in_progress"

        actions = sqlite_app_client.get(f"{API}/incidents/{incident_id}/actions", headers=headers)
        assert actions.status_code == 200
        assert actions.json()["data"] == []

        action = sqlite_app_client.post(
            f"{API}/incidents/{incident_id}/actions",
            json={"action_type": "block", "target_type": "ip", "target_value": "198.51.100.7"},
            headers=headers,
        )
        assert action.status_code == 200
        action_id = action.json()["data"]["id"]
        assert action.json()["data"]["status"] == "pending"

        executed = sqlite_app_client.post(
            f"{API}/incidents/{incident_id}/actions/{action_id}/execute", headers=headers
        )
        assert executed.status_code == 200
        assert executed.json()["data"]["status"] == "succeeded"

        already_done = sqlite_app_client.post(
            f"{API}/incidents/{incident_id}/actions/{action_id}/execute", headers=headers
        )
        assert already_done.status_code == 400

    def test_validation_and_not_found(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"vinc.{_uuid()}@example.com", "vinc"
        )
        headers = _auth(admin)

        bad_severity = sqlite_app_client.post(
            f"{API}/incidents",
            json={"title": "Bad severity", "severity": "urgent"},
            headers=headers,
        )
        assert bad_severity.status_code == 422

        missing_alerts = sqlite_app_client.post(
            f"{API}/incidents",
            json={"title": "Ghost alerts", "alert_ids": [123456]},
            headers=headers,
        )
        assert missing_alerts.status_code == 400

        not_found = sqlite_app_client.get(f"{API}/incidents/99999", headers=headers)
        assert not_found.status_code == 404

        no_change = sqlite_app_client.patch(
            f"{API}/incidents/99999", json={"title": "renamed"}, headers=headers
        )
        assert no_change.status_code == 404

        bad_status = sqlite_app_client.patch(
            f"{API}/incidents/99999/status", json={"status": "whatever"}, headers=headers
        )
        assert bad_status.status_code == 422

        bad_action = sqlite_app_client.post(
            f"{API}/incidents/99999/actions",
            json={"action_type": "explode", "target_type": "ip", "target_value": "1.2.3.4"},
            headers=headers,
        )
        assert bad_action.status_code == 422

        bad_target = sqlite_app_client.post(
            f"{API}/incidents/99999/actions",
            json={"action_type": "block", "target_type": "star", "target_value": "1.2.3.4"},
            headers=headers,
        )
        assert bad_target.status_code == 422

    def test_update_paths(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"uinc.{_uuid()}@example.com", "uinc"
        )
        headers = _auth(admin)

        incident = sqlite_app_client.post(
            f"{API}/incidents", json={"title": "Needs assignee"}, headers=headers
        ).json()["data"]

        bad_assignee = sqlite_app_client.patch(
            f"{API}/incidents/{incident['id']}",
            json={"assignee_id": 999999},
            headers=headers,
        )
        assert bad_assignee.status_code == 400

        incident_id = incident["id"]
        bad_severity = sqlite_app_client.patch(
            f"{API}/incidents/{incident_id}",
            json={"severity": "cosmic"},
            headers=headers,
        )
        assert bad_severity.status_code == 422

        no_changes = sqlite_app_client.patch(
            f"{API}/incidents/{incident_id}", json={"title": None}, headers=headers
        )
        assert no_changes.status_code == 400

        already = sqlite_app_client.patch(
            f"{API}/incidents/{incident_id}/status", json={"status": "open"}, headers=headers
        )
        assert already.status_code == 400

    def test_assignee_path(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        registered = _register(
            sqlite_app_client, f"assign.{_uuid()}@example.com", "assigneeuser"
        ).json()["data"]
        assignee_id = registered["id"]
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"assigna.{_uuid()}@example.com", "assignadmin"
        )
        headers = _auth(admin)

        incident = sqlite_app_client.post(
            f"{API}/incidents", json={"title": "Assign me"}, headers=headers
        ).json()["data"]

        assigned = sqlite_app_client.patch(
            f"{API}/incidents/{incident['id']}",
            json={"assignee_id": assignee_id},
            headers=headers,
        )
        assert assigned.status_code == 200
        assert assigned.json()["data"]["assignee_id"] == assignee_id


class TestPolicies:
    def _create(self, client: Any, headers: dict[str, str], name: str) -> dict[str, Any]:
        response = client.post(
            f"{API}/policies",
            json={
                "name": name,
                "enabled": True,
                "conditions": {"severity": ["high", "critical"], "min_risk_score": 70},
                "actions": [
                    {"action_type": "block", "target_type": "ip", "target_value": "{{src_ip}}"}
                ],
                "cooldown_seconds": 60,
            },
            headers=headers,
        )
        assert response.status_code == 200
        return response.json()["data"]

    def test_crud(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"pol.{_uuid()}@example.com", "poladmin"
        )
        headers = _auth(admin)

        policy = self._create(sqlite_app_client, headers, "Block scanners")

        listed = sqlite_app_client.get(f"{API}/policies?enabled=true", headers=headers)
        assert listed.status_code == 200
        assert listed.json()["data"]["total"] == 1

        single = sqlite_app_client.get(f"{API}/policies/{policy['id']}", headers=headers)
        assert single.status_code == 200
        assert single.json()["data"]["name"] == "Block scanners"

        updated = sqlite_app_client.patch(
            f"{API}/policies/{policy['id']}",
            json={"enabled": False, "cooldown_seconds": 120},
            headers=headers,
        )
        assert updated.status_code == 200
        assert updated.json()["data"]["enabled"] is False

        deleted = sqlite_app_client.delete(f"{API}/policies/{policy['id']}", headers=headers)
        assert deleted.status_code == 200
        assert deleted.json()["data"] is None

    def test_not_found(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"vpol.{_uuid()}@example.com", "vpol"
        )
        headers = _auth(admin)

        missing = sqlite_app_client.get(f"{API}/policies/99999", headers=headers)
        assert missing.status_code == 404

        missing_update = sqlite_app_client.patch(
            f"{API}/policies/99999", json={"enabled": False}, headers=headers
        )
        assert missing_update.status_code == 404

        missing_delete = sqlite_app_client.delete(f"{API}/policies/99999", headers=headers)
        assert missing_delete.status_code == 404


class TestNotifications:
    def test_lifecycle(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"notif.{_uuid()}@example.com", "notifadmin"
        )
        headers = _auth(admin)

        incident = sqlite_app_client.post(
            f"{API}/incidents",
            json={"title": "Critical event", "severity": "critical"},
            headers=headers,
        )
        assert incident.status_code == 200

        listed = sqlite_app_client.get(f"{API}/notifications", headers=headers)
        assert listed.status_code == 200
        assert listed.json()["data"]["total"] == 1
        notification_id = listed.json()["data"]["items"][0]["id"]

        unread = sqlite_app_client.get(f"{API}/notifications?unread_only=true", headers=headers)
        assert unread.status_code == 200
        assert unread.json()["data"]["total"] == 1

        count = sqlite_app_client.get(f"{API}/notifications/unread-count", headers=headers)
        assert count.status_code == 200
        assert count.json()["data"] == 1

        marked = sqlite_app_client.post(
            f"{API}/notifications/{notification_id}/read", headers=headers
        )
        assert marked.status_code == 200
        assert marked.json()["data"]["read"] is True

        again = sqlite_app_client.post(
            f"{API}/notifications/{notification_id}/read", headers=headers
        )
        assert again.status_code == 200

        missing = sqlite_app_client.post(f"{API}/notifications/99999/read", headers=headers)
        assert missing.status_code == 404

        read_all = sqlite_app_client.post(f"{API}/notifications/read-all", headers=headers)
        assert read_all.status_code == 200

        count_after = sqlite_app_client.get(f"{API}/notifications/unread-count", headers=headers)
        assert count_after.json()["data"] == 0


class TestSensors:
    def test_fleet_crud_and_agent(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"sen.{_uuid()}@example.com", "senadmin"
        )
        headers = _auth(admin)

        fleet = sqlite_app_client.get(f"{API}/sensors/fleet", headers=headers)
        assert fleet.status_code == 200

        listed = sqlite_app_client.get(f"{API}/sensors", headers=headers)
        assert listed.status_code == 200
        assert listed.json()["data"]["total"] == 0

        registered = sqlite_app_client.post(
            f"{API}/sensors",
            json={
                "name": "edge-01",
                "hostname": "edge-01.internal",
                "ip_address": "172.16.0.5",
                "version": "3.0.0",
                "config": {"capture_enabled": True, "capture_cycle_seconds": 30},
            },
            headers=headers,
        )
        assert registered.status_code == 201
        data = registered.json()["data"]
        sensor = data["sensor"]
        token = data["token"]
        assert token
        sensor_id = sensor["id"]

        single = sqlite_app_client.get(f"{API}/sensors/{sensor_id}", headers=headers)
        assert single.status_code == 200

        sensor_headers = {"X-Sensor-Token": token}
        heartbeat = sqlite_app_client.post(
            f"{API}/sensors/heartbeat",
            json={"version": "3.0.1", "hostname": "edge-01.internal"},
            headers=sensor_headers,
        )
        assert heartbeat.status_code == 200
        assert heartbeat.json()["data"]["status"] == "online"

        config = sqlite_app_client.get(f"{API}/sensors/config", headers=sensor_headers)
        assert config.status_code == 200
        assert config.json()["data"]["capture_enabled"] is True
        assert config.json()["data"]["capture_cycle_seconds"] == 30

        patched = sqlite_app_client.patch(
            f"{API}/sensors/{sensor_id}",
            json={"version": "3.0.2", "hostname": "edge-01.corp"},
            headers=headers,
        )
        assert patched.status_code == 200
        assert patched.json()["data"]["version"] == "3.0.2"

        rotated = sqlite_app_client.post(f"{API}/sensors/{sensor_id}/rotate-token", headers=headers)
        assert rotated.status_code == 200
        new_token = rotated.json()["data"]["token"]
        assert new_token != token

        old_token_rejected = sqlite_app_client.post(
            f"{API}/sensors/heartbeat", json={}, headers={"X-Sensor-Token": token}
        )
        assert old_token_rejected.status_code == 401

        new_token_works = sqlite_app_client.post(
            f"{API}/sensors/heartbeat", json={}, headers={"X-Sensor-Token": new_token}
        )
        assert new_token_works.status_code == 200

        removed = sqlite_app_client.delete(f"{API}/sensors/{sensor_id}", headers=headers)
        assert removed.status_code == 200
        assert removed.json()["data"]["deleted"] is True

    def test_disabled_sensor_rejected(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"dses.{_uuid()}@example.com", "dsensor"
        )
        headers = _auth(admin)

        data = sqlite_app_client.post(
            f"{API}/sensors",
            json={"name": "edge-02", "config": {}},
            headers=headers,
        ).json()["data"]
        sensor_id = data["sensor"]["id"]
        token = data["token"]

        disabled = sqlite_app_client.patch(
            f"{API}/sensors/{sensor_id}", json={"enabled": False}, headers=headers
        )
        assert disabled.status_code == 200

        heartbeat = sqlite_app_client.post(
            f"{API}/sensors/heartbeat", json={}, headers={"X-Sensor-Token": token}
        )
        assert heartbeat.status_code == 403

        no_token = sqlite_app_client.post(f"{API}/sensors/heartbeat", json={})
        assert no_token.status_code == 401

    def test_sensor_not_found(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"nses.{_uuid()}@example.com", "nsensor"
        )
        headers = _auth(admin)

        assert sqlite_app_client.get(f"{API}/sensors/99999", headers=headers).status_code == 404
        assert (
            sqlite_app_client.patch(f"{API}/sensors/99999", json={}, headers=headers).status_code
            == 404
        )
        assert (
            sqlite_app_client.post(f"{API}/sensors/99999/rotate-token", headers=headers).status_code
            == 404
        )
        assert sqlite_app_client.delete(f"{API}/sensors/99999", headers=headers).status_code == 404
        assert (
            sqlite_app_client.get(f"{API}/sensors?status=bogus", headers=headers).status_code == 422
        )

    def test_sensor_name_conflict(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"cses.{_uuid()}@example.com", "csensor"
        )
        headers = _auth(admin)
        payload = {"name": "edge-03", "config": {}}
        created = sqlite_app_client.post(f"{API}/sensors", json=payload, headers=headers)
        assert created.status_code == 201
        conflict = sqlite_app_client.post(f"{API}/sensors", json=payload, headers=headers)
        assert conflict.status_code == 409


class TestUsers:
    def test_list_get_update_delete(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        _register(sqlite_app_client, f"target.{_uuid()}@example.com", "targetuser")
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"usr.{_uuid()}@example.com", "usradmin"
        )
        headers = _auth(admin)

        listed = sqlite_app_client.get(f"{API}/users", headers=headers)
        assert listed.status_code == 200
        assert listed.json()["data"]["total"] == 2

        target_id = next(
            u["id"] for u in listed.json()["data"]["items"] if u["username"] == "targetuser"
        )

        single = sqlite_app_client.get(f"{API}/users/{target_id}", headers=headers)
        assert single.status_code == 200

        upgraded = sqlite_app_client.patch(
            f"{API}/users/{target_id}", json={"role": "admin"}, headers=headers
        )
        assert upgraded.status_code == 200
        assert upgraded.json()["data"]["role"] == "admin"

        renamed = sqlite_app_client.patch(
            f"{API}/users/{target_id}",
            json={"full_name": "Target Person", "is_active": True},
            headers=headers,
        )
        assert renamed.status_code == 200
        assert renamed.json()["data"]["full_name"] == "Target Person"

        removed = sqlite_app_client.delete(f"{API}/users/{target_id}", headers=headers)
        assert removed.status_code == 200
        assert removed.json()["data"] is True

    def test_guardrails(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        _register(sqlite_app_client, f"extra.{_uuid()}@example.com", "extrauser")
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"gusr.{_uuid()}@example.com", "gusradmin"
        )
        headers = _auth(admin)
        admin_id = _me_id(sqlite_app_client, headers)

        invalid_role = sqlite_app_client.patch(
            f"{API}/users/{admin_id}", json={"role": "superuser"}, headers=headers
        )
        assert invalid_role.status_code == 422

        self_role = sqlite_app_client.patch(
            f"{API}/users/{admin_id}", json={"role": "analyst"}, headers=headers
        )
        assert self_role.status_code == 400

        self_deactivate = sqlite_app_client.patch(
            f"{API}/users/{admin_id}", json={"is_active": False}, headers=headers
        )
        assert self_deactivate.status_code == 400

        self_delete = sqlite_app_client.delete(f"{API}/users/{admin_id}", headers=headers)
        assert self_delete.status_code == 400

        missing = sqlite_app_client.get(f"{API}/users/99999", headers=headers)
        assert missing.status_code == 404

        missing_delete = sqlite_app_client.delete(f"{API}/users/99999", headers=headers)
        assert missing_delete.status_code == 404

    def test_analyst_denied(self, sqlite_app_client: Any) -> None:
        _register(sqlite_app_client, f"denied.{_uuid()}@example.com", "denieduser")
        analyst = _tokens(sqlite_app_client, "denieduser")
        response = sqlite_app_client.get(f"{API}/users", headers=_auth(analyst))
        assert response.status_code == 403


def _me_id(client: Any, headers: dict[str, str]) -> int:
    return client.get(f"{API}/auth/me", headers=headers).json()["data"]["id"]


class TestIocs:
    def test_crud_and_bulk(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"ioc.{_uuid()}@example.com", "iocadmin"
        )
        headers = _auth(admin)

        created = sqlite_app_client.post(
            f"{API}/iocs",
            json={
                "type": "ipv4",
                "value": "203.0.113.55",
                "source": "threatintel",
                "confidence": 0.9,
            },
            headers=headers,
        )
        assert created.status_code == 200
        ioc = created.json()["data"]
        assert ioc["type"] == "ipv4"

        updated = sqlite_app_client.patch(
            f"{API}/iocs/{ioc['id']}",
            json={"source": "manual", "confidence": 1.0},
            headers=headers,
        )
        assert updated.status_code == 200
        assert updated.json()["data"]["confidence"] == 1.0

        single = sqlite_app_client.get(f"{API}/iocs/{ioc['id']}", headers=headers)
        assert single.status_code == 200

        listed = sqlite_app_client.get(f"{API}/iocs?type=ipv4&source=manual", headers=headers)
        assert listed.status_code == 200
        assert listed.json()["data"]["total"] == 1

        bulk = sqlite_app_client.post(
            f"{API}/iocs/bulk",
            json={
                "items": [
                    {"type": "domain", "value": "evil.example.org", "confidence": 0.8},
                    {"type": "email", "value": "spam@example.org", "confidence": 0.6},
                ]
            },
            headers=headers,
        )
        assert bulk.status_code == 200
        assert bulk.json()["data"]["total"] == 2

        deleted = sqlite_app_client.delete(f"{API}/iocs/{ioc['id']}", headers=headers)
        assert deleted.status_code == 200

    def test_errors(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"vioc.{_uuid()}@example.com", "vioc"
        )
        headers = _auth(admin)

        bad_type = sqlite_app_client.post(
            f"{API}/iocs",
            json={"type": "mac", "value": "aa:bb", "confidence": 0.5},
            headers=headers,
        )
        assert bad_type.status_code == 422

        bad_list = sqlite_app_client.get(f"{API}/iocs?type=mac", headers=headers)
        assert bad_list.status_code == 422

        missing = sqlite_app_client.get(f"{API}/iocs/99999", headers=headers)
        assert missing.status_code == 404

        missing_update = sqlite_app_client.patch(
            f"{API}/iocs/99999", json={"source": "x"}, headers=headers
        )
        assert missing_update.status_code == 404

        missing_delete = sqlite_app_client.delete(f"{API}/iocs/99999", headers=headers)
        assert missing_delete.status_code == 404


class TestRules:
    def _yaml(self, name: str) -> str:
        return f"name: {name}\nmatch:\n  proto: tcp\n"

    def test_crud(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"rul.{_uuid()}@example.com", "ruladmin"
        )
        headers = _auth(admin)

        created = sqlite_app_client.post(
            f"{API}/rules",
            json={
                "name": "Rule One",
                "category": "network",
                "severity": "medium",
                "yaml_content": self._yaml("Rule One"),
                "enabled": True,
            },
            headers=headers,
        )
        assert created.status_code == 200
        rule = created.json()["data"]

        listed = sqlite_app_client.get(
            f"{API}/rules?enabled=true&severity=medium&search=Rule", headers=headers
        )
        assert listed.status_code == 200
        assert listed.json()["data"]["total"] == 1

        single = sqlite_app_client.get(f"{API}/rules/{rule['id']}", headers=headers)
        assert single.status_code == 200

        updated = sqlite_app_client.patch(
            f"{API}/rules/{rule['id']}",
            json={"severity": "high", "enabled": False},
            headers=headers,
        )
        assert updated.status_code == 200
        assert updated.json()["data"]["severity"] == "high"
        assert updated.json()["data"]["version"] == 1

        deleted = sqlite_app_client.delete(f"{API}/rules/{rule['id']}", headers=headers)
        assert deleted.status_code == 200

    def test_errors(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"vrul.{_uuid()}@example.com", "vrul"
        )
        headers = _auth(admin)

        bad_yaml = sqlite_app_client.post(
            f"{API}/rules",
            json={
                "name": "Broken",
                "category": "network",
                "severity": "medium",
                "yaml_content": "name: Broken\nmatch: [unclosed",
            },
            headers=headers,
        )
        assert bad_yaml.status_code == 422

        bad_severity = sqlite_app_client.post(
            f"{API}/rules",
            json={
                "name": "Bad Sev",
                "category": "network",
                "severity": "epic",
                "yaml_content": self._yaml("Bad Sev"),
            },
            headers=headers,
        )
        assert bad_severity.status_code == 422

        missing = sqlite_app_client.get(f"{API}/rules/99999", headers=headers)
        assert missing.status_code == 404

        invalid_filter = sqlite_app_client.get(f"{API}/rules?severity=epic", headers=headers)
        assert invalid_filter.status_code == 422

    def test_duplicate_name(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"drul.{_uuid()}@example.com", "drul"
        )
        headers = _auth(admin)
        payload = {
            "name": "Dup Rule",
            "category": "network",
            "severity": "low",
            "yaml_content": self._yaml("Dup Rule"),
        }
        created = sqlite_app_client.post(f"{API}/rules", json=payload, headers=headers)
        assert created.status_code == 200
        duplicate = sqlite_app_client.post(f"{API}/rules", json=payload, headers=headers)
        assert duplicate.status_code == 422


class TestSiem:
    def test_status_default(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"siem.{_uuid()}@example.com", "siemadmin"
        )
        headers = _auth(admin)
        status = sqlite_app_client.get(f"{API}/system/siem/status", headers=headers)
        assert status.status_code == 200
        data = status.json()["data"]
        assert data["pending_alerts"] == 0
        assert data["last_run"] is None

    def test_test_and_export_skipped(self, sqlite_app_client: Any, sqlite_db_factory: Any) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"ssiem.{_uuid()}@example.com", "ssiem"
        )
        headers = _auth(admin)
        test = sqlite_app_client.post(f"{API}/system/siem/test", headers=headers)
        assert test.status_code == 200
        assert test.json()["data"]["status"] == "skipped"

        export = sqlite_app_client.post(f"{API}/system/siem/export", headers=headers)
        assert export.status_code == 200
        assert export.json()["data"]["status"] == "skipped"

    def test_export_success(
        self, sqlite_app_client: Any, sqlite_db_factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"esiem.{_uuid()}@example.com", "esiem"
        )
        headers = _auth(admin)

        sqlite_app_client.post(
            f"{API}/alerts",
            json=[
                {
                    "severity": "medium",
                    "category": "c2",
                    "src_ip": "10.0.0.5",
                    "dst_ip": "203.0.113.9",
                    "risk_score": 50.0,
                }
            ],
            headers=headers,
        )

        from app.services.siem import export

        async def stub_send(payload: str) -> None:
            assert "CEF" in payload

        monkeypatch.setattr(export, "_send_cef_payload", stub_send)
        monkeypatch.setattr(settings, "SIEM_EXPORT_ENABLED", True)
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", "https://collector.example:9000")

        response = sqlite_app_client.post(f"{API}/system/siem/export", headers=headers)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "succeeded"
        assert data["exported"] == 1

        status = sqlite_app_client.get(f"{API}/system/siem/status", headers=headers)
        assert status.json()["data"]["last_run"]["status"] == "succeeded"

    def test_test_and_export_failure(
        self, sqlite_app_client: Any, sqlite_db_factory: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        admin = _register_admin(
            sqlite_app_client, sqlite_db_factory, f"fsiem.{_uuid()}@example.com", "fsiem"
        )
        headers = _auth(admin)

        sqlite_app_client.post(
            f"{API}/alerts",
            json=[
                {
                    "severity": "high",
                    "category": "c2",
                    "src_ip": "10.0.0.9",
                    "dst_ip": "203.0.113.9",
                    "risk_score": 80.0,
                }
            ],
            headers=headers,
        )

        from app.services.siem import export

        async def boom(payload: str) -> None:
            raise httpx.ConnectError("connection refused")

        monkeypatch.setattr(export, "_send_cef_payload", boom)
        monkeypatch.setattr(settings, "SIEM_EXPORT_ENABLED", True)
        monkeypatch.setattr(settings, "SIEM_CEF_ENDPOINT_URL", "https://collector.example:9000")

        test = sqlite_app_client.post(f"{API}/system/siem/test", headers=headers)
        assert test.status_code == 502

        export_resp = sqlite_app_client.post(f"{API}/system/siem/export", headers=headers)
        assert export_resp.status_code == 200
        assert export_resp.json()["data"]["status"] == "failed"
