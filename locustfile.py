"""Sentinel IDS v3 load test (Phase 11)."""

import logging
import threading
import os
from itertools import count

from locust import HttpUser, between, task
from locust.exception import RequestException

logger = logging.getLogger("sentinel.loadtest")

TARGET_HOST: str = os.getenv("TARGET_HOST", "http://localhost:8000")
API_BASE: str = "/api/v1"
PASSWORD: str = "Str0ng!Passw0rd"
SEED_USER_COUNT: int = 50

_SEED_INDEX = count()
_SEED_LOCK = threading.Lock()


def _seed_identity(n: int) -> tuple[str, str]:
    email = f"load_{n}@load.test"
    username = f"load_{n}"
    return email, username


def _fake_ip(n: int) -> str:
    return f"10.200.{n // 250}.{n % 250}"


class SentinelApiUser(HttpUser):
    wait_time = between(0.5, 2)

    def _next_index(self) -> int:
        with _SEED_LOCK:
            return next(_SEED_INDEX) % SEED_USER_COUNT

    def on_start(self) -> None:
        self._index: int = self._next_index()
        self.email, self.username = _seed_identity(self._index)
        self.token: str | None = None
        self._headers = {"X-Forwarded-For": _fake_ip(self._index)}
        self._register()
        self._login()

    def _auth_headers(self) -> dict[str, str]:
        headers = {"X-Forwarded-For": _fake_ip(self._index)}
        if self.token is not None:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _register(self) -> None:
        payload = {
            "email": self.email,
            "username": self.username,
            "password": PASSWORD,
        }
        try:
            response = self.client.post(
                f"{API_BASE}/auth/register",
                json=payload,
                headers=self._headers,
                catch_response=False,
            )
            if response.status_code not in (200, 409):
                logger.debug(
                    "register for %s returned %s", self.email, response.status_code
                )
        except RequestException as exc:
            logger.debug("register for %s failed: %s", self.email, exc)

    def _login(self) -> None:
        response = self.client.post(
            f"{API_BASE}/auth/login",
            json={"identifier": self.email, "password": PASSWORD},
            headers=self._headers,
            catch_response=False,
        )
        try:
            self.token = str(response.json()["data"]["access_token"])
        except (KeyError, TypeError, ValueError) as exc:
            logger.debug(
                "login for %s returned %s: %s", self.email, response.status_code, exc
            )

    @task(5)
    def system_status(self) -> None:
        self.client.get(f"{API_BASE}/system/status", headers=self._auth_headers())

    @task(4)
    def list_alerts(self) -> None:
        self.client.get(
            f"{API_BASE}/alerts",
            params={"page": 1, "page_size": 25},
            headers=self._auth_headers(),
        )

    @task(3)
    def list_open_incidents(self) -> None:
        self.client.get(
            f"{API_BASE}/incidents",
            params={"status": "open"},
            headers=self._auth_headers(),
        )

    @task(2)
    def list_rules(self) -> None:
        self.client.get(f"{API_BASE}/rules", headers=self._auth_headers())

    @task(2)
    def list_sensors(self) -> None:
        self.client.get(f"{API_BASE}/sensors", headers=self._auth_headers())

    @task(1)
    def create_alert(self) -> None:
        alert = {
            "title": f"load alert {self._index}",
            "severity": "low",
            "category": "scan",
            "src_ip": f"10.20.{self._index}.1",
            "dst_ip": "203.0.113.9",
            "risk_score": 10.0,
        }
        self.client.post(
            f"{API_BASE}/alerts",
            json=[alert],
            headers=self._auth_headers(),
            catch_response=False,
        )

    @task(1)
    def create_incident(self) -> None:
        payload = {"title": f"load incident {self._index}", "severity": "medium"}
        self.client.post(
            f"{API_BASE}/incidents",
            json=payload,
            headers=self._auth_headers(),
            catch_response=False,
        )
