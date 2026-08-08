"""Tests for secret resolution: env -> file -> Vault."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from app.core.config import settings
from app.services import secrets as secrets_service
from app.services.secrets import SecretResolutionError, secret_key


@pytest.fixture(autouse=True)
def _clean_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "SECRET_KEY_FILE", None)
    monkeypatch.setattr(settings, "VAULT_URL", None)
    monkeypatch.setattr(settings, "VAULT_TOKEN", None)
    monkeypatch.setattr(settings, "VAULT_PATH", None)
    secrets_service._vault_secret.cache_clear()


class TestSecretKeyEnv:
    def test_returns_env_key(self) -> None:
        assert secret_key() == "test-secret-key-not-for-production"


class TestSecretFile:
    def test_returns_file_contents(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        secret_file = tmp_path / "secret"
        secret_file.write_text("file-based-secret\n", encoding="utf-8")
        monkeypatch.setattr(settings, "SECRET_KEY_FILE", str(secret_file))
        assert secret_key() == "file-based-secret"

    def test_missing_file_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(settings, "SECRET_KEY_FILE", str(tmp_path / "missing"))
        with pytest.raises(SecretResolutionError):
            secret_key()

    def test_empty_file_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.write_text("  \n", encoding="utf-8")
        monkeypatch.setattr(settings, "SECRET_KEY_FILE", str(empty))
        with pytest.raises(SecretResolutionError):
            secret_key()

    def test_file_priority_over_vault(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        secret_file = tmp_path / "secret"
        secret_file.write_text("from-file", encoding="utf-8")
        monkeypatch.setattr(settings, "SECRET_KEY_FILE", str(secret_file))
        monkeypatch.setattr(settings, "VAULT_URL", "https://vault.example")
        monkeypatch.setattr(settings, "VAULT_TOKEN", "token")
        monkeypatch.setattr(settings, "VAULT_PATH", "sentinel")
        assert secret_key() == "from-file"


class TestVault:
    def _enable_vault(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "VAULT_URL", "https://vault.example/")
        monkeypatch.setattr(settings, "VAULT_TOKEN", "token-1")
        monkeypatch.setattr(settings, "VAULT_PATH", "sentinel/secrets")
        monkeypatch.setattr(settings, "VAULT_MOUNT", "kv")

    def test_vault_read_dict_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._enable_vault(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/v1/kv/data/sentinel/secrets"
            assert request.headers["X-Vault-Token"] == "token-1"
            return httpx.Response(200, json={"data": {"data": {"SECRET_KEY": "vault-key"}}})

        with httpx.MockTransport(handler) as transport:
            real = httpx.Client
            monkeypatch.setattr(httpx, "Client", lambda **kw: real(**kw, transport=transport))
            secrets_service._vault_secret.cache_clear()
            value = secret_key()
        assert value == "vault-key"

    def test_vault_read_string_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._enable_vault(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"data": "plain-secret"}})

        with httpx.MockTransport(handler) as transport:
            real = httpx.Client

            class _FakeClient:  # pragma: no cover - exercised below
                pass

            monkeypatch.setattr(httpx, "Client", lambda **kw: real(**kw, transport=transport))
            secrets_service._vault_secret.cache_clear()
            value = secret_key()
        assert value == "plain-secret"

    def test_vault_http_error_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._enable_vault(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        with httpx.MockTransport(handler) as transport:
            real = httpx.Client
            monkeypatch.setattr(httpx, "Client", lambda **kw: real(**kw, transport=transport))
            secrets_service._vault_secret.cache_clear()
            with pytest.raises(SecretResolutionError):
                secret_key()

    def test_vault_missing_secret_key_field_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._enable_vault(monkeypatch)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"data": {"OTHER": "nope"}}})

        with httpx.MockTransport(handler) as transport:
            real = httpx.Client
            monkeypatch.setattr(httpx, "Client", lambda **kw: real(**kw, transport=transport))
            secrets_service._vault_secret.cache_clear()
            with pytest.raises(SecretResolutionError):
                secret_key()

    def test_vault_uses_config_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._enable_vault(monkeypatch)
        monkeypatch.setattr(settings, "OIDC_HTTP_TIMEOUT_SECONDS", 7)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"data": "x"}})

        with httpx.MockTransport(handler) as transport:
            real = httpx.Client
            monkeypatch.setattr(httpx, "Client", lambda **kw: real(**kw, transport=transport))
            secrets_service._vault_secret.cache_clear()
            assert secret_key() == "x"
