"""Secret resolution: environment -> file -> HashiCorp Vault KV v2 (Phase 9).

Secrets should never live in the repository. ``SECRET_KEY`` is resolved in
priority order: an env value, a mounted secrets file (``SECRET_KEY_FILE``), or a
HashiCorp Vault KV v2 read (``VAULT_URL`` + ``VAULT_TOKEN`` + ``VAULT_PATH``).
File reads are refreshed on every call; Vault fetches are cached per process.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger("sentinel.secrets")


class SecretResolutionError(RuntimeError):
    """Raised when a configured secret source cannot be read."""


def secret_key() -> str:
    """Return the effective SECRET_KEY (env -> file -> Vault)."""
    if settings.SECRET_KEY_FILE:
        value = _read_secret_file(settings.SECRET_KEY_FILE)
        if value:
            return value
        raise SecretResolutionError(
            f"SECRET_KEY_FILE set but unreadable: {settings.SECRET_KEY_FILE}"
        )
    if settings.VAULT_PATH and settings.VAULT_URL and settings.VAULT_TOKEN:
        return _vault_secret(
            settings.VAULT_URL,
            settings.VAULT_TOKEN,
            settings.VAULT_MOUNT,
            settings.VAULT_PATH,
        )
    return settings.SECRET_KEY


def _read_secret_file(path: str) -> str:
    file_path = Path(path)
    if not file_path.is_file():
        return ""
    return file_path.read_text(encoding="utf-8").strip()


@lru_cache(maxsize=16)
def _vault_secret(url: str, token: str, mount: str, vault_path: str) -> str:
    """Read ``vault_path`` from a Vault KV v2 secret engine and return its value.

    Expects the secret data to carry a ``SECRET_KEY`` field (the convention used
    by the compose env), or a plain string value.
    """
    base = url.rstrip("/")
    encoded = "/".join(part.replace("/", "%2F") for part in vault_path.strip("/").split("/"))
    endpoint = f"{base}/v1/{mount}/data/{encoded}"
    headers = {"X-Vault-Token": token}
    timeout = httpx.Timeout(settings.OIDC_HTTP_TIMEOUT_SECONDS)
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(endpoint, headers=headers)
        response.raise_for_status()
        data: dict[str, Any] = response.json().get("data", {})
    except (httpx.HTTPError, ValueError) as exc:
        raise SecretResolutionError(f"Vault read failed for {vault_path}: {exc}") from exc

    value = data.get("data")
    if isinstance(value, dict):
        secret = value.get("SECRET_KEY")
        if isinstance(secret, str) and secret:
            return secret
    if isinstance(value, str) and value:
        return value
    raise SecretResolutionError(f"Vault secret {vault_path} has no SECRET_KEY field")
