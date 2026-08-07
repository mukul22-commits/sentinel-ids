"""OIDC single sign-on (Phase 9).

Implements the authorization-code flow against any standards-compliant
OpenID Connect provider:

  - ``fetch_discovery`` - fetch and cache ``.well-known/openid-configuration``
  - ``authorization_url`` - build the provider's authorization URL (login)
  - ``exchange_code`` - swap the ``code`` for ID/access/refresh tokens
  - ``verify_id_token`` - validate the ID token (signature, issuer, audience,
    expiry, ``nonce``) and return its claims
  - ``subject_from_claims`` - normalise the email subject for user provisioning

All outbound HTTP goes through the injected ``http`` client so tests can
stub the provider without a live server. The module is a no-op (raising
``OidcUnavailable``) when OIDC is disabled via settings.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlencode

import httpx
import jwt

from app.core.config import settings

logger = logging.getLogger("sentinel.oidc")

DEFAULT_SCOPE = "openid email profile"


class OidcUnavailable(RuntimeError):
    """Raised when OIDC is not enabled/configured."""


class OidcError(RuntimeError):
    """Raised on any provider interaction failure."""


@dataclass(frozen=True)
class OidcTokens:
    access_token: str
    refresh_token: str | None
    id_token: str
    expires_in: int


def oidc_enabled() -> bool:
    return bool(settings.OIDC_ENABLED and settings.OIDC_ISSUER and settings.OIDC_CLIENT_ID)


def _require_enabled() -> None:
    if not oidc_enabled():
        raise OidcUnavailable("OIDC is not enabled")


def discovery_url() -> str:
    _require_enabled()
    assert settings.OIDC_ISSUER is not None
    return settings.OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration"


async def fetch_discovery(http: httpx.AsyncClient) -> dict[str, Any]:
    """Fetch (and cache) the provider discovery document."""
    _require_enabled()
    url = discovery_url()
    try:
        resp = await http.get(url, timeout=settings.OIDC_HTTP_TIMEOUT_SECONDS)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise OidcError(f"discovery document fetch failed: {exc}") from exc
    try:
        return cast(dict[str, Any], resp.json())
    except ValueError as exc:
        raise OidcError("discovery document is not valid JSON") from exc


async def authorization_url(
    http: httpx.AsyncClient,
    state: str,
    nonce: str,
    redirect_uri: str,
    scope: str | None = None,
) -> str:
    """Build the provider authorization URL for the code flow."""
    _require_enabled()
    meta = await fetch_discovery(http)
    params = {
        "response_type": "code",
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": scope or settings.OIDC_SCOPES or DEFAULT_SCOPE,
        "state": state,
        "nonce": nonce,
    }
    return f"{meta['authorization_endpoint']}?{urlencode(params)}"


async def exchange_code(
    code: str,
    redirect_uri: str,
    http: httpx.AsyncClient,
) -> OidcTokens:
    """Exchange the authorization ``code`` for tokens at the token endpoint."""
    _require_enabled()
    meta = await fetch_discovery(http)
    try:
        resp = await http.post(
            meta["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            },
            auth=(settings.OIDC_CLIENT_ID or "", settings.OIDC_CLIENT_SECRET or ""),
            timeout=settings.OIDC_HTTP_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise OidcError(f"token exchange failed: {exc}") from exc
    data = resp.json()
    if "id_token" not in data:
        raise OidcError("token endpoint response missing id_token")
    return OidcTokens(
        access_token=str(data.get("access_token", "")),
        refresh_token=data.get("refresh_token"),
        id_token=str(data["id_token"]),
        expires_in=int(data.get("expires_in", 0)),
    )


async def verify_id_token(id_token: str, nonce: str, http: httpx.AsyncClient) -> dict[str, Any]:
    """Verify the ID token and return its claims."""
    _require_enabled()
    meta = await fetch_discovery(http)
    try:
        jwks = jwt.PyJWKClient(
            meta["jwks_uri"],
            cache_keys=True,
            timeout=settings.OIDC_HTTP_TIMEOUT_SECONDS,
        )
        signing_key = jwks.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            key=signing_key.key,
            algorithms=[signing_key.algorithm_name or "RS256"],
            audience=settings.OIDC_CLIENT_ID,
            issuer=meta["issuer"],
            options={"require": ["iss", "sub", "exp", "iat"], "verify_exp": True},
        )
    except (httpx.HTTPError, jwt.PyJWTError) as exc:
        raise OidcError(f"id_token verification failed: {exc}") from exc
    if claims.get("nonce") != nonce:
        raise OidcError("id_token nonce mismatch")
    return claims


def subject_from_claims(claims: dict[str, Any]) -> str:
    """Return the normalized email (or ``sub``) identifying the user."""
    email = claims.get("email")
    if isinstance(email, str) and email.strip():
        return email.strip().lower()
    sub = claims.get("sub")
    if isinstance(sub, str) and sub.strip():
        return sub.strip()
    raise OidcError("id_token missing email and sub claims")


def generate_nonce() -> str:
    return secrets.token_urlsafe(24)
