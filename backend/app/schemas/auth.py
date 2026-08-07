"""Authentication request/response schemas (Phase 3)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)


class LoginRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=16)
    new_password: str = Field(min_length=1, max_length=128)


class OidcConfigRead(BaseModel):
    """Public OIDC discovery info exposed to the frontend."""

    enabled: bool
    issuer: str | None
    client_id: str | None
    scopes: str
    redirect_path: str


class OidcAuthorizeResponse(BaseModel):
    """Result of the ``/auth/oidc/authorize`` step: the provider URL to
    redirect the browser to, plus the ``state`` to hand back on callback."""

    url: str
    state: str
