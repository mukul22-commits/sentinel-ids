"""Authentication endpoints: register, login, refresh, change/reset password."""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import httpx
from app.api.v1.deps import DbSession, get_bearer_token, get_current_user, get_request_id
from app.core.config import settings
from app.core.limiter import limiter
from app.core.rbac import ROLE_ANALYST
from app.core.security import (
    AuthError,
    WeakPasswordError,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.core.token_store import token_store
from app.models.user import User
from app.schemas.auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    OidcAuthorizeResponse,
    OidcConfigRead,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenPair,
)
from app.schemas.common import Envelope
from app.schemas.user import UserRead
from app.services import oidc as oidc_service
from app.services.audit import audit, client_ip_from
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("sentinel.auth")
router = APIRouter(prefix="/auth", tags=["auth"])

BearerToken = Annotated[str, Depends(get_bearer_token)]
CurrentUser = Annotated[User, Depends(get_current_user)]


async def _find_user(db: AsyncSession, identifier: str) -> User | None:
    stmt = select(User).where(
        or_(User.email == identifier.lower().strip(), User.username == identifier)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


def _token_pair(user: User) -> TokenPair:
    access = create_access_token(user.id, user.role)
    refresh = create_refresh_token(user.id, user.role, uuid.uuid4().hex)
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_expires_in=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )


def _reject_weak_password(password: str, *, email: str = "", username: str = "") -> None:
    try:
        validate_password_strength(password, email=email, username=username)
    except WeakPasswordError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/register", response_model=Envelope[UserRead])
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def register(
    request: Request,
    payload: RegisterRequest,
    db: DbSession,
) -> Envelope[UserRead]:
    request_id = get_request_id(request)
    email = payload.email.lower().strip()

    if await db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email already registered")
    if await db.scalar(select(User.id).where(User.username == payload.username)):
        raise HTTPException(status_code=409, detail="Username already taken")
    _reject_weak_password(payload.password, email=email, username=payload.username)

    user = User(
        email=email,
        username=payload.username,
        full_name=payload.full_name,
        role=ROLE_ANALYST,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await audit(
        db,
        action="user.register",
        resource=f"user:{user.id}",
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Envelope(success=True, data=UserRead.model_validate(user), request_id=request_id)


@router.post("/login", response_model=Envelope[TokenPair])
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def login(
    request: Request,
    payload: LoginRequest,
    db: DbSession,
) -> Envelope[TokenPair]:
    request_id = get_request_id(request)
    user = await _find_user(db, payload.identifier)
    now = datetime.now(UTC)

    if user is None:
        await audit(
            db,
            action="auth.login_failed",
            resource="auth",
            ip=client_ip_from(request),
            user_agent=request.headers.get("user-agent"),
            details={"identifier": payload.identifier},
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.locked_until is not None and user.locked_until > now:
        await audit(
            db,
            action="auth.login_blocked",
            resource=f"user:{user.id}",
            ip=client_ip_from(request),
            details={"reason": "temporarily_locked"},
        )
        raise HTTPException(status_code=403, detail="Account is temporarily locked")

    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= settings.LOGIN_MAX_FAILED_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
            user.failed_login_attempts = 0
        await db.commit()
        await audit(
            db,
            action="auth.login_failed",
            resource=f"user:{user.id}",
            ip=client_ip_from(request),
            user_agent=request.headers.get("user-agent"),
            details={"identifier": payload.identifier, "attempt": user.failed_login_attempts},
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        await audit(
            db,
            action="auth.login_blocked",
            resource=f"user:{user.id}",
            ip=client_ip_from(request),
            details={"reason": "inactive"},
        )
        raise HTTPException(status_code=403, detail="Account is inactive")

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    await db.commit()
    await audit(
        db,
        action="auth.login",
        resource=f"user:{user.id}",
        actor_id=user.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Envelope(success=True, data=_token_pair(user), request_id=request_id)


@router.post("/refresh", response_model=Envelope[TokenPair])
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def refresh(
    request: Request,
    payload: RefreshRequest,
    db: DbSession,
) -> Envelope[TokenPair]:
    request_id = get_request_id(request)
    try:
        claims = decode_refresh_token(payload.refresh_token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=exc.code) from exc

    user = await db.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    if await token_store.is_used(claims["jti"]):
        # A rotated refresh token was presented again: assume theft, revoke all.
        await token_store.revoke_user_tokens(user.id)
        raise HTTPException(status_code=401, detail="Refresh token already used")

    revoked_since = await token_store.user_revoked_since(user.id)
    issued_at = datetime.fromtimestamp(claims["iat"], tz=UTC)
    if revoked_since is not None and issued_at < revoked_since:
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")

    await token_store.mark_used(claims["jti"], ttl=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400)
    await audit(
        db,
        action="auth.refresh",
        resource=f"user:{user.id}",
        actor_id=user.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Envelope(success=True, data=_token_pair(user), request_id=request_id)


@router.post("/logout", response_model=Envelope[bool])
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def logout(
    request: Request,
    token: BearerToken,
    user: CurrentUser,
    db: DbSession,
) -> Envelope[bool]:
    request_id = get_request_id(request)
    try:
        claims = decode_access_token(token)
    except AuthError:
        claims = {}
    if claims.get("jti"):
        await token_store.block_jti(claims["jti"], ttl=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    await token_store.revoke_user_tokens(user.id)
    await audit(
        db,
        action="auth.logout",
        resource=f"user:{user.id}",
        actor_id=user.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Envelope(success=True, data=True, request_id=request_id)


@router.post("/change-password", response_model=Envelope[bool])
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    user: CurrentUser,
    db: DbSession,
) -> Envelope[bool]:
    request_id = get_request_id(request)
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    _reject_weak_password(payload.new_password, email=user.email, username=user.username)
    user.hashed_password = hash_password(payload.new_password)
    await db.commit()
    await token_store.revoke_user_tokens(user.id)
    await audit(
        db,
        action="auth.change_password",
        resource=f"user:{user.id}",
        actor_id=user.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Envelope(success=True, data=True, request_id=request_id)


@router.post("/forgot-password", response_model=Envelope[bool])
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    db: DbSession,
) -> Envelope[bool]:
    """Issue a single-use reset token. Always returns success to avoid user
    enumeration; email delivery is stubbed (token is logged in non-prod)."""
    request_id = get_request_id(request)
    user = await db.scalar(select(User).where(User.email == payload.email.lower().strip()))
    if user is not None:
        reset_token = secrets.token_urlsafe(32)
        await token_store.store_reset_token(
            reset_token, user.id, settings.PASSWORD_RESET_TTL_MINUTES * 60
        )
        await audit(
            db,
            action="auth.forgot_password",
            resource=f"user:{user.id}",
            actor_id=user.id,
            ip=client_ip_from(request),
            user_agent=request.headers.get("user-agent"),
        )
        if settings.ENVIRONMENT != "prod":
            logger.info("password reset token for user=%s (dev stub): %s", user.id, reset_token)
    else:
        await audit(
            db,
            action="auth.forgot_password",
            resource="auth",
            ip=client_ip_from(request),
            details={"identifier": payload.email},
        )
    return Envelope(success=True, data=True, request_id=request_id)


@router.post("/reset-password", response_model=Envelope[bool])
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def reset_password(
    request: Request,
    payload: ResetPasswordRequest,
    db: DbSession,
) -> Envelope[bool]:
    request_id = get_request_id(request)
    user_id = await token_store.consume_reset_token(payload.token)
    user = await db.get(User, user_id) if user_id is not None else None
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    _reject_weak_password(payload.new_password, email=user.email, username=user.username)
    user.hashed_password = hash_password(payload.new_password)
    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()
    await token_store.revoke_user_tokens(user.id)
    await audit(
        db,
        action="auth.reset_password",
        resource=f"user:{user.id}",
        actor_id=user.id,
        ip=client_ip_from(request),
        user_agent=request.headers.get("user-agent"),
    )
    return Envelope(success=True, data=True, request_id=request_id)


@router.get("/me", response_model=Envelope[UserRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def me(
    request: Request,
    user: CurrentUser,
) -> Envelope[UserRead]:
    return Envelope(
        success=True,
        data=UserRead.model_validate(user),
        request_id=get_request_id(request),
    )


# --- OIDC single sign-on (Phase 9) -------------------------------------------


def _oidc_redirect_uri(request: Request) -> str:
    return str(request.base_url).rstrip("/") + settings.OIDC_REDIRECT_PATH


def _oidc_subject_email(claims: dict[str, Any]) -> str:
    email = oidc_service.subject_from_claims(claims)
    if settings.OIDC_DOMAIN and not email.endswith(f"@{settings.OIDC_DOMAIN}"):
        raise HTTPException(status_code=403, detail="Email domain not allowed by OIDC_DOMAIN")
    return email


@router.get("/oidc/config", response_model=Envelope[OidcConfigRead])
@limiter.limit(settings.RATE_LIMIT_API)
async def oidc_config(request: Request) -> Envelope[OidcConfigRead]:
    return Envelope(
        success=True,
        data=OidcConfigRead(
            enabled=oidc_service.oidc_enabled(),
            issuer=settings.OIDC_ISSUER,
            client_id=settings.OIDC_CLIENT_ID,
            scopes=settings.OIDC_SCOPES,
            redirect_path=settings.OIDC_REDIRECT_PATH,
        ),
        request_id=get_request_id(request),
    )


@router.get("/oidc/authorize", response_model=Envelope[OidcAuthorizeResponse])
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def oidc_authorize(request: Request) -> Envelope[OidcAuthorizeResponse]:
    """Start the authorization-code flow: issue a ``state``/``nonce`` pair,
    persist them, and return the provider's authorization URL."""
    request_id = get_request_id(request)
    if not oidc_service.oidc_enabled():
        raise HTTPException(status_code=404, detail="OIDC is not enabled")
    state = secrets.token_urlsafe(24)
    nonce = oidc_service.generate_nonce()
    payload = f"nonce:{nonce}"
    await token_store.store_oidc_state(state, payload, settings.OIDC_STATE_TTL_SECONDS)
    try:
        async with httpx.AsyncClient() as http:
            url = await oidc_service.authorization_url(
                http,
                state=state,
                nonce=nonce,
                redirect_uri=_oidc_redirect_uri(request),
            )
    except oidc_service.OidcError as exc:
        await token_store.consume_oidc_state(state)
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return Envelope(
        success=True,
        data=OidcAuthorizeResponse(url=url, state=state),
        request_id=request_id,
    )


@router.get("/oidc/callback")
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def oidc_callback(
    request: Request,
    db: DbSession,
    code: str = Query(min_length=1),
    state: str = Query(min_length=1),
) -> RedirectResponse:
    """Complete the flow: validate ``state``, exchange ``code`` for tokens,
    verify the ID token, then auto-provision/lookup the user and redirect the
    browser back to the SPA with the token pair in a URL fragment."""
    payload = await token_store.consume_oidc_state(state)
    if payload is None or not payload.startswith("nonce:"):
        raise HTTPException(status_code=400, detail="Invalid or expired OIDC state")
    nonce = payload.removeprefix("nonce:")
    if not nonce:
        raise HTTPException(status_code=400, detail="Invalid or expired OIDC state")

    try:
        async with httpx.AsyncClient() as http:
            tokens = await oidc_service.exchange_code(code, _oidc_redirect_uri(request), http)
            claims = await oidc_service.verify_id_token(tokens.id_token, nonce, http)
    except oidc_service.OidcError as exc:
        await audit(
            db,
            action="auth.oidc_failed",
            resource="auth",
            ip=client_ip_from(request),
            user_agent=request.headers.get("user-agent"),
            details={"error": str(exc)},
        )
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    email = _oidc_subject_email(claims)
    user = await db.scalar(select(User).where(User.email == email))
    if user is not None and not user.is_active:
        raise HTTPException(status_code=403, detail="Account is inactive")
    if user is None:
        username = email.partition("@")[0] or claims.get("preferred_username", "oidc")
        if await db.scalar(select(User.id).where(User.username == username)):
            username = f"{username}.{uuid.uuid4().hex[:6]}"
        user = User(
            email=email,
            username=username,
            full_name=claims.get("name"),
            role=ROLE_ANALYST,
            hashed_password=hash_password(secrets.token_urlsafe(32)),
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        await audit(
            db,
            action="auth.oidc_provision",
            resource=f"user:{user.id}",
            actor_id=user.id,
            ip=client_ip_from(request),
            user_agent=request.headers.get("user-agent"),
        )
    else:
        user.last_login_at = datetime.now(UTC)
        await db.commit()
        await audit(
            db,
            action="auth.login",
            resource=f"user:{user.id}",
            actor_id=user.id,
            ip=client_ip_from(request),
            user_agent=request.headers.get("user-agent"),
        )
    pair = _token_pair(user)
    fragment = (
        f"access_token={pair.access_token}"
        f"&refresh_token={pair.refresh_token}"
        f"&expires_in={pair.expires_in}"
        f"&refresh_expires_in={pair.refresh_expires_in}"
    )
    return RedirectResponse(
        url=f"{settings.FRONTEND_URL}/#/auth/oidc/callback?{fragment}", status_code=302
    )
