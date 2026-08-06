"""Global exception handlers that wrap errors in the standard Envelope."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.schemas.common import Envelope

logger = logging.getLogger("sentinel.errors")


def _request_id(request: Request) -> str:
    return request.headers.get("x-request-id", "")


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Wrap HTTPException details in an Envelope (keeps auth errors consistent)."""
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    body: Envelope[Any] = Envelope(
        success=False, data=None, error=detail, request_id=_request_id(request)
    )
    return JSONResponse(status_code=exc.status_code, content=body.model_dump())


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return a 422 Envelope for malformed request bodies/params."""
    body: Envelope[Any] = Envelope(
        success=False,
        data=None,
        error="Request validation failed",
        request_id=_request_id(request),
    )
    return JSONResponse(status_code=422, content=body.model_dump())


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Never leak internals: log the traceback, return a generic 500 Envelope."""
    logger.exception("unhandled error while processing %s %s", request.method, request.url.path)
    body: Envelope[Any] = Envelope(
        success=False,
        data=None,
        error="Internal server error",
        request_id=_request_id(request),
    )
    return JSONResponse(status_code=500, content=body.model_dump())
