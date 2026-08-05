"""Shared FastAPI dependencies for API endpoints."""

from __future__ import annotations

from fastapi import Request


def get_request_id(request: Request) -> str:
    """Return the request id assigned by RequestIdMiddleware (if any)."""
    return request.headers.get("x-request-id", "")
