"""Shared API schemas: the standard response envelope."""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class Envelope(BaseModel, Generic[T]):
    """Standard response envelope for every v1 endpoint."""

    success: bool
    data: T | None = None
    error: str | None = None
    request_id: str | None = None


class ErrorEnvelope(BaseModel):
    """Envelope shape used when a v1 endpoint reports an error."""

    success: bool = False
    data: Any = None
    error: str
    request_id: str | None = None
