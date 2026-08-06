"""User schemas (auth implemented in Phase 3)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    username: str
    full_name: str | None = None
    role: str
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)
    role: str = "analyst"


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, max_length=255)
    role: str | None = None
    is_active: bool | None = None


class UserList(BaseModel):
    items: list[UserRead]
    total: int
    page: int
    page_size: int
