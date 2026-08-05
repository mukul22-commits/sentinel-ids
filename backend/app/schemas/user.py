"""User schemas (auth lands in Phase 3)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class UserBase(BaseModel):
    email: str
    username: str
    role: str = "analyst"
    is_active: bool = True


class UserCreate(UserBase):
    hashed_password: str


class UserRead(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
