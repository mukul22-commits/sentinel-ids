"""Test environment setup. Loaded before any test module imports the app."""

from __future__ import annotations

import os

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://sentinel:sentinel@localhost:59999/sentinel_ids_test",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:59999/0")
