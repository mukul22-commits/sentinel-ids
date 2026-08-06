"""Pytest bootstrap: force the test environment before app modules load."""

from __future__ import annotations

import os

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6390/0")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
