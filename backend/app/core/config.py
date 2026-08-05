"""Application configuration, loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["dev", "test", "prod"]


class Settings(BaseSettings):
    """Typed application settings driven by environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    APP_NAME: str = "Sentinel IDS Platform"
    APP_VERSION: str = "3.0.0"
    ENVIRONMENT: Environment = "dev"

    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_ids"
    )
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_RECYCLE_SECONDS: int = 300

    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_CACHE_TTL_SECONDS: int = 300

    CELERY_TASK_ALWAYS_EAGER: bool = False
    CELERY_WORKER_CONCURRENCY: int = 4
    CELERY_BEAT_SCHEDULE_ENABLED: bool = True

    TIMESCALE_CHUNK_INTERVAL_DAYS: int = 1

    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    SECRET_KEY: str = "change-me-in-production"

    @model_validator(mode="after")
    def validate_environment(self) -> Self:
        if self.ENVIRONMENT == "prod" and self.SECRET_KEY == "change-me-in-production":
            raise ValueError("SECRET_KEY must be set to a strong value in production")
        if not self.DATABASE_URL.startswith("postgresql+asyncpg://"):
            raise ValueError("DATABASE_URL must use the asyncpg driver (postgresql+asyncpg://)")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return a cached, validated Settings instance."""
    return Settings()


settings = get_settings()
