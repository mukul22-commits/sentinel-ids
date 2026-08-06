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

    # --- Auth (Phase 3) ---
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "sentinel-ids"
    JWT_AUDIENCE: str = "sentinel-ids-api"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    BCRYPT_ROUNDS: int = 12
    PASSWORD_RESET_TTL_MINUTES: int = 15
    LOGIN_MAX_FAILED_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15
    MIN_PASSWORD_LENGTH: int = 12

    # --- Rate limiting (Phase 3) ---
    RATE_LIMIT_AUTH: str = "5/minute"
    RATE_LIMIT_API: str = "100/minute"

    # --- Detection engine (Phase 5) ---
    DETECTION_ENABLED: bool = True
    ML_DETECTOR_ENABLED: bool = False
    ML_MODEL_PATH: str = "app/ml_models/flow_anomaly.joblib"

    @property
    def rate_limit_storage_uri(self) -> str:
        """Rate-limit storage: in-memory for tests, Redis for dev/prod."""
        if self.ENVIRONMENT == "test":
            return "memory://"
        return self.REDIS_URL

    @model_validator(mode="after")
    def validate_environment(self) -> Self:
        if self.ENVIRONMENT == "prod" and (
            self.SECRET_KEY == "change-me-in-production" or len(self.SECRET_KEY) < 32
        ):
            raise ValueError(
                "SECRET_KEY must be a strong value of at least 32 characters in production"
            )
        if not self.DATABASE_URL.startswith("postgresql+asyncpg://"):
            raise ValueError("DATABASE_URL must use the asyncpg driver (postgresql+asyncpg://)")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return a cached, validated Settings instance."""
    return Settings()


settings = get_settings()
