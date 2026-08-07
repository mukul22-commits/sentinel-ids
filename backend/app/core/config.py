"""Application configuration, loaded from environment variables."""

from __future__ import annotations

import os
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
    LOG_LEVEL: str = "INFO"

    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_ids"
    )
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_RECYCLE_SECONDS: int = 300
    DB_POOL_PRE_PING: bool = True
    DB_POOL_TIMEOUT: int = 10

    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_CACHE_TTL_SECONDS: int = 300

    CELERY_TASK_ALWAYS_EAGER: bool = False
    CELERY_WORKER_CONCURRENCY: int = 4
    CELERY_BEAT_SCHEDULE_ENABLED: bool = True
    CELERY_WORKER_MAX_TASKS_PER_CHILD: int = 200

    TIMESCALE_CHUNK_INTERVAL_DAYS: int = 1

    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    SECRET_KEY: str = "change-me-in-production"
    FRONTEND_URL: str = "http://localhost:5173"

    # --- Production hardening (Phase 7) ---
    UVICORN_WORKERS: int = 1
    UVICORN_GRACEFUL_TIMEOUT: int = 30
    PROMETHEUS_MULTIPROC_DIR: str | None = None

    # --- Connector plugins (Phase 7) ---
    HTTP_CONNECTOR_URL: str | None = None
    HTTP_CONNECTOR_TOKEN: str | None = None
    HTTP_CONNECTOR_TIMEOUT_SECONDS: float = 5.0
    EMAIL_SMTP_HOST: str | None = None
    EMAIL_SMTP_PORT: int = 587
    EMAIL_SMTP_USERNAME: str | None = None
    EMAIL_SMTP_PASSWORD: str | None = None
    EMAIL_SMTP_USE_TLS: bool = True
    EMAIL_FROM_ADDR: str = "sentinel-ids@localhost"

    # --- External SIEM export (Phase 7) ---
    SIEM_EXPORT_ENABLED: bool = False
    SIEM_CEF_ENDPOINT_URL: str | None = None
    SIEM_AUTH_TOKEN: str | None = None
    SIEM_BATCH_SIZE: int = 100
    SIEM_EXPORT_SECONDS: int = 60
    SIEM_HTTP_TIMEOUT_SECONDS: float = 5.0

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

    # --- Live capture (Phase 6) ---
    CAPTURE_ENABLED: bool = True
    CAPTURE_CYCLE_SECONDS: int = 30
    SNIFF_INTERFACE: str | None = None
    SNIFF_COUNT: int = 100
    SNIFF_TIMEOUT: int = 5
    SURICATA_EVE_PATH: str | None = None
    ZEEK_CONN_LOG_PATH: str | None = None

    # --- ML retraining (Phase 6) ---
    ML_RETRAIN_MIN_SAMPLES: int = 500
    ML_RETRAIN_CONTAMINATION: float = 0.1

    # --- Fleet / multi-sensor management (Phase 8) ---
    SENSOR_TOKEN_BYTES: int = 32
    SENSOR_WATCHDOG_SECONDS: int = 30
    SENSOR_STALE_AFTER_SECONDS: int = 90

    # --- Advanced detection: YARA + neural autoencoder (Phase 9) ---
    YARA_DETECTOR_ENABLED: bool = True
    YARA_RULES_DIR: str = "app/yara_rules"
    YARA_MAX_PAYLOAD_BYTES: int = 1_048_576
    AUTOENCODER_DETECTOR_ENABLED: bool = False
    ML_AE_MODEL_PATH: str = "app/ml_models/flow_autoencoder.joblib"
    AUTOENCODER_THRESHOLD: float = 1.0

    # --- UEBA / behavioral analytics (Phase 9) ---
    UEBA_ENABLED: bool = True
    UEBA_PROFILES_PATH: str = "app/ueba_profiles/baselines.joblib"
    UEBA_WINDOW_HOURS: int = 24
    UEBA_MIN_SAMPLES: int = 20
    UEBA_THRESHOLD: float = 3.0

    # --- OIDC single sign-on (Phase 9) ---
    OIDC_ENABLED: bool = False
    OIDC_ISSUER: str | None = None
    OIDC_CLIENT_ID: str | None = None
    OIDC_CLIENT_SECRET: str | None = None
    OIDC_SCOPES: str = "openid email profile"
    OIDC_DOMAIN: str | None = None
    OIDC_REDIRECT_PATH: str = "/api/v1/auth/oidc/callback"
    OIDC_HTTP_TIMEOUT_SECONDS: float = 5.0
    OIDC_STATE_TTL_SECONDS: int = 600

    # --- Secret management (Phase 9) ---
    SECRET_KEY_FILE: str | None = None
    VAULT_URL: str | None = None
    VAULT_TOKEN: str | None = None
    VAULT_MOUNT: str = "secret"
    VAULT_PATH: str | None = None

    # --- SOAR connectors: firewall / EDR (Phase 9) ---
    OPNSENSE_CONNECTOR_URL: str | None = None
    OPNSENSE_CONNECTOR_KEY: str | None = None
    OPNSENSE_CONNECTOR_SECRET: str | None = None
    OPNSENSE_CONNECTOR_TIMEOUT_SECONDS: float = 5.0
    OPNSENSE_BLOCKLIST_ALIAS: str = "sentinel_blocklist"
    EDR_CONNECTOR_URL: str | None = None
    EDR_CONNECTOR_TOKEN: str | None = None
    EDR_CONNECTOR_TIMEOUT_SECONDS: float = 5.0

    @property
    def rate_limit_storage_uri(self) -> str:
        """Rate-limit storage: in-memory for tests, Redis for dev/prod."""
        if self.ENVIRONMENT == "test":
            return "memory://"
        return self.REDIS_URL

    @property
    def prometheus_multiproc_dir(self) -> str | None:
        """Return the Prometheus multiprocess dir, echoing it into the process env.

        ``prometheus_client`` must observe ``PROMETHEUS_MULTIPROC_DIR`` at import
        time to enable multiprocess (multi-worker HA) metric aggregation, so the
        environment variable is set here before any prometheus import happens.
        """
        directory = self.PROMETHEUS_MULTIPROC_DIR
        if directory:
            os.environ.setdefault("PROMETHEUS_MULTIPROC_DIR", directory)
        return directory

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
    instance = Settings()
    instance.prometheus_multiproc_dir  # noqa: B018 - sets PROMETHEUS_MULTIPROC_DIR before prometheus import
    return instance


settings = get_settings()
