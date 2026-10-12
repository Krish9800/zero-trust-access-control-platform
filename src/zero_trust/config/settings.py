"""Application configuration using Pydantic Settings.

Manages cryptographic keys, trust evaluation weights, database connection,
and zero-trust policy defaults with strict typing and environment loading.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Zero-Trust Access Control Platform runtime settings."""

    model_config = SettingsConfigDict(
        env_prefix="ZTAC_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General Application Settings
    app_name: str = Field(
        default="Zero-Trust Access Control Platform",
        description="Name of the zero-trust application",
    )
    environment: Literal["development", "staging", "production", "testing"] = Field(
        default="development",
        description="Deployment runtime environment",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug logging and diagnostic details",
    )

    # Database Configuration (SQLite WAL Mode)
    db_path: Path = Field(
        default=Path("data/zero_trust.db"),
        description="Path to SQLite database file",
    )
    db_timeout_seconds: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="SQLite transaction timeout in seconds",
    )

    # Cryptography & Token Configuration
    jwt_secret_key: str = Field(
        default="ztac-dev-secret-key-change-in-production-0123456789abcdef",
        min_length=32,
        description="Secret key used for signing ephemeral access tokens",
    )
    jwt_algorithm: str = Field(
        default="HS256",
        description="Cryptographic algorithm for token signatures",
    )
    token_lifetime_seconds: int = Field(
        default=900,  # 15 minutes default for Zero-Trust ephemeral tokens
        ge=60,
        le=86400,
        description="Default lifetime for access tokens in seconds",
    )

    # Dynamic Trust Engine Thresholds & Scoring
    trust_score_allow_threshold: float = Field(
        default=75.0,
        ge=0.0,
        le=100.0,
        description="Minimum trust score required for unconditional access",
    )
    trust_score_step_up_threshold: float = Field(
        default=50.0,
        ge=0.0,
        le=100.0,
        description="Trust score threshold below which step-up verification is required",
    )
    trust_score_deny_threshold: float = Field(
        default=30.0,
        ge=0.0,
        le=100.0,
        description="Trust score at or below which access is strictly denied",
    )

    # Trust Engine Component Weights (sum = 1.0)
    device_weight: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
        description="Weight allocated to device health & posture",
    )
    identity_weight: float = Field(
        default=0.25,
        ge=0.0,
        le=1.0,
        description="Weight allocated to subject authentication strength",
    )
    network_weight: float = Field(
        default=0.20,
        ge=0.0,
        le=1.0,
        description="Weight allocated to network location and CIDR trust",
    )
    behavior_weight: float = Field(
        default=0.20,
        ge=0.0,
        le=1.0,
        description="Weight allocated to temporal & geovelocity behavior",
    )

    # API Server Configuration
    api_host: str = Field(
        default="127.0.0.1",
        description="Host interface for FastAPI REST server",
    )
    api_port: int = Field(
        default=8000,
        ge=1024,
        le=65535,
        description="Port for FastAPI REST server",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()
