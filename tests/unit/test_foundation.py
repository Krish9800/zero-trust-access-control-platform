"""Unit tests for Phase 1 Foundation & Settings."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from zero_trust import __version__
from zero_trust.config.settings import Settings, get_settings


def test_package_version() -> None:
    """Verify package version is defined and valid."""
    assert __version__ == "0.1.0"


def test_default_settings() -> None:
    """Verify default settings instantiation and NIST-aligned defaults."""
    settings = Settings()
    assert settings.app_name == "Zero-Trust Access Control Platform"
    assert settings.environment == "development"
    assert settings.debug is False
    assert settings.trust_score_allow_threshold == 75.0
    assert settings.trust_score_step_up_threshold == 50.0
    assert settings.trust_score_deny_threshold == 30.0
    # Component weights sum to 1.0
    total_weights = (
        settings.device_weight
        + settings.identity_weight
        + settings.network_weight
        + settings.behavior_weight
    )
    assert pytest.approx(total_weights, rel=1e-5) == 1.0


def test_get_settings_cached() -> None:
    """Verify get_settings returns cached singleton."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_custom_settings(test_settings: Settings, temp_db_path: Path) -> None:
    """Verify settings customization via constructor arguments."""
    assert test_settings.environment == "testing"
    assert test_settings.debug is True
    assert test_settings.db_path == temp_db_path
    assert len(test_settings.jwt_secret_key) >= 32


def test_settings_validation_errors() -> None:
    """Verify validation constraints on settings fields."""
    # Secret key too short (< 32 chars)
    with pytest.raises(ValidationError):
        Settings(jwt_secret_key="short")

    # Invalid port (< 1024)
    with pytest.raises(ValidationError):
        Settings(api_port=80)

    # Invalid threshold (> 100)
    with pytest.raises(ValidationError):
        Settings(trust_score_allow_threshold=150.0)


def test_settings_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify environment variable prefix overrides."""
    monkeypatch.setenv("ZTAC_APP_NAME", "Overridden App Name")
    monkeypatch.setenv("ZTAC_TRUST_SCORE_ALLOW_THRESHOLD", "85.0")
    settings = Settings()
    assert settings.app_name == "Overridden App Name"
    assert settings.trust_score_allow_threshold == 85.0
