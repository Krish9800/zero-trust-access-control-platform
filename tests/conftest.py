"""Pytest fixtures and configuration for Zero-Trust Access Control Platform."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from zero_trust.config.settings import Settings


@pytest.fixture
def temp_db_path() -> Generator[Path, None, None]:
    """Provide a temporary database file path and clean up after test."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir) / "test_zero_trust.db"


@pytest.fixture
def test_settings(temp_db_path: Path) -> Settings:
    """Provide a test Settings instance with isolated database path."""
    return Settings(
        environment="testing",
        debug=True,
        db_path=temp_db_path,
        jwt_secret_key="test-secret-key-that-is-at-least-32-chars-long!",
        token_lifetime_seconds=300,
        trust_score_allow_threshold=75.0,
        trust_score_step_up_threshold=50.0,
        trust_score_deny_threshold=30.0,
    )
