"""Integration tests for Phase 9: Typer CLI Commands."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from zero_trust.cli.main import app
from zero_trust.db.database import DatabaseManager
from zero_trust.models.enums import PolicyEffect
from zero_trust.models.schemas import ZeroTrustPolicy
from zero_trust.sessions.manager import ActiveSession


@pytest.fixture
def cli_runner() -> CliRunner:
    """Fixture returning Typer CliRunner."""
    return CliRunner()


def test_cli_policies_command(
    monkeypatch: pytest.MonkeyPatch, temp_db_path: Path, cli_runner: CliRunner
) -> None:
    """Verify `ztac policies` lists registered policies."""
    monkeypatch.setenv("ZTAC_DB_PATH", str(temp_db_path))
    db = DatabaseManager(db_path=temp_db_path)
    policy = ZeroTrustPolicy(
        policy_id="POL-CLI-01",
        name="CLI Test Policy",
        effect=PolicyEffect.PERMIT,
        priority=10,
        min_trust_score=75.0,
    )
    db.save_policy(policy)

    result = cli_runner.invoke(app, ["policies"])
    assert result.exit_code == 0
    assert "POL-CLI-01" in result.stdout
    assert "CLI Test Policy" in result.stdout


def test_cli_eval_command(
    monkeypatch: pytest.MonkeyPatch, temp_db_path: Path, cli_runner: CliRunner
) -> None:
    """Verify `ztac eval` evaluates request and displays styled table."""
    monkeypatch.setenv("ZTAC_DB_PATH", str(temp_db_path))
    db = DatabaseManager(db_path=temp_db_path)
    policy = ZeroTrustPolicy(
        policy_id="POL-CLI-ALLOW",
        name="CLI Allow Policy",
        effect=PolicyEffect.PERMIT,
        priority=5,
        allowed_roles=["employee"],
        min_trust_score=50.0,
    )
    db.save_policy(policy)

    result = cli_runner.invoke(
        app,
        ["eval", "--subject", "alice@corp.example", "--roles", "employee", "--resource", "/data"],
    )
    assert result.exit_code == 0
    assert "Zero-Trust Access Evaluation Result" in result.stdout
    assert "ALLOW" in result.stdout


def test_cli_sessions_and_revoke_command(
    monkeypatch: pytest.MonkeyPatch, temp_db_path: Path, cli_runner: CliRunner
) -> None:
    """Verify `ztac sessions` and `ztac revoke` commands."""
    monkeypatch.setenv("ZTAC_DB_PATH", str(temp_db_path))
    db = DatabaseManager(db_path=temp_db_path)

    session = ActiveSession(
        subject_id="bob@corp.example",
        device_id="DEV-CLI",
        device_fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        resource_id="/vault/secret",
        session_token="token-cli",
        ip_address="10.0.0.5",
    )
    db.save_session(session)

    # List active sessions
    res_list = cli_runner.invoke(app, ["sessions"])
    assert res_list.exit_code == 0
    assert "bob@corp.example" in res_list.stdout

    # Revoke session
    res_revoke = cli_runner.invoke(
        app, ["revoke", session.session_id, "--reason", "Compromised device"]
    )
    assert res_revoke.exit_code == 0
    assert "revoked" in res_revoke.stdout.lower()

    # Revoking non-existent session fails with code 1
    res_404 = cli_runner.invoke(app, ["revoke", "non-existent-session-id"])
    assert res_404.exit_code == 1
