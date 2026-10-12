"""Unit tests for Phase 7: SQLite WAL Persistence Layer."""

from pathlib import Path

import pytest

from zero_trust.db.database import DatabaseManager
from zero_trust.models.enums import (
    AccessDecision,
    NetworkZone,
    PolicyEffect,
    SensitivityLevel,
)
from zero_trust.models.schemas import (
    AccessEvaluationResult,
    TrustScoreBreakdown,
    ZeroTrustPolicy,
)
from zero_trust.sessions.manager import ActiveSession


@pytest.fixture
def db_manager(temp_db_path: Path) -> DatabaseManager:
    """Fixture returning an initialized DatabaseManager on a temporary database."""
    return DatabaseManager(db_path=temp_db_path)


def test_schema_initialization_wal_pragmas(db_manager: DatabaseManager) -> None:
    """Verify tables are created and SQLite runs in WAL mode."""
    with db_manager.transaction() as conn:
        cursor = conn.execute("PRAGMA journal_mode;")
        row = cursor.fetchone()
        assert row[0].lower() == "wal"

        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
        tables = [r[0] for r in cursor.fetchall()]
        assert "policies" in tables
        assert "access_evaluations" in tables
        assert "active_sessions" in tables
        assert "audit_events" in tables


def test_policy_crud_operations(db_manager: DatabaseManager) -> None:
    """Verify saving, retrieving, listing, and deleting ZeroTrustPolicy records."""
    policy = ZeroTrustPolicy(
        policy_id="POL-DB-TEST-01",
        name="DB Test Policy",
        description="Test policy for SQLite WAL",
        effect=PolicyEffect.PERMIT,
        priority=25,
        min_trust_score=70.0,
        allowed_roles=["developer"],
        allowed_departments=["R&D"],
        max_sensitivity=SensitivityLevel.HIGH,
        require_encryption=True,
        require_edr=True,
        conditions={"env": "staging"},
    )

    db_manager.save_policy(policy)

    # Retrieve
    fetched = db_manager.get_policy("POL-DB-TEST-01")
    assert fetched is not None
    assert fetched.policy_id == policy.policy_id
    assert fetched.name == policy.name
    assert fetched.priority == 25
    assert fetched.conditions["env"] == "staging"

    # List
    all_policies = db_manager.list_policies()
    assert len(all_policies) == 1
    assert all_policies[0].policy_id == "POL-DB-TEST-01"

    # Delete
    deleted = db_manager.delete_policy("POL-DB-TEST-01")
    assert deleted is True
    assert db_manager.get_policy("POL-DB-TEST-01") is None


def test_record_and_list_evaluations(db_manager: DatabaseManager) -> None:
    """Verify recording and querying PDP evaluation audit records."""
    breakdown = TrustScoreBreakdown(
        total_score=88.0,
        device_score=90.0,
        identity_score=85.0,
        network_score=90.0,
        behavior_score=87.0,
        risk_penalties=[],
    )
    eval_result = AccessEvaluationResult(
        request_id="REQ-DB-001",
        decision=AccessDecision.ALLOW,
        trust_score=breakdown,
        matched_policy_id=None,
        reasons=["Healthy device and corporate subnet"],
    )

    db_manager.record_evaluation(
        evaluation=eval_result,
        subject_id="alice@corp.example",
        device_id="DEV-001",
        resource_id="/api/v1/assets",
    )

    evals = db_manager.list_evaluations()
    assert len(evals) == 1
    assert evals[0]["subject_id"] == "alice@corp.example"
    assert evals[0]["decision"] == "ALLOW"
    assert evals[0]["total_trust_score"] == 88.0


def test_session_persistence(db_manager: DatabaseManager) -> None:
    """Verify saving, retrieving, and listing active sessions."""
    session = ActiveSession(
        subject_id="bob@corp.example",
        device_id="DEV-002",
        device_fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        resource_id="/vault/prod",
        session_token="token-val-12345",
        ip_address="10.100.1.20",
        network_zone=NetworkZone.CORPORATE_MANAGED,
    )

    db_manager.save_session(session)

    fetched = db_manager.get_session(session.session_id)
    assert fetched is not None
    assert fetched.subject_id == "bob@corp.example"
    assert fetched.is_revoked is False

    active_list = db_manager.list_sessions(active_only=True)
    assert len(active_list) == 1


def test_log_audit_event(db_manager: DatabaseManager) -> None:
    """Verify append-only audit event logging."""
    event_id = db_manager.log_audit_event(
        event_type="SESSION_REVOCATION",
        actor_id="admin@corp.example",
        target_id="SESSION-999",
        details={"reason": "Compromise detection"},
    )
    assert event_id is not None
    assert len(event_id) > 10
