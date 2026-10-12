"""Adversarial Security Testbed for Zero-Trust Access Control Platform.

Tests platform resilience against real-world adversarial attacks:
1. Forged / Tampered device posture claims
2. Stolen session token reuse from unauthorized devices (Pass-the-Cookie)
3. Revoked session token reuse attempts
4. Malicious SQL injection payloads in ABAC policy rules and session queries
5. Extreme boundary conditions and trust score manipulation
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from zero_trust.db.database import DatabaseManager
from zero_trust.engine.pdp import PolicyDecisionPoint
from zero_trust.engine.trust_calculator import TrustCalculator
from zero_trust.models.enums import (
    AccessDecision,
    AuthenticationStrength,
    DeviceHealthStatus,
    PolicyEffect,
    SensitivityLevel,
)
from zero_trust.models.schemas import (
    AccessRequest,
    DeviceContext,
    NetworkContext,
    ResourceContext,
    SubjectContext,
    ZeroTrustPolicy,
)
from zero_trust.pep.gateway import PEPGateway
from zero_trust.sessions.manager import SessionManager


def test_adversarial_forged_device_posture_compromised_override() -> None:
    """Adversary claims high-privilege credentials on compromised device."""
    calc = TrustCalculator()
    pdp = PolicyDecisionPoint(trust_calculator=calc)

    # Attacker supplies high clearance role, but endpoint telemetry indicates compromise
    subject = SubjectContext(
        subject_id="admin@corp.example",
        roles=["root", "cloud_admin"],
        auth_strength=AuthenticationStrength.FIDO2_HARDWARE_KEY,
        is_privileged=True,
        clearance_level=SensitivityLevel.CRITICAL,
    )
    compromised_device = DeviceContext(
        device_id="DEV-INFECTED",
        os_name="Linux",
        os_version="6.5.0",
        disk_encrypted=True,
        edr_active=False,
        is_jailbroken=True,
        health_status=DeviceHealthStatus.COMPROMISED,
        fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
    )
    req = AccessRequest(
        subject=subject,
        device=compromised_device,
        network=NetworkContext(ip_address="192.168.1.10"),
        resource=ResourceContext(
            resource_id="/secrets/database",
            resource_type="secret",
            action="read",
            sensitivity_level=SensitivityLevel.CRITICAL,
        ),
    )

    eval_result = pdp.evaluate(req)
    assert eval_result.decision == AccessDecision.DENY
    assert eval_result.trust_score.total_score <= 15.0
    assert any("compromised" in r.lower() for r in eval_result.reasons)


def test_adversarial_pass_the_cookie_token_exfiltration() -> None:
    """Attacker captures valid token and replays from different machine."""
    policy = ZeroTrustPolicy(
        policy_id="POL-DEV",
        name="Dev Access",
        effect=PolicyEffect.PERMIT,
        priority=10,
        min_trust_score=50.0,
        allowed_roles=["developer"],
    )
    pdp = PolicyDecisionPoint(policies=[policy])
    pep = PEPGateway(pdp)

    legit_device_hash = "sha256:legitimate-corporate-hardware-mac-001"
    token = pep.create_bound_token(
        subject_id="alice@corp.example",
        device_fingerprint=legit_device_hash,
        resource_id="/api/git/repo",
    )

    # Attacker machine has different hardware fingerprint
    attacker_device_hash = "sha256:attacker-rogue-virtual-machine-999"
    verified_claims = pep.verify_token(
        token=token,
        expected_device_fingerprint=attacker_device_hash,
        expected_resource_id="/api/git/repo",
    )
    # Verification MUST fail
    assert verified_claims is None


def test_adversarial_revoked_session_reuse_blocked() -> None:
    """Adversary attempts to continue using an active session after instant revocation."""
    session_mgr = SessionManager()
    session = session_mgr.register_session(
        subject_id="victim@corp.example",
        device_id="DEV-V1",
        device_fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        resource_id="/api/data",
        session_token="token-session-12345",
        ip_address="10.0.0.1",
    )

    # Security team detects compromise and revokes session
    session_mgr.revoke_session(session.session_id, "SOC Quarantine Order")

    # Attacker presents session for verification
    device = DeviceContext(
        device_id="DEV-V1",
        os_name="macOS",
        os_version="14.0",
        disk_encrypted=True,
        edr_active=True,
        fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
    )
    valid, reason = session_mgr.continuous_verify_posture(
        session.session_id,
        device,
        NetworkContext(ip_address="10.0.0.1"),
    )
    assert valid is False
    assert "already revoked" in (reason or "").lower()


def test_adversarial_sql_injection_resilience(temp_db_path: Path) -> None:
    """Verify parameterized queries withstand SQL injection payloads."""
    db = DatabaseManager(db_path=temp_db_path)

    # Attacker crafts SQL injection in policy_id and name
    malicious_policy_id = "'; DROP TABLE policies; --"
    malicious_name = "' OR '1'='1"

    malicious_policy = ZeroTrustPolicy(
        policy_id=malicious_policy_id,
        name=malicious_name,
        effect=PolicyEffect.PERMIT,
        priority=1,
        min_trust_score=50.0,
    )

    db.save_policy(malicious_policy)

    # Verify table was NOT dropped
    retrieved = db.get_policy(malicious_policy_id)
    assert retrieved is not None
    assert retrieved.name == malicious_name

    # Check that policies table still exists and operates normally
    assert len(db.list_policies()) == 1


def test_adversarial_invalid_ip_network_context() -> None:
    """Attacker injects malformed or command injection IP strings."""
    with pytest.raises(ValidationError):
        NetworkContext(ip_address="127.0.0.1; rm -rf /")

    with pytest.raises(ValidationError):
        NetworkContext(ip_address="999.999.999.999")
