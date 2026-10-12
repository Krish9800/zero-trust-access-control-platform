"""Unit tests for Phase 5: Policy Enforcement Point (PEP) Gateway."""

import pytest

from tests.unit.test_pdp import create_request
from zero_trust.engine.pdp import PolicyDecisionPoint
from zero_trust.models.enums import (
    AccessDecision,
    PolicyEffect,
)
from zero_trust.models.schemas import ZeroTrustPolicy
from zero_trust.pep.gateway import PEPGateway


@pytest.fixture
def allow_policy() -> ZeroTrustPolicy:
    """Fixture providing a standard permit policy."""
    return ZeroTrustPolicy(
        policy_id="POL-ALLOW-STANDARD",
        name="Allow Standard Access",
        effect=PolicyEffect.PERMIT,
        priority=50,
        min_trust_score=50.0,
        allowed_roles=["employee"],
        require_encryption=True,
        require_edr=True,
    )


def test_pep_intercept_allow_issues_token(allow_policy: ZeroTrustPolicy) -> None:
    """Verify PEP intercepts ALLOW evaluation and issues a cryptographically signed token."""
    pdp = PolicyDecisionPoint(policies=[allow_policy])
    pep = PEPGateway(pdp)
    req = create_request()

    result = pep.intercept_request(req)
    assert result.decision == AccessDecision.ALLOW
    assert result.session_token is not None

    # Verify issued token
    claims = pep.verify_token(
        token=result.session_token,
        expected_device_fingerprint=req.device.fingerprint_hash,
        expected_resource_id=req.resource.resource_id,
    )
    assert claims is not None
    assert claims["sub"] == req.subject.subject_id
    assert claims["res"] == req.resource.resource_id


def test_pep_token_binding_prevents_device_theft(allow_policy: ZeroTrustPolicy) -> None:
    """Verify stolen token presented by a different device fingerprint is rejected."""
    pdp = PolicyDecisionPoint(policies=[allow_policy])
    pep = PEPGateway(pdp)
    req = create_request()

    result = pep.intercept_request(req)
    assert result.session_token is not None

    # Attacker on rogue device attempts to use stolen token
    rogue_fingerprint = "sha256:attacker-different-hardware-hash-12345"
    claims = pep.verify_token(
        token=result.session_token,
        expected_device_fingerprint=rogue_fingerprint,
    )
    assert claims is None  # Binding validation fails


def test_pep_token_signature_tampering_rejected(allow_policy: ZeroTrustPolicy) -> None:
    """Verify modifying token payload invalidates HMAC signature."""
    pdp = PolicyDecisionPoint(policies=[allow_policy])
    pep = PEPGateway(pdp)
    req = create_request()

    result = pep.intercept_request(req)
    assert result.session_token is not None

    # Tamper with payload portion
    payload_raw, sig = result.session_token.rsplit(".", 1)
    tampered_payload = payload_raw.replace("alice@corp.example", "admin@corp.example")
    tampered_token = f"{tampered_payload}.{sig}"

    claims = pep.verify_token(
        token=tampered_token,
        expected_device_fingerprint=req.device.fingerprint_hash,
    )
    assert claims is None


def test_pep_expired_token_rejected(allow_policy: ZeroTrustPolicy) -> None:
    """Verify token past TTL is rejected."""
    pdp = PolicyDecisionPoint(policies=[allow_policy])
    pep = PEPGateway(pdp)
    req = create_request()

    # Create token with -10 second lifetime (expired)
    expired_token = pep.create_bound_token(
        subject_id=req.subject.subject_id,
        device_fingerprint=req.device.fingerprint_hash,
        resource_id=req.resource.resource_id,
        lifetime_seconds=-10,
    )

    claims = pep.verify_token(
        token=expired_token,
        expected_device_fingerprint=req.device.fingerprint_hash,
    )
    assert claims is None


def test_pep_intercept_deny_does_not_issue_token() -> None:
    """Verify DENY evaluation does not issue a session token."""
    pdp = PolicyDecisionPoint(policies=[])  # Default deny
    pep = PEPGateway(pdp)
    req = create_request()

    result = pep.intercept_request(req)
    assert result.decision == AccessDecision.DENY
    assert result.session_token is None


def test_pep_verify_token_malformed_formats() -> None:
    """Verify malformed token formats are safely rejected."""
    pdp = PolicyDecisionPoint(policies=[])
    pep = PEPGateway(pdp)

    assert pep.verify_token("invalid-no-dot", "dfp") is None
    assert pep.verify_token("not-json.sig", "dfp") is None
    assert pep.verify_token("{}.sig", "dfp") is None
