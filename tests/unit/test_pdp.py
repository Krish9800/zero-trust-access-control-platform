"""Unit tests for Phase 4: Policy Decision Point (PDP) & ABAC Engine."""

import pytest

from zero_trust.config.settings import Settings
from zero_trust.engine.pdp import PolicyDecisionPoint
from zero_trust.models.enums import (
    AccessDecision,
    AuthenticationStrength,
    DeviceHealthStatus,
    NetworkZone,
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


@pytest.fixture
def base_policy() -> ZeroTrustPolicy:
    """Fixture providing a standard corporate access policy."""
    return ZeroTrustPolicy(
        policy_id="POL-CORP-STANDARD",
        name="Standard Corporate Workload Access",
        effect=PolicyEffect.PERMIT,
        priority=100,
        min_trust_score=60.0,
        allowed_roles=["employee", "engineer"],
        allowed_departments=["Engineering", "IT"],
        max_sensitivity=SensitivityLevel.HIGH,
        require_encryption=True,
        require_edr=True,
    )


@pytest.fixture
def admin_policy() -> ZeroTrustPolicy:
    """Fixture providing a high-priority privileged access policy."""
    return ZeroTrustPolicy(
        policy_id="POL-ADMIN-CRITICAL",
        name="Critical Infrastructure Access",
        effect=PolicyEffect.PERMIT,
        priority=10,
        min_trust_score=80.0,
        allowed_roles=["secops", "cloud_admin"],
        max_sensitivity=SensitivityLevel.CRITICAL,
        require_encryption=True,
        require_edr=True,
        conditions={"resource_type": "secret_vault"},
    )


def create_request(
    subject_id: str = "alice@corp.example",
    roles: list[str] | None = None,
    departments: list[str] | None = None,
    auth_strength: AuthenticationStrength = AuthenticationStrength.FIDO2_HARDWARE_KEY,
    is_privileged: bool = False,
    disk_encrypted: bool = True,
    edr_active: bool = True,
    is_jailbroken: bool = False,
    health_status: DeviceHealthStatus = DeviceHealthStatus.HEALTHY,
    network_zone: NetworkZone = NetworkZone.CORPORATE_MANAGED,
    resource_id: str = "/api/v1/workloads",
    resource_type: str = "api",
    action: str = "read",
    sensitivity_level: SensitivityLevel = SensitivityLevel.MEDIUM,
    country_code: str = "US",
) -> AccessRequest:
    """Helper to assemble AccessRequest objects for PDP evaluation."""
    subject = SubjectContext(
        subject_id=subject_id,
        roles=roles if roles is not None else ["employee"],
        departments=departments if departments is not None else ["Engineering"],
        auth_strength=auth_strength,
        is_privileged=is_privileged,
    )
    device = DeviceContext(
        device_id="DEV-VALID-01",
        os_name="Ubuntu",
        os_version="24.04",
        disk_encrypted=disk_encrypted,
        edr_active=edr_active,
        is_jailbroken=is_jailbroken,
        health_status=health_status,
        fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
    )
    network = NetworkContext(
        ip_address="10.0.1.25",
        network_zone=network_zone,
        country_code=country_code,
    )
    resource = ResourceContext(
        resource_id=resource_id,
        resource_type=resource_type,
        action=action,
        sensitivity_level=sensitivity_level,
    )
    return AccessRequest(
        subject=subject,
        device=device,
        network=network,
        resource=resource,
    )


def test_pdp_allows_compliant_request(base_policy: ZeroTrustPolicy) -> None:
    """Verify PDP returns ALLOW when request matches policy and trust is high."""
    pdp = PolicyDecisionPoint(policies=[base_policy])
    req = create_request()

    result = pdp.evaluate(req)
    assert result.decision == AccessDecision.ALLOW
    assert result.matched_policy_id == base_policy.policy_id
    assert result.trust_score.total_score >= 75.0


def test_pdp_default_deny_when_no_policy_matches() -> None:
    """Verify default-deny when no policies match subject role."""
    pdp = PolicyDecisionPoint(policies=[])
    req = create_request()

    result = pdp.evaluate(req)
    assert result.decision == AccessDecision.DENY
    assert result.matched_policy_id is None
    assert any("Default Deny" in r for r in result.reasons)


def test_pdp_hard_deny_on_compromised_endpoint(base_policy: ZeroTrustPolicy) -> None:
    """Verify immediate DENY when endpoint is marked compromised."""
    pdp = PolicyDecisionPoint(policies=[base_policy])
    req = create_request(health_status=DeviceHealthStatus.COMPROMISED)

    result = pdp.evaluate(req)
    assert result.decision == AccessDecision.DENY
    assert any("compromised" in r for r in result.reasons)


def test_pdp_requires_mfa_for_high_sensitivity_password_only(
    base_policy: ZeroTrustPolicy,
) -> None:
    """Verify REQUIRE_MFA when accessing high sensitivity asset with weak auth."""
    pdp = PolicyDecisionPoint(policies=[base_policy])
    req = create_request(
        auth_strength=AuthenticationStrength.PASSWORD_ONLY,
        sensitivity_level=SensitivityLevel.HIGH,
    )

    result = pdp.evaluate(req)
    assert result.decision == AccessDecision.REQUIRE_MFA
    assert any("secondary authentication factor" in r for r in result.reasons)


def test_pdp_step_up_when_trust_score_suboptimal() -> None:
    """Verify STEP_UP decision when trust score falls between deny and allow thresholds."""
    flexible_policy = ZeroTrustPolicy(
        policy_id="POL-FLEX",
        name="Flexible Access Policy",
        effect=PolicyEffect.PERMIT,
        priority=100,
        min_trust_score=50.0,
        allowed_roles=["employee"],
        require_encryption=False,
        require_edr=False,
    )
    pdp = PolicyDecisionPoint(policies=[flexible_policy])
    req = create_request(
        network_zone=NetworkZone.PUBLIC_INTERNET,
        auth_strength=AuthenticationStrength.TOTP_MFA,
        disk_encrypted=False,
        edr_active=False,
    )

    result = pdp.evaluate(req)
    assert result.decision == AccessDecision.STEP_UP
    assert any("STEP_UP" in r for r in result.reasons)


def test_pdp_explicit_deny_policy() -> None:
    """Verify explicit DENY policy takes effect."""
    deny_policy = ZeroTrustPolicy(
        policy_id="POL-DENY-CONTRACTORS",
        name="Contractor Secret Access Deny",
        effect=PolicyEffect.DENY,
        priority=5,
        allowed_roles=["contractor"],
    )
    pdp = PolicyDecisionPoint(policies=[deny_policy])
    req = create_request(roles=["contractor"])

    result = pdp.evaluate(req)
    assert result.decision == AccessDecision.DENY
    assert result.matched_policy_id == "POL-DENY-CONTRACTORS"


def test_pdp_policy_registration_and_priority(
    base_policy: ZeroTrustPolicy, admin_policy: ZeroTrustPolicy
) -> None:
    """Verify policy registration order and priority sorting."""
    pdp = PolicyDecisionPoint()
    pdp.register_policy(base_policy)
    pdp.register_policy(admin_policy)

    policies = pdp.get_policies()
    assert len(policies) == 2
    assert policies[0].priority == 10
    assert policies[1].priority == 100


def test_pdp_abac_conditions_matching() -> None:
    """Verify custom ABAC conditions for action, resource_type, and country_code."""
    abac_policy = ZeroTrustPolicy(
        policy_id="POL-ABAC-GEO",
        name="US Regional Policy",
        effect=PolicyEffect.PERMIT,
        priority=20,
        min_trust_score=60.0,
        allowed_roles=["employee"],
        require_encryption=False,
        require_edr=False,
        conditions={"country_code": "US", "action": "read"},
    )
    pdp = PolicyDecisionPoint(policies=[abac_policy])

    # Matching condition
    req_match = create_request(
        country_code="US", action="read", disk_encrypted=False, edr_active=False
    )
    assert pdp.evaluate(req_match).decision == AccessDecision.ALLOW

    # Non-matching country code
    req_mismatch_country = create_request(
        country_code="CA", action="read", disk_encrypted=False, edr_active=False
    )
    assert pdp.evaluate(req_mismatch_country).decision == AccessDecision.DENY

    # Non-matching action
    req_mismatch_action = create_request(
        country_code="US", action="delete", disk_encrypted=False, edr_active=False
    )
    assert pdp.evaluate(req_mismatch_action).decision == AccessDecision.DENY


def test_pdp_trust_score_floor_denies() -> None:
    """Verify trust score at or below deny threshold forces DENY."""
    custom_settings = Settings(trust_score_deny_threshold=80.0)
    pdp = PolicyDecisionPoint(settings=custom_settings)
    # Force low score by setting untrusted anonymizer
    req_low = create_request(network_zone=NetworkZone.UNTRUSTED_ANONYMIZED)
    res = pdp.evaluate(req_low)
    assert res.decision == AccessDecision.DENY
