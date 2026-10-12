"""Unit tests for Phase 2: Domain Models, Enums, and Schemas."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from zero_trust.models import (
    AccessDecision,
    AccessEvaluationResult,
    AccessRequest,
    AuthenticationStrength,
    DeviceContext,
    DeviceHealthStatus,
    NetworkContext,
    NetworkZone,
    PolicyEffect,
    ResourceContext,
    SensitivityLevel,
    SubjectContext,
    TrustScoreBreakdown,
    ZeroTrustPolicy,
)


def test_access_decision_enum_values() -> None:
    """Verify AccessDecision contains all required NIST ZTA decision directives."""
    assert AccessDecision.ALLOW == "ALLOW"
    assert AccessDecision.DENY == "DENY"
    assert AccessDecision.REQUIRE_MFA == "REQUIRE_MFA"
    assert AccessDecision.STEP_UP == "STEP_UP"


def test_device_health_status_enum_values() -> None:
    """Verify DeviceHealthStatus enum values."""
    assert DeviceHealthStatus.HEALTHY == "HEALTHY"
    assert DeviceHealthStatus.DEGRADED == "DEGRADED"
    assert DeviceHealthStatus.NON_COMPLIANT == "NON_COMPLIANT"
    assert DeviceHealthStatus.COMPROMISED == "COMPROMISED"
    assert DeviceHealthStatus.UNKNOWN == "UNKNOWN"


def test_sensitivity_level_ordering() -> None:
    """Verify SensitivityLevel enum values."""
    levels = [
        SensitivityLevel.LOW,
        SensitivityLevel.MEDIUM,
        SensitivityLevel.HIGH,
        SensitivityLevel.CRITICAL,
    ]
    assert len(levels) == 4
    assert SensitivityLevel.CRITICAL == "CRITICAL"


def test_subject_context_valid() -> None:
    """Verify instantiation of valid SubjectContext."""
    subject = SubjectContext(
        subject_id="alice@enterprise.corp",
        roles=["security_analyst", "operator"],
        departments=["SOC", "SecOps"],
        auth_strength=AuthenticationStrength.FIDO2_HARDWARE_KEY,
        is_privileged=True,
        clearance_level=SensitivityLevel.HIGH,
    )
    assert subject.subject_id == "alice@enterprise.corp"
    assert "security_analyst" in subject.roles
    assert subject.is_privileged is True


def test_subject_context_immutable() -> None:
    """Verify that models are frozen/immutable."""
    subject = SubjectContext(subject_id="bob@corp.internal")
    with pytest.raises(ValidationError):
        subject.roles = ["admin"]


def test_device_context_valid() -> None:
    """Verify instantiation and defaults of DeviceContext."""
    device = DeviceContext(
        device_id="DEV-8890-MAC",
        os_name="macOS",
        os_version="14.4.1",
        disk_encrypted=True,
        edr_active=True,
        is_jailbroken=False,
        health_status=DeviceHealthStatus.HEALTHY,
        fingerprint_hash="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert device.disk_encrypted is True
    assert device.health_status == DeviceHealthStatus.HEALTHY
    assert device.is_jailbroken is False


def test_network_context_ip_validation() -> None:
    """Verify IPv4 and IPv6 validation and invalid IP rejection."""
    valid_ipv4 = NetworkContext(
        ip_address="192.168.1.100",
        network_zone=NetworkZone.CORPORATE_MANAGED,
    )
    assert valid_ipv4.ip_address == "192.168.1.100"

    valid_ipv6 = NetworkContext(
        ip_address="2001:db8::1",
        network_zone=NetworkZone.TRUSTED_PARTNER,
    )
    assert valid_ipv6.ip_address == "2001:db8::1"

    with pytest.raises(ValidationError):
        NetworkContext(ip_address="invalid-ip-string")


def test_resource_context_valid() -> None:
    """Verify valid ResourceContext model instantiation."""
    resource = ResourceContext(
        resource_id="/api/v1/vault/secrets/database-creds",
        resource_type="secret_vault",
        action="read",
        sensitivity_level=SensitivityLevel.CRITICAL,
        required_roles=["admin", "db_admin"],
    )
    assert resource.sensitivity_level == SensitivityLevel.CRITICAL
    assert resource.action == "read"


def test_access_request_assembly() -> None:
    """Verify end-to-end AccessRequest schema assembly."""
    subject = SubjectContext(subject_id="charlie@enterprise.corp")
    device = DeviceContext(
        device_id="DEV-100",
        os_name="Linux",
        os_version="6.5.0-generic",
        fingerprint_hash="fingerprint-hash-1234567890",
    )
    network = NetworkContext(ip_address="10.0.4.50")
    resource = ResourceContext(
        resource_id="corp-wiki/docs",
        resource_type="document",
        action="read",
    )

    request = AccessRequest(
        subject=subject,
        device=device,
        network=network,
        resource=resource,
    )
    assert request.request_id is not None
    assert isinstance(request.timestamp, datetime)
    assert request.timestamp.tzinfo == UTC


def test_access_evaluation_result() -> None:
    """Verify AccessEvaluationResult serialization and validation."""
    breakdown = TrustScoreBreakdown(
        total_score=85.5,
        device_score=90.0,
        identity_score=80.0,
        network_score=85.0,
        behavior_score=87.0,
        risk_penalties=[],
    )
    result = AccessEvaluationResult(
        request_id="REQ-TEST-001",
        decision=AccessDecision.ALLOW,
        trust_score=breakdown,
        matched_policy_id="POL-CORP-DEFAULT",
        reasons=["Device compliant with LUKS disk encryption and Falcon EDR active"],
        session_token="jwt-bound-token-value-sample",
    )
    assert result.decision == AccessDecision.ALLOW
    assert result.trust_score.total_score == 85.5
    assert result.session_token is not None


def test_zero_trust_policy_model() -> None:
    """Verify ZeroTrustPolicy model instantiation and rule fields."""
    policy = ZeroTrustPolicy(
        policy_id="POL-SEC-PROD-01",
        name="Production Database Admin Policy",
        description="Requires FIDO2 MFA and healthy EDR for database write actions",
        effect=PolicyEffect.PERMIT,
        priority=10,
        min_trust_score=80.0,
        allowed_roles=["db_admin"],
        allowed_departments=["PlatformOps"],
        max_sensitivity=SensitivityLevel.CRITICAL,
        require_encryption=True,
        require_edr=True,
        conditions={"environment": "production"},
    )
    assert policy.min_trust_score == 80.0
    assert policy.priority == 10
    assert policy.require_edr is True
    assert policy.conditions["environment"] == "production"
