"""Unit tests for Phase 3: Dynamic Trust Calculation Engine."""

from datetime import UTC, datetime

from zero_trust.engine.trust_calculator import TrustCalculator
from zero_trust.models.enums import (
    AuthenticationStrength,
    DeviceHealthStatus,
    NetworkZone,
    SensitivityLevel,
)
from zero_trust.models.schemas import (
    AccessRequest,
    DeviceContext,
    NetworkContext,
    ResourceContext,
    SubjectContext,
)


def create_sample_request(
    auth_strength: AuthenticationStrength = AuthenticationStrength.FIDO2_HARDWARE_KEY,
    is_privileged: bool = False,
    disk_encrypted: bool = True,
    edr_active: bool = True,
    is_jailbroken: bool = False,
    health_status: DeviceHealthStatus = DeviceHealthStatus.HEALTHY,
    network_zone: NetworkZone = NetworkZone.CORPORATE_MANAGED,
    is_vpn_or_proxy: bool = False,
    sensitivity_level: SensitivityLevel = SensitivityLevel.MEDIUM,
    req_hour: int = 14,
) -> AccessRequest:
    """Helper to generate parameterized AccessRequest objects for testing."""
    subject = SubjectContext(
        subject_id="user1@corp.example",
        roles=["analyst"],
        auth_strength=auth_strength,
        is_privileged=is_privileged,
    )
    device = DeviceContext(
        device_id="DEV-001",
        os_name="Linux",
        os_version="6.8.0",
        disk_encrypted=disk_encrypted,
        edr_active=edr_active,
        is_jailbroken=is_jailbroken,
        health_status=health_status,
        fingerprint_hash="sha256:fedcba9876543210123456789abcdef",
    )
    network = NetworkContext(
        ip_address="10.10.1.5",
        network_zone=network_zone,
        is_vpn_or_proxy=is_vpn_or_proxy,
    )
    resource = ResourceContext(
        resource_id="/api/data/records",
        resource_type="database",
        action="read",
        sensitivity_level=sensitivity_level,
    )
    ts = datetime(2026, 10, 12, req_hour, 30, 0, tzinfo=UTC)
    return AccessRequest(
        timestamp=ts,
        subject=subject,
        device=device,
        network=network,
        resource=resource,
    )


def test_high_trust_score_for_healthy_context() -> None:
    """Verify maximum compliance results in high trust score (> 85.0)."""
    calculator = TrustCalculator()
    req = create_sample_request()
    breakdown = calculator.evaluate_trust(req)

    assert breakdown.total_score >= 85.0
    assert breakdown.device_score == 100.0
    assert breakdown.identity_score == 100.0
    assert breakdown.network_score == 100.0
    assert len(breakdown.risk_penalties) == 0


def test_device_penalties_unencrypted_no_edr() -> None:
    """Verify penalties for unencrypted disk and absent EDR."""
    calculator = TrustCalculator()
    req = create_sample_request(disk_encrypted=False, edr_active=False)
    breakdown = calculator.evaluate_trust(req)

    assert breakdown.device_score <= 60.0
    assert any("unencrypted" in p for p in breakdown.risk_penalties)
    assert any("EDR" in p for p in breakdown.risk_penalties)


def test_compromised_device_override() -> None:
    """Verify that actively compromised device drops total score <= 15.0."""
    calculator = TrustCalculator()
    req = create_sample_request(health_status=DeviceHealthStatus.COMPROMISED)
    breakdown = calculator.evaluate_trust(req)

    assert breakdown.device_score == 0.0
    assert breakdown.total_score <= 15.0
    assert any("compromised" in p for p in breakdown.risk_penalties)


def test_jailbroken_device_heavy_penalty() -> None:
    """Verify jailbroken/rooted endpoint triggers severe score deduction."""
    calculator = TrustCalculator()
    req = create_sample_request(is_jailbroken=True)
    breakdown = calculator.evaluate_trust(req)

    assert breakdown.total_score <= 15.0
    assert any("jailbreak" in p for p in breakdown.risk_penalties)


def test_weak_auth_privileged_user_penalty() -> None:
    """Verify privileged user with password-only auth receives high risk penalty."""
    calculator = TrustCalculator()
    req = create_sample_request(
        auth_strength=AuthenticationStrength.PASSWORD_ONLY,
        is_privileged=True,
    )
    breakdown = calculator.evaluate_trust(req)

    assert breakdown.identity_score == 15.0
    assert any(
        "Privileged identity authenticated without mandatory MFA" in p
        for p in breakdown.risk_penalties
    )


def test_network_zone_penalties() -> None:
    """Verify public and anonymized network zones incur risk penalties."""
    calculator = TrustCalculator()

    # Public Internet with VPN proxy
    req_vpn = create_sample_request(
        network_zone=NetworkZone.PUBLIC_INTERNET,
        is_vpn_or_proxy=True,
    )
    breakdown_vpn = calculator.evaluate_trust(req_vpn)
    assert breakdown_vpn.network_score == 15.0  # 45 - 30

    # Untrusted anonymizer
    req_tor = create_sample_request(
        network_zone=NetworkZone.UNTRUSTED_ANONYMIZED,
    )
    breakdown_tor = calculator.evaluate_trust(req_tor)
    assert breakdown_tor.network_score == 10.0


def test_off_hours_and_critical_resource_penalties() -> None:
    """Verify off-hours access and non-privileged targeting critical asset incur penalties."""
    calculator = TrustCalculator()
    req = create_sample_request(
        req_hour=2,  # 02:00 UTC off-hours
        sensitivity_level=SensitivityLevel.CRITICAL,
        is_privileged=False,
    )
    breakdown = calculator.evaluate_trust(req)
    assert breakdown.behavior_score == 50.0  # 80 - 15 - 15
    assert any("outside core operating hours" in p for p in breakdown.risk_penalties)
    assert any("critical sensitivity asset" in p for p in breakdown.risk_penalties)


def test_device_health_degraded_and_unknown() -> None:
    """Verify degraded and unknown device health states are scored appropriately."""
    calculator = TrustCalculator()

    req_degraded = create_sample_request(health_status=DeviceHealthStatus.DEGRADED)
    assert calculator.calculate_device_score(req_degraded.device, []) == 85.0

    req_non_compliant = create_sample_request(health_status=DeviceHealthStatus.NON_COMPLIANT)
    assert calculator.calculate_device_score(req_non_compliant.device, []) == 65.0

    req_unknown = create_sample_request(health_status=DeviceHealthStatus.UNKNOWN)
    assert calculator.calculate_device_score(req_unknown.device, []) == 90.0


def test_auth_strength_tiers() -> None:
    """Verify all authentication strength tiers score correctly."""
    calculator = TrustCalculator()

    penalties: list[str] = []
    assert (
        calculator.calculate_identity_score(
            SubjectContext(subject_id="u1", auth_strength=AuthenticationStrength.CERTIFICATE_BASED),
            penalties,
        )
        == 90.0
    )

    assert (
        calculator.calculate_identity_score(
            SubjectContext(subject_id="u2", auth_strength=AuthenticationStrength.TOTP_MFA),
            penalties,
        )
        == 75.0
    )
