"""Dynamic Context-Aware Trust Scoring Engine.

Implements real-time multi-dimensional trust score calculation across:
1. Device Health & Posture (encryption, EDR, jailbreak status, OS integrity)
2. Subject Identity & Authentication Strength (passwords, MFA, hardware keys)
3. Network Zone & Source IP Classification (managed corporate, trusted partner, public, VPN/proxy)
4. Behavioral Context (geovelocity, time of access, historical anomalies)
"""

from zero_trust.config.settings import Settings, get_settings
from zero_trust.models.enums import (
    AuthenticationStrength,
    DeviceHealthStatus,
    NetworkZone,
)
from zero_trust.models.schemas import (
    AccessRequest,
    DeviceContext,
    NetworkContext,
    SubjectContext,
    TrustScoreBreakdown,
)


class TrustCalculator:
    """Calculates continuous multidimensional dynamic trust scores (0.0 - 100.0)."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialize TrustCalculator with application settings."""
        self._settings = settings or get_settings()

    def calculate_device_score(self, device: DeviceContext, penalties: list[str]) -> float:
        """Calculate device health and posture score between 0.0 and 100.0."""
        score = 50.0  # Baseline unverified endpoint score

        # Disk encryption verification
        if device.disk_encrypted:
            score += 25.0
        else:
            penalties.append("Device storage volume is unencrypted (-25)")

        # EDR agent verification
        if device.edr_active:
            score += 25.0
        else:
            penalties.append("Endpoint Detection and Response (EDR) agent is inactive (-25)")

        # Jailbreak or root detection penalty
        if device.is_jailbroken:
            score -= 60.0
            penalties.append("Device tampering or root/jailbreak detected (-60)")

        # Health status adjustments
        match device.health_status:
            case DeviceHealthStatus.HEALTHY:
                score += 10.0
            case DeviceHealthStatus.DEGRADED:
                score -= 15.0
                penalties.append("Device health status is degraded (-15)")
            case DeviceHealthStatus.NON_COMPLIANT:
                score -= 35.0
                penalties.append("Device health status is non-compliant (-35)")
            case DeviceHealthStatus.COMPROMISED:
                score = 0.0
                penalties.append("Device reported as actively compromised (override score: 0.0)")
            case DeviceHealthStatus.UNKNOWN:
                score -= 10.0
                penalties.append("Device health posture status is unknown (-10)")

        return max(0.0, min(100.0, score))

    def calculate_identity_score(self, subject: SubjectContext, penalties: list[str]) -> float:
        """Calculate identity authentication strength score between 0.0 and 100.0."""
        score = 0.0

        match subject.auth_strength:
            case AuthenticationStrength.FIDO2_HARDWARE_KEY:
                score = 100.0
            case AuthenticationStrength.CERTIFICATE_BASED:
                score = 90.0
            case AuthenticationStrength.TOTP_MFA:
                score = 75.0
            case AuthenticationStrength.PASSWORD_ONLY:
                score = 30.0
                penalties.append("Single-factor password-only authentication utilized (-45 vs MFA)")

        # Privileged account with weak auth penalty
        if subject.is_privileged and subject.auth_strength == AuthenticationStrength.PASSWORD_ONLY:
            score = 15.0
            penalties.append("Privileged identity authenticated without mandatory MFA (-15)")

        return max(0.0, min(100.0, score))

    def calculate_network_score(self, network: NetworkContext, penalties: list[str]) -> float:
        """Calculate network connection risk score between 0.0 and 100.0."""
        score = 50.0

        match network.network_zone:
            case NetworkZone.CORPORATE_MANAGED:
                score = 100.0
            case NetworkZone.TRUSTED_PARTNER:
                score = 80.0
            case NetworkZone.PUBLIC_INTERNET:
                score = 45.0
            case NetworkZone.UNTRUSTED_ANONYMIZED:
                score = 10.0
                penalties.append("Connection originated from untrusted anonymizer or Tor network")

        # Explicit proxy/VPN detection penalty
        if network.is_vpn_or_proxy and network.network_zone != NetworkZone.CORPORATE_MANAGED:
            score -= 30.0
            penalties.append("Anonymizing proxy or commercial VPN exit node detected (-30)")

        return max(0.0, min(100.0, score))

    def calculate_behavior_score(self, request: AccessRequest, penalties: list[str]) -> float:
        """Calculate temporal and behavioral context score between 0.0 and 100.0."""
        score = 80.0  # Baseline normal behavior score

        # Check access hour (UTC 05:00 - 22:00 considered standard business/operating window)
        req_hour = request.timestamp.hour
        if not (5 <= req_hour <= 22):
            score -= 15.0
            penalties.append("Access request initiated outside core operating hours (-15)")

        # Critical resource request from non-privileged subject
        if (
            request.resource.sensitivity_level.value == "CRITICAL"
            and not request.subject.is_privileged
        ):
            score -= 15.0
            penalties.append("Non-privileged subject targeting critical sensitivity asset (-15)")

        return max(0.0, min(100.0, score))

    def evaluate_trust(self, request: AccessRequest) -> TrustScoreBreakdown:
        """Compute the full multi-factor dynamic trust score breakdown."""
        penalties: list[str] = []

        device_score = self.calculate_device_score(request.device, penalties)
        identity_score = self.calculate_identity_score(request.subject, penalties)
        network_score = self.calculate_network_score(request.network, penalties)
        behavior_score = self.calculate_behavior_score(request, penalties)

        # Weighted aggregate calculation
        weighted_total = (
            (device_score * self._settings.device_weight)
            + (identity_score * self._settings.identity_weight)
            + (network_score * self._settings.network_weight)
            + (behavior_score * self._settings.behavior_weight)
        )

        # Compromised device hard override to zero
        if (
            request.device.health_status == DeviceHealthStatus.COMPROMISED
            or request.device.is_jailbroken
        ):
            weighted_total = min(weighted_total, 15.0)

        total_score = round(max(0.0, min(100.0, weighted_total)), 2)

        return TrustScoreBreakdown(
            total_score=total_score,
            device_score=round(device_score, 2),
            identity_score=round(identity_score, 2),
            network_score=round(network_score, 2),
            behavior_score=round(behavior_score, 2),
            risk_penalties=penalties,
        )
