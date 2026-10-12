"""Domain enumerations for Zero-Trust Access Control Platform.

Defines decision outcomes, device health statuses, sensitivity levels,
authentication methods, and risk tiers aligned with NIST SP 800-207.
"""

from enum import StrEnum


class AccessDecision(StrEnum):
    """Access evaluation decision directives emitted by Policy Engine/PDP."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_MFA = "REQUIRE_MFA"
    STEP_UP = "STEP_UP"


class DeviceHealthStatus(StrEnum):
    """Device posture and compliance assessment state."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    NON_COMPLIANT = "NON_COMPLIANT"
    COMPROMISED = "COMPROMISED"
    UNKNOWN = "UNKNOWN"


class SensitivityLevel(StrEnum):
    """Resource classification and data sensitivity tiers."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuthenticationStrength(StrEnum):
    """Authentication factor assurance levels."""

    PASSWORD_ONLY = "PASSWORD_ONLY"  # nosec B105
    TOTP_MFA = "TOTP_MFA"
    FIDO2_HARDWARE_KEY = "FIDO2_HARDWARE_KEY"
    CERTIFICATE_BASED = "CERTIFICATE_BASED"


class NetworkZone(StrEnum):
    """Categorized network perimeter classification."""

    CORPORATE_MANAGED = "CORPORATE_MANAGED"
    TRUSTED_PARTNER = "TRUSTED_PARTNER"
    PUBLIC_INTERNET = "PUBLIC_INTERNET"
    UNTRUSTED_ANONYMIZED = "UNTRUSTED_ANONYMIZED"  # Tor, Proxy, VPN exit nodes


class PolicyEffect(StrEnum):
    """Declarative policy rule evaluation effect."""

    PERMIT = "PERMIT"
    DENY = "DENY"
    CHALLENGE = "CHALLENGE"
