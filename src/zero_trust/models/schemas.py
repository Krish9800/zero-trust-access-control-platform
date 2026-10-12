"""Domain schemas and context models for Zero-Trust Access Control Platform.

Implements strict validation models for SubjectContext, DeviceContext, ResourceContext,
AccessRequest, AccessEvaluationResult, and ZeroTrustPolicy.
"""

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from zero_trust.models.enums import (
    AccessDecision,
    AuthenticationStrength,
    DeviceHealthStatus,
    NetworkZone,
    PolicyEffect,
    SensitivityLevel,
)


def get_utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class SubjectContext(BaseModel):
    """Contextual metadata representing the requesting user/workload identity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Unique identifier for the subject (e.g. email or UUID)",
    )
    roles: list[str] = Field(
        default_factory=list,
        description="Assigned enterprise roles for RBAC matching",
    )
    departments: list[str] = Field(
        default_factory=list,
        description="Departmental assignments for ABAC attribute matching",
    )
    auth_strength: AuthenticationStrength = Field(
        default=AuthenticationStrength.PASSWORD_ONLY,
        description="Assurance level of current subject authentication",
    )
    is_privileged: bool = Field(
        default=False,
        description="Flag indicating if subject is a privileged administrative account",
    )
    clearance_level: SensitivityLevel = Field(
        default=SensitivityLevel.LOW,
        description="Security clearance assigned to the subject",
    )


class DeviceContext(BaseModel):
    """Contextual diagnostics and posture telemetry of the connecting endpoint."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    device_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Unique endpoint device hardware identifier",
    )
    os_name: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Operating system name (e.g., Ubuntu, macOS, Windows)",
    )
    os_version: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Operating system kernel or build version string",
    )
    disk_encrypted: bool = Field(
        default=False,
        description="True if endpoint storage volume is encrypted (LUKS/FileVault/BitLocker)",
    )
    edr_active: bool = Field(
        default=False,
        description="True if endpoint detection & response agent is actively running",
    )
    is_jailbroken: bool = Field(
        default=False,
        description="True if endpoint displays signs of rooting or jailbreak",
    )
    health_status: DeviceHealthStatus = Field(
        default=DeviceHealthStatus.UNKNOWN,
        description="Aggregated device health posture",
    )
    fingerprint_hash: str = Field(
        ...,
        min_length=16,
        max_length=128,
        description="Cryptographic hardware-bound fingerprint hash",
    )


class NetworkContext(BaseModel):
    """Network connection parameters and geo-telemetry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ip_address: str = Field(
        ...,
        description="Client IPv4 or IPv6 source address",
    )
    network_zone: NetworkZone = Field(
        default=NetworkZone.PUBLIC_INTERNET,
        description="Network classification of connection source",
    )
    country_code: str = Field(
        default="US",
        min_length=2,
        max_length=2,
        description="ISO 3166-1 alpha-2 country code",
    )
    is_vpn_or_proxy: bool = Field(
        default=False,
        description="Whether the IP address matches known proxy/VPN/Tor registries",
    )

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate that ip_address is a valid IPv4 or IPv6 address string."""
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address format: {v}") from exc
        return v


class ResourceContext(BaseModel):
    """Metadata describing the enterprise resource being accessed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    resource_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="URI or identifier of the targeted resource",
    )
    resource_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Category of resource (e.g. database, api, file_share, secret)",
    )
    action: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="Action performed on resource (e.g. read, write, execute, delete)",
    )
    sensitivity_level: SensitivityLevel = Field(
        default=SensitivityLevel.MEDIUM,
        description="Data classification level of the target asset",
    )
    required_roles: list[str] = Field(
        default_factory=list,
        description="Roles permitted to access this resource",
    )


class AccessRequest(BaseModel):
    """Unified access request submitted by PEP to PDP."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique request tracing correlation ID",
    )
    timestamp: datetime = Field(
        default_factory=get_utc_now,
        description="UTC timestamp of the access request",
    )
    subject: SubjectContext = Field(
        ...,
        description="Subject identity context",
    )
    device: DeviceContext = Field(
        ...,
        description="Endpoint device posture context",
    )
    network: NetworkContext = Field(
        ...,
        description="Network location context",
    )
    resource: ResourceContext = Field(
        ...,
        description="Target resource context",
    )


class TrustScoreBreakdown(BaseModel):
    """Detailed score component weights and risk deductions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Consolidated dynamic trust score (0.0 - 100.0)",
    )
    device_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Endpoint posture score contribution",
    )
    identity_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Authentication strength score contribution",
    )
    network_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Network zone and location trust contribution",
    )
    behavior_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Temporal and velocity behavioral contribution",
    )
    risk_penalties: list[str] = Field(
        default_factory=list,
        description="List of specific risk factors and deductions applied",
    )


class AccessEvaluationResult(BaseModel):
    """Policy Decision Point evaluation outcome returned to PEP."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evaluation_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique evaluation identifier for auditing",
    )
    request_id: str = Field(
        ...,
        description="Correlated AccessRequest identifier",
    )
    decision: AccessDecision = Field(
        ...,
        description="Directive decision (ALLOW, DENY, REQUIRE_MFA, STEP_UP)",
    )
    trust_score: TrustScoreBreakdown = Field(
        ...,
        description="Detailed trust score breakdown computed by TrustEngine",
    )
    matched_policy_id: str | None = Field(
        default=None,
        description="Identifier of primary policy governing the decision",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable decision rationales and compliance findings",
    )
    evaluated_at: datetime = Field(
        default_factory=get_utc_now,
        description="UTC timestamp when evaluation concluded",
    )
    session_token: str | None = Field(
        default=None,
        description="Cryptographically signed ephemeral token (only if ALLOW)",
    )


class ZeroTrustPolicy(BaseModel):
    """Declarative ABAC + RBAC zero-trust policy definition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Unique policy identifier",
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Descriptive policy name",
    )
    description: str = Field(
        default="",
        description="Explanation of policy scope and business intent",
    )
    effect: PolicyEffect = Field(
        default=PolicyEffect.PERMIT,
        description="Policy effect if conditions match (PERMIT, DENY, CHALLENGE)",
    )
    priority: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Evaluation priority (lower value = higher priority)",
    )
    min_trust_score: float = Field(
        default=50.0,
        ge=0.0,
        le=100.0,
        description="Minimum trust score required to qualify for PERMIT",
    )
    allowed_roles: list[str] = Field(
        default_factory=list,
        description="Allowed subject roles; empty implies any authenticated role",
    )
    allowed_departments: list[str] = Field(
        default_factory=list,
        description="Allowed departments; empty implies any department",
    )
    max_sensitivity: SensitivityLevel = Field(
        default=SensitivityLevel.CRITICAL,
        description="Maximum resource sensitivity covered by this policy",
    )
    require_encryption: bool = Field(
        default=True,
        description="Require disk encryption on connecting endpoint",
    )
    require_edr: bool = Field(
        default=True,
        description="Require active EDR agent on connecting endpoint",
    )
    conditions: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary ABAC attribute key-value conditions",
    )
