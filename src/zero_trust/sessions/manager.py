"""Continuous Session Posture Monitor & Real-Time Revocation Manager.

Implements NIST SP 800-207 continuous diagnostics & mitigation (CDM).
Tracks active sessions, validates ongoing endpoint posture, detects telemetry
degradation (e.g. disk unencrypted midway, EDR killed, network shift to Tor/proxy),
and triggers immediate cryptographic session termination.
"""

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from zero_trust.models.enums import DeviceHealthStatus, NetworkZone
from zero_trust.models.schemas import DeviceContext, NetworkContext


class ActiveSession(BaseModel):
    """Represents an active authorized zero-trust access session."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique active session identifier",
    )
    subject_id: str = Field(
        ...,
        description="Authenticated subject identity",
    )
    device_id: str = Field(
        ...,
        description="Endpoint device ID",
    )
    device_fingerprint_hash: str = Field(
        ...,
        description="Hardware fingerprint hash bound to session",
    )
    resource_id: str = Field(
        ...,
        description="Authorized target resource",
    )
    session_token: str = Field(
        ...,
        description="Cryptographically signed ephemeral token",
    )
    ip_address: str = Field(
        ...,
        description="Initial client IP address",
    )
    network_zone: NetworkZone = Field(
        default=NetworkZone.CORPORATE_MANAGED,
        description="Initial network zone classification",
    )
    is_revoked: bool = Field(
        default=False,
        description="Revocation status flag",
    )
    revocation_reason: str | None = Field(
        default=None,
        description="Explanation for session termination",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when session was minted",
    )
    last_verified_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of most recent continuous verification",
    )


class SessionManager:
    """Manages continuous session lifecycle and real-time posture revocation."""

    def __init__(self) -> None:
        """Initialize session registry."""
        self._sessions: dict[str, ActiveSession] = {}

    def register_session(
        self,
        subject_id: str,
        device_id: str,
        device_fingerprint_hash: str,
        resource_id: str,
        session_token: str,
        ip_address: str,
        network_zone: NetworkZone = NetworkZone.CORPORATE_MANAGED,
    ) -> ActiveSession:
        """Register a newly authorized session in the active tracking ledger."""
        session = ActiveSession(
            subject_id=subject_id,
            device_id=device_id,
            device_fingerprint_hash=device_fingerprint_hash,
            resource_id=resource_id,
            session_token=session_token,
            ip_address=ip_address,
            network_zone=network_zone,
        )
        self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> ActiveSession | None:
        """Retrieve an active session by its ID."""
        return self._sessions.get(session_id)

    def list_active_sessions(self) -> list[ActiveSession]:
        """List all currently active (non-revoked) sessions."""
        return [s for s in self._sessions.values() if not s.is_revoked]

    def revoke_session(self, session_id: str, reason: str) -> bool:
        """Instantly revoke an active session."""
        session = self._sessions.get(session_id)
        if not session or session.is_revoked:
            return False

        updated_session = ActiveSession(
            session_id=session.session_id,
            subject_id=session.subject_id,
            device_id=session.device_id,
            device_fingerprint_hash=session.device_fingerprint_hash,
            resource_id=session.resource_id,
            session_token=session.session_token,
            ip_address=session.ip_address,
            network_zone=session.network_zone,
            is_revoked=True,
            revocation_reason=reason,
            created_at=session.created_at,
            last_verified_at=datetime.now(UTC),
        )
        self._sessions[session_id] = updated_session
        return True

    def continuous_verify_posture(
        self,
        session_id: str,
        current_device: DeviceContext,
        current_network: NetworkContext,
    ) -> tuple[bool, str | None]:
        """Verify continuous health and network posture.

        Triggers automatic revocation if degradation or compromise is detected.
        Returns (is_valid, optional_revocation_reason).
        """
        session = self._sessions.get(session_id)
        if not session:
            return False, "Session does not exist"

        if session.is_revoked:
            return False, f"Session already revoked: {session.revocation_reason}"

        # 1. Hardware fingerprint mismatch (Device hijacking)
        if current_device.fingerprint_hash != session.device_fingerprint_hash:
            reason = "Device hardware fingerprint mismatch detected during continuous monitoring"
            self.revoke_session(session_id, reason)
            return False, reason

        # 2. Endpoint compromise or jailbreak
        if current_device.is_jailbroken:
            reason = "Continuous posture detected endpoint jailbreak/root"
            self.revoke_session(session_id, reason)
            return False, reason

        if current_device.health_status in (
            DeviceHealthStatus.COMPROMISED,
            DeviceHealthStatus.NON_COMPLIANT,
        ):
            reason = f"Endpoint health degraded to {current_device.health_status}"
            self.revoke_session(session_id, reason)
            return False, reason

        # 3. Security controls disabled midway (EDR stopped or disk unencrypted)
        if not current_device.edr_active:
            reason = "EDR agent terminated during active session"
            self.revoke_session(session_id, reason)
            return False, reason

        if not current_device.disk_encrypted:
            reason = "Disk encryption disabled during active session"
            self.revoke_session(session_id, reason)
            return False, reason

        # 4. Network zone shifted to untrusted/anonymized network
        if (
            current_network.network_zone == NetworkZone.UNTRUSTED_ANONYMIZED
            or current_network.is_vpn_or_proxy
        ):
            reason = "Session network shifted to untrusted anonymizer or commercial proxy"
            self.revoke_session(session_id, reason)
            return False, reason

        # Update last verified timestamp
        updated_session = ActiveSession(
            session_id=session.session_id,
            subject_id=session.subject_id,
            device_id=session.device_id,
            device_fingerprint_hash=session.device_fingerprint_hash,
            resource_id=session.resource_id,
            session_token=session.session_token,
            ip_address=current_network.ip_address,
            network_zone=current_network.network_zone,
            is_revoked=False,
            revocation_reason=None,
            created_at=session.created_at,
            last_verified_at=datetime.now(UTC),
        )
        self._sessions[session_id] = updated_session
        return True, None
