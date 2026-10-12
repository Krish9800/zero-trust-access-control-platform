"""FastAPI Control Plane Application.

Provides RESTful endpoints for:
- Health check & diagnostics (`/health`)
- Contextual Access Evaluation (`/api/v1/access/evaluate`)
- Active Session Listing (`/api/v1/sessions`)
- Instant Session Revocation (`/api/v1/sessions/{session_id}/revoke`)
- Policy Administration (`/api/v1/policies`, `/api/v1/policies/{policy_id}`)
"""

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from zero_trust.config.settings import Settings, get_settings
from zero_trust.db.database import DatabaseManager
from zero_trust.engine.pdp import PolicyDecisionPoint
from zero_trust.engine.trust_calculator import TrustCalculator
from zero_trust.models.enums import AccessDecision
from zero_trust.models.schemas import (
    AccessEvaluationResult,
    AccessRequest,
    ZeroTrustPolicy,
)
from zero_trust.pep.gateway import PEPGateway
from zero_trust.sessions.manager import ActiveSession, SessionManager


class RevokeSessionRequest(BaseModel):
    """Payload for manual administrative session revocation."""

    reason: str = Field(
        ...,
        min_length=3,
        max_length=256,
        description="Administrative rationale for terminating session",
    )


class ControlPlaneState:
    """Singleton state holding database, PDP, PEP, and session manager."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.db = DatabaseManager(settings=self.settings)
        # Load persisted policies into PDP
        existing_policies = self.db.list_policies()
        self.trust_calculator = TrustCalculator(self.settings)
        self.pdp = PolicyDecisionPoint(
            policies=existing_policies,
            trust_calculator=self.trust_calculator,
            settings=self.settings,
        )
        self.pep = PEPGateway(self.pdp, self.settings)
        self.session_manager = SessionManager()


def create_app(state: ControlPlaneState | None = None) -> FastAPI:
    """Application factory for FastAPI Control Plane."""
    app_state = state or ControlPlaneState()

    app = FastAPI(
        title="Zero-Trust Access Control Platform",
        version="0.1.0",
        description="NIST SP 800-207 Contextual Continuous Authentication & Authorization Engine",
    )
    app.state.control_plane = app_state

    def get_state() -> ControlPlaneState:
        return app_state

    # ---------------- Health Check ----------------

    @app.get("/health", tags=["Diagnostics"])
    async def health_check() -> dict[str, Any]:
        """Health and readiness probe."""
        return {
            "status": "healthy",
            "version": "0.1.0",
            "architecture": "NIST SP 800-207",
            "active_policies_count": len(app_state.pdp.get_policies()),
        }

    # ---------------- Access Evaluation ----------------

    @app.post(
        "/api/v1/access/evaluate",
        response_model=AccessEvaluationResult,
        status_code=status.HTTP_200_OK,
        tags=["PDP & PEP Evaluation"],
    )
    async def evaluate_access(
        request: AccessRequest,
        st: ControlPlaneState = Depends(get_state),
    ) -> AccessEvaluationResult:
        """Evaluate an ingress access request via PEP interceptor and PDP."""
        result = st.pep.intercept_request(request)

        # Audit evaluation in database
        st.db.record_evaluation(
            evaluation=result,
            subject_id=request.subject.subject_id,
            device_id=request.device.device_id,
            resource_id=request.resource.resource_id,
        )

        # If ALLOW, also track in session manager and persist session
        if result.decision == AccessDecision.ALLOW and result.session_token:
            session = st.session_manager.register_session(
                subject_id=request.subject.subject_id,
                device_id=request.device.device_id,
                device_fingerprint_hash=request.device.fingerprint_hash,
                resource_id=request.resource.resource_id,
                session_token=result.session_token,
                ip_address=request.network.ip_address,
                network_zone=request.network.network_zone,
            )
            st.db.save_session(session)

        return result

    # ---------------- Session Management ----------------

    @app.get(
        "/api/v1/sessions",
        response_model=list[ActiveSession],
        tags=["Session Management"],
    )
    async def list_sessions(
        active_only: bool = True,
        st: ControlPlaneState = Depends(get_state),
    ) -> list[ActiveSession]:
        """List active sessions from database / session monitor."""
        return st.db.list_sessions(active_only=active_only)

    @app.post(
        "/api/v1/sessions/{session_id}/revoke",
        status_code=status.HTTP_200_OK,
        tags=["Session Management"],
    )
    async def revoke_session(
        session_id: str,
        payload: RevokeSessionRequest,
        st: ControlPlaneState = Depends(get_state),
    ) -> dict[str, str]:
        """Trigger instant real-time session revocation."""
        # Revoke in memory
        st.session_manager.revoke_session(session_id, payload.reason)

        # Retrieve and update in DB
        db_session = st.db.get_session(session_id)
        if not db_session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session with ID '{session_id}' not found",
            )

        updated_session = ActiveSession(
            session_id=db_session.session_id,
            subject_id=db_session.subject_id,
            device_id=db_session.device_id,
            device_fingerprint_hash=db_session.device_fingerprint_hash,
            resource_id=db_session.resource_id,
            session_token=db_session.session_token,
            ip_address=db_session.ip_address,
            network_zone=db_session.network_zone,
            is_revoked=True,
            revocation_reason=payload.reason,
            created_at=db_session.created_at,
        )
        st.db.save_session(updated_session)
        st.db.log_audit_event(
            event_type="SESSION_REVOKED",
            actor_id="admin_api",
            target_id=session_id,
            details={"reason": payload.reason},
        )
        return {"session_id": session_id, "status": "REVOKED", "reason": payload.reason}

    # ---------------- Policy Administration ----------------

    @app.get(
        "/api/v1/policies",
        response_model=list[ZeroTrustPolicy],
        tags=["Policy Administration"],
    )
    async def list_policies(
        st: ControlPlaneState = Depends(get_state),
    ) -> list[ZeroTrustPolicy]:
        """List all active Zero-Trust policies ordered by priority."""
        return st.pdp.get_policies()

    @app.post(
        "/api/v1/policies",
        response_model=ZeroTrustPolicy,
        status_code=status.HTTP_201_CREATED,
        tags=["Policy Administration"],
    )
    async def create_or_update_policy(
        policy: ZeroTrustPolicy,
        st: ControlPlaneState = Depends(get_state),
    ) -> ZeroTrustPolicy:
        """Register or update an ABAC/RBAC zero-trust policy."""
        st.db.save_policy(policy)
        st.pdp.register_policy(policy)
        st.db.log_audit_event(
            event_type="POLICY_REGISTERED",
            actor_id="admin_api",
            target_id=policy.policy_id,
            details={"name": policy.name, "priority": policy.priority},
        )
        return policy

    @app.delete(
        "/api/v1/policies/{policy_id}",
        status_code=status.HTTP_200_OK,
        tags=["Policy Administration"],
    )
    async def delete_policy(
        policy_id: str,
        st: ControlPlaneState = Depends(get_state),
    ) -> dict[str, str]:
        """Delete policy by ID."""
        deleted = st.db.delete_policy(policy_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy with ID '{policy_id}' not found",
            )
        # Refresh PDP policy cache
        st.pdp = PolicyDecisionPoint(
            policies=st.db.list_policies(),
            trust_calculator=st.trust_calculator,
            settings=st.settings,
        )
        st.pep = PEPGateway(st.pdp, st.settings)
        return {"policy_id": policy_id, "status": "DELETED"}

    return app
