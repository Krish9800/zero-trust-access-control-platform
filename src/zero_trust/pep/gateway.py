"""Policy Enforcement Point (PEP) Gateway.

Acts as the security perimeter enforcement interceptor according to NIST SP 800-207.
Intercepts ingress access requests, forwards evaluation to PDP, issues cryptographically
signed ephemeral authorization tokens bound to hardware fingerprints, and validates
tokens for upstream resource access.
"""

import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from zero_trust.config.settings import Settings, get_settings
from zero_trust.engine.pdp import PolicyDecisionPoint
from zero_trust.models.enums import AccessDecision
from zero_trust.models.schemas import AccessEvaluationResult, AccessRequest


class PEPGateway:
    """NIST SP 800-207 Policy Enforcement Point (PEP) Gateway."""

    def __init__(
        self,
        pdp: PolicyDecisionPoint,
        settings: Settings | None = None,
    ) -> None:
        """Initialize PEP Gateway with PDP dependency and configuration."""
        self._pdp = pdp
        self._settings = settings or get_settings()

    def create_bound_token(
        self,
        subject_id: str,
        device_fingerprint: str,
        resource_id: str,
        lifetime_seconds: int | None = None,
    ) -> str:
        """Issue an ephemeral HMAC-SHA256 signed access token cryptographically bound to device."""
        now = datetime.now(UTC)
        ttl = lifetime_seconds or self._settings.token_lifetime_seconds
        expires_at = now + timedelta(seconds=ttl)

        payload: dict[str, Any] = {
            "token_id": str(uuid.uuid4()),
            "sub": subject_id,
            "res": resource_id,
            "dfp": hashlib.sha256(device_fingerprint.encode("utf-8")).hexdigest(),
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }

        serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        signature = hmac.new(
            self._settings.jwt_secret_key.encode("utf-8"),
            serialized.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return f"{serialized}.{signature}"

    def verify_token(
        self,
        token: str,
        expected_device_fingerprint: str,
        expected_resource_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Verify token authenticity, expiration, and cryptographic device binding.

        Returns decoded payload dict if valid, or None if invalid or tampered.
        """
        try:
            parts = token.rsplit(".", 1)
            if len(parts) != 2:
                return None

            payload_raw, signature = parts
            expected_sig = hmac.new(
                self._settings.jwt_secret_key.encode("utf-8"),
                payload_raw.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            # Constant-time signature comparison to defeat timing attacks
            if not hmac.compare_digest(signature, expected_sig):
                return None

            payload = json.loads(payload_raw)
            if not isinstance(payload, dict):
                return None

            # Verify expiration
            now_ts = int(datetime.now(UTC).timestamp())
            if payload.get("exp", 0) < now_ts:
                return None

            # Verify device fingerprint binding (Pass-the-cookie / token theft mitigation)
            expected_dfp_hash = hashlib.sha256(
                expected_device_fingerprint.encode("utf-8")
            ).hexdigest()
            if not hmac.compare_digest(payload.get("dfp", ""), expected_dfp_hash):
                return None

            # Verify targeted resource if provided
            if expected_resource_id and payload.get("res") != expected_resource_id:
                return None

            return payload

        except Exception:
            return None

    def intercept_request(self, request: AccessRequest) -> AccessEvaluationResult:
        """Intercept access request, query PDP, and issue bound token on ALLOW."""
        result = self._pdp.evaluate(request)

        # On ALLOW, generate cryptographically bound session token
        if result.decision == AccessDecision.ALLOW:
            token = self.create_bound_token(
                subject_id=request.subject.subject_id,
                device_fingerprint=request.device.fingerprint_hash,
                resource_id=request.resource.resource_id,
            )
            return AccessEvaluationResult(
                evaluation_id=result.evaluation_id,
                request_id=result.request_id,
                decision=result.decision,
                trust_score=result.trust_score,
                matched_policy_id=result.matched_policy_id,
                reasons=result.reasons,
                evaluated_at=result.evaluated_at,
                session_token=token,
            )

        return result
