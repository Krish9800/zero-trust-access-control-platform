"""Policy Decision Point (PDP) & ABAC Rule Engine.

Evaluates AccessRequest contexts against registered ZeroTrustPolicy definitions,
incorporating dynamic trust scores, MFA challenges, and step-up verification logic.
Conforms to NIST SP 800-207 Policy Engine specifications.
"""

import uuid
from datetime import UTC, datetime

from zero_trust.config.settings import Settings, get_settings
from zero_trust.engine.trust_calculator import TrustCalculator
from zero_trust.models.enums import (
    AccessDecision,
    AuthenticationStrength,
    DeviceHealthStatus,
    PolicyEffect,
    SensitivityLevel,
)
from zero_trust.models.schemas import (
    AccessEvaluationResult,
    AccessRequest,
    TrustScoreBreakdown,
    ZeroTrustPolicy,
)


class PolicyDecisionPoint:
    """NIST SP 800-207 Policy Decision Point (PDP) and ABAC Rule Engine."""

    def __init__(
        self,
        policies: list[ZeroTrustPolicy] | None = None,
        trust_calculator: TrustCalculator | None = None,
        settings: Settings | None = None,
    ) -> None:
        """Initialize Policy Decision Point with policies, trust calculator, and settings."""
        self._settings = settings or get_settings()
        self._trust_calculator = trust_calculator or TrustCalculator(self._settings)
        # Sort policies by priority ascending (lower number = higher priority)
        self._policies: list[ZeroTrustPolicy] = sorted(policies or [], key=lambda p: p.priority)

    def register_policy(self, policy: ZeroTrustPolicy) -> None:
        """Register or update an access policy in the PDP rule registry."""
        self._policies = [p for p in self._policies if p.policy_id != policy.policy_id]
        self._policies.append(policy)
        self._policies.sort(key=lambda p: p.priority)

    def get_policies(self) -> list[ZeroTrustPolicy]:
        """Return the list of currently registered policies ordered by priority."""
        return list(self._policies)

    def _matches_policy(self, policy: ZeroTrustPolicy, request: AccessRequest) -> bool:
        """Determine if an access request matches the scope of a given policy."""
        # 1. Role matching (if policy specifies allowed_roles)
        if policy.allowed_roles:
            has_matching_role = any(r in policy.allowed_roles for r in request.subject.roles)
            if not has_matching_role:
                return False

        # 2. Department matching (if policy specifies allowed_departments)
        if policy.allowed_departments:
            has_matching_dept = any(
                d in policy.allowed_departments for d in request.subject.departments
            )
            if not has_matching_dept:
                return False

        # 3. Sensitivity Level checking
        sensitivity_rank: dict[SensitivityLevel, int] = {
            SensitivityLevel.LOW: 1,
            SensitivityLevel.MEDIUM: 2,
            SensitivityLevel.HIGH: 3,
            SensitivityLevel.CRITICAL: 4,
        }
        if (
            sensitivity_rank[request.resource.sensitivity_level]
            > sensitivity_rank[policy.max_sensitivity]
        ):
            return False

        # 4. Mandatory endpoint compliance checks
        if policy.require_encryption and not request.device.disk_encrypted:
            return False

        if policy.require_edr and not request.device.edr_active:
            return False

        # 5. ABAC Custom attribute conditions
        for cond_key, cond_val in policy.conditions.items():
            if cond_key == "resource_type" and request.resource.resource_type != cond_val:
                return False
            if cond_key == "action" and request.resource.action != cond_val:
                return False
            if cond_key == "country_code" and request.network.country_code != cond_val:
                return False

        return True

    def evaluate(self, request: AccessRequest) -> AccessEvaluationResult:
        """Evaluate access request against dynamic trust and active zero-trust policies."""
        evaluation_id = str(uuid.uuid4())
        evaluated_at = datetime.now(UTC)
        reasons: list[str] = []

        # 1. Calculate continuous dynamic trust score
        trust_breakdown: TrustScoreBreakdown = self._trust_calculator.evaluate_trust(request)
        total_score = trust_breakdown.total_score

        # 2. Hard Deny on compromised or jailbroken devices
        if (
            request.device.health_status == DeviceHealthStatus.COMPROMISED
            or request.device.is_jailbroken
        ):
            reasons.append("Endpoint is compromised or rooted/jailbroken. Immediate DENY enforced.")
            return AccessEvaluationResult(
                evaluation_id=evaluation_id,
                request_id=request.request_id,
                decision=AccessDecision.DENY,
                trust_score=trust_breakdown,
                matched_policy_id=None,
                reasons=reasons,
                evaluated_at=evaluated_at,
            )

        # 3. Trust Score Deny Floor
        if total_score <= self._settings.trust_score_deny_threshold:
            reasons.append(
                f"Trust score {total_score:.2f} is at or below deny threshold "
                f"({self._settings.trust_score_deny_threshold:.2f})."
            )
            return AccessEvaluationResult(
                evaluation_id=evaluation_id,
                request_id=request.request_id,
                decision=AccessDecision.DENY,
                trust_score=trust_breakdown,
                matched_policy_id=None,
                reasons=reasons,
                evaluated_at=evaluated_at,
            )

        # 4. Find matching policy by priority order
        matched_policy: ZeroTrustPolicy | None = None
        for policy in self._policies:
            if self._matches_policy(policy, request):
                matched_policy = policy
                break

        # 5. Default-Deny rule if no policy matches
        if not matched_policy:
            reasons.append("No zero-trust policy matched criteria (Default Deny enforced).")
            return AccessEvaluationResult(
                evaluation_id=evaluation_id,
                request_id=request.request_id,
                decision=AccessDecision.DENY,
                trust_score=trust_breakdown,
                matched_policy_id=None,
                reasons=reasons,
                evaluated_at=evaluated_at,
            )

        # 6. Explicit DENY policy effect
        if matched_policy.effect == PolicyEffect.DENY:
            reasons.append(
                f"Explicit deny policy applied: {matched_policy.name} ({matched_policy.policy_id})."
            )
            return AccessEvaluationResult(
                evaluation_id=evaluation_id,
                request_id=request.request_id,
                decision=AccessDecision.DENY,
                trust_score=trust_breakdown,
                matched_policy_id=matched_policy.policy_id,
                reasons=reasons,
                evaluated_at=evaluated_at,
            )

        # 7. Check policy-specific minimum trust score requirement
        if total_score < matched_policy.min_trust_score:
            reasons.append(
                f"Trust score {total_score:.2f} is below policy minimum requirement "
                f"({matched_policy.min_trust_score:.2f}). Triggering STEP_UP."
            )
            return AccessEvaluationResult(
                evaluation_id=evaluation_id,
                request_id=request.request_id,
                decision=AccessDecision.STEP_UP,
                trust_score=trust_breakdown,
                matched_policy_id=matched_policy.policy_id,
                reasons=reasons,
                evaluated_at=evaluated_at,
            )

        # 8. Check MFA Requirement for high sensitivity or password-only authentication
        if (
            request.resource.sensitivity_level in (SensitivityLevel.HIGH, SensitivityLevel.CRITICAL)
            and request.subject.auth_strength == AuthenticationStrength.PASSWORD_ONLY
        ):
            reasons.append(
                "High/Critical sensitivity asset requires secondary authentication factor."
            )
            return AccessEvaluationResult(
                evaluation_id=evaluation_id,
                request_id=request.request_id,
                decision=AccessDecision.REQUIRE_MFA,
                trust_score=trust_breakdown,
                matched_policy_id=matched_policy.policy_id,
                reasons=reasons,
                evaluated_at=evaluated_at,
            )

        # 9. Step-Up threshold check
        if total_score < self._settings.trust_score_allow_threshold:
            reasons.append(
                f"Trust score {total_score:.2f} is below allow threshold "
                f"({self._settings.trust_score_allow_threshold:.2f}). Triggering STEP_UP."
            )
            return AccessEvaluationResult(
                evaluation_id=evaluation_id,
                request_id=request.request_id,
                decision=AccessDecision.STEP_UP,
                trust_score=trust_breakdown,
                matched_policy_id=matched_policy.policy_id,
                reasons=reasons,
                evaluated_at=evaluated_at,
            )

        # 10. Unconditional Access Granted
        reasons.append(
            f"Policy '{matched_policy.name}' matched with compliant trust score {total_score:.2f}."
        )
        return AccessEvaluationResult(
            evaluation_id=evaluation_id,
            request_id=request.request_id,
            decision=AccessDecision.ALLOW,
            trust_score=trust_breakdown,
            matched_policy_id=matched_policy.policy_id,
            reasons=reasons,
            evaluated_at=evaluated_at,
        )
