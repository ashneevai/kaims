from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from common.models import Approval, ApprovalDecision, RemediationAction
from common.resolution_models import ExecutionStrategy, RemediationPlan


@dataclass(frozen=True)
class RollbackGovernanceDecision:
    allowed: bool
    requires_hitl: bool
    reasons: tuple[str, ...]
    required_strategy: ExecutionStrategy | None = None

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "rollback governance passed"


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "approved", "authorized"}


def _normalized(value: Any) -> str:
    return str(value or "").strip().lower()


def _is_production(environment: Any) -> bool:
    return _normalized(environment) in {"prod", "production", "prd"}


def _rollback_requested(action: RemediationAction) -> bool:
    values = [
        action.action_type,
        action.parameters.get("capability_id"),
        action.parameters.get("recommended_capability"),
    ]
    return any("rollback" in _normalized(value) or "revert" in _normalized(value) for value in values)


def evaluate_rollback_governance(
    *,
    approval: Approval,
    action: RemediationAction,
) -> RollbackGovernanceDecision:
    """Fail-closed governance for production rollback execution.

    This layer is intentionally independent of the executor.  It proves that a
    rollback is bound to an approved structured plan and recoverable pre-action
    state before any provider-specific command can execute.
    """

    if not _rollback_requested(action):
        return RollbackGovernanceDecision(True, False, ())

    failures: list[str] = []
    metadata = approval.metadata if isinstance(approval.metadata, dict) else {}
    plan_payload = metadata.get("remediation_plan")
    if not isinstance(plan_payload, dict):
        return RollbackGovernanceDecision(
            False,
            True,
            ("ROLLBACK_STRUCTURED_PLAN_REQUIRED",),
        )

    try:
        plan = RemediationPlan.model_validate(plan_payload)
    except Exception:
        return RollbackGovernanceDecision(False, True, ("ROLLBACK_PLAN_INVALID",))

    if approval.decision != ApprovalDecision.APPROVED:
        failures.append("ROLLBACK_HUMAN_APPROVAL_REQUIRED")
    if str(plan.incident_id) != str(action.incident_id):
        failures.append("ROLLBACK_INCIDENT_BINDING_MISMATCH")
    if plan.target_resource_id != action.target:
        failures.append("ROLLBACK_TARGET_BINDING_MISMATCH")

    rollback = plan.rollback_plan
    if rollback is None or not rollback.available:
        failures.append("ROLLBACK_PLAN_NOT_AVAILABLE")
    else:
        if not rollback.pre_action_state:
            failures.append("ROLLBACK_PRE_ACTION_STATE_REQUIRED")
        if rollback.target_resource_id and rollback.target_resource_id != plan.target_resource_id:
            failures.append("ROLLBACK_TARGET_STATE_MISMATCH")
        if rollback.capability_id and "rollback" not in _normalized(rollback.capability_id) and "revert" not in _normalized(rollback.capability_id):
            failures.append("ROLLBACK_CAPABILITY_NOT_EXPLICIT")

    preflight = plan.preflight_assessment
    if preflight is None or not preflight.passed:
        failures.append("ROLLBACK_PREFLIGHT_REQUIRED")
    else:
        if not preflight.target_identity_verified:
            failures.append("ROLLBACK_TARGET_IDENTITY_UNVERIFIED")
        if not preflight.connector_available:
            failures.append("ROLLBACK_CONNECTOR_UNAVAILABLE")
        if not preflight.credentials_valid:
            failures.append("ROLLBACK_CREDENTIALS_INVALID")
        if not preflight.permissions_sufficient:
            failures.append("ROLLBACK_PERMISSIONS_INSUFFICIENT")
        if not preflight.rollback_available:
            failures.append("ROLLBACK_PREFLIGHT_ROLLBACK_UNAVAILABLE")
        if not preflight.environment_allowed:
            failures.append("ROLLBACK_ENVIRONMENT_NOT_ALLOWED")
        if preflight.conflicting_remediation:
            failures.append("ROLLBACK_CONFLICTING_REMEDIATION")
        if preflight.change_freeze_active:
            failures.append("ROLLBACK_CHANGE_FREEZE_ACTIVE")

    if plan.risk_assessment is None:
        failures.append("ROLLBACK_RISK_ASSESSMENT_REQUIRED")

    environment = (
        plan.parameters.get("environment")
        or metadata.get("environment")
        or action.parameters.get("environment")
    )
    change_window_authorized = _truthy(
        metadata.get("change_window_authorized")
        or action.parameters.get("change_window_authorized")
    )
    emergency_change_approved = _truthy(
        metadata.get("emergency_change_approved")
        or action.parameters.get("emergency_change_approved")
    )
    if _is_production(environment) and not (change_window_authorized or emergency_change_approved):
        failures.append("ROLLBACK_CHANGE_AUTHORIZATION_REQUIRED")

    blast = plan.blast_radius if isinstance(plan.blast_radius, dict) else {}
    affected_instances = blast.get("affected_instances") or blast.get("instance_count")
    affected_percent = blast.get("affected_percent") or blast.get("percentage")
    broad_blast = False
    try:
        broad_blast = int(affected_instances or 0) > 1
    except (TypeError, ValueError):
        broad_blast = True
    try:
        broad_blast = broad_blast or float(affected_percent or 0) > 10.0
    except (TypeError, ValueError):
        broad_blast = True

    required_strategy: ExecutionStrategy | None = None
    if broad_blast or _is_production(environment):
        required_strategy = ExecutionStrategy.CANARY
        if plan.execution_strategy not in {ExecutionStrategy.CANARY, ExecutionStrategy.PROGRESSIVE}:
            failures.append("ROLLBACK_CANARY_OR_PROGRESSIVE_REQUIRED")

    if not plan.validation_plan.checks:
        failures.append("ROLLBACK_POST_VALIDATION_REQUIRED")

    return RollbackGovernanceDecision(
        allowed=not failures,
        requires_hitl=bool(failures),
        reasons=tuple(failures),
        required_strategy=required_strategy,
    )


def apply_rollback_governance(
    *,
    approval: Approval,
    action: RemediationAction,
) -> RemediationAction:
    decision = evaluate_rollback_governance(approval=approval, action=action)
    action.parameters["rollback_governance"] = {
        "allowed": decision.allowed,
        "requires_hitl": decision.requires_hitl,
        "reasons": list(decision.reasons),
        "required_strategy": decision.required_strategy.value if decision.required_strategy else None,
    }
    if decision.allowed:
        return action

    original_action_type = action.action_type
    action.action_type = "unsupported_capability"
    action.parameters["blocked_action_type"] = original_action_type
    action.parameters["safety_block_reason"] = decision.reason
    return action
