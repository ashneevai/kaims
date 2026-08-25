from __future__ import annotations

from uuid import uuid4

from common.models import Approval, ApprovalDecision, RemediationAction
from common.rollback_governance import evaluate_rollback_governance
from common.resolution_models import (
    ExecutionStrategy,
    PreflightAssessment,
    RemediationPlan,
    RiskAssessment,
    RollbackPlan,
    ValidationCheck,
    ValidationPlan,
)


def _plan(*, change_freeze: bool = False, strategy: ExecutionStrategy = ExecutionStrategy.CANARY, pre_state: bool = True) -> RemediationPlan:
    incident_id = uuid4()
    return RemediationPlan(
        incident_id=incident_id,
        root_cause="bad deployment",
        rca_confidence=0.95,
        evidence_confidence=0.95,
        recommended_capability="kubernetes.rollback_deployment",
        target_resource_id="kai://workload/checkout",
        connector_id="kubernetes-prod",
        parameters={"environment": "production"},
        expected_effect="restore prior healthy deployment",
        blast_radius={"affected_instances": 3, "affected_percent": 25},
        execution_strategy=strategy,
        validation_plan=ValidationPlan(
            checks=[
                ValidationCheck(
                    check_id="health",
                    provider="prometheus",
                    signal="up{service='checkout'}",
                    operator="==",
                    expected_value=1,
                )
            ]
        ),
        rollback_plan=RollbackPlan(
            capability_id="kubernetes.rollback_deployment",
            target_resource_id="kai://workload/checkout",
            pre_action_state={"revision": "41"} if pre_state else {},
            available=True,
        ),
        risk_assessment=RiskAssessment(risk_score=0.45, risk_class="high"),
        preflight_assessment=PreflightAssessment(
            passed=True,
            target_identity_verified=True,
            connector_available=True,
            credentials_valid=True,
            permissions_sufficient=True,
            capability_supported=True,
            preconditions_hold=True,
            rollback_available=True,
            validation_available=True,
            environment_allowed=True,
            resource_type_supported=True,
            change_freeze_active=change_freeze,
        ),
    )


def _approval_and_action(plan: RemediationPlan, *, change_authorized: bool = True):
    approval = Approval(
        incident_id=plan.incident_id,
        recommendation_id=uuid4(),
        decision=ApprovalDecision.APPROVED,
        approver="operator@example.com",
        metadata={
            "remediation_plan": plan.model_dump(mode="json"),
            "change_window_authorized": change_authorized,
        },
    )
    action = RemediationAction(
        incident_id=plan.incident_id,
        approval_id=approval.id,
        action_type="rollback_deployment",
        target=plan.target_resource_id,
        parameters={"capability_id": plan.recommended_capability, "environment": "production"},
    )
    return approval, action


def test_production_rollback_passes_with_bound_state_change_auth_and_canary() -> None:
    plan = _plan()
    approval, action = _approval_and_action(plan)

    decision = evaluate_rollback_governance(approval=approval, action=action)

    assert decision.allowed is True
    assert decision.requires_hitl is False
    assert decision.required_strategy == ExecutionStrategy.CANARY


def test_production_rollback_requires_change_authorization() -> None:
    plan = _plan()
    approval, action = _approval_and_action(plan, change_authorized=False)

    decision = evaluate_rollback_governance(approval=approval, action=action)

    assert decision.allowed is False
    assert "ROLLBACK_CHANGE_AUTHORIZATION_REQUIRED" in decision.reasons


def test_rollback_requires_pre_action_state_provenance() -> None:
    plan = _plan(pre_state=False)
    approval, action = _approval_and_action(plan)

    decision = evaluate_rollback_governance(approval=approval, action=action)

    assert decision.allowed is False
    assert "ROLLBACK_PRE_ACTION_STATE_REQUIRED" in decision.reasons


def test_change_freeze_blocks_rollback_even_when_change_window_is_authorized() -> None:
    plan = _plan(change_freeze=True)
    approval, action = _approval_and_action(plan)

    decision = evaluate_rollback_governance(approval=approval, action=action)

    assert decision.allowed is False
    assert "ROLLBACK_CHANGE_FREEZE_ACTIVE" in decision.reasons


def test_broad_production_rollback_requires_canary_or_progressive() -> None:
    plan = _plan(strategy=ExecutionStrategy.FULL)
    approval, action = _approval_and_action(plan)

    decision = evaluate_rollback_governance(approval=approval, action=action)

    assert decision.allowed is False
    assert "ROLLBACK_CANARY_OR_PROGRESSIVE_REQUIRED" in decision.reasons


def test_target_binding_mismatch_blocks_execution() -> None:
    plan = _plan()
    approval, action = _approval_and_action(plan)
    action.target = "kai://workload/payments"

    decision = evaluate_rollback_governance(approval=approval, action=action)

    assert decision.allowed is False
    assert "ROLLBACK_TARGET_BINDING_MISMATCH" in decision.reasons


def test_non_rollback_action_is_not_affected_by_rollback_governance() -> None:
    plan = _plan()
    approval, action = _approval_and_action(plan)
    action.action_type = "restart_deployment"
    action.parameters["capability_id"] = "kubernetes.restart_deployment"

    decision = evaluate_rollback_governance(approval=approval, action=action)

    assert decision.allowed is True
