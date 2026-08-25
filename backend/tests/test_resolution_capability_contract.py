from uuid import uuid4

from common.models import AlertSeverity, Recommendation
from common.resolution_models import (
    PreflightAssessment,
    RemediationPlan,
    RiskAssessment,
    ValidationCheck,
    ValidationPlan,
)
from resolution_agent.capability_contract import CapabilityContractGate


def _recommendation(*, action: str, commands: list[str] | None = None) -> Recommendation:
    return Recommendation(
        incident_id=uuid4(),
        root_cause="Deployment regression",
        confidence=0.9,
        impact="Elevated payment errors",
        recommended_action=action,
        severity=AlertSeverity.HIGH,
        rationale="Supported by deployment and metric evidence",
        commands=commands or [],
    )


def test_legacy_command_text_is_display_only_and_not_execution_authority() -> None:
    recommendation = _recommendation(
        action="restart the payment pods",
        commands=["kubectl rollout restart deployment/payment-api -n prod"],
    )
    gated = CapabilityContractGate().apply(recommendation)

    assert gated.metadata["execution_allowed"] is False
    assert gated.metadata["governance_ready"] is False
    assert gated.metadata["planning_status"] == "CAPABILITY_SELECTION_REQUIRED"
    assert gated.metadata["legacy_execution_preview"]["display_only"] is True
    assert gated.metadata["legacy_execution_preview"]["commands"] == recommendation.commands
    assert "recommended_capability" not in gated.metadata


def test_exact_registered_capability_becomes_intent_but_not_execution_authority() -> None:
    gated = CapabilityContractGate().apply(_recommendation(action="kubernetes.restart_workload"))

    assert gated.metadata["recommended_capability"] == "kubernetes.restart_workload"
    assert gated.metadata["planning_status"] == "TARGET_RESOLUTION_REQUIRED"
    assert gated.metadata["execution_allowed"] is False
    assert gated.metadata["governance_ready"] is False


def test_valid_structured_plan_is_governance_ready_but_not_self_authorized() -> None:
    recommendation = _recommendation(action="kubernetes.restart_workload")
    plan = RemediationPlan(
        incident_id=recommendation.incident_id,
        root_cause=recommendation.root_cause,
        rca_confidence=0.9,
        evidence_confidence=0.95,
        recommended_capability="kubernetes.restart_workload",
        target_resource_id="kai://workload/payment-api",
        target_version="v7",
        connector_id="k8s-a",
        expected_effect="Restore workload health",
        validation_plan=ValidationPlan(
            checks=[
                ValidationCheck(
                    check_id="ready",
                    provider="kubernetes",
                    signal="ready_replicas",
                    operator=">=",
                    expected_value=3,
                )
            ]
        ),
        preflight_assessment=PreflightAssessment(
            passed=True,
            target_identity_verified=True,
            connector_available=True,
            credentials_valid=True,
            permissions_sufficient=True,
            capability_supported=True,
            preconditions_hold=True,
            validation_available=True,
            incident_still_active=True,
            target_version_current=True,
            environment_allowed=True,
            resource_type_supported=True,
        ),
        risk_assessment=RiskAssessment(risk_score=0.35, risk_class="medium"),
    )
    recommendation.metadata["remediation_plan"] = plan.model_dump(mode="json")

    gated = CapabilityContractGate().apply(recommendation)

    assert gated.metadata["planning_status"] == "STRUCTURED_PLAN_READY"
    assert gated.metadata["governance_ready"] is True
    assert gated.metadata["governance_status"] == "POLICY_EVALUATION_REQUIRED"
    assert gated.metadata["execution_allowed"] is False
    assert gated.metadata["quality_gate"]["trusted_for_auto_execution"] is False
    assert gated.metadata["quality_gate"]["requires_human_review"] is True
    assert gated.metadata["plan_revision"] == 1
    assert len(gated.metadata["plan_hash"]) == 64


def test_unknown_capability_in_structured_plan_is_blocked() -> None:
    recommendation = _recommendation(action="unknown.powercycle_everything")
    plan = RemediationPlan(
        incident_id=recommendation.incident_id,
        root_cause=recommendation.root_cause,
        rca_confidence=0.9,
        recommended_capability="unknown.powercycle_everything",
        target_resource_id="kai://workload/payment-api",
        connector_id="unknown",
        expected_effect="Unknown",
        validation_plan=ValidationPlan(checks=[]),
    )
    recommendation.metadata["remediation_plan"] = plan.model_dump(mode="json")

    gated = CapabilityContractGate().apply(recommendation)

    assert gated.metadata["execution_allowed"] is False
    assert gated.metadata["governance_ready"] is False
    assert gated.metadata["planning_status"] == "INVALID_REMEDIATION_PLAN"
    assert gated.metadata["governance_status"] == "BLOCKED_INVALID_PLAN"
    assert "UNSUPPORTED_CAPABILITY" in gated.metadata["planning_error"]
