import pytest
from closure_service import ClosureValidationAgent
from common.models import Approval, ApprovalDecision, RemediationStatus
from remediation_engine import RemediationEngine


@pytest.mark.asyncio
async def test_remediation_engine_executes_rollback_strategy() -> None:
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre@example.com",
        comment="Rollback deployment",
    )
    engine = RemediationEngine()

    action = engine.build_action(approval)
    completed = await engine.execute(action)

    assert action.action_type == "rollback_deployment"
    assert completed.status == RemediationStatus.SKIPPED
    assert completed.parameters["execution_result"]["executed"] is False
    assert "No real jenkins executor is configured" in str(completed.error)
    assert "Execution not performed" in completed.output


@pytest.mark.asyncio
async def test_closure_validation_requires_independent_evidence() -> None:
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre@example.com",
        comment="Rollback deployment",
    )
    action = await RemediationEngine().execute(RemediationEngine().build_action(approval))

    report = await ClosureValidationAgent().validate(action)

    assert report.health_restored is False
    assert report.alerts_cleared is False
    assert report.metadata["validation_status"] == "VALIDATION_DATA_UNAVAILABLE"
    assert report.metadata["validation_evidence_count"] == 0
    assert report.validation["independent_validation"] is True
    assert report.validation["validation_data_available"] is False


def test_unknown_remediation_is_not_mapped_to_rollback() -> None:
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre@example.com",
        comment="Investigate and choose a safe recovery action",
    )
    engine = RemediationEngine()

    action = engine.build_action(approval)

    assert action.action_type == "unsupported_capability"
    assert engine.is_action_allowed(action.action_type) is False
    assert "unknown actions never default to rollback" in action.parameters["safety_block_reason"]


def test_remediation_allowlist_blocks_unknown_action_type() -> None:
    engine = RemediationEngine()

    assert engine.is_action_allowed("rollback_deployment") is True
    assert engine.is_action_allowed("unsupported_action") is False
