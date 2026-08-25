from __future__ import annotations

from uuid import UUID

import pytest

from common.execution_safety import (
    ExecutionSafetyDecision,
    build_execution_safety_assessment,
    execution_stages,
    immutable_pre_execution_snapshot,
)
from common.models import RemediationAction
from common.staged_execution import StageGateDecision, evaluate_stage_health_gate
from remediation_engine.execution_coordinator import InMemoryExecutionCoordinator


INCIDENT_ID = UUID("11111111-1111-1111-1111-111111111111")


def _action(*, action_type: str = "rollback_deployment", strategy: str = "CANARY") -> RemediationAction:
    return RemediationAction(
        incident_id=INCIDENT_ID,
        action_type=action_type,
        target="kai://workload/checkout",
        parameters={
            "plan_id": "22222222-2222-2222-2222-222222222222",
            "plan_revision": 2,
            "plan_hash": "abc123",
            "capability_id": "kubernetes.rollback_deployment",
            "capability_version": "1.0",
            "target_version": "v41",
            "environment": "production",
            "execution_strategy": strategy,
            "validation_plan": {"checks": [{"check_id": "health"}]},
            "rollback_plan": {
                "pre_action_state": {
                    "resource_version": "v42",
                    "replicas": 6,
                }
            },
        },
    )


def test_snapshot_is_bound_to_plan_target_and_pre_action_state() -> None:
    snapshot = immutable_pre_execution_snapshot(_action())
    assert snapshot["plan_hash"] == "abc123"
    assert snapshot["target"] == "kai://workload/checkout"
    assert snapshot["pre_action_state"]["resource_version"] == "v42"


def test_canary_strategy_has_health_gated_stages() -> None:
    stages = execution_stages(_action(strategy="CANARY"))
    assert [stage.percent for stage in stages] == [5, 25, 100]
    assert all(stage.requires_health_gate for stage in stages)


def test_recursive_rollback_is_blocked() -> None:
    action = _action()
    action.parameters["rollback_lineage"] = ["rollback_deployment"]
    result = build_execution_safety_assessment(action)
    assert result.decision == ExecutionSafetyDecision.BLOCK
    assert "ROLLBACK_CHAIN_BLOCKED" in result.reason


def test_missing_plan_hash_is_blocked() -> None:
    action = _action()
    action.parameters["plan_hash"] = ""
    result = build_execution_safety_assessment(action)
    assert result.decision == ExecutionSafetyDecision.BLOCK


@pytest.mark.asyncio
async def test_coordinator_prevents_concurrent_target_execution_and_duplicates() -> None:
    coordinator = InMemoryExecutionCoordinator()
    first = await coordinator.acquire(lock_key="target", idempotency_key="idem")
    second = await coordinator.acquire(lock_key="target", idempotency_key="idem-2")
    assert first.acquired is True
    assert second.acquired is False
    assert second.duplicate is False

    await coordinator.complete(lock_key="target", idempotency_key="idem", success=True)
    duplicate = await coordinator.acquire(lock_key="target", idempotency_key="idem")
    assert duplicate.acquired is False
    assert duplicate.duplicate is True


def test_stage_gate_advances_only_with_live_healthy_provenance() -> None:
    result = evaluate_stage_health_gate(
        {
            "mode": "LIVE",
            "evidence_ids": ["metric:1", "alert:2"],
            "required_checks": {"health": True, "error_rate": True},
        }
    )
    assert result.decision == StageGateDecision.ADVANCE


def test_stage_gate_aborts_on_regression() -> None:
    result = evaluate_stage_health_gate(
        {
            "mode": "LIVE",
            "evidence_ids": ["metric:1"],
            "required_checks": {"health": True},
            "error_rate_regression": True,
        }
    )
    assert result.decision == StageGateDecision.ABORT


def test_stage_gate_holds_without_provenance() -> None:
    result = evaluate_stage_health_gate(
        {
            "mode": "LIVE",
            "required_checks": {"health": True},
        }
    )
    assert result.decision == StageGateDecision.HOLD
