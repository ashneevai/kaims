from types import SimpleNamespace
from unittest.mock import patch

import pytest

from common.capability_registry import CapabilityRegistry, LEGACY_ACTION_CAPABILITIES
from common.event_publishers import _resolve_required_scope
from common.models import Approval, ApprovalDecision
from common.resolution_models import PlanSnapshot, RemediationPlan, ValidationCheck, ValidationPlan
from remediation_engine import RemediationEngine


def test_all_legacy_execution_actions_map_to_registered_capabilities() -> None:
    registry = CapabilityRegistry()

    for capability_id in LEGACY_ACTION_CAPABILITIES.values():
        assert registry.is_registered(capability_id)


def test_unknown_capability_is_rejected() -> None:
    registry = CapabilityRegistry()

    with pytest.raises(ValueError, match="UNSUPPORTED_CAPABILITY"):
        registry.require("unknown.operation")


def test_production_scope_refuses_missing_tenant_and_environment() -> None:
    alert = SimpleNamespace(metadata={}, labels={}, environment="")
    incident = SimpleNamespace(metadata={}, environment="")

    with patch("common.event_publishers.get_settings", return_value=SimpleNamespace(environment="production")):
        with pytest.raises(ValueError, match="tenant scope is required"):
            _resolve_required_scope(alert, incident)


def test_local_scope_uses_explicit_local_identity_for_development_only() -> None:
    alert = SimpleNamespace(metadata={}, labels={}, environment="")
    incident = SimpleNamespace(metadata={}, environment="")

    with patch("common.event_publishers.get_settings", return_value=SimpleNamespace(environment="local")):
        tenant_id, environment = _resolve_required_scope(alert, incident)

    assert tenant_id == "local"
    assert environment == "local"


def _structured_plan() -> RemediationPlan:
    return RemediationPlan(
        incident_id="11111111-1111-1111-1111-111111111111",
        root_cause="Deployment regression supported by change and error evidence",
        rca_confidence=0.92,
        evidence_confidence=0.90,
        affected_resource_ids=["kai://workload/payment-api"],
        recommended_capability="kubernetes.restart_workload",
        target_resource_id="kai://workload/payment-api",
        target_version="resource-version-7",
        connector_id="kubernetes-prod-cluster-a",
        parameters={"strategy": "canary"},
        preconditions=["target identity verified"],
        expected_effect="Restore healthy workload replicas",
        validation_plan=ValidationPlan(
            checks=[
                ValidationCheck(
                    check_id="alert-cleared",
                    provider="prometheus",
                    signal="original_alert",
                    operator="cleared",
                    expected_value=True,
                )
            ]
        ),
        evidence_ids=["EV-1", "EV-2"],
    )


def test_structured_plan_hash_is_stable_and_bound_to_action() -> None:
    plan = _structured_plan()
    snapshot = PlanSnapshot.from_plan(plan)
    approval = Approval(
        incident_id=plan.incident_id,
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre@example.com",
        metadata={
            "remediation_plan": plan.model_dump(mode="json"),
            "plan_hash": snapshot.plan_hash,
            "plan_revision": plan.revision,
        },
    )

    action = RemediationEngine().build_action(approval)

    assert action.action_type == "restart_pod"
    assert action.target == "kai://workload/payment-api"
    assert action.parameters["capability_id"] == "kubernetes.restart_workload"
    assert action.parameters["plan_hash"] == snapshot.plan_hash
    assert action.parameters["planning_contract"] == "structured-remediation-plan-v1"


def test_modified_structured_plan_is_blocked_after_approval_hash() -> None:
    plan = _structured_plan()
    snapshot = PlanSnapshot.from_plan(plan)
    payload = plan.model_dump(mode="json")
    payload["target_resource_id"] = "kai://workload/other-service"
    approval = Approval(
        incident_id=plan.incident_id,
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="sre@example.com",
        metadata={
            "remediation_plan": payload,
            "plan_hash": snapshot.plan_hash,
            "plan_revision": plan.revision,
        },
    )

    action = RemediationEngine().build_action(approval)

    assert action.action_type == "unsupported_capability"
    assert "plan hash mismatch" in action.parameters["safety_block_reason"]
