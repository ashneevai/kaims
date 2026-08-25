import pytest

from common.capability_registry import CapabilityRegistry
from common.preflight_engine import PreflightEngine, PreflightInputs
from common.resolution_models import (
    Evidence,
    EvidenceMode,
    EvidenceTrust,
    EvidenceType,
    Hypothesis,
    HypothesisStatus,
    Investigation,
    PlanSnapshot,
    RollbackPlan,
    ValidationCheck,
    ValidationPlan,
)
from common.structured_resolution_planner import (
    PlanningContext,
    StructuredPlanRequest,
    StructuredResolutionPlanner,
)
from common.target_resolution import DictResourceLookup, TargetResolver


INCIDENT_ID = "11111111-1111-1111-1111-111111111111"
RESOURCE_ID = "kai://workload/payment-api"


def _lookup(version: str = "v7") -> DictResourceLookup:
    return DictResourceLookup(
        {
            RESOURCE_ID: {
                "tenant_id": "tenant-a",
                "project_id": "proj-a",
                "application_id": "app-a",
                "environment": "production",
                "provider": "kubernetes",
                "resource_type": "deployment",
                "resource_name": "payment-api",
                "resource_uid": "uid-123",
                "current_version": version,
                "connector_id": "k8s-a",
                "confidence": 1.0,
                "source_type": "verified",
            }
        }
    )


def _validation_plan() -> ValidationPlan:
    return ValidationPlan(
        checks=[
            ValidationCheck(
                check_id="workload-ready",
                provider="kubernetes",
                signal="ready_replicas",
                operator=">=",
                expected_value=3,
                resource_id=RESOURCE_ID,
            ),
            ValidationCheck(
                check_id="alert-cleared",
                provider="prometheus",
                signal="original_alert_firing",
                operator="==",
                expected_value=False,
                resource_id=RESOURCE_ID,
            ),
        ]
    )


def _request() -> StructuredPlanRequest:
    return StructuredPlanRequest(
        incident_id=INCIDENT_ID,
        root_cause="Deployment regression supported by live evidence",
        rca_confidence=0.91,
        evidence_confidence=0.95,
        recommended_capability="kubernetes.rollback_deployment",
        target_resource_id=RESOURCE_ID,
        target_version="v7",
        connector_id="k8s-a",
        parameters={"revision": "v6"},
        preconditions=["incident_active", "target_version=v7"],
        expected_effect="Restore payment-api workload health",
        validation_plan=_validation_plan(),
        rollback_plan=RollbackPlan(
            capability_id="kubernetes.rollback_deployment",
            target_resource_id=RESOURCE_ID,
            parameters={"revision": "v7"},
            pre_action_state={"revision": "v7"},
            available=True,
        ),
        evidence_ids=["evidence-1", "evidence-2"],
    )


def _preflight_inputs() -> PreflightInputs:
    return PreflightInputs(
        connector_available=True,
        credentials_valid=True,
        permissions_sufficient=True,
        preconditions_hold=True,
        incident_still_active=True,
    )


def test_live_evidence_is_production_usable_but_simulation_is_not() -> None:
    common = dict(
        tenant_id="tenant-a",
        incident_id=INCIDENT_ID,
        provider="prometheus",
        evidence_type=EvidenceType.METRIC,
        observed_at="2026-08-25T06:00:00Z",
        content_hash=Evidence.hash_content({"value": 18.0}),
        summary="5xx rate is 18%",
        trust_level=EvidenceTrust.VERIFIED,
    )
    assert Evidence(**common, mode=EvidenceMode.LIVE).usable_for_production_rca is True
    assert Evidence(**common, mode=EvidenceMode.SIMULATION).usable_for_production_rca is False


def test_investigation_preserves_multiple_hypotheses_and_uncertainty() -> None:
    hypotheses = [
        Hypothesis(
            incident_id=INCIDENT_ID,
            statement="Deployment regression",
            status=HypothesisStatus.SUPPORTED,
            confidence=0.72,
        ),
        Hypothesis(
            incident_id=INCIDENT_ID,
            statement="Database saturation",
            status=HypothesisStatus.UNRESOLVED,
            confidence=0.41,
        ),
    ]
    investigation = Investigation(
        tenant_id="tenant-a",
        incident_id=INCIDENT_ID,
        hypotheses=hypotheses,
    )
    assert len(investigation.hypotheses) == 2
    assert investigation.hypotheses[0].confidence != investigation.hypotheses[1].confidence


def test_structured_planner_resolves_target_runs_preflight_risk_and_snapshot() -> None:
    planner = StructuredResolutionPlanner(
        registry=CapabilityRegistry(),
        target_resolver=TargetResolver(_lookup()),
    )
    result = planner.build(
        request=_request(),
        preflight_inputs=_preflight_inputs(),
        planning_context=PlanningContext(
            environment_criticality=1.0,
            target_criticality=0.8,
            blast_radius_fraction=0.2,
        ),
    )

    assert result.plan.preflight_assessment is not None
    assert result.plan.preflight_assessment.passed is True
    assert result.plan.risk_assessment is not None
    assert result.plan.recommended_capability == "kubernetes.rollback_deployment"
    assert result.plan.target_resource_id == RESOURCE_ID
    assert result.plan.target_version == "v7"
    assert result.snapshot.verifies(result.plan) is True


def test_structured_planner_blocks_stale_target_before_plan_can_execute() -> None:
    planner = StructuredResolutionPlanner(
        registry=CapabilityRegistry(),
        target_resolver=TargetResolver(_lookup(version="v8")),
    )
    with pytest.raises(ValueError, match="STALE_PLAN"):
        planner.build(
            request=_request(),
            preflight_inputs=_preflight_inputs(),
            planning_context=PlanningContext(
                environment_criticality=1.0,
                target_criticality=0.8,
                blast_radius_fraction=0.2,
            ),
        )


def test_preflight_blocks_missing_validation_for_validation_required_capability() -> None:
    registry = CapabilityRegistry()
    capability = registry.require("kubernetes.restart_workload")
    target = TargetResolver(_lookup()).resolve(
        resource_id=RESOURCE_ID,
        connector_id="k8s-a",
        expected_version="v7",
    )
    request = _request()
    plan = StructuredResolutionPlanner(
        registry=registry,
        target_resolver=TargetResolver(_lookup()),
    )
    base = plan.build(
        request=request,
        preflight_inputs=_preflight_inputs(),
        planning_context=PlanningContext(
            environment_criticality=0.5,
            target_criticality=0.5,
            blast_radius_fraction=0.1,
        ),
    ).plan
    missing_validation = base.model_copy(
        update={
            "recommended_capability": "kubernetes.restart_workload",
            "validation_plan": ValidationPlan(checks=[]),
        }
    )
    assessment = PreflightEngine().assess(
        plan=missing_validation,
        capability=capability,
        target=target,
        inputs=_preflight_inputs(),
    )
    assert assessment.passed is False
    assert "VALIDATION_UNAVAILABLE" in assessment.failures


def test_plan_snapshot_detects_executable_parameter_tampering() -> None:
    planner = StructuredResolutionPlanner(
        registry=CapabilityRegistry(),
        target_resolver=TargetResolver(_lookup()),
    )
    result = planner.build(
        request=_request(),
        preflight_inputs=_preflight_inputs(),
        planning_context=PlanningContext(
            environment_criticality=1.0,
            target_criticality=0.8,
            blast_radius_fraction=0.2,
        ),
    )
    changed = result.plan.model_copy(update={"parameters": {"revision": "v5"}})
    assert PlanSnapshot.model_validate(result.snapshot.model_dump()).verifies(changed) is False
