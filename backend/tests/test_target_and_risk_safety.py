import pytest

from common.capability_registry import CapabilityRegistry
from common.resolution_models import RemediationPlan, RollbackPlan, ValidationPlan
from common.risk_engine import RiskEngine
from common.target_resolution import DictResourceLookup, TargetResolutionError, TargetResolver


def _plan() -> RemediationPlan:
    return RemediationPlan(
        incident_id="11111111-1111-1111-1111-111111111111",
        root_cause="Verified deployment regression",
        rca_confidence=0.90,
        evidence_confidence=0.90,
        affected_resource_ids=["kai://workload/payment-api"],
        recommended_capability="kubernetes.restart_workload",
        target_resource_id="kai://workload/payment-api",
        target_version="v7",
        connector_id="k8s-a",
        expected_effect="Restore workload health",
        validation_plan=ValidationPlan(),
        rollback_plan=RollbackPlan(available=True),
    )


def test_target_resolver_requires_stable_verified_identity() -> None:
    lookup = DictResourceLookup(
        {
            "kai://workload/payment-api": {
                "tenant_id": "tenant-a",
                "project_id": "proj-a",
                "application_id": "app-a",
                "environment": "production",
                "provider": "kubernetes",
                "resource_type": "deployment",
                "resource_name": "payment-api",
                "resource_uid": "uid-123",
                "current_version": "v7",
                "connector_id": "k8s-a",
                "confidence": 1.0,
                "source_type": "verified",
            }
        }
    )

    target = TargetResolver(lookup).resolve(
        resource_id="kai://workload/payment-api",
        connector_id="k8s-a",
        expected_version="v7",
    )

    assert target.tenant_id == "tenant-a"
    assert target.resource_uid == "uid-123"


def test_target_resolver_blocks_inferred_or_stale_target() -> None:
    lookup = DictResourceLookup(
        {
            "kai://workload/payment-api": {
                "confidence": 0.95,
                "source_type": "inferred",
            }
        }
    )

    with pytest.raises(TargetResolutionError, match="TARGET_IDENTITY_UNCERTAIN"):
        TargetResolver(lookup).resolve(
            resource_id="kai://workload/payment-api",
            connector_id="k8s-a",
        )


def test_target_resolver_blocks_version_change_after_plan() -> None:
    lookup = DictResourceLookup(
        {
            "kai://workload/payment-api": {
                "tenant_id": "tenant-a",
                "project_id": "proj-a",
                "application_id": "app-a",
                "environment": "production",
                "provider": "kubernetes",
                "resource_type": "deployment",
                "resource_name": "payment-api",
                "resource_uid": "uid-123",
                "current_version": "v8",
                "connector_id": "k8s-a",
                "confidence": 1.0,
                "source_type": "verified",
            }
        }
    )

    with pytest.raises(TargetResolutionError, match="STALE_PLAN"):
        TargetResolver(lookup).resolve(
            resource_id="kai://workload/payment-api",
            connector_id="k8s-a",
            expected_version="v7",
        )


def test_risk_engine_uses_action_risk_not_incident_severity() -> None:
    plan = _plan()
    capability = CapabilityRegistry().require(plan.recommended_capability)

    assessment = RiskEngine().assess(
        plan=plan,
        capability=capability,
        environment_criticality=1.0,
        target_criticality=0.9,
        blast_radius_fraction=0.2,
    )

    assert 0.0 <= assessment.risk_score <= 1.0
    assert assessment.capability_risk > 0
    assert assessment.risk_class in {"low", "medium", "high", "critical"}
    assert any("capability=" in reason for reason in assessment.reasons)
