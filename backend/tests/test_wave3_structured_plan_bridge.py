from types import SimpleNamespace
from uuid import uuid4

from common.capability_registry import CapabilityRegistry
from common.models import AlertSeverity, Recommendation
from resolution_agent.structured_plan_bridge import StructuredPlanBridge


RESOURCE_ID = "kai://workload/payment-api"


def _recommendation() -> Recommendation:
    recommendation = Recommendation(
        incident_id=uuid4(),
        root_cause="Payment deployment is unhealthy",
        confidence=0.92,
        impact="Checkout errors increased",
        recommended_action="kubernetes.restart_workload",
        severity=AlertSeverity.HIGH,
        rationale="Restart the verified workload and validate service health.",
        commands=[],
    )
    recommendation.metadata["recommended_capability"] = "kubernetes.restart_workload"
    recommendation.metadata["target_resource_id"] = RESOURCE_ID
    recommendation.metadata["evidence_ids"] = ["evidence-1", "evidence-2"]
    return recommendation


def _context(*, complete_preflight: bool = True):
    preflight = {
        "connector_available": complete_preflight,
        "credentials_valid": complete_preflight,
        "permissions_sufficient": complete_preflight,
        "preconditions_hold": complete_preflight,
        "incident_still_active": True,
    }
    return SimpleNamespace(
        metadata={
            "tenant_id": "tenant-a",
            "target_resource_id": RESOURCE_ID,
            "operational_resources": {
                RESOURCE_ID: {
                    "tenant_id": "tenant-a",
                    "project_id": "project-a",
                    "application_id": "application-a",
                    "environment": "production",
                    "provider": "kubernetes",
                    "account_id": "account-a",
                    "region": "us-east-1",
                    "resource_type": "deployment",
                    "resource_name": "payment-api",
                    "resource_uid": "uid-payment-api",
                    "current_version": "v7",
                    "connector_id": "k8s-prod",
                    "confidence": 1.0,
                    "source_type": "verified",
                }
            },
            "preflight": preflight,
            "environment_criticality": 1.0,
            "target_criticality": 0.9,
            "blast_radius_fraction": 0.1,
        }
    )


def test_bridge_builds_immutable_governance_ready_plan_from_verified_context() -> None:
    planned = StructuredPlanBridge().apply(context=_context(), recommendation=_recommendation())

    assert planned.metadata["planning_status"] == "STRUCTURED_PLAN_READY"
    assert planned.metadata["governance_status"] == "POLICY_EVALUATION_REQUIRED"
    assert planned.metadata["governance_ready"] is True
    assert planned.metadata["execution_allowed"] is False
    assert planned.metadata["remediation_plan"]["target_resource_id"] == RESOURCE_ID
    assert planned.metadata["remediation_plan"]["target_version"] == "v7"
    assert planned.metadata["remediation_plan"]["connector_id"] == "k8s-prod"
    assert len(planned.metadata["plan_hash"]) == 64
    assert planned.metadata["plan_revision"] == 1


def test_bridge_fails_closed_when_preflight_facts_are_missing() -> None:
    planned = StructuredPlanBridge().apply(
        context=_context(complete_preflight=False),
        recommendation=_recommendation(),
    )

    assert planned.metadata["planning_status"] == "BLOCKED_PRE_GOVERNANCE"
    assert planned.metadata["execution_allowed"] is False
    assert "PREFLIGHT_FAILED" in planned.metadata["planning_error"]
    assert "CONNECTOR_UNAVAILABLE" in planned.metadata["planning_error"]


def test_bridge_never_infers_a_target_from_display_text() -> None:
    recommendation = _recommendation()
    recommendation.metadata.pop("target_resource_id")
    context = SimpleNamespace(metadata={"service": "payment-api"})

    planned = StructuredPlanBridge().apply(context=context, recommendation=recommendation)

    assert planned.metadata["planning_status"] == "TARGET_RESOLUTION_REQUIRED"
    assert planned.metadata["execution_allowed"] is False
    assert "remediation_plan" not in planned.metadata


def test_capability_registry_enforces_parameter_schema() -> None:
    registry = CapabilityRegistry()

    registry.validate_parameters("kubernetes.scale_workload", {"replicas": 3})

    try:
        registry.validate_parameters("kubernetes.scale_workload", {})
    except ValueError as exc:
        assert "CAPABILITY_PARAMETER_REQUIRED" in str(exc)
    else:
        raise AssertionError("missing required parameter was accepted")

    try:
        registry.validate_parameters("kubernetes.scale_workload", {"replicas": "three"})
    except ValueError as exc:
        assert "CAPABILITY_PARAMETER_INVALID" in str(exc)
    else:
        raise AssertionError("invalid parameter type was accepted")


def test_registry_contains_cross_platform_wave3_catalog() -> None:
    registry = CapabilityRegistry()
    expected = {
        "kubernetes.restart_workload",
        "windows.restart_service",
        "database.collect_diagnostics",
        "database.failover",
        "kafka.restart_consumer",
        "airflow.retry_task",
        "cloud.restart_vm",
        "cache.invalidate_keyspace",
        "jenkins.rollback_deployment",
        "terraform.rollback",
    }
    assert expected.issubset({definition.capability_id for definition in registry.list()})
