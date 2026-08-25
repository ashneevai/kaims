from __future__ import annotations

from typing import Any

from common.capability_registry import CapabilityRegistry
from common.models import Recommendation
from common.preflight_engine import PreflightInputs
from common.resolution_models import (
    AutonomyRecommendation,
    RollbackPlan,
    ValidationCheck,
    ValidationPlan,
)
from common.structured_resolution_planner import PlanningContext, StructuredPlanRequest, StructuredResolutionPlanner
from common.target_resolution import DictResourceLookup, TargetResolver


class StructuredPlanBridge:
    """Convert an AI recommendation into a governed RemediationPlan when facts permit it.

    This bridge never invents target identity, connector readiness, permissions, or
    validation evidence. Missing execution-grade context leaves the recommendation in
    a non-executable planning state.
    """

    def __init__(self, registry: CapabilityRegistry | None = None) -> None:
        self.registry = registry or CapabilityRegistry()

    @staticmethod
    def _metadata(context: Any) -> dict[str, Any]:
        value = getattr(context, "metadata", {})
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _resources(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
        raw = metadata.get("operational_resources") or metadata.get("resource_catalog") or {}
        if isinstance(raw, dict):
            return {str(key): dict(value) for key, value in raw.items() if isinstance(value, dict)}
        if isinstance(raw, list):
            result: dict[str, dict[str, Any]] = {}
            for value in raw:
                if not isinstance(value, dict):
                    continue
                resource_id = str(value.get("resource_id") or value.get("stable_id") or "").strip()
                if resource_id:
                    result[resource_id] = dict(value)
            return result
        return {}

    @staticmethod
    def _truthy(value: Any) -> bool:
        return value is True

    def apply(self, *, context: Any, recommendation: Recommendation) -> Recommendation:
        metadata = dict(recommendation.metadata if isinstance(recommendation.metadata, dict) else {})
        context_metadata = self._metadata(context)

        capability_id = str(
            metadata.get("recommended_capability")
            or context_metadata.get("recommended_capability")
            or ""
        ).strip().lower()
        if not capability_id or not self.registry.is_registered(capability_id):
            metadata["planning_status"] = "CAPABILITY_SELECTION_REQUIRED"
            metadata["execution_allowed"] = False
            return recommendation.model_copy(update={"metadata": metadata})

        target_resource_id = str(
            metadata.get("target_resource_id")
            or context_metadata.get("target_resource_id")
            or ""
        ).strip()
        if not target_resource_id.startswith("kai://"):
            metadata["planning_status"] = "TARGET_RESOLUTION_REQUIRED"
            metadata["execution_allowed"] = False
            return recommendation.model_copy(update={"metadata": metadata})

        resources = self._resources(context_metadata)
        target_payload = resources.get(target_resource_id)
        if not target_payload:
            metadata["planning_status"] = "TARGET_RESOLUTION_REQUIRED"
            metadata["planning_error"] = "TARGET_NOT_FOUND_IN_OPERATIONAL_CONTEXT"
            metadata["execution_allowed"] = False
            return recommendation.model_copy(update={"metadata": metadata})

        connector_id = str(
            metadata.get("connector_id")
            or context_metadata.get("connector_id")
            or target_payload.get("connector_id")
            or ""
        ).strip()
        if not connector_id:
            metadata["planning_status"] = "TARGET_RESOLUTION_REQUIRED"
            metadata["planning_error"] = "CONNECTOR_ID_REQUIRED"
            metadata["execution_allowed"] = False
            return recommendation.model_copy(update={"metadata": metadata})

        capability = self.registry.require(capability_id)
        validation_checks = [
            ValidationCheck(
                check_id=str(check),
                provider=capability.provider,
                signal=str(check),
                operator="eq",
                expected_value=True,
                resource_id=target_resource_id,
                required=True,
            )
            for check in capability.validation_template.get("checks", [])
        ]
        validation_plan = ValidationPlan(checks=validation_checks)
        if capability.validation_required and not validation_checks:
            metadata["planning_status"] = "VALIDATION_PLAN_REQUIRED"
            metadata["execution_allowed"] = False
            return recommendation.model_copy(update={"metadata": metadata})

        pre_action_state = context_metadata.get("pre_action_state")
        if not isinstance(pre_action_state, dict):
            pre_action_state = {}
        rollback_plan = None
        if capability.reversible:
            rollback_plan = RollbackPlan(
                capability_id=capability.rollback_capability,
                target_resource_id=target_resource_id,
                pre_action_state=pre_action_state,
                available=bool(capability.rollback_capability and pre_action_state),
            )

        preflight = context_metadata.get("preflight")
        preflight = preflight if isinstance(preflight, dict) else {}
        preflight_inputs = PreflightInputs(
            connector_available=self._truthy(preflight.get("connector_available")),
            credentials_valid=self._truthy(preflight.get("credentials_valid")),
            permissions_sufficient=self._truthy(preflight.get("permissions_sufficient")),
            preconditions_hold=self._truthy(preflight.get("preconditions_hold")),
            incident_still_active=preflight.get("incident_still_active") is not False,
            conflicting_remediation=self._truthy(preflight.get("conflicting_remediation")),
            change_freeze_active=self._truthy(preflight.get("change_freeze_active")),
        )

        affected = context_metadata.get("affected_resource_ids")
        affected_resource_ids = [str(item) for item in affected] if isinstance(affected, list) else [target_resource_id]
        evidence_ids = metadata.get("evidence_ids") or context_metadata.get("evidence_ids") or []
        if not isinstance(evidence_ids, list):
            evidence_ids = []

        planner = StructuredResolutionPlanner(
            registry=self.registry,
            target_resolver=TargetResolver(DictResourceLookup(resources)),
        )
        try:
            planned = planner.build(
                request=StructuredPlanRequest(
                    incident_id=recommendation.incident_id,
                    root_cause=recommendation.root_cause,
                    rca_confidence=float(recommendation.confidence),
                    evidence_confidence=float(metadata.get("evidence_confidence") or recommendation.confidence),
                    recommended_capability=capability_id,
                    target_resource_id=target_resource_id,
                    target_version=str(target_payload.get("current_version") or target_payload.get("version") or "").strip() or None,
                    connector_id=connector_id,
                    parameters=dict(metadata.get("capability_parameters") or {}),
                    preconditions=[str(item) for item in metadata.get("preconditions", []) if str(item).strip()],
                    expected_effect=str(metadata.get("expected_effect") or recommendation.rationale or "Recovery expected after capability execution."),
                    validation_plan=validation_plan,
                    rollback_plan=rollback_plan,
                    evidence_ids=[str(item) for item in evidence_ids],
                    affected_resource_ids=affected_resource_ids,
                    hypothesis_id=str(metadata.get("hypothesis_id") or "").strip() or None,
                    blast_radius=dict(metadata.get("blast_radius") or {}),
                    dry_run_required=True,
                    autonomy_recommendation=AutonomyRecommendation.HITL_REQUIRED,
                ),
                preflight_inputs=preflight_inputs,
                planning_context=PlanningContext(
                    environment_criticality=float(context_metadata.get("environment_criticality", 1.0)),
                    target_criticality=float(context_metadata.get("target_criticality", 1.0)),
                    blast_radius_fraction=float(context_metadata.get("blast_radius_fraction", 1.0)),
                    previous_failure_risk=float(context_metadata.get("previous_failure_risk", 0.0)),
                ),
            )
        except Exception as exc:
            metadata["planning_status"] = "BLOCKED_PRE_GOVERNANCE"
            metadata["planning_error"] = str(exc)[:500]
            metadata["execution_allowed"] = False
            return recommendation.model_copy(update={"metadata": metadata})

        metadata["remediation_plan"] = planned.plan.model_dump(mode="json")
        metadata["plan_hash"] = planned.snapshot.plan_hash
        metadata["plan_revision"] = planned.snapshot.plan_revision
        metadata["recommended_capability"] = planned.plan.recommended_capability
        metadata["target_resource_id"] = planned.plan.target_resource_id
        metadata["connector_id"] = planned.plan.connector_id
        metadata["planning_status"] = "STRUCTURED_PLAN_READY"
        metadata["governance_status"] = "POLICY_EVALUATION_REQUIRED"
        metadata["governance_ready"] = True
        metadata["execution_allowed"] = False
        return recommendation.model_copy(update={"metadata": metadata})
