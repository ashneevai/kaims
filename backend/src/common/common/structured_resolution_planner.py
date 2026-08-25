from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from common.capability_registry import CapabilityRegistry
from common.preflight_engine import PreflightEngine, PreflightInputs
from common.resolution_models import (
    AutonomyRecommendation,
    ExecutionStrategy,
    PlanSnapshot,
    RemediationPlan,
    RollbackPlan,
    ValidationPlan,
)
from common.risk_engine import RiskEngine
from common.target_resolution import TargetResolver


@dataclass(slots=True)
class StructuredPlanRequest:
    incident_id: UUID
    root_cause: str
    rca_confidence: float
    evidence_confidence: float
    recommended_capability: str
    target_resource_id: str
    target_version: str | None
    connector_id: str
    parameters: dict[str, Any]
    preconditions: list[str]
    expected_effect: str
    validation_plan: ValidationPlan
    rollback_plan: RollbackPlan | None = None
    evidence_ids: list[str] | None = None
    affected_resource_ids: list[str] | None = None
    hypothesis_id: str | None = None
    blast_radius: dict[str, Any] | None = None
    dry_run_required: bool = True
    execution_strategy: ExecutionStrategy = ExecutionStrategy.SINGLE
    autonomy_recommendation: AutonomyRecommendation = AutonomyRecommendation.HITL_REQUIRED


@dataclass(slots=True)
class PlanningContext:
    environment_criticality: float
    target_criticality: float
    blast_radius_fraction: float
    previous_failure_risk: float = 0.0


@dataclass(slots=True)
class PlannedResolution:
    plan: RemediationPlan
    snapshot: PlanSnapshot


class StructuredResolutionPlanner:
    """Build the only governance-ready remediation contract.

    Planning is deterministic after the AI has selected a registered capability. The
    planner validates parameters, resolves a stable target, runs preflight and risk,
    and creates the immutable snapshot consumed by approval/execution.
    """

    def __init__(
        self,
        *,
        registry: CapabilityRegistry,
        target_resolver: TargetResolver,
        preflight_engine: PreflightEngine | None = None,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        self.registry = registry
        self.target_resolver = target_resolver
        self.preflight_engine = preflight_engine or PreflightEngine()
        self.risk_engine = risk_engine or RiskEngine()

    def build(
        self,
        *,
        request: StructuredPlanRequest,
        preflight_inputs: PreflightInputs,
        planning_context: PlanningContext,
    ) -> PlannedResolution:
        capability = self.registry.require(request.recommended_capability)
        self.registry.validate_parameters(request.recommended_capability, request.parameters)

        target = self.target_resolver.resolve(
            resource_id=request.target_resource_id,
            connector_id=request.connector_id,
            expected_version=request.target_version,
        )
        self.registry.validate_for_target(
            request.recommended_capability,
            resource_type=target.resource_type,
            environment=target.environment,
        )

        if request.dry_run_required and not capability.dry_run_supported and capability.risk_class.lower() in {"high", "critical"}:
            raise ValueError(
                f"DRY_RUN_UNSUPPORTED_FOR_HIGH_RISK_CAPABILITY: {capability.capability_id}"
            )

        plan = RemediationPlan(
            incident_id=request.incident_id,
            hypothesis_id=request.hypothesis_id,
            root_cause=request.root_cause,
            rca_confidence=request.rca_confidence,
            evidence_confidence=request.evidence_confidence,
            affected_resource_ids=request.affected_resource_ids or [request.target_resource_id],
            recommended_capability=capability.capability_id,
            target_resource_id=target.resource_id,
            target_version=target.current_version,
            connector_id=target.connector_id,
            parameters=request.parameters,
            preconditions=request.preconditions,
            expected_effect=request.expected_effect,
            blast_radius=request.blast_radius or {},
            dry_run_required=request.dry_run_required,
            execution_strategy=request.execution_strategy,
            validation_plan=request.validation_plan,
            rollback_plan=request.rollback_plan,
            evidence_ids=request.evidence_ids or [],
            autonomy_recommendation=request.autonomy_recommendation,
        )

        preflight = self.preflight_engine.assess(
            plan=plan,
            capability=capability,
            target=target,
            inputs=preflight_inputs,
        )
        plan = plan.model_copy(update={"preflight_assessment": preflight})
        if not preflight.passed:
            raise ValueError(f"PREFLIGHT_FAILED: {', '.join(preflight.failures)}")

        risk = self.risk_engine.assess(
            plan=plan,
            capability=capability,
            environment_criticality=planning_context.environment_criticality,
            target_criticality=planning_context.target_criticality,
            blast_radius_fraction=planning_context.blast_radius_fraction,
            previous_failure_risk=planning_context.previous_failure_risk,
        )
        plan = plan.model_copy(update={"risk_assessment": risk})

        if risk.risk_class in {"high", "critical"}:
            plan = plan.model_copy(update={"autonomy_recommendation": AutonomyRecommendation.HITL_REQUIRED})
        if capability.required_approval or capability.trust_level.value in {"EXPERIMENTAL", "HITL_ONLY"}:
            plan = plan.model_copy(update={"autonomy_recommendation": AutonomyRecommendation.HITL_REQUIRED})

        return PlannedResolution(plan=plan, snapshot=PlanSnapshot.from_plan(plan))
