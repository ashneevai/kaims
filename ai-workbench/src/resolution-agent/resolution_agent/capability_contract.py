from __future__ import annotations

from typing import Any

from common.capability_registry import CapabilityRegistry, LEGACY_ACTION_CAPABILITIES
from common.models import Recommendation
from common.resolution_models import PlanSnapshot, RemediationPlan


class CapabilityContractGate:
    """Separate AI recommendation text from the governed execution contract.

    Legacy commands remain available only as an operator-facing preview. They never
    grant execution authority. A valid structured plan becomes governance-ready;
    policy and approval remain independent requirements before execution.
    """

    def __init__(self, registry: CapabilityRegistry | None = None) -> None:
        self.registry = registry or CapabilityRegistry()

    @staticmethod
    def _exact_capability_intent(recommendation: Recommendation) -> str | None:
        metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
        remediation = (
            metadata.get("remediation_analysis")
            if isinstance(metadata.get("remediation_analysis"), dict)
            else {}
        )
        candidates: list[Any] = [
            metadata.get("recommended_capability"),
            remediation.get("recommended_capability"),
            recommendation.recommended_action,
        ]
        for candidate in candidates:
            token = str(candidate or "").strip().lower()
            if token:
                return token
        return None

    @staticmethod
    def _force_quality_gate_review(metadata: dict[str, Any]) -> None:
        quality_gate = (
            metadata.get("quality_gate")
            if isinstance(metadata.get("quality_gate"), dict)
            else {}
        )
        quality_gate["trusted_for_auto_execution"] = False
        quality_gate["requires_human_review"] = True
        quality_gate["execution_contract_reason"] = (
            "structured remediation plan and independent governance are required before execution"
        )
        metadata["quality_gate"] = quality_gate

    def apply(self, recommendation: Recommendation) -> Recommendation:
        metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
        metadata["execution_contract"] = "structured-remediation-plan-v1"
        metadata["legacy_execution_preview"] = {
            "recommended_action": recommendation.recommended_action,
            "commands": list(recommendation.commands),
            "display_only": True,
        }
        metadata["execution_allowed"] = False
        metadata["governance_ready"] = False
        metadata["governance_status"] = "PLANNING_REQUIRED"
        metadata["planning_status"] = "CAPABILITY_SELECTION_REQUIRED"
        self._force_quality_gate_review(metadata)

        plan_payload = metadata.get("remediation_plan")
        if isinstance(plan_payload, dict):
            try:
                plan = RemediationPlan.model_validate(plan_payload)
                self.registry.require(plan.recommended_capability)
            except Exception as exc:
                metadata["planning_status"] = "INVALID_REMEDIATION_PLAN"
                metadata["governance_status"] = "BLOCKED_INVALID_PLAN"
                metadata["planning_error"] = str(exc)[:500]
                metadata.pop("plan_hash", None)
                metadata.pop("plan_revision", None)
                return recommendation.model_copy(update={"metadata": metadata})

            snapshot = PlanSnapshot.from_plan(plan)
            governance_ready = bool(
                plan.preflight_assessment
                and plan.preflight_assessment.passed
                and plan.risk_assessment is not None
            )
            metadata["remediation_plan"] = plan.model_dump(mode="json")
            metadata["plan_hash"] = snapshot.plan_hash
            metadata["plan_revision"] = snapshot.plan_revision
            metadata["recommended_capability"] = plan.recommended_capability
            metadata["planning_status"] = "STRUCTURED_PLAN_READY"
            metadata["governance_ready"] = governance_ready
            metadata["governance_status"] = (
                "POLICY_EVALUATION_REQUIRED"
                if governance_ready
                else "BLOCKED_PRE_GOVERNANCE"
            )
            quality_gate = metadata["quality_gate"]
            quality_gate["requires_human_review"] = True
            quality_gate["trusted_for_auto_execution"] = False
            quality_gate["execution_contract_reason"] = (
                "structured plan is ready for independent policy and approval evaluation"
                if governance_ready
                else "structured plan has not passed mandatory pre-governance checks"
            )
            return recommendation.model_copy(update={"metadata": metadata})

        exact_intent = self._exact_capability_intent(recommendation)
        if exact_intent and self.registry.is_registered(exact_intent):
            metadata["recommended_capability"] = exact_intent
            metadata["planning_status"] = "TARGET_RESOLUTION_REQUIRED"
        elif exact_intent in LEGACY_ACTION_CAPABILITIES:
            metadata["recommended_capability"] = LEGACY_ACTION_CAPABILITIES[exact_intent]
            metadata["planning_status"] = "TARGET_RESOLUTION_REQUIRED"

        return recommendation.model_copy(update={"metadata": metadata})
