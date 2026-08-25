from __future__ import annotations

from typing import Any

from common.capability_registry import CapabilityRegistry, LEGACY_ACTION_CAPABILITIES
from common.models import Recommendation
from common.resolution_models import PlanSnapshot, RemediationPlan


class CapabilityContractGate:
    """Separates AI recommendation text from the governed execution contract.

    Legacy commands remain available only as an operator-facing preview. They never
    grant execution authority. A recommendation is execution-eligible only when it
    carries a valid structured `RemediationPlan` whose capability is registered.
    """

    def __init__(self, registry: CapabilityRegistry | None = None) -> None:
        self.registry = registry or CapabilityRegistry()

    @staticmethod
    def _exact_capability_intent(recommendation: Recommendation) -> str | None:
        metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
        remediation = metadata.get("remediation_analysis") if isinstance(metadata.get("remediation_analysis"), dict) else {}
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

    def apply(self, recommendation: Recommendation) -> Recommendation:
        metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
        metadata["execution_contract"] = "structured-remediation-plan-v1"
        metadata["legacy_execution_preview"] = {
            "recommended_action": recommendation.recommended_action,
            "commands": list(recommendation.commands),
            "display_only": True,
        }
        metadata["execution_allowed"] = False
        metadata["planning_status"] = "CAPABILITY_SELECTION_REQUIRED"

        plan_payload = metadata.get("remediation_plan")
        if isinstance(plan_payload, dict):
            try:
                plan = RemediationPlan.model_validate(plan_payload)
                self.registry.require(plan.recommended_capability)
            except Exception as exc:
                metadata["planning_status"] = "INVALID_REMEDIATION_PLAN"
                metadata["planning_error"] = str(exc)[:500]
                metadata.pop("plan_hash", None)
                metadata.pop("plan_revision", None)
                return recommendation.model_copy(update={"metadata": metadata})

            snapshot = PlanSnapshot.from_plan(plan)
            metadata["remediation_plan"] = plan.model_dump(mode="json")
            metadata["plan_hash"] = snapshot.plan_hash
            metadata["plan_revision"] = snapshot.plan_revision
            metadata["recommended_capability"] = plan.recommended_capability
            metadata["planning_status"] = "STRUCTURED_PLAN_READY"
            metadata["execution_allowed"] = bool(
                plan.preflight_assessment
                and plan.preflight_assessment.passed
                and plan.risk_assessment is not None
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
