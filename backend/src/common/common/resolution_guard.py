from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from common.reassessment import action_is_excluded


@dataclass(frozen=True)
class ResolutionGuardDecision:
    allowed: bool
    reason: str
    requires_hitl: bool


def evaluate_reassessment_recommendation(
    *,
    recommended_action: Any,
    recommended_capability: Any = None,
    decision_payload: dict[str, Any] | None = None,
) -> ResolutionGuardDecision:
    decision = decision_payload if isinstance(decision_payload, dict) else {}
    constraints = decision.get("reassessment_constraints")
    if not isinstance(constraints, dict):
        return ResolutionGuardDecision(True, "not a reassessment recommendation", False)

    if int(constraints.get("attempt") or 0) > int(constraints.get("max_attempts") or 3):
        return ResolutionGuardDecision(
            False,
            "reassessment retry budget exhausted",
            True,
        )

    if action_is_excluded(recommended_action, constraints):
        return ResolutionGuardDecision(
            False,
            "recommended action repeats an action that already failed validation",
            True,
        )
    if action_is_excluded(recommended_capability, constraints):
        return ResolutionGuardDecision(
            False,
            "recommended capability repeats a capability that already failed validation",
            True,
        )

    return ResolutionGuardDecision(
        True,
        "alternative action satisfies reassessment exclusion guard",
        False,
    )


def build_resolution_guard_hitl_payload(
    *,
    incident_id: str,
    recommendation: Any,
    decision_payload: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    constraints = decision_payload.get("reassessment_constraints")
    constraints = constraints if isinstance(constraints, dict) else {}
    recommendation_payload = (
        recommendation.model_dump(mode="json")
        if hasattr(recommendation, "model_dump")
        else recommendation
        if isinstance(recommendation, dict)
        else {"value": str(recommendation)}
    )
    return {
        "incident_id": incident_id,
        "route_action": "REQUEST_HITL",
        "route_reason": reason,
        "source": "resolution-agent-reassessment-guard",
        "flow_id": str(decision_payload.get("flow_id") or constraints.get("flow_id") or incident_id),
        "trace_id": str(decision_payload.get("trace_id") or constraints.get("trace_id") or ""),
        "correlation_id": str(
            decision_payload.get("correlation_id") or constraints.get("correlation_id") or ""
        ) or None,
        "reassessment_constraints": constraints,
        "blocked_recommendation": recommendation_payload,
    }
