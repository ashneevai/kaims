from __future__ import annotations

from common.resolution_guard import evaluate_reassessment_recommendation


def _decision(*, attempt: int = 1) -> dict:
    return {
        "workflow": "REASSESSMENT",
        "reassessment_constraints": {
            "attempt": attempt,
            "max_attempts": 3,
            "excluded_action_signatures": [
                "kubernetes.rollback.deployment",
                "rollback.deployment",
            ],
        },
    }


def test_normal_resolution_is_not_blocked() -> None:
    result = evaluate_reassessment_recommendation(
        recommended_action="rollback deployment",
        decision_payload={},
    )
    assert result.allowed is True
    assert result.requires_hitl is False


def test_reassessment_blocks_repeated_failed_action() -> None:
    result = evaluate_reassessment_recommendation(
        recommended_action="Rollback Deployment",
        decision_payload=_decision(),
    )
    assert result.allowed is False
    assert result.requires_hitl is True
    assert "repeats" in result.reason


def test_reassessment_blocks_repeated_failed_capability() -> None:
    result = evaluate_reassessment_recommendation(
        recommended_action="restart pod",
        recommended_capability="kubernetes.rollback_deployment",
        decision_payload=_decision(),
    )
    assert result.allowed is False
    assert result.requires_hitl is True


def test_reassessment_allows_alternative_action() -> None:
    result = evaluate_reassessment_recommendation(
        recommended_action="restart pod",
        recommended_capability="kubernetes.restart_pod",
        decision_payload=_decision(),
    )
    assert result.allowed is True
    assert result.requires_hitl is False


def test_exhausted_retry_budget_is_blocked() -> None:
    result = evaluate_reassessment_recommendation(
        recommended_action="restart pod",
        decision_payload=_decision(attempt=4),
    )
    assert result.allowed is False
    assert result.requires_hitl is True
    assert "budget" in result.reason
