from __future__ import annotations

import pytest

from common.reassessment import (
    action_is_excluded,
    build_reassessment_constraints,
    normalize_action_signature,
)


def _event() -> dict:
    return {
        "incident_id": "11111111-1111-1111-1111-111111111111",
        "action": "REASSESS",
        "destination_topic": "incident-reassessment-events",
        "payload": {
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "flow_id": "flow-a",
            "trace_id": "trace-a",
            "correlation_id": "corr-a",
            "remediation_action_id": "22222222-2222-2222-2222-222222222222",
            "source_payload": {
                "report": {
                    "root_cause": "bad deployment",
                },
                "remediation_action": {
                    "id": "22222222-2222-2222-2222-222222222222",
                    "action_type": "kubernetes.rollback_deployment",
                    "target": "kai://workload/checkout",
                    "parameters": {
                        "root_cause": "bad deployment",
                        "recommended_action": "Rollback Deployment",
                    },
                },
                "event_contract": {"metadata": {"root_cause": "bad deployment"}},
            },
        },
    }


def test_reassessment_extracts_failed_action_and_hypothesis_from_nested_dispatch() -> None:
    constraints = build_reassessment_constraints(_event())

    assert constraints.attempt == 1
    assert constraints.exhausted is False
    assert "kubernetes.rollback.deployment" in constraints.excluded_action_signatures
    assert "rollback.deployment" in constraints.excluded_action_signatures
    assert constraints.rejected_hypotheses == ("bad deployment",)
    assert constraints.previous_remediation_action_ids == (
        "22222222-2222-2222-2222-222222222222",
    )
    assert constraints.flow_id == "flow-a"
    assert constraints.trace_id == "trace-a"
    assert constraints.correlation_id == "corr-a"


def test_retry_budget_exhausts_after_configured_attempts() -> None:
    constraints = build_reassessment_constraints(_event(), prior_attempts=3, max_attempts=3)
    assert constraints.attempt == 4
    assert constraints.exhausted is True


def test_action_exclusion_is_format_insensitive() -> None:
    constraints = build_reassessment_constraints(_event())

    assert action_is_excluded("Kubernetes Rollback Deployment", constraints)
    assert action_is_excluded("rollback_deployment", constraints)
    assert not action_is_excluded("kubernetes.restart_pod", constraints)


def test_action_signature_is_deterministic() -> None:
    assert normalize_action_signature("  kubernetes/Restart_Pod ") == "kubernetes.restart.pod"


def test_missing_incident_fails_closed() -> None:
    with pytest.raises(ValueError, match="incident_id"):
        build_reassessment_constraints({"payload": {}})


def test_invalid_retry_budget_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        build_reassessment_constraints(_event(), max_attempts=0)
