from __future__ import annotations

import pytest

from common.lifecycle_controller import build_dispatch_from_closure_event, build_lifecycle_dispatch
from common.topics import HITL_REVIEW_EVENTS, REASSESSMENT_EVENTS, ROLLBACK_APPROVAL_EVENTS


def _event(outcome: str, next_action: str | None = None) -> dict:
    metadata = {"validation_outcome": outcome}
    if next_action:
        metadata["validation_next_action"] = next_action
    return {
        "report": {
            "id": "report-1",
            "metadata": metadata,
        },
        "remediation_action": {
            "id": "action-1",
            "incident_id": "11111111-1111-1111-1111-111111111111",
        },
        "event_contract": {
            "flow_id": "flow-1",
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "trace_id": "trace-1",
            "correlation_id": "corr-1",
            "payload": {"validation_outcome": outcome},
        },
    }


def test_recovered_is_terminal_and_emits_no_followup_topic() -> None:
    dispatch = build_dispatch_from_closure_event(_event("RECOVERED"))

    assert dispatch.terminal is True
    assert dispatch.destination_topic is None
    assert dispatch.action.value == "COMPLETE"
    assert dispatch.payload["terminal"] is True


def test_partial_recovery_routes_to_reassessment() -> None:
    dispatch = build_dispatch_from_closure_event(_event("PARTIALLY_RECOVERED", "REASSESS"))

    assert dispatch.destination_topic == REASSESSMENT_EVENTS
    assert dispatch.action.value == "REASSESS"
    assert dispatch.payload["requires_human_approval"] is False


def test_unchanged_routes_to_reassessment() -> None:
    dispatch = build_dispatch_from_closure_event(_event("UNCHANGED"))

    assert dispatch.destination_topic == REASSESSMENT_EVENTS


def test_worse_routes_to_dedicated_rollback_approval_topic() -> None:
    dispatch = build_dispatch_from_closure_event(_event("WORSE", "ROLLBACK_REQUIRED"))

    assert dispatch.destination_topic == ROLLBACK_APPROVAL_EVENTS
    assert dispatch.action.value == "REQUEST_ROLLBACK_APPROVAL"
    assert dispatch.payload["requires_human_approval"] is True


def test_inconclusive_routes_to_hitl() -> None:
    dispatch = build_dispatch_from_closure_event(_event("INCONCLUSIVE"))

    assert dispatch.destination_topic == HITL_REVIEW_EVENTS
    assert dispatch.action.value == "REQUEST_HITL"


def test_validation_data_unavailable_routes_to_hitl() -> None:
    dispatch = build_dispatch_from_closure_event(_event("VALIDATION_DATA_UNAVAILABLE"))

    assert dispatch.destination_topic == HITL_REVIEW_EVENTS


def test_unknown_outcome_fails_closed_to_hitl() -> None:
    dispatch = build_dispatch_from_closure_event(_event("SOMETHING_NEW"))

    assert dispatch.destination_topic == HITL_REVIEW_EVENTS
    assert dispatch.action.value == "REQUEST_HITL"


def test_trace_and_correlation_are_preserved() -> None:
    dispatch = build_dispatch_from_closure_event(_event("PARTIALLY_RECOVERED"))

    assert dispatch.payload["flow_id"] == "flow-1"
    assert dispatch.payload["trace_id"] == "trace-1"
    assert dispatch.payload["correlation_id"] == "corr-1"
    assert dispatch.payload["report_id"] == "report-1"
    assert dispatch.payload["remediation_action_id"] == "action-1"


def test_missing_incident_id_fails_closed() -> None:
    with pytest.raises(ValueError, match="incident_id"):
        build_lifecycle_dispatch(incident_id="", outcome="RECOVERED")
