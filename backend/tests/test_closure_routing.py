from __future__ import annotations

from common.closure_routing import ClosureRouteAction, build_closure_route_payload, route_closure_outcome
from common.resolution_models import ValidationOutcome
from common.topics import APPROVAL_EVENTS, ORCHESTRATION_EVENTS


def test_recovered_is_terminal_and_emits_no_followup_topic() -> None:
    decision = route_closure_outcome(ValidationOutcome.RECOVERED)

    assert decision.action == ClosureRouteAction.COMPLETE
    assert decision.topic is None
    assert decision.terminal is True
    assert decision.requires_human_approval is False


def test_partial_recovery_reassesses_without_forcing_human_approval() -> None:
    decision = route_closure_outcome(
        ValidationOutcome.PARTIALLY_RECOVERED,
        next_action="REASSESS",
    )

    assert decision.action == ClosureRouteAction.REASSESS
    assert decision.topic == ORCHESTRATION_EVENTS
    assert decision.terminal is False
    assert decision.requires_human_approval is False


def test_unchanged_reassesses() -> None:
    decision = route_closure_outcome(ValidationOutcome.UNCHANGED)

    assert decision.action == ClosureRouteAction.REASSESS
    assert decision.topic == ORCHESTRATION_EVENTS


def test_worse_never_routes_directly_to_remediation() -> None:
    decision = route_closure_outcome(
        ValidationOutcome.WORSE,
        next_action="ROLLBACK_REQUIRED",
    )

    assert decision.action == ClosureRouteAction.REQUEST_ROLLBACK_APPROVAL
    assert decision.topic == APPROVAL_EVENTS
    assert decision.requires_human_approval is True
    assert decision.terminal is False


def test_inconclusive_routes_to_hitl() -> None:
    decision = route_closure_outcome(
        ValidationOutcome.INCONCLUSIVE,
        next_action="EXTEND_VALIDATION_OR_HITL",
    )

    assert decision.action == ClosureRouteAction.REQUEST_HITL
    assert decision.topic == APPROVAL_EVENTS
    assert decision.requires_human_approval is True


def test_validation_data_unavailable_holds_open_for_hitl() -> None:
    decision = route_closure_outcome(
        ValidationOutcome.VALIDATION_DATA_UNAVAILABLE,
        next_action="HOLD_OPEN_VALIDATION_PLAN_REQUIRED",
    )

    assert decision.action == ClosureRouteAction.REQUEST_HITL
    assert decision.topic == APPROVAL_EVENTS
    assert decision.terminal is False


def test_unknown_outcome_fails_closed_to_hitl() -> None:
    decision = route_closure_outcome("SOMETHING_NEW")

    assert decision.action == ClosureRouteAction.REQUEST_HITL
    assert decision.topic == APPROVAL_EVENTS
    assert decision.requires_human_approval is True


def test_route_payload_preserves_traceability() -> None:
    payload = build_closure_route_payload(
        incident_id="incident-1",
        outcome=ValidationOutcome.WORSE,
        next_action="ROLLBACK_REQUIRED",
        source_event_contract={
            "flow_id": "flow-1",
            "trace_id": "trace-1",
            "correlation_id": "corr-1",
        },
        report_id="report-1",
        remediation_action_id="action-1",
    )

    assert payload["incident_id"] == "incident-1"
    assert payload["closure_outcome"] == ValidationOutcome.WORSE.value
    assert payload["route_action"] == ClosureRouteAction.REQUEST_ROLLBACK_APPROVAL.value
    assert payload["requires_human_approval"] is True
    assert payload["flow_id"] == "flow-1"
    assert payload["trace_id"] == "trace-1"
    assert payload["correlation_id"] == "corr-1"
    assert payload["report_id"] == "report-1"
    assert payload["remediation_action_id"] == "action-1"
