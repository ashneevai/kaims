from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from common.resolution_models import ValidationOutcome
from common.topics import APPROVAL_EVENTS, ORCHESTRATION_EVENTS


class ClosureRouteAction(StrEnum):
    COMPLETE = "COMPLETE"
    REASSESS = "REASSESS"
    REQUEST_ROLLBACK_APPROVAL = "REQUEST_ROLLBACK_APPROVAL"
    REQUEST_HITL = "REQUEST_HITL"


@dataclass(frozen=True)
class ClosureRouteDecision:
    action: ClosureRouteAction
    topic: str | None
    reason: str
    terminal: bool
    requires_human_approval: bool


def _coerce_outcome(value: ValidationOutcome | str | None) -> ValidationOutcome:
    if isinstance(value, ValidationOutcome):
        return value
    try:
        return ValidationOutcome(str(value or "").upper())
    except ValueError:
        return ValidationOutcome.INCONCLUSIVE


def route_closure_outcome(
    outcome: ValidationOutcome | str | None,
    *,
    next_action: str | None = None,
) -> ClosureRouteDecision:
    """Translate post-remediation validation into the next safe lifecycle step.

    The router deliberately never sends a rollback directly to remediation.
    A regression is higher risk than the original failed action and must pass
    through approval/HITL unless a later policy layer explicitly proves that a
    pre-approved rollback authorization exists.
    """

    resolved = _coerce_outcome(outcome)
    requested = str(next_action or "").strip().upper()

    if resolved == ValidationOutcome.RECOVERED:
        return ClosureRouteDecision(
            action=ClosureRouteAction.COMPLETE,
            topic=None,
            reason="independent validation proved sustained recovery",
            terminal=True,
            requires_human_approval=False,
        )

    if resolved in {ValidationOutcome.PARTIALLY_RECOVERED, ValidationOutcome.UNCHANGED}:
        return ClosureRouteDecision(
            action=ClosureRouteAction.REASSESS,
            topic=ORCHESTRATION_EVENTS,
            reason=requested or "post-remediation state requires reassessment",
            terminal=False,
            requires_human_approval=False,
        )

    if resolved == ValidationOutcome.WORSE:
        return ClosureRouteDecision(
            action=ClosureRouteAction.REQUEST_ROLLBACK_APPROVAL,
            topic=APPROVAL_EVENTS,
            reason=requested or "regression detected; rollback requires policy approval",
            terminal=False,
            requires_human_approval=True,
        )

    return ClosureRouteDecision(
        action=ClosureRouteAction.REQUEST_HITL,
        topic=APPROVAL_EVENTS,
        reason=requested or "validation is inconclusive or evidence is unavailable",
        terminal=False,
        requires_human_approval=True,
    )


def build_closure_route_payload(
    *,
    incident_id: str,
    outcome: ValidationOutcome | str | None,
    next_action: str | None,
    source_event_contract: dict[str, Any] | None = None,
    report_id: str | None = None,
    remediation_action_id: str | None = None,
) -> dict[str, Any]:
    decision = route_closure_outcome(outcome, next_action=next_action)
    source = source_event_contract if isinstance(source_event_contract, dict) else {}
    return {
        "incident_id": incident_id,
        "closure_outcome": _coerce_outcome(outcome).value,
        "route_action": decision.action.value,
        "route_reason": decision.reason,
        "terminal": decision.terminal,
        "requires_human_approval": decision.requires_human_approval,
        "report_id": report_id,
        "remediation_action_id": remediation_action_id,
        "flow_id": str(source.get("flow_id") or incident_id),
        "trace_id": str(source.get("trace_id") or ""),
        "correlation_id": str(source.get("correlation_id") or "") or None,
    }
