from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from common.closure_routing import ClosureRouteAction, build_closure_route_payload, route_closure_outcome
from common.topics import HITL_REVIEW_EVENTS, REASSESSMENT_EVENTS, ROLLBACK_APPROVAL_EVENTS


@dataclass(frozen=True)
class LifecycleDispatch:
    incident_id: str
    action: ClosureRouteAction
    destination_topic: str | None
    payload: dict[str, Any]

    @property
    def terminal(self) -> bool:
        return self.destination_topic is None

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["action"] = self.action.value
        return value


def _destination_for(action: ClosureRouteAction) -> str | None:
    if action == ClosureRouteAction.COMPLETE:
        return None
    if action == ClosureRouteAction.REASSESS:
        return REASSESSMENT_EVENTS
    if action == ClosureRouteAction.REQUEST_ROLLBACK_APPROVAL:
        return ROLLBACK_APPROVAL_EVENTS
    return HITL_REVIEW_EVENTS


def build_lifecycle_dispatch(
    *,
    incident_id: str,
    outcome: Any,
    next_action: str | None = None,
    source_event_contract: dict[str, Any] | None = None,
    report_id: str | None = None,
    remediation_action_id: str | None = None,
    source_payload: dict[str, Any] | None = None,
) -> LifecycleDispatch:
    """Build the next post-validation lifecycle command.

    This controller deliberately publishes to dedicated feedback topics rather
    than reusing orchestration or approval topics whose payload schemas were
    designed for different stages of the incident pipeline.
    """

    normalized_incident_id = str(incident_id or "").strip()
    if not normalized_incident_id:
        raise ValueError("incident_id is required for lifecycle dispatch")

    decision = route_closure_outcome(outcome, next_action=next_action)
    route_payload = build_closure_route_payload(
        incident_id=normalized_incident_id,
        outcome=outcome,
        next_action=next_action,
        source_event_contract=source_event_contract,
        report_id=report_id,
        remediation_action_id=remediation_action_id,
    )
    route_payload["source_payload"] = source_payload if isinstance(source_payload, dict) else {}
    route_payload["dispatch_contract_version"] = "1.0"

    return LifecycleDispatch(
        incident_id=normalized_incident_id,
        action=decision.action,
        destination_topic=_destination_for(decision.action),
        payload=route_payload,
    )


def build_dispatch_from_closure_event(event: dict[str, Any]) -> LifecycleDispatch:
    """Translate a closure event into one safe feedback-loop dispatch."""

    if not isinstance(event, dict):
        raise ValueError("closure event must be a mapping")

    report = event.get("report")
    report_payload = report if isinstance(report, dict) else {}
    remediation = event.get("remediation_action")
    remediation_payload = remediation if isinstance(remediation, dict) else {}
    contract = event.get("event_contract")
    contract_payload = contract if isinstance(contract, dict) else {}
    contract_body = contract_payload.get("payload")
    contract_body = contract_body if isinstance(contract_body, dict) else {}
    metadata = report_payload.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    incident_id = str(
        remediation_payload.get("incident_id")
        or contract_payload.get("incident_id")
        or contract_body.get("incident_id")
        or ""
    ).strip()
    outcome = (
        metadata.get("validation_outcome")
        or metadata.get("validation_status")
        or contract_body.get("validation_outcome")
    )
    next_action = metadata.get("validation_next_action") or contract_body.get("next_action")

    return build_lifecycle_dispatch(
        incident_id=incident_id,
        outcome=outcome,
        next_action=next_action,
        source_event_contract=contract_payload,
        report_id=str(report_payload.get("id") or "") or None,
        remediation_action_id=str(remediation_payload.get("id") or "") or None,
        source_payload=event,
    )
